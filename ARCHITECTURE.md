
# proto-fuzz-virtio-*: in-process LPM-driven structured fuzzers for QEMU virtio devices

Currently shipped: `virtio-blk`, `virtio-net`, `virtio-gpu`,
`virtio-scsi`, `virtio-fs`, `virtio-snd`, `virtio-vsock`,
`virtio-console`, `virtio-input`, `virtio-balloon` -- 10 targets.
This document uses `virtio-blk` as the worked example throughout
because it was the first target written; every other target
follows the same pattern.

This document describes the architecture and build of the
`proto-fuzz-virtio-blk` fuzz target inside `qemu-fuzz-aarch64`. The
goal of this work was to fuzz QEMU's virtio-blk emulation **inside a
single process** -- libFuzzer + libprotobuf-mutator + the QEMU machine
model + the test harness all live together in one Mach-O binary on
Apple Silicon, with no Linux container, no qtest socket, and no VM
boot.

The reader is assumed to know roughly what virtio is and what
libFuzzer / libprotobuf-mutator (LPM) do. Everything else is below.

Example invocations (any of the 10 targets):

```sh
B=$BUILD/build-fuzz/qemu-fuzz-aarch64
$B --fuzz-target=proto-fuzz-virtio-gpu -close_fd_mask=2 -max_len=65536 /tmp/proto_fuzz_run/corpus_gpu
$B --fuzz-target=proto-fuzz-virtio-net -close_fd_mask=2 -max_len=65536 /tmp/proto_fuzz_run/corpus_net
```

---

## 1. The high-level picture

```text
+---------------------------------------------------------------------+
|                                                                     |
|                    qemu-fuzz-aarch64  (one Mach-O)                  |
|                                                                     |
|   +-------------------+      +-------------------------------+      |
|   |  libFuzzer +      |      |   libprotobuf-mutator (LPM)   |      |
|   |  SanitizerCoverage|<---->|   + libprotobuf + abseil      |      |
|   |  + AddressSanit.  |      |                               |      |
|   +---------+---------+      +---------------+---------------+      |
|             |                                |                      |
|             | LLVMFuzzerInitialize           | CustomProtoMutator   |
|             | LLVMFuzzerTestOneInput         | LoadProtoInput       |
|             v                                v                      |
|   +---------------------+    +-------------------------------+      |
|   |  fuzz.c dispatcher  |    |  proto_fuzz_virtio_blk.cc     |      |
|   |  (FuzzTarget table) +--->|  (registered FuzzTarget)      |      |
|   +---------------------+    +---------------+---------------+      |
|                                              |                      |
|                                              | qtest_writel/memwrite|
|                                              v                      |
|   +-------------------------------------------------------------+   |
|   |                   QEMU machine model (vl_main)              |   |
|   |  -machine virt  -m 128  -device virtio-blk-device,drive=hd0 |   |
|   |  -drive ...,file=null-co://,read-zeroes=on                  |   |
|   |                                                             |   |
|   |   +-------------+    +-----------------+   +-------------+  |   |
|   |   | DRAM        |    | virtio-mmio[0]  |   | virtio-blk  |  |   |
|   |   | 0x40000000  |    | 0x0a000000      |-->| device      |  |   |
|   |   |  ...        |    | size 0x200      |   | emulation   |  |   |
|   |   | 0x48000000  |    +-----------------+   +------+------+  |   |
|   |   +------+------+                                 |         |   |
|   |          ^                                        |         |   |
|   |          | descriptor / avail / used / buffer GPAs|         |   |
|   |          +----------------------------------------+         |   |
|   +-------------------------------------------------------------+   |
|                                                                     |
+---------------------------------------------------------------------+
```

Every arrow is a function call inside the same address space. There is
no IPC anywhere. The vCPU is not running -- the qtest accelerator
provides synchronous in-thread "guest" accesses, which is what makes
the whole thing single-threaded and deterministic.

---

## 2. Per-iteration data flow

This is what happens for **each fuzz input** libFuzzer produces:

```text
   libFuzzer main loop                    proto_fuzz_virtio_blk_run()
   --------------------                   ---------------------------

   pick / mutate input                    LoadProtoInput(false, data,
   uint8_t* data, size_t size                          size, &prog)
            |                                          |
            v                                          v
   LLVMFuzzerCustomMutator   <--- LPM ---     parse text-format proto
   (our LPM-aware mutator)                    into a VirtioBlkProgram
            |
            v                                 reset_iteration_state()
   LLVMFuzzerTestOneInput                       virtio status = 0
            |                                   then ACK | DRIVER
            v
   fuzz.c: fuzz_target->fuzz(...)           for op in prog.ops():
            |                                   dispatch(op)
            v                                       |
   proto_fuzz_virtio_blk_run -----------------------+
                                                    |
                                                    |  GetFeatures
                                                    |  SetFeatures
                                                    |  VqSetup
                                                    |  GuestMemWrite
                                                    |  VqAddDesc
                                                    |  VqKick
                                                    |  VqWaitUsed
                                                    |  Reset
                                                    v
                                               qtest_writel/memwrite
                                                    (in-process)
                                                    |
                                                    v
                                          virtio-mmio register dispatch
                                                    |
                                                    v
                                          hw/virtio/virtio.c +
                                          hw/block/virtio-blk.c run
                                                    |
                                                    v
                                          flush_events(): main_loop_wait
                                          handles bottom halves on the
                                          same thread

           coverage diff  <----- SanCov instrumentation -----+
                                 (PC-tables + 8-bit counters)
```

There is exactly one OS thread doing all of this. libFuzzer never
forks during the hot loop (we don't pass `-fork=N`), and the qtest
accelerator never spins up a vCPU thread.

---

## 3. Why this is in-process and not VM-booting

A "real VM" virtio path looks like:

```text
        guest userland
                |                                Linux kernel
                v                                ------------------------
        syscall (e.g. read)
                |
                v
        block layer / VFS / fs
                |
                v
        struct virtio_blk        virtio_blk.c (guest)
                |
                v
        struct virtqueue add     virtio_ring.c (guest)
                |
                v
        virtqueue_kick           writes to virtio_mmio.c (guest)
                |
                v                                ========================
        MMIO write to            HVF/KVM/TCG VM exit
        0x0a000050 (QueueNotify) ------------------------------------------
                                                  QEMU
                                 +---------------------------+
                                 |  hw/virtio/virtio-mmio.c  |
                                 |    decode register        |
                                 +-------------+-------------+
                                               |
                                               v
                                 +---------------------------+
                                 |  hw/virtio/virtio.c       |
                                 |    walk descriptor chain  |
                                 +-------------+-------------+
                                               |
                                               v
                                 +---------------------------+
                                 |  hw/block/virtio-blk.c    |
                                 |    request emulation      |
                                 +---------------------------+
```

Every layer above the dashed line is *inside the guest*. To reach the
QEMU code we need a functioning kernel, a working virtio_mmio.c
driver, a working block layer, and a process making syscalls. To
fuzz, we'd have to mutate the guest userland behavior, then crank the
whole stack through HVF or TCG every iteration.

Our path collapses all of that:

```text
        proto_fuzz_virtio_blk.cc
                |
                v                                ========================
        qtest_writel(s, 0x0a000050, vq_idx)
                |
                |  (weak-symbol indirection -- next section)
                v
                                 +---------------------------+
                                 |  hw/virtio/virtio-mmio.c  |
                                 |    decode register        |
                                 +-------------+-------------+
                                               |
                                               v
                                 +---------------------------+
                                 |  hw/virtio/virtio.c       |
                                 |    walk descriptor chain  |
                                 +-------------+-------------+
                                               |
                                               v
                                 +---------------------------+
                                 |  hw/block/virtio-blk.c    |
                                 |    request emulation      |
                                 +---------------------------+
```

`qtest_writel` is just a function call -- it lands in the same code
the guest's kernel write would land in, but with no kernel, no driver
stack, no MMU, no exit, and no mode switch. **A bug we trigger here
is reachable from a real guest** because both paths converge on
`hw/virtio/virtio-mmio.c`. The harness is more direct, not a
different surface.

---

## 4. The qtest_* weak-symbol indirection

This is the load-bearing trick that lets a `qtest_*` call land
in-process instead of going over a Unix socket to a separate
`qemu-system-*`.

In a normal qos-test binary, `qtest_writel` looks like:

```text
        qtest_writel(s, addr, value)
                |
                v
        qtest_sendf(s, "writel 0x%lx 0x%x\n", addr, value)
                |
                v
        write(socket_fd, ...)              <-- crosses to qemu-system-*
                                               which receives the
                                               command, decodes the
                                               register, and runs the
                                               device emulation
```

For fuzzing we want the device emulation to run **in the same
process**, so that the cost of one iteration is ~one MMIO dispatch
plus a tiny bit of bookkeeping, not a syscall + IPC + scheduling.

Upstream QEMU achieves this on Linux by using the GNU linker's
`-Wl,-wrap,qtest_writel`: ld renames the original symbol to
`__real_qtest_writel`, redirects every caller to `__wrap_qtest_writel`,
and the wrapper (`qtest_wrappers.c`) calls `address_space_write(...)`
directly when fuzzing.

Apple's `ld` and `ld64.lld` do not implement `-Wl,-wrap`. So on macOS
this whole mechanism cannot work. We replaced it with **weak symbols**:

```text
   tests/qtest/libqtest.c                     tests/qtest/fuzz/
                                              qtest_wrappers.c
   ----------------------                     ---------------------------

   /* normal socket impl */                   /* in-process impl */
   uint32_t qtest_writel_real(...)            uint32_t qtest_writel(
                                                QTestState *s,
                                                ...)
   {                                          {
       qtest_sendf(s, "writel ...");              if (!serialize) {
       qtest_rsp(s);                                 address_space_write(
   }                                                     first_cpu->as,
                                                          addr, ...);
   __attribute__((weak))                          } else {
   uint32_t qtest_writel(                            qtest_writel_real(
       QTestState *s, ...)                                s, addr, value);
   {                                              }
       return qtest_writel_real(              }
                  s, addr, value);
   }
```

When the build links `qos-test`, only `libqtest.c`'s definitions exist
-- the weak `qtest_writel` is the only `qtest_writel` symbol, so it
wins, and qtest_writel_real does the socket I/O. qos-test still works
exactly like before.

When the build links `qemu-fuzz-aarch64`, both definitions are
present: `qtest_wrappers.c` provides a *strong* `qtest_writel`, and
the linker prefers strong over weak, so calls to `qtest_writel` land
in the wrapper, which can either dispatch in-process
(`address_space_write`) or fall back to the socket impl
(`qtest_writel_real`) when `FUZZ_SERIALIZE_QTEST=1` is set for
reproducer building.

This is portable: works on Mach-O **and** ELF, no `-Wl,-wrap`.

---

## 5. The LPM structured layer

Without LPM, libFuzzer mutates input bytes blindly. For a virtio
device that's mostly fine for the register surface (parsers, decoders)
but rarely produces a valid feature-negotiation prologue, let alone a
well-formed descriptor chain. Most iterations get rejected before the
device does any interesting work.

LPM solves this by mutating in **proto space**: the input is a
serialized `qemu.fuzz.VirtioBlkProgram`, and mutations preserve
proto-shape (insert / remove / reorder / change typed fields). Every
mutated input still parses back to a valid program; what changes is
*which* operations and what arguments.

```text
        proto_fuzz_virtio_blk.proto
        ---------------------------

        message VirtioBlkProgram {
          repeated VirtioOp ops = 1;
        }

        message VirtioOp {
          oneof op {
            GetFeatures   get_features    = 1;
            SetFeatures   set_features    = 2;
            ConfigRead    config_read     = 3;
            ConfigWrite   config_write    = 4;
            VqSelect      vq_select       = 5;
            VqSetup       vq_setup        = 6;
            SetStatus     set_status      = 7;
            GuestMemWrite guest_mem_write = 8;
            VqAddDesc     vq_add_desc     = 9;
            VqKick        vq_kick         = 10;
            VqWaitUsed    vq_wait_used    = 11;
            Reset         reset           = 12;
          }
        }
```

A text-format seed (humans can hand-author these) looks like:

```protobuf
        ops { get_features {} }
        ops { set_features { features: 0x100000040 } }
        ops { vq_setup { vq_idx: 0 size: 64 } }
        ops { set_status { bits: 4 } }     # DRIVER_OK
        ops { guest_mem_write { buf_id: 1 data: "\x00\x00..." } }
        ops { vq_add_desc { vq_idx: 0 buf_id: 1 len: 16
                            device_writable: false chain_next: true } }
        ops { vq_kick { vq_idx: 0 } }
```

LPM hooks into libFuzzer at three points:

```text
        LLVMFuzzerInitialize    -> our weak-side QEMU init runs
                                   (see fuzz.c:164)

        LLVMFuzzerCustomMutator -> CustomProtoMutator(false, ..., &input)
                                   (proto-aware mutation)

        LLVMFuzzerTestOneInput  -> fuzz.c dispatcher routes by name
                                   to proto_fuzz_virtio_blk_run, which
                                   calls LoadProtoInput then walks
                                   prog.ops() and dispatches
```

Note that we use LPM's underlying primitives directly rather than the
`DEFINE_TEXT_PROTO_FUZZER` macro: the macro wants to *own*
`LLVMFuzzerTestOneInput`, but QEMU's `fuzz.c` already defines that as
a multi-target dispatcher. By calling `LoadProtoInput` /
`CustomProtoMutator` ourselves we keep the multi-target dispatch and
still get every benefit of structured fuzzing.

---

## 6. fuzz.c and generic_fuzz.c -- what we use, what we coexist with

`qemu-fuzz-aarch64` links several fuzz targets into one binary. Some
we depend on, some we just live next to. Here is a quick guide so it
is clear which is which.

### fuzz.c -- the dispatcher (we depend on it)

`fuzz.c` is the harness framework. It owns the two libFuzzer entry
points (`LLVMFuzzerInitialize`, `LLVMFuzzerTestOneInput`) and a third
optional one (`LLVMFuzzerCustomCrossOver`). It knows nothing about
virtio. Its job:

```text
   1. module_call_init(MODULE_INIT_FUZZ_TARGET)
        -> fires every fuzz_target_init() constructor in the link
           image, populating fuzz_target_list with FuzzTargets

   2. parse --fuzz-target=NAME from argv
        -> look up NAME in fuzz_target_list, store in fuzz_target

   3. fuzz_target->get_init_cmdline()
        -> build the QEMU args for the target's chosen machine

   4. qtest_setup()
        -> wire up the in-process qtest channel
           (qtest_server_set_send_handler + qtest_inproc_init)

   5. qemu_init(argc, argv)
        -> run vl_main; QEMU's machine model is now built and idle

   per input:
   6. fuzz_target->fuzz(fuzz_qts, data, size)
        -> dispatch to the per-target callback
```

We use this exactly as upstream intends. `proto_fuzz_virtio_blk.cc`
registers a `FuzzTarget`; the dispatcher does steps 1-6. We never
redefine `LLVMFuzzerInitialize` or `LLVMFuzzerTestOneInput` -- this
is the reason we deliberately avoided `DEFINE_TEXT_PROTO_FUZZER`,
which would have stolen `LLVMFuzzerTestOneInput` from `fuzz.c` and
broken the multi-target dispatch.

**Virtio-aware?** No. `fuzz.c` is pure dispatcher; it has no
knowledge of any device class.

### generic_fuzz.c -- sibling target (we coexist, never invoke)

`generic_fuzz.c` registers a separate `FuzzTarget` named
`generic-fuzz`. `tests/qtest/fuzz/meson.build` adds it
unconditionally to `specific_fuzz_ss`, so it is compiled and linked
into `qemu-fuzz-aarch64` alongside us. Its constructor runs at
startup and registers `generic-fuzz` in the same `fuzz_target_list`
as our target. But unless you launch with
`--fuzz-target=generic-fuzz`, none of its code runs -- the dispatcher
picks exactly one target by name.

What generic-fuzz does, *when* it is selected:

```text
   1. read QEMU_FUZZ_ARGS env -> the QEMU machine command line
   2. read QEMU_FUZZ_OBJECTS env -> a glob pattern matched against
        MemoryRegion names and owner names; matching MRs become the
        fuzz surface
   3. per input:
        walk the bytes as a sequence of typed ops (in/out/read/write/
        memwrite/memset/clock-step) and dispatch them at random
        addresses inside the matched MemoryRegions
```

The bytes from libFuzzer are interpreted as raw operations. There is
no schema, no understanding of feature negotiation, no understanding
of virtqueue layout, no understanding of descriptor chains.

`tests/qtest/fuzz/generic_fuzz_configs.h` ships pre-canned env
configs for various devices including virtio-blk, virtio-scsi,
virtio-net-pci-slirp, virtio-rng, virtio-balloon, virtio-9p,
virtio-9p-synth, virtio-gpu, virtio-vga, virtio-serial,
virtio-mouse. These are convenience presets -- the harness behaviour
is identical, only the QEMU args and the MR pattern differ.

**Virtio-aware?** Effectively no. It can be *pointed at* virtio
MemoryRegions, but it bangs random bytes at the device's register
surface. It does not know what bits to set in `Status`, what shape
`DriverFeatures` takes, where the descriptor table goes, what the
doorbell address is. Most iterations against a virtio device do not
make it past the early register-decode path, because no valid
feature-negotiation prologue was set up.

That is the gap our `proto-fuzz-virtio-blk` fills: we model the
protocol in the proto schema, every input parses to a sequence of
real virtio operations, and the harness always emits a valid init
prologue before mutating downstream behaviour.

### virtio_blk_fuzz.c -- virtio-blk-flags-fuzz

`tests/qtest/fuzz/virtio_blk_fuzz.c` registers one target named
`virtio-blk-flags-fuzz`. Per fuzz iteration:

```text
   1. libqos walks the qos graph: i386_pc-machine -> i440FX-pcihost
        -> pci-bus-pc -> virtio-blk-pci -> virtio-blk
   2. virtio-blk init:
        qvirtio_get_features, qvirtio_set_features,
        qvirtqueue_setup(vq=0, alloc, ...),
        qvirtio_set_driver_ok
   3. allocate guest memory for a virtio_blk_outhdr (16B), a 512B
        data buffer, a 1B status byte
   4. fill virtio_blk_outhdr with type=VIRTIO_BLK_T_IN (read),
        sector=0, ioprio=0
   5. *** take libFuzzer input bytes and write them into the
         "type" / "ioprio" fields of the outhdr ***   <-- the fuzz
   6. qvirtqueue_add three descriptors (header out, data in, status
        in), qvirtqueue_kick, qvirtio_wait_used_elem
   7. reboot the VM (i440fx-fuzz uses qemu_system_reset between
        iterations to keep state clean)
```

So the outgoing request is *almost* always a valid virtio-blk read.
The fuzzer mutates only the type/flags/ioprio bytes of the request
header. Narrow window. Most of the protocol surface is held
constant; we are exploring one tiny slice of input space.

### virtio_scsi_fuzz.c -- virtio-scsi-flags-fuzz

Same shape as virtio-blk-flags-fuzz, but the libqos graph walk goes
to `virtio-scsi-pci` and the request fuzzed is a
`virtio_scsi_cmd_req` (a SCSI CDB header on top of a virtio-scsi
wrapper). libFuzzer bytes mutate the SCSI request flags field. Same
narrow per-iteration window: valid setup, valid descriptor chain,
fuzz one field.

### virtio_net_fuzz.c -- virtio-net-socket-check-used

Slightly different shape. Instead of "fuzz one header field", this
one drives the receive path: it pushes packets into the device via
the host-side "socket" netdev backend, then checks that the used
ring is updated correctly. The fuzz input becomes the packet
payload. Narrow in a different way -- one direction (RX), one
operation (frame in, used out).

### Why none of these run in `qemu-fuzz-aarch64`

All three are wired through libqos's `tests/qtest/libqos/x86_64_pc-machine.c`
with virtio-pci on the i440fx PCI bus. The qos graph for
`arm-virt-machine` (which is what we boot in `qemu-fuzz-aarch64`)
does not have a path that produces a `virtio-blk-pci` /
`virtio-scsi-pci` / `virtio-net-pci` node, because arm `virt` uses
virtio-mmio, not virtio-pci, by default. Result: their names appear
in the binary's `fuzz_target_list`, but the qos graph traversal
yields zero working test instances when init runs.

To actually run them you build `qemu-fuzz-i386` (also produced by
our `--target-list=aarch64-softmmu,i386-softmmu` configure) and run
there. Same source tree, same patches:

```text
   $BUILD/build-fuzz/qemu-fuzz-i386 \
       --fuzz-target=virtio-blk-flags-fuzz \
       -close_fd_mask=2 -runs=10000
```

### Summary

```text
   File                       | in our binary | invoked by us  | virtio-aware
   ---------------------------+---------------+----------------+------------------
   fuzz.c                     | yes (framework)| yes (always)  | no -- pure
                              |                |               |    dispatcher
   ---------------------------+---------------+----------------+------------------
   generic_fuzz.c             | yes (sibling) | no            | no -- byte-banging
                              |               |               |    at MemoryRegions
   ---------------------------+---------------+----------------+------------------
   virtio_blk_fuzz.c          | yes (sibling, | no, and not   | partly -- valid
   virtio_net_fuzz.c          |  but i440fx-  | reachable on  |    init via libqos,
   virtio_scsi_fuzz.c         |  PC tied)     | arm virt      |    fuzzes ONE field
   ---------------------------+---------------+----------------+------------------
   proto_fuzz_virtio_blk.cc   | yes (target)  | yes (selected | yes -- full
   (this work)                |               | with --fuzz-  |    protocol via
                              |               | target=...)   |    .proto schema
```

---

## 7. Are we a virtio-aware fuzzer?

Short answer: **yes -- at the virtio common-protocol layer. No -- at
the per-device layer.** This is a deliberate design split, and worth
reading carefully because it determines what kinds of bugs the
harness reaches efficiently and what kinds it does not.

### What we ARE aware of (full coverage)

The proto schema and the dispatcher in `proto_fuzz_virtio_blk.cc`
model the *common* virtio plumbing exactly:

```text
   layer                            modeled in our schema as
   -----------------------------    --------------------------
   virtio-mmio register layout      hard-coded in dispatch();
                                    every op writes specific
                                    register offsets

   Status register state machine    SetStatus(bits=...) ORs into
   (RESET -> ACK -> DRIVER ->       Status; Reset clears it;
    FEATURES_OK -> DRIVER_OK)       reset_iteration_state() always
                                    drives ACK | DRIVER as the
                                    valid prologue

   Feature negotiation              GetFeatures (sel=0,1 reads),
   (DeviceFeatures, DriverFeatures, SetFeatures (sel=0,1 writes;
    two halves)                     OR FEATURES_OK afterwards)

   Virtqueue selection / sizing     VqSelect, VqSetup (size, GPAs)

   Split-virtqueue layout:
     16-byte descriptors            VqAddDesc encodes the descriptor
       le64 addr, le32 len,         (addr, len, flags, next) and
       le16 flags, le16 next        writes it into the descriptor
                                    table at the right offset

     descriptor flags               VqAddDesc.{device_writable,
       VRING_DESC_F_WRITE = 0x2     chain_next}
       VRING_DESC_F_NEXT  = 0x1

     avail ring publishing          VqAddDesc(chain_next=false) bumps
                                    avail.idx and writes the head
                                    index into ring[]

   Doorbell                         VqKick writes QueueNotify

   Interrupt handling               VqWaitUsed reads InterruptStatus,
   (level/EDGE)                     ACKs back at InterruptACK

   Device config space              ConfigRead / ConfigWrite at
                                    offset 0x100 + N
```

That is the full common-protocol surface. A bug in feature
negotiation, descriptor walking, ring index handling, or
notification logic in `hw/virtio/virtio.c` /
`hw/virtio/virtio-mmio.c` is reachable.

### What we are NOT aware of (deliberately not modeled)

The **virtio-blk per-device protocol** is not in the schema. We do
not know:

  * the shape of `struct virtio_blk_outhdr` (type, ioprio, sector)
  * the request types (`VIRTIO_BLK_T_IN`, `_OUT`, `_FLUSH`,
    `_GET_ID`, `_DISCARD`, `_WRITE_ZEROES`, `_SECURE_ERASE`)
  * the canonical 3-descriptor chain shape
    (out: header, in/out: data, in: status)
  * the per-feature bit semantics
    (`VIRTIO_BLK_F_SIZE_MAX`, `_SEG_MAX`, `_GEOMETRY`, `_RO`,
     `_BLK_SIZE`, `_FLUSH`, `_TOPOLOGY`, `_CONFIG_WCE`, ...)

Bugs that need a parser-aware request -- e.g. an integer overflow
when parsing a sector field, an out-of-bounds read in a
discard-zeroes range -- have to be discovered by LPM mutating the
contents of `GuestMemWrite` payloads and the chain shape until a
valid blk request happens to fall out. That works given enough
corpus + time, but is slower than a per-device-aware fuzzer would
be.

### Why we drew the line there

Two reasons:

1. **Reuse**. The schema and dispatcher work for any virtio device
   that uses virtio-mmio. To fuzz virtio-net, change the QEMU args
   from `-device virtio-blk-device` to `-device virtio-net-device`
   and run the same harness against the same proto -- you would
   reach the device's transport surface immediately. To fuzz
   virtio-9p, same. To fuzz virtio-rng, same. The device-level
   protocol is the only thing that changes, and we deferred it.

2. **Surface coverage first**. The common virtio code in
   `hw/virtio/virtio.c` is shared by *every* virtio device in QEMU,
   so the ROI of fuzzing it well is high: bugs there affect all
   devices. Per-device protocols can be layered on top later
   without rewriting anything.

### What "device-aware" would look like (next iteration)

If/when we want virtio-blk-aware fuzzing, the path is to add typed
sub-messages to the proto:

```protobuf
   message VirtioBlkRequest {
     enum Type {
       READ  = 0;   WRITE        = 1;   FLUSH         = 4;
       GET_ID = 8;  DISCARD      = 11;  WRITE_ZEROES  = 13;
       SECURE_ERASE = 14;
     }
     Type   type   = 1;
     uint32 ioprio = 2;
     uint64 sector = 3;
     bytes  data   = 4;   // for WRITE: the data payload; for READ:
                          // the expected data length
   }

   message BlkSubmitRequest {
     uint32 vq_idx = 1;
     VirtioBlkRequest req = 2;
   }
```

The dispatcher would auto-build a valid 3-descriptor chain for each
`BlkSubmitRequest` (header out / data in-or-out / status in), let
LPM mutate `type` / `sector` / `data` while preserving blk shape,
and still allow raw `VqAddDesc` ops side-by-side for shape-fuzzing.
This is straightforward; it just was not v1.

### Comparison table

```text
  layer                | upstream    | upstream     | upstream     | proto-fuzz-
                       | generic-fuzz| virtio-blk-  | virtio-scsi- |   virtio-blk
                       |             | flags-fuzz   | flags-fuzz   |   (this work)
  ---------------------+-------------+--------------+--------------+--------------
  virtio-mmio xport    |   no        |   no         |   no         |   yes
                       | (raw bytes  |  (uses PCI   |  (uses PCI   |  (full
                       |   at MRs)   |  transport)  |  transport)  |   modeled)
  ---------------------+-------------+--------------+--------------+--------------
  status / features    |   no        |   yes        |   yes        |   yes
                       | (random)    | (libqos init)| (libqos init)| (proto ops)
  ---------------------+-------------+--------------+--------------+--------------
  virtqueue layout +   |   no        |   yes        |   yes        |   yes
  descriptor chains    | (random)    |  (3-desc     |  (3-desc     | (chain shape
                       |             |   fixed)     |   fixed)     |  is fuzzed)
  ---------------------+-------------+--------------+--------------+--------------
  per-device request   |   no        |   partial    |   partial    |   no (left
  format               |             | (one field   | (one field   |  to LPM byte
                       |             |  fuzzed)     |  fuzzed)     |  mutations)
  ---------------------+-------------+--------------+--------------+--------------
  reusable across      |   yes       |   no         |   no         |   yes (same
  virtio devices       | (any device | (blk only)   | (scsi only)  |  schema; just
                       |  by env)    |              |              |  swap QEMU
                       |             |              |              |  args)
```

Bottom line: we are virtio-aware where it pays off most for shared
QEMU code, and intentionally device-naive at the layer where each
virtio class has its own private protocol. Adding device-aware
sub-messages is a small, additive change for the next iteration.

---

## 8. Memory layout used by the harness

The arm `virt` machine has DRAM at `0x40000000` and we boot it with
`-m 128`, so DRAM ends at `0x48000000`. We carve out the high end:

```text
  0x40000000  +---------------------------+
              |  Reserved by QEMU machine |
              |  init: kernel (none),     |
              |  device tree, etc.        |
              |                           |
  0x47000000  +===========================+  <- kPoolBase
              |  vq[0] desc table  (4 KB) |
              |  vq[0] avail ring  (4 KB) |
              |  vq[0] used ring   (4 KB) |
              |  vq[1] desc/avail/used    |
              |  vq[2] desc/avail/used    |
              |  vq[3] desc/avail/used    |
  0x4700C000  +---------------------------+  <- kBufPoolBase
              |  Sequentially allocated   |
              |  buffer pool. Each        |
              |  GuestMemWrite consumes   |
              |  the next chunk.          |
              |                           |
  0x47F00000  +===========================+  <- kBufPoolEnd
              |   (unused)                |
  0x48000000  +---------------------------+
```

Everything from `kPoolBase` onwards is reset between iterations:
`reset_iteration_state()` zeros the bookkeeping (queue sizes, head
indices, buf_id -> GPA map, allocator pointer) and rewrites the
virtio-mmio status register to put the device back into the
ACK | DRIVER state. The DRAM contents themselves are not cleared,
which is intentional -- it's free entropy.

A single iteration touches at most a few KB of DRAM and a handful of
MMIO registers, so the cost per iteration is dominated by libFuzzer's
own bookkeeping, not by the device emulation. We measured ~333
exec/s with one seed and ~666+ exec/s as the corpus grew.

---

## 9. virtio-mmio register cheatsheet

For reference, here is what each proto op writes / reads:

```text
  0x000  R   MagicValue       'virt'
  0x004  R   Version          2
  0x008  R   DeviceID         2 (virtio-blk)
  0x00c  R   VendorID
  0x010  R   DeviceFeatures   <-- GetFeatures
  0x014  W   DeviceFeaturesSel
  0x020  W   DriverFeatures   <-- SetFeatures (then OR FEATURES_OK
                                   into Status)
  0x024  W   DriverFeaturesSel
  0x030  W   QueueSel         <-- VqSelect / first step of VqSetup
  0x034  R   QueueNumMax
  0x038  W   QueueNum         <-- VqSetup
  0x044  RW  QueueReady       <-- VqSetup writes 1 last
  0x050  W   QueueNotify      <-- VqKick (value = vq_idx)
  0x060  R   InterruptStatus  <-- VqWaitUsed reads, ACKs back at 0x064
  0x064  W   InterruptACK
  0x070  RW  Status           <-- Reset, SetStatus, FEATURES_OK,
                                   DRIVER_OK
  0x080  W   QueueDescLow     <-- VqSetup (desc table GPA)
  0x084  W   QueueDescHigh
  0x090  W   QueueDriverLow   <-- VqSetup (avail ring GPA)
  0x094  W   QueueDriverHigh
  0x0a0  W   QueueDeviceLow   <-- VqSetup (used ring GPA)
  0x0a4  W   QueueDeviceHigh
  0x100+ RW  Config (device-specific) <-- ConfigRead / ConfigWrite
```

This is exactly the register layout the Linux `virtio_mmio.c` driver
talks to. The writes our harness emits are bit-for-bit what a real
guest driver would emit. That is why a crash here reproduces in a VM.

---

## 10. How we got here -- the build journey

This is the order in which obstacles appeared and how each was
resolved. It explains why the meson rules look the way they do.

### Step 1 - native qemu-system-aarch64

The starting point. We built `qemu-system-aarch64` natively on Apple
Silicon with brewed clang 22, libslirp, libpixman, libglib, libcapstone.
No fuzzing yet, just confirming the toolchain. Worked first try.

```text
   meson setup --target-list=aarch64-softmmu ... \
       --enable-fuzzing --enable-slirp --enable-hvf
   ninja qemu-system-aarch64
```

### Step 2 - qos-test (libqos virtio testing, separate process)

Built `tests/qtest/qos-test` and confirmed `virtio-blk-pci/.../basic`
passes: a libqos-based test program that spawns `qemu-system-i386`
over a Unix qtest socket, does feature negotiation, builds a
virtqueue, submits a request, waits for the used ring. Two processes,
plenty of overhead per request -- but it proved that libqos's virtio
APIs work natively on macOS.

This is the upstream "talk to virtio from outside" path. It works and
it's perfectly viable for unit tests. It's just not fast enough for
fuzzing.

### Step 3 - try qemu-fuzz-aarch64 (link fails on -Wl,-wrap)

`--enable-fuzzing` wires the meson rule that builds `qemu-fuzz-*`.
Apple's `ld` rejected the link line:

```text
   ld: unknown options: -wrap -wrap -wrap -wrap ...
```

Upstream uses `-Wl,-wrap,qtest_writel` (and 18 friends) to redirect
qtest I/O calls to in-process implementations. Apple's `ld` and
LLVM's `ld64.lld` do not support `-wrap`.

### Step 4 - replace -Wl,-wrap with weak symbols

Three-file patch:

```text
   tests/qtest/libqtest.c
       split each of 19 qtest_* I/O fns into:
         qtest_X_real(...)              <-- the original socket impl
         __attribute__((weak)) qtest_X  <-- thin thunk -> _real

   tests/qtest/fuzz/qtest_wrappers.c
       drop the __wrap_/__real_ macros entirely; provide a strong
       qtest_X(...) that either does the in-process direct call
       (when serialize == false) or delegates to qtest_X_real
       (when serialize == true, used for FUZZ_SERIALIZE_QTEST=1)

   tests/qtest/fuzz/meson.build
       drop all 19 -Wl,-wrap link flags
```

This is portable. Linkers everywhere prefer strong over weak symbols,
so qos-test (no wrappers in the link) keeps the socket impl;
qemu-fuzz-* (wrappers in the link) gets in-process direct calls.

### Step 5 - link succeeds, but binary segfaults at runtime

`qemu-fuzz-aarch64` linked, but every invocation died inside
`LLVMFuzzerTestOneInput` with `EXC_BAD_ACCESS` on `fuzz_target->...`
-- `fuzz_target` was NULL, meaning `LLVMFuzzerInitialize` had not
populated it.

Cause: `plugins/meson.build` adds
`-Wl,-exported_symbols_list,plugins/qemu-plugins-ld64.symbols` to
every emulator binary. That list contains only `qemu_*` plugin API
symbols, so every other global symbol -- including the LLVMFuzzer
entry points -- got demoted to private_extern. libFuzzer's main
declares `LLVMFuzzerInitialize` as a weak external, looks it up, and
when the symbol is private_extern the lookup resolves to NULL, so
init never ran.

### Step 6 - re-export the LLVMFuzzer entry points

Added macOS-only flags in `tests/qtest/fuzz/meson.build`:

```meson
   if host_os == 'darwin'
     fuzz_link_args += [
       '-Wl,-exported_symbol,_LLVMFuzzerInitialize',
       '-Wl,-exported_symbol,_LLVMFuzzerTestOneInput',
       '-Wl,-exported_symbol,_LLVMFuzzerCustomCrossOver',
       '-Wl,-exported_symbol,_LLVMFuzzerCustomMutator',  # added later, see Step 14
     ]
   endif
```

`-Wl,-exported_symbol,X` doesn't override `-exported_symbols_list`,
it adds X to the export set. Now the LLVMFuzzer symbols are external
(`T` in `nm`), libFuzzer finds them, init runs, and `generic-fuzz`
works:

```text
   QEMU_FUZZ_ARGS='-machine virt -nodefaults -m 128 \
       -device virtio-blk-device,drive=hd0 \
       -drive if=none,id=hd0,file=null-co://,...,format=raw' \
   QEMU_FUZZ_OBJECTS='virtio*' \
   qemu-fuzz-aarch64 --fuzz-target=generic-fuzz -runs=10000
```

This was the first version that worked: in-process, native, ASan +
SanCov + libFuzzer all alive. But it was raw-byte fuzzing -- no proto.

### Step 7 - install libprotobuf-mutator from source

`brew install protobuf-mutator` does not exist. We built it from the
upstream repo against brewed protobuf 7.34 + brewed clang 22. First
attempt crashed in libc++ headers because brewed clang couldn't find
the macOS SDK. Fixed by passing `SDKROOT=$(xcrun --show-sdk-path)`
and `-DCMAKE_OSX_SYSROOT="$(xcrun --show-sdk-path)"` to cmake.

Resulting archives, kept in-tree (not installed to /opt/homebrew):

```text
   $HOME/libprotobuf-mutator/build/src/libprotobuf-mutator.a
   $HOME/libprotobuf-mutator/build/src/libfuzzer/
                                  libprotobuf-mutator-libfuzzer.a
```

### Step 8 - write the proto + harness

`tests/qtest/fuzz/proto_fuzz_virtio_blk.proto` describes the schema.
`tests/qtest/fuzz/proto_fuzz_virtio_blk.cc` implements the harness.

Key design decisions:

  * **Register a `FuzzTarget`, do not use `DEFINE_TEXT_PROTO_FUZZER`**.
    The macro defines `LLVMFuzzerTestOneInput`, which conflicts with
    QEMU's `fuzz.c`. Use LPM's primitives (`LoadProtoInput`,
    `CustomProtoMutator`) directly inside our `FuzzTarget.fuzz`
    callback.

  * **Forward-declare QEMU's tiny ABI in the .cc**, do not include
    `qemu/osdep.h` from C++. This is what lets us compile the .cc
    without `-I..` on the command line -- see Step 9.

### Step 9 - the `<version>` vs `VERSION` collision

First C++ compile attempt failed with:

```text
   In file included from .../include/c++/v1/functional:572:
   ../version:1:1: error: expected unqualified-id
       1 | 11.0.50
```

macOS APFS is case-insensitive. Clang searches `-I` paths *before*
its own libc++ include path for `<>` includes. The QEMU project
build adds `-I..` (the QEMU source root) to every target. The QEMU
source root contains the file `VERSION` (uppercase). When libc++'s
`<functional>` does `#include <version>`, the search resolves to
`../VERSION`, whose contents (`11.0.50\n`) are not valid C++.

We tried `-cxx-isystem` and prepending `-I libcxx` via meson's
`compile_args`. Both lost the arg-order race -- meson's
`include_directories` ended up earlier on the command line than our
`compile_args`, so `-I..` still won.

### Step 10 - sidestep meson's flag management entirely

For the C++ files only, we use a `custom_target` that runs `clang++`
directly with hand-picked flags, producing `.o` files. We then add
those `.o` files to `specific_fuzz_ss` so meson links them into
`qemu-fuzz-aarch64`:

```meson
   proto_pb = custom_target('..._pb',
       command: [protoc, '--cpp_out=@OUTDIR@', ...])

   cxx_common = [clangxx, '-c', '-std=c++17', '-O2', '-g', '-fPIC',
                 '-fsanitize=fuzzer-no-link', '-fsanitize=address',
                 '-isysroot', $(xcrun --show-sdk-path),
                 '-I' + brew_prefix / 'opt/llvm/include/c++/v1',
                 '-I' + lpm_root,
                 '-I' + lpm_root / 'src',     # for libfuzzer/libfuzzer_macro.h
                 '-I' + brew_incdir,
                 '-I' + meson.current_build_dir(),  # for proto_fuzz_virtio_blk.pb.h
                 ... glib_includes ...]

   proto_pb_o = custom_target('..._pb_o',
       input: proto_pb, output: '...pb.o',
       command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

   proto_cc_o = custom_target('..._cc_o',
       input: ['proto_fuzz_virtio_blk.cc', proto_pb],
       output: '...cc.o',
       command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])
```

Crucially the `cxx_common` invocation does **not** include `-I..`,
so `<version>` resolves to libc++'s real header. Because our .cc
forward-declares QEMU's ABI, it doesn't need `qemu/osdep.h` and so
doesn't need `-I..`.

### Step 11 - link errors for absl symbols

brewed protobuf 7.34 inlines absl's logging into its public headers,
so `proto_fuzz_virtio_blk.pb.o` had direct references to a long list
of `absl_log_internal_*` symbols. We resolved the link line via
`pkg-config`:

```meson
   pb_libs = run_command('pkg-config', '--libs', 'protobuf',
                         check: true).stdout().strip().split()
```

This expands to `-L$BREW_PREFIX/opt/protobuf/lib -lprotobuf
-L$BREW_PREFIX/opt/abseil/lib -labsl_*` for ~70 absl libs.
Plus `-Wl,-rpath` so the dylibs are findable at runtime.

### Step 12 - duplicate symbols (378 of them)

Our `declare_dependency` listed the `.o` files in both `sources:`
*and* `link_args:`. meson treats `.o` files in `sources:` as
implicit objects on the link line, and our explicit `link_args:`
copies double-counted. Fix: drop them from `link_args`, keep them
in `sources`.

### Step 13 - smoke test passes

```text
   #2  INITED cov: 80  ft: 80  corp: 1/1b ...
   #2  DONE   cov: 80  ft: 80  corp: 1/1b lim: 4 exec/s: 0 rss: 130Mb
   Done 2 runs in 0 second(s)
```

In-process structured fuzzer is alive. ASan + SanCov + libFuzzer +
LPM all linked. `proto-fuzz-virtio-blk` registered alongside the
existing `generic-fuzz` and friends.

### Step 14 - LPM mutator wasn't actually being called

`nm` showed `t _LLVMFuzzerCustomMutator` (lowercase = local). We had
re-exported `LLVMFuzzerInitialize` / `TestOneInput` / `CustomCrossOver`
in Step 6 but forgot `LLVMFuzzerCustomMutator`. libFuzzer's weak
extern lookup resolved it to NULL and fell back to byte-level
mutations.

Added to the export list. Re-link. Now:

```text
   INFO: found LLVMFuzzerCustomMutator (0x10463b6fc).
         Disabling -len_control by default.
```

and `MS:` lines began showing `Custom-` mutations from LPM:

```text
   #117  NEW cov: 514 ft: 1048 ... MS: 8 CrossOver-Custom-ChangeBit-
                                          Custom-Custom-EraseBytes-
                                          ChangeBinInt-Custom-
```

Structured proto-aware fuzzing of QEMU's virtio-blk emulation, in a
single process, native macOS arm64, no Docker, no Linux, no boot.

---

## 11. Files involved

```text
   tests/qtest/
       libqtest.c                        weak qtest_* + qtest_*_real
       fuzz/
           fuzz.c                        unchanged dispatcher
           fuzz.h                        FuzzTarget definition
           qtest_wrappers.c              strong qtest_* in-process
           generic_fuzz.c                unchanged
           virtio_blk_fuzz.c             unchanged (PC-only)
           proto_fuzz_virtio_blk.proto   schema (this work)
           proto_fuzz_virtio_blk.cc      LPM harness (this work)
           meson.build                   protoc + LPM linkage rules

   $HOME/libprotobuf-mutator/    LPM source build, used by
                                          custom_target rules above
```

---

## 12. Running it

```text
   $BUILD/build-fuzz/qemu-fuzz-aarch64 \
       --fuzz-target=proto-fuzz-virtio-blk \
       -close_fd_mask=2 \
       /tmp/proto_fuzz_run/corpus_runtime2
```

Useful flags:

  -runs=N             cap iterations (omit = forever)
  -max_total_time=S   wall-clock cap, in seconds
  -max_len=N          biggest input libFuzzer will generate (default 4096)
  -jobs=N -workers=N  parallel processes that share the corpus dir
  -artifact_prefix=P  filename prefix for crash files

A crash drops a `crash-<sha1>` file with the offending text-format
proto. To turn it into a non-fuzzer reproducer:

```sh
   FUZZ_SERIALIZE_QTEST=1 QTEST_LOG=1 \
   qemu-fuzz-aarch64 --fuzz-target=proto-fuzz-virtio-blk \
                      ./crash-<sha1>  &> /tmp/trace
   scripts/oss-fuzz/reorder_fuzzer_qtest_trace.py /tmp/trace \
       > /tmp/reproducer
   qemu-system-aarch64 <args from top of /tmp/trace> \
                        -qtest stdio < /tmp/reproducer
```

The same crash, in a clean `qemu-system-aarch64` with no fuzzer in
the image. From there it is one more step to a guest-driver
reproducer, because every line in `/tmp/reproducer` is a write to
the same MMIO register a Linux `virtio_mmio.c` driver would write.


## 13. Why we weren't getting device coverage (harness bugs)

After the harness compiled and looked like it was running -- 100k+ executions,
coverage growing to ~394 PCs, no crashes -- a breakpoint on
`virtio_net_handle_ctrl` (the CVQ entry point) **never fired**. The fuzzer
was busy exploring the proto parser and prologue paths but not actually
exercising any virtio-net device code. Three compounding bugs explain it.

### Bug 1: wrong virtio-mmio base address

`kVirtioMmioBase` was hard-coded to `0x0a000000` -- arm-virt's *first*
virtio-mmio slot. arm-virt creates 32 such slots at
`0x0a000000 + i * 0x200` and **fills them high-address-first**, so a
single `-device virtio-net-device,...` lands at slot **31**
(`0x0a003e00`), not slot 0. Slot 0 is empty: MAGIC reads as `"virt"` but
`DEVICE_ID` reads `0`.

Symptom: every `mmio_writel` we sent was a no-op against a ghost device.
`QUEUE_NUM_MAX` reads returned `0`, so `op_vq_setup` bailed at
`if (max == 0) return;` for every queue, and `g_state.vqs[*].size` stayed
`0`. Every later op then bailed at `if (g_state.vqs[vq].size == 0) return;`.

Fix (`proto_fuzz_virtio_{net,gpu,blk}.cc`):

```cpp
constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;  /* arm-virt slot 31 */
```

If you ever load more than one virtio device on the bus, this needs to
become a runtime scan ("walk slots 31..0, pick the first one whose
`MAGIC == "virt"` and `DEVICE_ID` matches").

### Bug 2: virtio-mmio defaults to legacy (v1) mode

`virtio-mmio.c` declares:

```c
DEFINE_PROP_BOOL("force-legacy", VirtIOMMIOProxy, legacy, true),
```

Default `legacy = true`. In legacy mode the v2 register set
(`QUEUE_DESC_LO/HI` at 0x080/0x084, `QUEUE_AVAIL_LO/HI` at 0x090/0x094,
`QUEUE_USED_LO/HI` at 0x0a0/0x0a4, `QUEUE_READY` at 0x044) **does not
exist** -- the proxy's write handler bails:

```c
case VIRTIO_MMIO_QUEUE_READY:
    if (proxy->legacy) {
        qemu_log_mask(LOG_GUEST_ERROR, "...write to non-legacy register...");
        return;
    }
```

The harness writes the v2 layout because that's the only way to program
a 64-bit GPA into the proxy. With `legacy=true` those writes are
silently dropped: `proxy->vqs[i].desc[0/1]` stays zero, `QUEUE_READY=1`
never triggers `virtio_queue_set_rings`, `vq->vring.desc` stays `0`,
and **every subsequent kick bails at**

```c
void virtio_queue_notify(VirtIODevice *vdev, int n) {
    if (unlikely(!vq->vring.desc || vdev->broken)) return;
}
```

This is what actually kept `virtio_net_handle_ctrl` from ever being
called, even after Bug 1 was fixed.

Fix: add `-global virtio-mmio.force-legacy=false` to every fuzz
target's QEMU cmdline (`proto_fuzz_virtio_{net,gpu,blk}_cmdline`). Now
the proxy accepts the v2 register layout we were already writing.

### Bug 3: uint64 overflow in `op_memwrite_absolute`'s clamp

Independent of the above -- a host-side OOM that masqueraded as
"interesting fuzz coverage". The clamp was:

```cpp
if (gpa < kBufPoolBase || gpa + len > kBufPoolEnd) {  // unsafe
    gpa = kBufPoolBase + (gpa % span);
}
```

For LPM-generated `gpa = 0xffffffff_ffff0000`, `gpa + len` *overflows*
uint64 to a small value, fails the second check, and the write is
issued to the huge GPA as-is. `address_space_write` walks byte-by-byte
through the wrap, lands in the low MMIO range, hits **pflash**, which
toggles its mode on every write, which calls
`memory_region_transaction_commit`, which queues an RCU-pending
flatview rebuild. RCU doesn't drain in the in-process fuzzer fast
enough, host RSS climbs unbounded, libFuzzer reports
`out-of-memory (used: 2371Mb; limit: 2048Mb)`.

This *looked* like a guest-to-host DoS finding but was just a
miscoded clamp. (The underlying QEMU pflash thrashing is a known
class of issue, only reachable when the guest can write pflash
MMIO -- so on a normal locked-down OVMF setup it's not exploitable.)

Fix: compare against `kBufPoolEnd - len` instead of `gpa + len`,
which can't overflow because `kBufPoolEnd > len` always:

```cpp
if (gpa < kBufPoolBase || gpa > kBufPoolEnd - len) {
    gpa = kBufPoolBase + (gpa % span);
}
```

### Coverage delta after the fixes

Same fuzz target, same corpus, ~10 seconds wall-clock:

| | cov  | features |
|--|--|--|
| Before fixes (Bugs 1+2 active) |   394 |  2,011 |
| After Bug 1 fix only           | 1,419 |  2,141 |
| After Bugs 1+2 fix             | 2,244 | 11,920 |

`virtio_net_handle_ctrl` lldb breakpoint went from never-fires to
fires-on-the-first-`ctrl_cmd`-seed. The features count jumping ~6x is
the more meaningful signal: edges/contexts inside the device are now
being explored, not just the prologue and the proto parser.

### How to confirm the fix in your own run

```sh
lldb -b \
  -o "process handle -p true -s false SIGUSR2" \
  -o "br set -n virtio_net_handle_ctrl" \
  -o "run --fuzz-target=proto-fuzz-virtio-net -close_fd_mask=2 \
          -runs=20 ~/q_net/corpus" \
  ~/q_net/qemu-fuzz-aarch64
```

You should see `stop reason = breakpoint 1.1` inside the first few runs
of any seed that contains a `ctrl_cmd` op.

### Lessons

* **Never trust that an MMIO write reached the device** without
  reading back something device-defined (DEVICE_ID, MAGIC, NUM_MAX
  for a known queue). The harness was writing into the void for
  weeks; coverage growth from the empty-MMIO read/write handler and
  from the proto parser made the run *look* healthy.
* **Confirm coverage with a known-on-path function**, not with a
  rising `cov:` counter. cov going up only tells you *something*
  novel was hit, not that it was on the device path you care about.
* **virtio-mmio default == legacy** is a perpetual stumbling block
  for new harnesses on arm-virt. A new proto-fuzz target should
  always include `-global virtio-mmio.force-legacy=false` on day
  one.

---

## 14. DMA reentrancy and the `exotic_region` field

### The attack class

A virtio device processes a descriptor chain by reading or writing the
guest physical addresses (GPAs) stored in each descriptor. If the
harness points a descriptor at *MMIO space* instead of DRAM, the
device's DMA walk lands inside its own register file. For virtio-mmio
on arm-virt this creates a re-entrancy path:

```text
VqKick
  → virtio_mmio_write(QUEUE_NOTIFY)
      → virtio_queue_notify()
          → walk descriptor chain
              → address_space_write(gpa=kVirtioMmioBase+0x050)
                    ↑                   ↓
                    |      virtio_mmio_write(QUEUE_NOTIFY)
                    |          → virtio_queue_notify()
                    |              → walk descriptor chain (again)
                    +-------------------------------------------
```

Two concrete exploit primitives from this surface (Black Hat Asia 2022,
"Recursive MMIO Flaws in QEMU"):

**Reset gadget UAF** — a descriptor pointing at `STATUS` (offset
0x070). The device DMA-writes 0 into Status →
`virtio_mmio_soft_reset()` fires while the device is mid-chain. Queue
state is freed but the chain walk continues using the freed pointers.

**Recursive notify** — a chain of N descriptors each pointing at
`QUEUE_NOTIFY` (offset 0x050). Each DMA write re-kicks the same queue,
scheduling another bottom-half. A deep enough chain exhausts QEMU's
reentrancy guard or overflows the call stack.

All addresses used are from the QEMU source tree, not the conference
slides:

| Region | GPA | Source file | Symbol |
|--|--|--|--|
| virtio-mmio bus | `0x0a000000` | `hw/arm/virt.c` `base_memmap[]` | `VIRT_MMIO` |
| virtio-mmio slot 31 | `0x0a003e00` | above + `i=31`, step=0x200 | single-device landing slot |
| UART0 / PL011 | `0x09000000` | `hw/arm/virt.c` `base_memmap[]` | `VIRT_UART0` |
| GIC distributor | `0x08000000` | `hw/arm/virt.c` `base_memmap[]` | `VIRT_GIC_DIST` |

arm-virt fills virtio-mmio slots **high-address-first**, so a single
`-device virtio-*-device` always lands at slot 31 = `0x0a003e00`.

### The proto field

```protobuf
message VqAddDesc {
  uint32 vq_idx          = 1;
  uint32 buf_id          = 2;
  uint32 len             = 3;
  bool   device_writable = 4;
  bool   chain_next      = 5;
  uint32 exotic_region   = 6;  // 0=DRAM (default), 1=UART0, 2=virtio-mmio, 3=GIC
}
```

`exotic_region = 0` is the default: the descriptor GPA is
`kBufPoolBase + buf_id_index * 4` (DRAM buffer pool). For a non-zero
value the harness maps `buf_id` into the chosen region:

```
region 1 → gpa = 0x09000000 + (buf_id % (0x1000 / 4)) * 4   (UART0, 4 KB window)
region 2 → gpa = 0x0a003e00 + (buf_id % (0x200  / 4)) * 4   (virtio-mmio, 512 B window)
region 3 → gpa = 0x08000000 + (buf_id % (0x10000/ 4)) * 4   (GIC dist, 64 KB window)
```

For region 2, `buf_id % 128` selects a 4-byte-aligned offset in the
512-byte virtio-mmio register window. The `.cc` files carry an inline
comment listing every interesting offset:

| buf_id | offset | register | effect if DMA-written |
|--|--|--|--|
| 0 | 0x000 | MAGIC_VALUE | read-only; write ignored |
| 17 | 0x044 | QUEUE_READY | write 0 → disables queue mid-flight |
| 20 | 0x050 | QUEUE_NOTIFY | BH re-kick → recursive chain walk |
| 25 | 0x064 | INTERRUPT_ACK | clears pending interrupt |
| 28 | 0x070 | STATUS | write 0 → `virtio_mmio_soft_reset` → UAF |
| 32 | 0x080 | QUEUE_DESC_LOW | corrupts descriptor table GPA |
| 33 | 0x084 | QUEUE_DESC_HIGH | upper 32 bits of descriptor table GPA |
| 36 | 0x090 | QUEUE_AVAIL_LOW | corrupts avail ring GPA |
| 40 | 0x0a0 | QUEUE_USED_LOW | corrupts used ring GPA |

Register offsets are from
`include/standard-headers/linux/virtio_mmio.h` in the QEMU source tree.

### Seed structure

Each corpus generator emits five DMA reentrancy seeds. The `vq_idx`
matches each target's primary queue, but the seed shape is otherwise
identical across all 10 devices.

```protobuf
# seed_dma_reset_gadget.textpb
# Chain: read (buf 0) → STATUS write (buf 28) → tail (buf 0).
# DMA-write 0 into STATUS while mid-chain → soft_reset → UAF.
ops { get_features {} }
ops { set_features { features: 4294967296 } }
ops { vq_setup { vq_idx: 0 size: 64 } }
ops { set_status { bits: 4 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 0  len: 4 device_writable: false chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 28 len: 4 device_writable: true  chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 0  len: 4 device_writable: true  chain_next: false exotic_region: 2 } }
ops { vq_kick { vq_idx: 0 } }
```

```protobuf
# seed_dma_recursive_notify.textpb
# 9-deep chain all pointing at QUEUE_NOTIFY (buf_id=20 → offset 0x050).
# Each DMA write re-kicks the queue → recursive bottom-half scheduling.
ops { get_features {} }
ops { set_features { features: 4294967296 } }
ops { vq_setup { vq_idx: 0 size: 64 } }
ops { set_status { bits: 4 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: true  exotic_region: 2 } }
ops { vq_add_desc { vq_idx: 0 buf_id: 20 len: 4 device_writable: true chain_next: false exotic_region: 2 } }
ops { vq_kick { vq_idx: 0 } }
```

### Why this matters for coverage

Without `exotic_region` the harness can only explore bugs that are
reachable when descriptors point into DRAM. The reentrancy paths in
`virtio_mmio_write` and `virtio_queue_notify` -- the paths where a
mid-chain register write modifies shared device state -- are unreachable
from normal DRAM buffers, because `address_space_write` to DRAM never
calls back into the virtio-mmio handler. With `exotic_region = 2`
those code paths become first-class fuzz targets.

