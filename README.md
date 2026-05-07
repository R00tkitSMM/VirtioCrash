# qemu-virtio-protofuzz

LPM (libprotobuf-mutator) driven, in-process structured fuzzers for
QEMU's virtio devices on the arm-virt machine. Currently ships
**10 targets**: `virtio-blk`, `virtio-net`, `virtio-gpu`, `virtio-scsi`,
`virtio-fs`, `virtio-snd`, `virtio-vsock`, `virtio-console`,
`virtio-input`, `virtio-balloon`.

Each target gives libFuzzer a typed grammar (a `.proto` schema) instead
of raw bytes, and the harness compiles each input into a sequence of
virtio-mmio register writes + descriptor placements that exercise the
device exactly as a guest driver would. State-aware extras
(slot-keyed resources for virtio-gpu, multi-thread interleaved mode for
virtio-blk, typed CVQ commands for virtio-net) live alongside the
generic ops.

## Repo layout

```text
qemu-virtio-protofuzz/
├── README.md             this file
├── BUILD.md              detailed build / run / debug walkthrough
├── ARCHITECTURE.md       deep-dive: data flow, qtest wrappers, LPM
├── LICENSE               GPL-2.0 (matches QEMU)
├── apply.sh              copies these files into a QEMU tree
├── build.sh              configures + builds qemu-fuzz-aarch64
├── tests/qtest/
│   ├── libqtest.c                          (modified upstream)
│   └── fuzz/
│       ├── fuzz.c                           (modified upstream)
│       ├── fuzz.h                           (modified upstream)
│       ├── meson.build                      (modified upstream)
│       ├── qtest_wrappers.c                 (modified upstream)
│       ├── proto_fuzz_virtio_blk.{cc,proto}     (new harness + grammar)
│       ├── proto_fuzz_virtio_net.{cc,proto}     (new)
│       ├── proto_fuzz_virtio_gpu.{cc,proto}     (new)
│       ├── proto_fuzz_virtio_scsi.{cc,proto}    (new)
│       ├── proto_fuzz_virtio_fs.{cc,proto}      (new -- with mock vhost-user backend)
│       ├── proto_fuzz_virtio_snd.{cc,proto}     (new)
│       ├── proto_fuzz_virtio_vsock.{cc,proto}   (new)
│       ├── proto_fuzz_virtio_console.{cc,proto} (new)
│       ├── proto_fuzz_virtio_input.{cc,proto}   (new)
│       └── proto_fuzz_virtio_balloon.{cc,proto} (new)
└── scripts/oss-fuzz/
    ├── gen_virtio_blk_corpus.py             (new generator)
    ├── gen_virtio_net_corpus.py             (new)
    ├── gen_virtio_gpu_corpus.py             (new)
    ├── gen_virtio_scsi_corpus.py            (new)
    ├── gen_virtio_fs_corpus.py              (new)
    ├── gen_virtio_snd_corpus.py             (new)
    ├── gen_virtio_vsock_corpus.py           (new)
    ├── gen_virtio_console_corpus.py         (new)
    ├── gen_virtio_input_corpus.py           (new)
    └── gen_virtio_balloon_corpus.py         (new)
```

The directory layout mirrors the QEMU tree on purpose: `apply.sh` is
just a typed `cp -r`, no patch hunks involved.

## Quick start

### 1. Apply

```sh
git clone <this-repo>                              ~/qemu-virtio-protofuzz
git clone https://gitlab.com/qemu-project/qemu.git ~/qemu

~/qemu-virtio-protofuzz/apply.sh ~/qemu --dry-run   # list what would be copied
~/qemu-virtio-protofuzz/apply.sh ~/qemu             # actually copy
```

`apply.sh` is a typed `cp -r` -- it copies 25 files (5 modified upstream
+ 20 new: 10 `.cc` + 10 `.proto`) plus 10 corpus generators into the matching
QEMU paths. Before overwriting any of the 5 modified upstream files
(`fuzz.c`, `fuzz.h`, `meson.build`, `qtest_wrappers.c`, `libqtest.c`)
it stashes the originals into
`~/qemu/.proto-fuzz-backup-<unix-timestamp>/` so you can roll back with:

```sh
cp -R ~/qemu/.proto-fuzz-backup-*/* ~/qemu/
```

### 2. Build

```sh
~/qemu-virtio-protofuzz/build.sh ~/qemu
# -> ~/qemu/build-fuzz/qemu-fuzz-aarch64
```

`build.sh` runs `configure --enable-fuzzing --target-list=aarch64-softmmu`
on first invocation, then `ninja qemu-fuzz-aarch64`. It prepends
Homebrew LLVM to PATH because Apple `/usr/bin/clang` doesn't ship
`libclang_rt.fuzzer_osx.a`. Override with `LLVM_PREFIX=...` if your
LLVM lives elsewhere.

### 3. Generate corpus + run, per target

Each target has its own seed-corpus generator and gets its own corpus
directory.

#### virtio-net

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_net_corpus.py \
        -o /tmp/corpus_net --clean

~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-net \
    -close_fd_mask=2 -max_len=65536 \
    /tmp/corpus_net
```

#### virtio-gpu

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_gpu_corpus.py \
        -o /tmp/corpus_gpu --clean

~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-gpu \
    -close_fd_mask=2 -max_len=65536 \
    /tmp/corpus_gpu
```

#### virtio-blk

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_blk_corpus.py \
        -o /tmp/corpus_blk --clean

~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-blk \
    -close_fd_mask=2 -max_len=65536 \
    /tmp/corpus_blk
```

#### virtio-scsi

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_scsi_corpus.py \
        -o /tmp/corpus_scsi --clean

~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-scsi \
    -close_fd_mask=2 -max_len=65536 \
    /tmp/corpus_scsi
```

#### virtio-fs (Linux only)

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_fs_corpus.py \
        -o /tmp/corpus_fs --clean

~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-fs \
    -close_fd_mask=2 -max_len=65536 \
    /tmp/corpus_fs
```

`vhost-user-fs-device` is built into QEMU only on Linux (macOS builds
don't include it). The harness ships an in-process mock vhost-user
backend so no external `virtiofsd` is required -- it just needs the
QEMU device to be compiled in. On macOS the target registers and
compiles, but the QEMU launch fails with
`'vhost-user-fs-device' is not a valid device model name`.

#### virtio-snd

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_snd_corpus.py \
        -o /tmp/corpus_snd --clean
~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-snd \
    -close_fd_mask=2 -max_len=65536 /tmp/corpus_snd
```

#### virtio-vsock (Linux only)

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_vsock_corpus.py \
        -o /tmp/corpus_vsock --clean
~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-vsock \
    -close_fd_mask=2 -max_len=65536 /tmp/corpus_vsock
```

`vhost-vsock-device` requires `/dev/vhost-vsock` (Linux kernel module).
On macOS the target registers but QEMU launch fails.

#### virtio-console

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_console_corpus.py \
        -o /tmp/corpus_console --clean
~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-console \
    -close_fd_mask=2 -max_len=65536 /tmp/corpus_console
```

#### virtio-input

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_input_corpus.py \
        -o /tmp/corpus_input --clean
~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-input \
    -close_fd_mask=2 -max_len=65536 /tmp/corpus_input
```

#### virtio-balloon

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_balloon_corpus.py \
        -o /tmp/corpus_balloon --clean
~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-balloon \
    -close_fd_mask=2 -max_len=65536 /tmp/corpus_balloon
```

The generators accept `-n N` to cap or oversubscribe the seed count
(`gen_virtio_gpu_corpus.py -n 100` produces 13 base seeds + 87
deterministic perturbations). `--seed 0xN` pins the variation RNG.

### 4. Confirm a target is hitting device code

A rising `cov:` counter alone is not proof -- some of it comes from the
proto parser. Set a breakpoint on a known device-side function and
check it fires within a few runs:

```sh
# virtio-net: the CVQ entry point
lldb -b \
  -o "process handle -p true -s false SIGUSR2" \
  -o "br set -n virtio_net_handle_ctrl" \
  -o "run --fuzz-target=proto-fuzz-virtio-net -close_fd_mask=2 \
          -runs=20 /tmp/corpus_net" \
  ~/qemu/build-fuzz/qemu-fuzz-aarch64
```

Equivalent functions for the other targets:

| Target                       | Function to break on                |
|--|--|
| `proto-fuzz-virtio-net`      | `virtio_net_handle_ctrl`            |
| `proto-fuzz-virtio-gpu`      | `virtio_gpu_simple_process_cmd`     |
| `proto-fuzz-virtio-blk`      | `virtio_blk_handle_request`         |
| `proto-fuzz-virtio-scsi`     | `virtio_scsi_handle_cmd`            |
| `proto-fuzz-virtio-fs`       | `vuf_handle_output` (Linux only)    |
| `proto-fuzz-virtio-snd`      | `virtio_snd_handle_ctrl`            |
| `proto-fuzz-virtio-vsock`    | `vhost_vsock_handle_output` (Linux only) |
| `proto-fuzz-virtio-console`  | `control_out` / `flush_buf`         |
| `proto-fuzz-virtio-input`    | `virtio_input_handle_sts`           |
| `proto-fuzz-virtio-balloon`  | `virtio_balloon_handle_output`      |

If the breakpoint never fires, see ARCHITECTURE.md Section 13 for the
three classic harness bugs (all three are already fixed in this repo).

See **BUILD.md** for the full walkthrough (Linux setup, libprotobuf-mutator
from source, macOS codesigning quirk, crash reproducer building, and
rollback steps).

## Verified end-to-end on a fresh QEMU clone

Last sanity check (macOS arm64, Homebrew LLVM 22.1.4):

```sh
git clone --depth=1 https://gitlab.com/qemu-project/qemu.git /tmp/qemu  #  208 MB, ~30s
~/qemu-virtio-protofuzz/apply.sh /tmp/qemu                              #  0.3s, copies 30 files
~/qemu-virtio-protofuzz/build.sh  /tmp/qemu                             #  ~5 min first build
/tmp/qemu/build-fuzz/qemu-fuzz-aarch64                                  #  lists all 10 targets
```

5-second smoke test on virtio-net:

```text
#46     INITED cov: 1843 ft:  3332 corp: 19/77Kb
#4612   DONE   cov: 2184 ft: 10274 corp: 572/1466Kb  exec/s: 768
```

No build errors, no crashes, all 10 proto-fuzz targets register correctly.


## Targets

| Target name                  | Device          | Highlights |
|--|--|--|
| `proto-fuzz-virtio-blk`      | virtio-blk      | TOCTOU / stale-descriptor mode, mmio + DMA fault injection, DMA reentrancy seeds (reflection / reset-gadget UAF / recursive-notify), concurrent thread_b mode |
| `proto-fuzz-virtio-net`      | virtio-net      | typed CVQ commands, RSS, host-side `qmp_set_link`, VLAN tag insert, DMA reentrancy seeds |
| `proto-fuzz-virtio-gpu`      | virtio-gpu      | slot-keyed resources, blob resources, fence state, console hotplug, DMA reentrancy seeds |
| `proto-fuzz-virtio-scsi`     | virtio-scsi     | typed CDBs (INQUIRY/READ_CAP/READ/WRITE/MODE_SENSE/REPORT_LUNS/...), TMF + AN on the control queue, raw-CDB escape hatch, DMA reentrancy seeds |
| `proto-fuzz-virtio-fs`       | vhost-user-fs   | in-process mock vhost-user backend, typed FUSE requests (INIT/LOOKUP/GETATTR/OPEN/READ/WRITE/xattr/IOCTL/...), HP-queue forget, DMA reentrancy seeds. **Linux only** -- macOS builds don't include `vhost-user-fs-device`. |
| `proto-fuzz-virtio-snd`      | virtio-sound    | typed control commands (JACK_INFO, PCM_INFO/SET_PARAMS/PREPARE/START/STOP/RELEASE, CHMAP_INFO), TX/RX PCM data transfers, raw-CTRL escape hatch, DMA reentrancy seeds |
| `proto-fuzz-virtio-vsock`    | vhost-vsock     | typed packets (REQUEST/RESPONSE/RST/SHUTDOWN/RW/CREDIT_*), STREAM/DGRAM/SEQPACKET, RX-buffer staging, DMA reentrancy seeds. **Linux only** (needs `/dev/vhost-vsock`). |
| `proto-fuzz-virtio-console`  | virtio-serial   | multi-port TX/RX, control-queue events (PORT_READY/OPEN/RESIZE/PORT_NAME), 2 ports preconfigured, DMA reentrancy seeds |
| `proto-fuzz-virtio-input`    | virtio-keyboard | status-queue events (LED, REP), event-queue buffer staging, config-space probing, DMA reentrancy seeds |
| `proto-fuzz-virtio-balloon`  | virtio-balloon  | inflate/deflate PFN lists, stats blobs (free/total/avail/caches/...), free-page-hint cmd_id, DMA reentrancy seeds |

## DMA reentrancy

All 10 corpus generators ship five DMA reentrancy seeds in addition to
device-specific seeds. These exercise a class of bugs where the device
DMA-walks a descriptor whose buffer GPA points into MMIO space instead
of DRAM, causing the device to re-enter its own register handler
while still processing the current chain. This pattern was documented
in the Black Hat Asia 2022 talk "Recursive MMIO Flaws in QEMU".

### exotic_region field

`VqAddDesc` has an optional `exotic_region` field that controls where
the descriptor's buffer GPA lands:

| value | buffer GPA | region |
|--|--|--|
| 0 (default) | DRAM buffer pool (0x47…) | normal data buffer |
| 1 | UART0 / PL011 (0x09000000) | peripheral register fault injection |
| 2 | virtio-mmio self (0x0a003e00) | **DMA self-reflection / reentrancy** |
| 3 | GIC distributor (0x08000000) | interrupt-controller register fault |

All base addresses come from `hw/arm/virt.c base_memmap[]` in the QEMU
source tree, not from conference slides. `0x0a003e00` is slot 31
(`base + 31 × 0x200`) because arm-virt fills MMIO slots
high-address-first; a single device always lands at slot 31.

For `exotic_region = 2`, `buf_id % 128` selects a 4-byte-aligned offset
inside the 512-byte virtio-mmio window. Key offsets (from
`include/standard-headers/linux/virtio_mmio.h`):

| buf_id | register offset | register | reentrancy effect |
|--|--|--|--|
| 17 | 0x044 | QUEUE_READY | write 0 disables queue mid-flight |
| 20 | 0x050 | QUEUE_NOTIFY | BH re-kick → recursive chain walk |
| 25 | 0x064 | INTERRUPT_ACK | clears interrupt mid-processing |
| 28 | 0x070 | STATUS | write 0 → `virtio_mmio_soft_reset` → UAF |
| 32 | 0x080 | QUEUE_DESC_LOW | corrupts descriptor table pointer |
| 36 | 0x090 | QUEUE_AVAIL_LOW | corrupts avail ring pointer |
| 40 | 0x0a0 | QUEUE_USED_LOW | corrupts used ring pointer |

### Seed families (all 10 generators)

| Seed file | buf_id / register | Attack class |
|--|--|--|
| `seed_dma_reflection.textpb` | 5 / DeviceFeaturesSel | basic DMA self-reference |
| `seed_dma_all_regions.textpb` | regions 1–3 | all four DMA target regions |
| `seed_dma_reflection_concurrent.textpb` | region 2 | DMA reflection + concurrent thread_b ops |
| `seed_dma_reset_gadget.textpb` | 28 / STATUS (0x070) | DMA-write 0 → `soft_reset` → UAF |
| `seed_dma_recursive_notify.textpb` | 20 / QUEUE_NOTIFY (0x050) | 9-deep kick chain → recursion guard / stack overflow |

See ARCHITECTURE.md Section 14 for the full design and seed structure.

---

**Not in upstream QEMU:** `virtio-video` -- exists only in out-of-tree forks
(Cloud Hypervisor, vendor branches). Not shipped here.

## Did this patch QEMU's device code?

No. Every change is under `tests/qtest/` or `scripts/oss-fuzz/`.
`hw/net/virtio-net.c`, `hw/virtio/virtio.c`, `hw/virtio/virtio-mmio.c`
were briefly instrumented with `fprintf` while we were chasing a
coverage bug -- those prints were reverted before this repo was
generated. A `git status` after running `apply.sh` should only show
fuzz-tree changes.

## Documentation

- **BUILD.md** -- exact build / run / verification commands.
- **ARCHITECTURE.md** -- how the in-process harness works, what
  qtest_wrappers does, why we ended up doing it this way (the build
  journey), and Section 13 documenting the three harness bugs that
  were silently suppressing device-side coverage.

## License

GPL-2.0-or-later. Same license as QEMU itself; these files are
intended to be upstreamed someday.
