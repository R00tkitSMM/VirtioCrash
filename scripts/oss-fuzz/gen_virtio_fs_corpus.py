#!/usr/bin/env python3
"""
Seed corpus generator for proto-fuzz-virtio-fs.

The harness ships an in-process mock vhost-user backend that ACKs
every message, so vhost-user negotiation completes and the QEMU
virtio-fs frontend reaches the state where it forwards descriptor
chains. The seeds drive the typed FUSE request grammar.

Seeds:
  * init only                    -- bare prologue
  * FUSE_INIT
  * FUSE_LOOKUP
  * FUSE_GETATTR / FUSE_SETATTR
  * FUSE_OPEN + FUSE_READ + FUSE_RELEASE
  * FUSE_WRITE
  * FUSE_MKDIR / FUSE_RMDIR / FUSE_UNLINK
  * FUSE_GETXATTR / FUSE_SETXATTR / FUSE_LISTXATTR / FUSE_REMOVEXATTR
  * FUSE_IOCTL
  * FUSE_FORGET on the high-priority queue
  * Raw FUSE op (for opcodes we don't model)
"""

import argparse
import os
import random
import sys

VIRTIO_F_VERSION_1 = 1 << 32
STATUS_DRIVER_OK   = 0x04


def escape_bytes(b: bytes) -> str:
    out = []
    for x in b:
        if 32 <= x < 127 and x not in (ord('"'), ord('\\')):
            out.append(chr(x))
        else:
            out.append('\\%03o' % x)
    return ''.join(out)


def op_get_features():
    return "ops { get_features {} }"

def op_set_features(f):
    return "ops { set_features { features: %d } }" % f

def op_vq_setup(idx, size=64):
    return "ops { vq_setup { vq_idx: %d size: %d } }" % (idx, size)

def op_set_status(bits):
    return "ops { set_status { bits: %d } }" % bits

def op_vq_wait_used(idx):
    return "ops { vq_wait_used { vq_idx: %d } }" % idx

def op_reset():
    return "ops { reset {} }"



# ---- DMA reentrancy / fault-injection helpers --------------------------------

def op_vq_add_desc(vq_idx, buf_id, length, device_writable, chain_next,
                   exotic_region=0):
    s = ("ops { vq_add_desc { vq_idx: %d buf_id: %d len: %d "
         "device_writable: %s chain_next: %s"
         % (vq_idx, buf_id, length,
            'true' if device_writable else 'false',
            'true' if chain_next else 'false'))
    if exotic_region:
        s += " exotic_region: %d" % exotic_region
    return s + " } }"

def op_mmio_corrupt(offset, value, size=4):
    return ("ops { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))

def op_mem_write_absolute(gpa, data: bytes):
    return ('ops { mem_write_absolute { gpa: %d data: "' + escape_bytes(data) + '" } }') if False else (
        'ops { mem_write_absolute { gpa: %d data: "%s" } }' % (gpa, escape_bytes(data)))

def b_vq_add_desc(vq_idx, buf_id, length, device_writable, chain_next,
                  exotic_region=0):
    s = ("ops_thread_b { vq_add_desc { vq_idx: %d buf_id: %d len: %d "
         "device_writable: %s chain_next: %s"
         % (vq_idx, buf_id, length,
            'true' if device_writable else 'false',
            'true' if chain_next else 'false'))
    if exotic_region:
        s += " exotic_region: %d" % exotic_region
    return s + " } }"

def b_mmio_corrupt(offset, value, size=4):
    return ("ops_thread_b { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))

def prologue():
    """Bring the device up: HP queue (0), notification queue (1),
    request queue 0 (vq 2)."""
    return [
        op_get_features(),
        op_set_features(VIRTIO_F_VERSION_1),
        op_vq_setup(0, 64),    # high-priority queue
        op_vq_setup(1, 64),    # notification queue
        op_vq_setup(2, 64),    # request queue 0
        op_set_status(STATUS_DRIVER_OK),
    ]


def emit(path, ops, comment):
    body = "# " + comment.strip().replace("\n", "\n# ") + "\n"
    body += "\n".join(ops) + "\n"
    with open(path, "w") as f:
        f.write(body)


def fuse(unique=1, nodeid=1, in_buf=1024, op_block=""):
    return ('ops { fuse_request { vq_idx: 2 unique: %d nodeid: %d '
            'in_buf_size: %d %s } }') % (unique, nodeid, in_buf, op_block)


def hp(opcode, unique=1, nodeid=1, payload=b""):
    return ('ops { fuse_hp_req { opcode: %d unique: %d nodeid: %d '
            'payload: "%s" } }')\
        % (opcode, unique, nodeid, escape_bytes(payload))


# ---- typed FUSE op blocks --------------------------------------

def op_init(major=7, minor=38, max_ra=0x20000, flags=0):
    return ('init { major: %d minor: %d max_readahead: %d flags: %d }'
            % (major, minor, max_ra, flags))

def op_lookup(name):
    return 'lookup { name: "%s" }' % escape_bytes(name + b'\0')

def op_getattr(fh=0, flags=0):
    return 'getattr { fh: %d getattr_flags: %d }' % (fh, flags)

def op_setattr(fh=0, valid=0, size=0):
    return 'setattr { fh: %d valid: %d size: %d }' % (fh, valid, size)

def op_open(flags=0, open_flags=0):
    return 'open { flags: %d open_flags: %d }' % (flags, open_flags)

def op_read(fh, offset=0, size=4096):
    return 'read { fh: %d offset: %d size: %d }' % (fh, offset, size)

def op_write(fh, offset=0, data=b""):
    return ('write { fh: %d offset: %d size: %d data: "%s" }'
            % (fh, offset, len(data), escape_bytes(data)))

def op_release(fh, flags=0):
    return 'release { fh: %d flags: %d }' % (fh, flags)

def op_mkdir(name, mode=0o755):
    return 'mkdir { mode: %d umask: 0 name: "%s" }' % (mode, escape_bytes(name + b'\0'))

def op_unlink(name):
    return 'unlink { name: "%s" }' % escape_bytes(name + b'\0')

def op_rmdir(name):
    return 'rmdir { name: "%s" }' % escape_bytes(name + b'\0')

def op_flush(fh):
    return 'flush { fh: %d }' % fh

def op_getxattr(name, size=256):
    return 'getxattr { size: %d name: "%s" }' % (size, escape_bytes(name + b'\0'))

def op_setxattr(name, value, flags=0):
    return ('setxattr { flags: %d name: "%s" value: "%s" }'
            % (flags, escape_bytes(name + b'\0'), escape_bytes(value)))

def op_listxattr(size=512):
    return 'listxattr { size: %d }' % size

def op_removexattr(name):
    return 'removexattr { name: "%s" }' % escape_bytes(name + b'\0')

def op_ioctl(fh, cmd, arg=0, in_data=b"", out_size=0):
    return ('ioctl { fh: %d flags: 0 cmd: %d arg: %d '
            'in_size: %d out_size: %d in_data: "%s" }'
            % (fh, cmd, arg, len(in_data), out_size, escape_bytes(in_data)))

def op_raw(opcode, payload=b"", in_len=512):
    return ('raw { opcode: %d in_len: %d payload: "%s" }'
            % (opcode, in_len, escape_bytes(payload)))


# ---- seeds -----------------------------------------------------

def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue: queue setup for HP/notify/req0, DRIVER_OK. "
            "No FUSE I/O.",
            prologue())

def seed_fuse_init():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    return ("seed_02_fuse_init.textpb",
            "Send a FUSE_INIT (major=7 minor=38). Mandatory first FUSE "
            "request -- exercises the init responder.",
            ops)

def seed_lookup():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=2, nodeid=1, op_block=op_lookup(b"hello")))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=3, nodeid=1, op_block=op_lookup(b"a/b/c")))
    ops.append(op_vq_wait_used(2))
    return ("seed_03_lookup.textpb",
            "INIT + FUSE_LOOKUP for two paths. Exercises the path-component "
            "parsing.",
            ops)

def seed_getattr_setattr():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=2, nodeid=1, op_block=op_getattr(fh=0, flags=0)))
    ops.append(op_vq_wait_used(2))
    # setattr with FATTR_MODE | FATTR_UID | FATTR_GID | FATTR_SIZE
    ops.append(fuse(unique=3, nodeid=1,
                    op_block=op_setattr(fh=0, valid=0x1f, size=0x1000)))
    ops.append(op_vq_wait_used(2))
    return ("seed_04_attr.textpb",
            "INIT + GETATTR + SETATTR. Drives the attr cache + valid-mask "
            "handling.",
            ops)

def seed_open_read_release():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=2, nodeid=2, op_block=op_open(flags=0)))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=3, nodeid=2, in_buf=4096,
                    op_block=op_read(fh=1, offset=0, size=4096)))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=4, nodeid=2, op_block=op_release(fh=1)))
    ops.append(op_vq_wait_used(2))
    return ("seed_05_open_read.textpb",
            "INIT + OPEN + READ(4096) + RELEASE. Standard read flow.",
            ops)

def seed_write():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    payload = b"hello virtiofs" + b"\x00" * 200
    ops.append(fuse(unique=2, nodeid=2,
                    op_block=op_write(fh=1, offset=0, data=payload)))
    ops.append(op_vq_wait_used(2))
    return ("seed_06_write.textpb",
            "INIT + WRITE with ~200 bytes of payload at offset 0.",
            ops)

def seed_mkdir_rmdir():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=2, nodeid=1, op_block=op_mkdir(b"sub")))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=3, nodeid=1, op_block=op_unlink(b"victim")))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=4, nodeid=1, op_block=op_rmdir(b"sub")))
    ops.append(op_vq_wait_used(2))
    return ("seed_07_dir_ops.textpb",
            "INIT + MKDIR + UNLINK + RMDIR. Directory-op grammar.",
            ops)

def seed_xattr():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=2, nodeid=1,
                    op_block=op_getxattr(b"user.test", size=256)))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=3, nodeid=1,
                    op_block=op_setxattr(b"user.test", b"hello", flags=0)))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=4, nodeid=1, op_block=op_listxattr(size=512)))
    ops.append(op_vq_wait_used(2))
    ops.append(fuse(unique=5, nodeid=1,
                    op_block=op_removexattr(b"user.test")))
    ops.append(op_vq_wait_used(2))
    return ("seed_08_xattr.textpb",
            "INIT + GETXATTR + SETXATTR + LISTXATTR + REMOVEXATTR. "
            "xattr family has a length-handling CVE history.",
            ops)

def seed_ioctl():
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    # FS_IOC_GETFLAGS = 0x80086601 (Linux generic)
    ops.append(fuse(unique=2, nodeid=2, in_buf=128,
                    op_block=op_ioctl(fh=1, cmd=0x80086601,
                                       arg=0, out_size=8)))
    ops.append(op_vq_wait_used(2))
    return ("seed_09_ioctl.textpb",
            "INIT + IOCTL (FS_IOC_GETFLAGS). Catch-all extension point.",
            ops)

def seed_forget_hp():
    """FORGET goes on the high-priority queue (vq 0). Payload is
    a 64-bit nlookup count."""
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    # FORGET payload: u64 nlookup
    nlookup = (1).to_bytes(8, 'little')
    ops.append(hp(opcode=2, unique=2, nodeid=1, payload=nlookup))
    ops.append(op_vq_wait_used(0))
    return ("seed_10_forget_hp.textpb",
            "INIT + FORGET on high-priority queue (vq 0).",
            ops)

def seed_raw():
    """Vendor or new-spec opcode -- LPM mutates from here."""
    ops = prologue()
    ops.append(fuse(unique=1, op_block=op_init()))
    ops.append(op_vq_wait_used(2))
    # FUSE_FALLOCATE = 43
    payload = (1).to_bytes(8, 'little')          # fh
    payload += (0).to_bytes(8, 'little')          # offset
    payload += (4096).to_bytes(8, 'little')       # length
    payload += (0).to_bytes(4, 'little')          # mode
    payload += (0).to_bytes(4, 'little')          # padding
    ops.append(fuse(unique=2, nodeid=2,
                    op_block=op_raw(opcode=43, payload=payload, in_len=64)))
    ops.append(op_vq_wait_used(2))
    return ("seed_11_raw_fallocate.textpb",
            "INIT + raw opcode 43 (FALLOCATE). Lets LPM mutate the "
            "opcode and payload to reach unmodelled FUSE ops.",
            ops)


def variation(base_seed, idx, rng):
    name, comment, ops = base_seed
    new_name = name.replace(".textpb", "_v%03d.textpb" % idx)
    new_comment = comment + " -- variation %d (auto-perturbed)." % idx
    out = list(ops)
    if len(out) >= 2:
        s = rng.choice(["dup", "drop", "shuffle_tail", "repeat_one"])
        if s == "dup":
            i = rng.randrange(len(out))
            out.insert(i, out[i])
        elif s == "drop":
            i = rng.randrange(1, len(out))
            out.pop(i)
        elif s == "shuffle_tail":
            head_len = min(6, len(out))
            tail = out[head_len:]
            if tail:
                rng.shuffle(tail)
                out = out[:head_len] + tail
        elif s == "repeat_one":
            i = rng.randrange(len(out))
            n = rng.randint(2, 4)
            out[i:i+1] = [out[i]] * n
    return (new_name, new_comment, out)


def seed_dma_reflection():
    """DMA Reflection: device-writable descs point at the device's own
    MMIO (exotic_region=2). buf_id=20 → QueueNotify (offset 0x050, causes
    reentrancy kick); buf_id=28 → QueueDescLow (corrupts desc table ptr).
    CVE-2024-3446 class."""
    ops = prologue()
    ops += [
        op_vq_add_desc(1, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(1, 44, 4, True,  False, exotic_region=2),
        "ops { vq_kick { vq_idx: 1 } }",
    ]
    return ("seed_dma_reflection.textpb",
            "DMA Reflection: device-writable descs → own MMIO (exotic_region=2). "
            "buf_id=20→QueueNotify, buf_id=28→QueueDescLow. "
            "CVE-2024-3446 class.",
            ops)


def seed_dma_all_regions():
    """All four exotic GPA regions in one descriptor chain.

    Region 1 (UART, 0x09000000): hits UART read/write handler
    Region 2 (own MMIO / Reflection, kVirtioMmioBase): self-reentrancy
    Region 3 (GIC distributor, 0x08000000): interrupt controller MMIO
    Region 4 (virt-mmio bus slot 0, 0x0a000000): cross-device Refraction
    """
    ops = prologue()
    ops += [
        op_vq_add_desc(1, 1,  4, False, True,  exotic_region=1),
        op_vq_add_desc(1, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(1, 0,  4, True,  True,  exotic_region=3),
        op_vq_add_desc(1, 0,  4, True,  False, exotic_region=4),
        "ops { vq_kick { vq_idx: 1 } }",
    ]
    return ("seed_dma_all_exotic_regions.textpb",
            "All four exotic GPA regions: UART(1), own-MMIO Reflection(2), "
            "GIC(3), virt-mmio bus Refraction(4). Seeds all reentrancy primitives.",
            ops)


def seed_dma_reflection_concurrent():
    """Concurrent DMA Reflection: primary descs target own QueueNotify;
    secondary thread races with MMIO writes to the same register.
    Exercises concurrent reentrancy. CVE-2024-3446 class."""
    ops = prologue()
    ops += [
        op_vq_add_desc(1, 20, 4, True, True,  exotic_region=2),
        op_vq_add_desc(1, 44, 4, True, False, exotic_region=2),
        "ops { vq_kick { vq_idx: 1 } }",
        b_mmio_corrupt(0x050, 0),
        b_mmio_corrupt(0x070, 0),
        b_vq_add_desc(1, 20, 4, True, False, exotic_region=2),
        "thread_b_iter: 4",
    ]
    return ("seed_dma_reflection_concurrent.textpb",
            "Concurrent DMA Reflection: primary thread uses Reflection descs; "
            "secondary races with QueueNotify + Status MMIO writes.",
            ops)



def seed_dma_reset_gadget():
    """Reset-gadget UAF pattern (BH Asia 2022 talk):
    A descriptor's GPA points at the device's own Status register
    (exotic_region=2, buf_id=28 → offset 0x070).  When the device
    DMA-WRITES to that address, if it happens to write 0x00000000,
    virtio_mmio_soft_reset() fires mid-DMA: queues are freed and state
    is reset while the DMA code path still holds pointers into it.
    Any subsequent descriptor access → UAF.

    Chain layout:
      desc[0]: normal out-header   (device reads request)
      desc[1]: → Status reg write  (device DMA-write → may trigger reset)
      desc[2]: normal data buffer  (device uses freed state if reset fired)

    Even without the reset firing, this exercises the MMIO write path
    for Status with an arbitrary value produced by DMA, which exercises
    unusual status transitions."""
    ops = prologue()
    ops += [
        # head: device reads from own MagicValue reg (buf_id=0 → 0x000)
        op_vq_add_desc(1, 0,   4, False, True,  exotic_region=2),
        # body: device WRITES to own Status register → potential soft-reset
        op_vq_add_desc(1, 28,  4, True,  True,  exotic_region=2),
        # tail: device continues with (possibly freed) state → UAF path
        op_vq_add_desc(1, 0,   4, True,  False, exotic_region=2),
        "ops { vq_kick { vq_idx: 1 } }",
    ]
    return ("seed_dma_reset_gadget.textpb",
            "Reset-gadget UAF: chain targeting Status register (buf_id=28→0x070). "
            "DMA-write to Status may fire virtio_mmio_soft_reset() mid-DMA, leaving "
            "freed queue state in-use. BH Asia 2022 pattern.",
            ops)


def seed_dma_recursive_notify():
    """Endless-recursion / stack-overflow path (BH Asia 2022 talk):
    A chain of device-writable descs all pointing at QueueNotify
    (exotic_region=2, buf_id=20 → offset 0x050).  Each time the
    device DMA-writes to QueueNotify it schedules another BH for
    queue processing, potentially creating a deep call stack before
    QEMU's recursion guard (if any) fires.

    Without a guard: stack overflow (UBSan / ASan / SIGSTKSZ catch).
    With a guard: exercises the guard exit path and any error handling
    that follows.  Either way this is high-signal."""
    ops = prologue()
    for _ in range(8):
        ops.append(op_vq_add_desc(1, 20, 4, True, True,  exotic_region=2))
    ops.append(op_vq_add_desc(1, 20, 4, True, False, exotic_region=2))
    ops.append("ops { vq_kick { vq_idx: 1 } }")
    return ("seed_dma_recursive_notify.textpb",
            "Endless-recursion test: 9-deep chain of descs all targeting "
            "QueueNotify (buf_id=20 → offset 0x050). Each DMA-write to "
            "QueueNotify may schedule another BH kick → deep recursion. "
            "Exercises QEMU recursion guard or triggers stack overflow.",
            ops)

SEED_BUILDERS = [
    seed_init,
    seed_fuse_init,
    seed_lookup,
    seed_getattr_setattr,
    seed_open_read_release,
    seed_write,
    seed_mkdir_rmdir,
    seed_xattr,
    seed_ioctl,
    seed_forget_hp,
    seed_raw,
    seed_dma_reflection,
    seed_dma_all_regions,
    seed_dma_reflection_concurrent,
    seed_dma_reset_gadget,
    seed_dma_recursive_notify,
]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-o", "--out", default="/tmp/proto_fuzz_run/corpus_fs",
                   help="output directory (default: %(default)s)")
    p.add_argument("--clean", action="store_true",
                   help="remove existing .textpb files before generating")
    p.add_argument("-n", "--count", type=int, default=None,
                   help="number of seeds to emit (default: %d)" %
                        len(SEED_BUILDERS))
    p.add_argument("--seed", type=lambda x: int(x, 0), default=0xC0FFEE,
                   help="rng seed for variation generation (default: 0xC0FFEE)")
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)
    if args.clean:
        for name in os.listdir(args.out):
            if name.endswith(".textpb"):
                os.unlink(os.path.join(args.out, name))

    target = args.count if args.count is not None else len(SEED_BUILDERS)
    rng = random.Random(args.seed)
    base_seeds = [b() for b in SEED_BUILDERS]

    seeds = list(base_seeds[:target])
    v_idx = 1
    while len(seeds) < target:
        base = base_seeds[(v_idx - 1) % len(base_seeds)]
        seeds.append(variation(base, v_idx, rng))
        v_idx += 1

    n = 0
    for name, comment, ops in seeds:
        path = os.path.join(args.out, name)
        emit(path, ops, comment)
        n += 1
        print("wrote", path, "(%d ops)" % len(ops))

    print("\n%d seeds written to %s" % (n, args.out))


if __name__ == "__main__":
    sys.exit(main())
