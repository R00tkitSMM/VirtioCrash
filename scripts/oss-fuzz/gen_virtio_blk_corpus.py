#!/usr/bin/env python3
"""
Seed corpus generator for proto-fuzz-virtio-blk.

Includes seeds covering:
  * the standard init prologue
  * a complete virtio-blk read request (3-descriptor chain)
  * a complete virtio-blk write request
  * fault injection via MemwriteAbsolute (DMA-region corruption)
  * fault injection via MmioCorrupt (register-decoder corruption)
  * Phase B interleaved mode: stale-descriptor pattern where a
    secondary-list op mutates a descriptor's backing memory between
    the primary list's vq_add_desc and vq_kick.
"""

import argparse
import os
import struct
import sys

VIRTIO_F_VERSION_1   = 1 << 32
STATUS_DRIVER        = 0x02
STATUS_DRIVER_OK     = 0x04

# virtio-blk request types (virtio_blk.h)
VIRTIO_BLK_T_IN      = 0
VIRTIO_BLK_T_OUT     = 1
VIRTIO_BLK_T_FLUSH   = 4
VIRTIO_BLK_T_GET_ID  = 8

# virtio-mmio offsets we care about for MmioCorrupt seeds
R_DEV_FEATURES_SEL = 0x014
R_DRV_FEATURES_SEL = 0x024
R_QUEUE_SEL        = 0x030
R_QUEUE_NUM        = 0x038
R_QUEUE_READY      = 0x044
R_QUEUE_NOTIFY     = 0x050
R_INT_ACK          = 0x064
R_STATUS           = 0x070

# Reserved DRAM region the harness uses
kPoolBase    = 0x47000000
kBufPoolBase = 0x4700C000   # kPoolBase + kMaxQueues(4) * kVqStride(0x3000)


def escape_bytes(b: bytes) -> str:
    out = []
    for x in b:
        if 32 <= x < 127 and x not in (ord('"'), ord('\\')):
            out.append(chr(x))
        else:
            out.append('\\%03o' % x)
    return ''.join(out)


# -- common ops ---------------------------------------------------------------

def op_get_features():
    return "ops { get_features {} }"

def op_set_features(f):
    return "ops { set_features { features: %d } }" % f

def op_vq_setup(idx, size=64):
    return "ops { vq_setup { vq_idx: %d size: %d } }" % (idx, size)

def op_set_status(bits):
    return "ops { set_status { bits: %d } }" % bits

def op_reset():
    return "ops { reset {} }"

def op_config_read(offset, size):
    return ("ops { config_read { offset: %d size: %d } }"
            % (offset, size))

def op_config_write(offset, data: bytes):
    return ('ops { config_write { offset: %d data: "%s" } }'
            % (offset, escape_bytes(data)))

def op_vq_select(vq_idx):
    return "ops { vq_select { vq_idx: %d } }" % vq_idx

def op_guest_mem_write(buf_id, data: bytes):
    return ('ops { guest_mem_write { buf_id: %d data: "%s" } }'
            % (buf_id, escape_bytes(data)))

def op_vq_add_desc(vq_idx, buf_id, length, device_writable, chain_next):
    return ("ops { vq_add_desc { vq_idx: %d buf_id: %d len: %d "
            "device_writable: %s chain_next: %s } }"
            % (vq_idx, buf_id, length,
               'true' if device_writable else 'false',
               'true' if chain_next else 'false'))

def op_vq_kick(vq_idx):
    return "ops { vq_kick { vq_idx: %d } }" % vq_idx

def op_vq_wait_used(vq_idx):
    return "ops { vq_wait_used { vq_idx: %d } }" % vq_idx

def op_mem_write_absolute(gpa, data: bytes):
    return ('ops { mem_write_absolute { gpa: %d data: "%s" } }'
            % (gpa, escape_bytes(data)))

def op_mmio_corrupt(offset, value, size=4):
    return ("ops { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))


# -- thread_b variants (same ops, different field name) ----------------------

def b_mem_write_absolute(gpa, data: bytes):
    return ('ops_thread_b { mem_write_absolute { gpa: %d data: "%s" } }'
            % (gpa, escape_bytes(data)))

def b_mmio_corrupt(offset, value, size=4):
    return ("ops_thread_b { mmio_corrupt { offset: %d value: %d "
            "size: %d } }" % (offset, value, size))

def b_guest_mem_write(buf_id, data: bytes):
    return ('ops_thread_b { guest_mem_write { buf_id: %d data: "%s" } }'
            % (buf_id, escape_bytes(data)))


def prologue():
    return [
        op_get_features(),
        op_set_features(VIRTIO_F_VERSION_1),
        op_vq_setup(0, 64),
        op_set_status(STATUS_DRIVER_OK),
    ]


def emit(path, lines, comment, thread_b_iter=0):
    body = "# " + comment.strip().replace("\n", "\n# ") + "\n"
    body += "\n".join(lines) + "\n"
    if thread_b_iter > 0:
        body += "thread_b_iter: %d\n" % thread_b_iter
    with open(path, "w") as f:
        f.write(body)


# -- seeds --------------------------------------------------------------------

def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue: features negotiation, queue setup, "
            "DRIVER_OK. No I/O.",
            prologue(), 0)


def seed_read_request():
    """A canonical virtio-blk read request: 3-descriptor chain.
       desc[0]: virtio_blk_outhdr (16B, out)
       desc[1]: data buffer (512B, in/device-writable)
       desc[2]: status byte (1B, in/device-writable)"""
    # virtio_blk_outhdr: type, ioprio, sector
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0)
    ops = prologue()
    ops += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=2, data=b"\x00" * 512),
        op_guest_mem_write(buf_id=3, data=b"\x00"),
        op_vq_add_desc(0, 1, 16,  False, True),
        op_vq_add_desc(0, 2, 512, True,  True),
        op_vq_add_desc(0, 3, 1,   True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    return ("seed_02_read_request.textpb",
            "Canonical virtio-blk read request: 3-descriptor chain "
            "(out-header / in-data / in-status). LPM can mutate the "
            "header type, sector, descriptor lengths, etc.",
            ops, 0)


def seed_write_request():
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_OUT, 0, 1)
    payload = b"\xa5" * 512
    ops = prologue()
    ops += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=2, data=payload),
        op_guest_mem_write(buf_id=3, data=b"\xff"),
        op_vq_add_desc(0, 1, 16,  False, True),
        op_vq_add_desc(0, 2, 512, False, True),
        op_vq_add_desc(0, 3, 1,   True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    return ("seed_03_write_request.textpb",
            "Canonical virtio-blk write request to sector 1.",
            ops, 0)


def seed_mmio_corrupt():
    """MmioCorrupt fault injection: write garbage to virtio-mmio
       registers, including reserved offsets that no typed op writes."""
    ops = prologue()
    ops += [
        op_mmio_corrupt(offset=0x01c, value=0xdeadbeef, size=4),    # reserved
        op_mmio_corrupt(offset=0x028, value=0xcafebabe, size=4),    # reserved
        op_mmio_corrupt(offset=R_QUEUE_NUM, value=0xffffffff, size=4),
        op_mmio_corrupt(offset=R_STATUS,    value=0x00,        size=4),
        op_mmio_corrupt(offset=R_QUEUE_NOTIFY, value=0,        size=4),
    ]
    return ("seed_04_mmio_corrupt.textpb",
            "Init + MmioCorrupt sequences targeting reserved / RO / "
            "out-of-spec virtio-mmio offsets. Register-decoder fault "
            "injection.",
            ops, 0)


def seed_memwrite_absolute_pool():
    """MemwriteAbsolute hammers GPAs inside the harness's reserved
       pool. Useful by itself (corrupts descriptor tables / buffer
       contents) and also as a building block for interleaved mode."""
    ops = prologue()
    # hammer the descriptor table area + ring areas at known offsets
    ops += [
        op_mem_write_absolute(0x47000000, b"\xff" * 64),
        op_mem_write_absolute(0x47001000, b"\xaa" * 32),
        op_mem_write_absolute(0x47002000, b"\x55" * 32),
        op_mem_write_absolute(kBufPoolBase + 0,   b"\x00" * 16),
        op_mem_write_absolute(kBufPoolBase + 256, b"\xde\xad\xbe\xef"),
    ]
    return ("seed_05_memwrite_absolute.textpb",
            "Init + MemwriteAbsolute hammers across the reserved DRAM "
            "pool (descriptor tables, avail/used rings, buffer pool). "
            "Memory-region fault injection.",
            ops, 0)


def seed_toctou_stale_descriptor():
    """Phase B interleaved mode: primary list submits a virtio-blk read
       request; secondary list (run thread_b_iter times after EACH
       primary op) repeatedly mutates the buffer pool. Between the
       vq_add_desc and the vq_kick, the secondary mutations land on
       the descriptor's backing memory.

       Demonstrates the stale-descriptor pattern: the device handler
       triggered by vq_kick reads memory that has been overwritten
       since vq_add_desc placed it. Catches CVE-2021-3416-class bugs
       deterministically (no real OS race needed).

       The pool layout in the harness (constants from
       proto_fuzz_virtio_blk.cc):
         kBufPoolBase = 0x4700C000
       Allocation is sequential at 16-byte alignment, so the first
       guest_mem_write lands at exactly 0x4700C000."""
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0)
    primary = prologue()
    primary += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=2, data=b"\x00" * 512),
        op_guest_mem_write(buf_id=3, data=b"\x00"),
        op_vq_add_desc(0, 1, 16,  False, True),
        op_vq_add_desc(0, 2, 512, True,  True),
        op_vq_add_desc(0, 3, 1,   True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    # Secondary: hammer the request header (at kBufPoolBase) with
    # different request types between every primary op. Especially
    # interesting if a hammer lands between vq_add_desc(buf_id=1) and
    # vq_kick: when the device walks the chain, it sees a different
    # type/sector than the test thought it placed.
    secondary = [
        # mutate request header to FLUSH (no data buffer expected!)
        b_mem_write_absolute(kBufPoolBase,
            struct.pack("<IIQ", VIRTIO_BLK_T_FLUSH, 0, 0)),
        # mutate to GET_ID (expects a 20-byte id buffer)
        b_mem_write_absolute(kBufPoolBase,
            struct.pack("<IIQ", VIRTIO_BLK_T_GET_ID, 0, 0)),
        # mutate sector to a huge value
        b_mem_write_absolute(kBufPoolBase,
            struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0xffffffff_ffffffff)),
        # mutate request header back to a valid READ
        b_mem_write_absolute(kBufPoolBase, outhdr),
    ]
    return ("seed_06_toctou_stale_descriptor.textpb",
            "Phase B interleaved mode. Primary list submits a valid "
            "virtio-blk read; secondary list (4 ops, repeated 4x per "
            "primary op) hammers the request header at kBufPoolBase "
            "with conflicting request types. Catches stale-descriptor "
            "and out-of-order-mutation bugs deterministically.",
            primary + secondary, 4)


def seed_toctou_descriptor_table():
    """Phase B interleaved: hammer the descriptor TABLE memory itself
       (not the backing buffers) so the device sees a different
       desc.addr / desc.len than the harness wrote at vq_add_desc."""
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0)
    primary = prologue()
    primary += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=2, data=b"\x00" * 512),
        op_guest_mem_write(buf_id=3, data=b"\x00"),
        op_vq_add_desc(0, 1, 16,  False, True),
        op_vq_add_desc(0, 2, 512, True,  True),
        op_vq_add_desc(0, 3, 1,   True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    # Mutate descriptor #1's `len` field (16-byte descriptor: addr(8)
    # len(4) flags(2) next(2)). Position: 0x47000000 + 1*16 + 8 = 0x47000018.
    secondary = [
        b_mem_write_absolute(0x47000018, struct.pack("<I", 0xffffffff)),
        b_mem_write_absolute(0x47000018, struct.pack("<I", 0)),
        b_mem_write_absolute(0x47000018, struct.pack("<I", 0xfffe)),
    ]
    return ("seed_07_toctou_descriptor_table.textpb",
            "Phase B interleaved: secondary list mutates descriptor "
            "table entries directly, racing-by-ordering against the "
            "device's descriptor walk on every kick.",
            primary + secondary, 3)


def seed_combined_fault_injection():
    """Mix MmioCorrupt + MemwriteAbsolute in primary list to exercise
       both fault classes in one run."""
    ops = prologue()
    ops += [
        op_mmio_corrupt(offset=0x01c, value=0x12345678),
        op_guest_mem_write(buf_id=1, data=b"\xff" * 16),
        op_vq_add_desc(0, 1, 16, False, False),
        op_mem_write_absolute(kBufPoolBase, b"\xaa" * 16),  # corrupt buf 1
        op_vq_kick(0),
        op_mmio_corrupt(offset=R_QUEUE_NOTIFY, value=0xdeadbeef),
        op_vq_wait_used(0),
    ]
    return ("seed_08_combined_faults.textpb",
            "Mixed: MmioCorrupt + MemwriteAbsolute interleaved with "
            "real ops. Stress-tests the device's handling of "
            "concurrent register and memory corruption.",
            ops, 0)


def seed_config_probe():
    """ConfigRead/Write across virtio-blk config space (capacity, size_max,
    seg_max, geometry, blk_size, ...) plus VqSelect and Reset. Exercises
    the proto messages not used by any other seed."""
    ops = prologue()
    ops.append(op_vq_select(0))
    for off in (0, 4, 8, 12, 16, 20, 24, 28, 32):
        ops.append(op_config_read(off, 4))
    ops.append(op_config_read(0, 8))
    ops.append(op_config_write(0, struct.pack("<Q", 0xdeadbeefcafebabe)))
    ops.append(op_reset())
    return ("seed_09_config_probe.textpb",
            "Init + VqSelect + ConfigRead/Write across virtio-blk "
            "config space + Reset. Covers the proto messages no other "
            "seed exercises.",
            ops, 0)


SEED_BUILDERS = [
    seed_init,
    seed_read_request,
    seed_write_request,
    seed_mmio_corrupt,
    seed_memwrite_absolute_pool,
    seed_toctou_stale_descriptor,
    seed_toctou_descriptor_table,
    seed_combined_fault_injection,
    seed_config_probe,
]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-o", "--out", default="/tmp/proto_fuzz_run/corpus_blk",
                   help="output directory (default: %(default)s)")
    p.add_argument("--clean", action="store_true",
                   help="remove existing .textpb files before generating")
    args = p.parse_args()

    os.makedirs(args.out, exist_ok=True)
    if args.clean:
        for name in os.listdir(args.out):
            if name.endswith(".textpb"):
                os.unlink(os.path.join(args.out, name))

    n = 0
    for build in SEED_BUILDERS:
        name, comment, ops, tbi = build()
        path = os.path.join(args.out, name)
        emit(path, ops, comment, tbi)
        n += 1
        print("wrote", path, "(%d ops, thread_b_iter=%d)" % (len(ops), tbi))

    print("\n%d seeds written to %s" % (n, args.out))


if __name__ == "__main__":
    sys.exit(main())
