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


def seed_dma_reflection():
    """DMA Reflection: the device-writable data buffer descriptor points at
    the device's own MMIO register space (exotic_region=2).

    When the device DMA-writes the read result into the descriptor buffer,
    the write lands on a virtio-mmio register, potentially triggering the
    MMIO write handler while the device is already in its processing path.

    buf_id=20 → QueueNotify (offset 0x050): most dangerous; re-triggers queue
    buf_id=28 → Status (offset 0x070, reset gadget!): corrupts descriptor table pointer
    buf_id=28 → Status (offset 0x070): changes device status mid-flight
    """
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0)
    ops = prologue()
    ops += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=3, data=b"\x00"),
        op_vq_add_desc(0, 1,  16, False, True),
        # data desc → own QueueNotify: device DMA-writes → MMIO write → reentrancy
        op_vq_add_desc(0, 20,  4, True,  True,  exotic_region=2),
        # chain continuation → own QueueDescLow: corrupts desc table ptr mid-flight
        op_vq_add_desc(0, 44,  4, True,  True,  exotic_region=2),
        op_vq_add_desc(0, 3,   1, True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    return ("seed_10_dma_reflection.textpb",
            "DMA Reflection: data-buffer descriptors point at the device's "
            "own MMIO (exotic_region=2). buf_id=20→QueueNotify, buf_id=28→"
            "QueueDescLow. Device DMA-writes to its own registers, triggering "
            "reentrancy. CVE-2024-3446 class.",
            ops, 0)


def seed_dma_all_regions():
    """One descriptor per exotic GPA region in a single input.

    Region 1 (UART, 0x09000000): device reads/writes hit UART MMIO handler
    Region 2 (own MMIO / Reflection, kVirtioMmioBase): self-reentrancy
    Region 3 (GIC distributor, 0x08000000): access to interrupt controller
    Region 4 (virt-mmio bus slot 0, 0x0a000000): cross-device Refraction stub
    """
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0)
    ops = prologue()
    ops += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=3, data=b"\x00"),
        # out-header: device reads from UART MMIO (region 1)
        op_vq_add_desc(0, 1,  4, False, True,  exotic_region=1),
        # data: device writes to own QueueNotify (region 2, Reflection)
        op_vq_add_desc(0, 20, 4, True,  True,  exotic_region=2),
        # data: device writes to GIC (region 3)
        op_vq_add_desc(0, 0,  4, True,  True,  exotic_region=3),
        # data: device writes to virtio-mmio bus slot 0 (region 4, Refraction)
        op_vq_add_desc(0, 0,  4, True,  False, exotic_region=4),
        op_vq_kick(0),
    ]
    return ("seed_11_dma_all_exotic_regions.textpb",
            "All four exotic GPA regions in one chain: UART (1), own-MMIO "
            "Reflection (2), GIC (3), virtio-mmio bus Refraction (4). Ensures "
            "LPM finds all reentrancy primitives from a single starting point.",
            ops, 0)


def seed_dma_reflection_concurrent():
    """Concurrent DMA Reflection: thread A submits a reflection-targeted
    read request; thread B simultaneously fires MMIO writes to the same
    registers. Produces a true concurrent reentrancy race.

    Thread A: read chain where data descs → QueueNotify + QueueDescLow
    Thread B: repeated MMIO writes to QueueNotify and Status
    """
    outhdr = struct.pack("<IIQ", VIRTIO_BLK_T_IN, 0, 0)
    primary = prologue()
    primary += [
        op_guest_mem_write(buf_id=1, data=outhdr),
        op_guest_mem_write(buf_id=3, data=b"\x00"),
        op_vq_add_desc(0, 1,  16, False, True),
        op_vq_add_desc(0, 20,  4, True,  True,  exotic_region=2),  # → QueueNotify
        op_vq_add_desc(0, 44,  4, True,  True,  exotic_region=2),  # → QueueDescLow
        op_vq_add_desc(0, 3,   1, True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    secondary = [
        b_mmio_corrupt(R_QUEUE_NOTIFY, 0),        # concurrent queue kick
        b_mmio_corrupt(R_STATUS,       0),        # reset status mid-flight
        b_mem_write_absolute(0x47000000, b"\xcc" * 16),  # corrupt desc table
        b_mmio_corrupt(R_INT_ACK,      0xffffffff),
    ]
    return ("seed_12_dma_reflection_concurrent.textpb",
            "Concurrent DMA Reflection: thread A reflection chain targeting "
            "QueueNotify and QueueDescLow; thread B races with MMIO writes to "
            "the same registers. True concurrent reentrancy race. "
            "CVE-2024-3446 class.",
            primary + secondary, 4)


def seed_dma_read_exotic():
    """Device-reads from exotic regions (device_writable=false on exotic desc).

    When the device DMA-reads the request header or data from an MMIO
    address, the read triggers the MMIO read handler of that device while
    the original device is processing. Exercises DMA Refraction read paths.
    """
    ops = prologue()
    ops += [
        # out-header read from own MMIO (Reflection, buf_id=0 → MagicValue reg)
        op_vq_add_desc(0, 0, 4, False, True,  exotic_region=2),
        # data read from GIC region
        op_vq_add_desc(0, 4, 4, False, True,  exotic_region=3),
        # data read from virt-mmio bus start (Refraction)
        op_vq_add_desc(0, 0, 4, False, False, exotic_region=4),
        op_vq_kick(0),
    ]
    return ("seed_13_dma_read_exotic.textpb",
            "DMA-reads from exotic MMIO regions: Reflection (own registers, "
            "buf_id=0→MagicValue), GIC, Refraction (bus slot 0). Device reads "
            "from MMIO during request processing → cross-handler reentrancy.",
            ops, 0)



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
        op_vq_add_desc(0, 0,   4, False, True,  exotic_region=2),
        # body: device WRITES to own Status register → potential soft-reset
        op_vq_add_desc(0, 28,  4, True,  True,  exotic_region=2),
        # tail: device continues with (possibly freed) state → UAF path
        op_vq_add_desc(0, 0,   4, True,  False, exotic_region=2),
        "ops { vq_kick { vq_idx: 0 } }",
    ]
    return ("seed_dma_reset_gadget.textpb",
            "Reset-gadget UAF: chain targeting Status register (buf_id=28→0x070). "
            "DMA-write to Status may fire virtio_mmio_soft_reset() mid-DMA, leaving "
            "freed queue state in-use. BH Asia 2022 pattern.",
            ops, 0)


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
        ops.append(op_vq_add_desc(0, 20, 4, True, True,  exotic_region=2))
    ops.append(op_vq_add_desc(0, 20, 4, True, False, exotic_region=2))
    ops.append("ops { vq_kick { vq_idx: 0 } }")
    return ("seed_dma_recursive_notify.textpb",
            "Endless-recursion test: 9-deep chain of descs all targeting "
            "QueueNotify (buf_id=20 → offset 0x050). Each DMA-write to "
            "QueueNotify may schedule another BH kick → deep recursion. "
            "Exercises QEMU recursion guard or triggers stack overflow.",
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
    seed_dma_reflection,
    seed_dma_all_regions,
    seed_dma_reflection_concurrent,
    seed_dma_read_exotic,
    seed_dma_reset_gadget,
    seed_dma_recursive_notify,
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
