#!/usr/bin/env python3
"""Seed corpus generator for proto-fuzz-virtio-vsock."""

import argparse, os, random, sys

VIRTIO_F_VERSION_1 = 1 << 32
STATUS_DRIVER_OK   = 0x04

# vsock op codes
OP_REQUEST=1; OP_RESPONSE=2; OP_RST=3; OP_SHUTDOWN=4
OP_RW=5; OP_CREDIT_UPDATE=6; OP_CREDIT_REQUEST=7

# vsock types
TYPE_STREAM=1; TYPE_DGRAM=2; TYPE_SEQPACKET=3


def escape_bytes(b):
    out = []
    for x in b:
        if 32 <= x < 127 and x not in (ord('"'), ord('\\')): out.append(chr(x))
        else: out.append('\\%03o' % x)
    return ''.join(out)



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
    return [
        "ops { get_features {} }",
        "ops { set_features { features: %d } }" % VIRTIO_F_VERSION_1,
        "ops { vq_setup { vq_idx: 0 size: 64 } }",  # RX
        "ops { vq_setup { vq_idx: 1 size: 64 } }",  # TX
        "ops { vq_setup { vq_idx: 2 size: 64 } }",  # event
        "ops { set_status { bits: %d } }" % STATUS_DRIVER_OK,
    ]

def emit(path, ops, comment):
    with open(path, "w") as f:
        f.write("# " + comment.replace("\n", "\n# ") + "\n")
        f.write("\n".join(ops) + "\n")

def pkt(src_cid=3, dst_cid=2, src_port=1024, dst_port=22,
        type=TYPE_STREAM, op=OP_REQUEST, flags=0,
        buf_alloc=4096, fwd_cnt=0, payload=b""):
    return ('ops { vsock_tx { pkt { src_cid: %d dst_cid: %d '
            'src_port: %d dst_port: %d type: %d op: %d flags: %d '
            'buf_alloc: %d fwd_cnt: %d payload: "%s" } } }'
            % (src_cid, dst_cid, src_port, dst_port, type, op, flags,
               buf_alloc, fwd_cnt, escape_bytes(payload)))

def rx_buf(size=4096):
    return 'ops { vsock_rx_buf { size: %d } }' % size

def wait(idx):
    return 'ops { vq_wait_used { vq_idx: %d } }' % idx


def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue (rx/tx/event queues + DRIVER_OK).",
            prologue())

def seed_connect():
    ops = prologue()
    ops.append(rx_buf(4096))
    ops.append(pkt(op=OP_REQUEST))
    ops.append(wait(1))
    return ("seed_02_connect.textpb",
            "Stage one RX buffer + send a STREAM REQUEST. Connection "
            "init flow.",
            ops)

def seed_rw():
    ops = prologue()
    ops.append(rx_buf(4096))
    ops.append(pkt(op=OP_REQUEST))
    ops.append(wait(1))
    ops.append(pkt(op=OP_RW, payload=b"hello vsock\n"))
    ops.append(wait(1))
    return ("seed_03_rw.textpb",
            "REQUEST + RW with a small payload.",
            ops)

def seed_shutdown():
    ops = prologue()
    ops.append(pkt(op=OP_SHUTDOWN, flags=0x3))    # SHUTDOWN both
    ops.append(wait(1))
    return ("seed_04_shutdown.textpb",
            "SHUTDOWN with flags=0x3 (both directions).",
            ops)

def seed_credit():
    ops = prologue()
    ops.append(pkt(op=OP_CREDIT_REQUEST))
    ops.append(wait(1))
    ops.append(pkt(op=OP_CREDIT_UPDATE, buf_alloc=8192, fwd_cnt=1024))
    ops.append(wait(1))
    return ("seed_05_credit.textpb",
            "CREDIT_REQUEST + CREDIT_UPDATE -- exercises credit-based "
            "flow control.",
            ops)

def seed_dgram():
    ops = prologue()
    ops.append(pkt(type=TYPE_DGRAM, op=OP_RW, payload=b"dgram"))
    ops.append(wait(1))
    return ("seed_06_dgram.textpb",
            "DGRAM packet (no connection setup).",
            ops)

def seed_seqpacket():
    ops = prologue()
    ops.append(pkt(type=TYPE_SEQPACKET, op=OP_REQUEST))
    ops.append(wait(1))
    return ("seed_07_seqpacket.textpb",
            "SEQPACKET REQUEST.",
            ops)

def seed_rx_buffers():
    ops = prologue()
    for _ in range(8):
        ops.append(rx_buf(4096))
    ops.append(wait(0))
    return ("seed_08_rx_buffers.textpb",
            "Stage 8 RX buffers. Exercises avail-ring publish for the "
            "RX queue.",
            ops)


def variation(base, idx, rng):
    name, comment, ops = base
    new_name = name.replace(".textpb", "_v%03d.textpb" % idx)
    new_comment = comment + " -- variation %d." % idx
    out = list(ops)
    if len(out) >= 2:
        s = rng.choice(["dup", "drop", "shuffle", "repeat"])
        if s == "dup":
            i = rng.randrange(len(out)); out.insert(i, out[i])
        elif s == "drop":
            i = rng.randrange(1, len(out)); out.pop(i)
        elif s == "shuffle":
            head_len = min(6, len(out)); tail = out[head_len:]
            if tail: rng.shuffle(tail); out = out[:head_len] + tail
        elif s == "repeat":
            i = rng.randrange(len(out)); n = rng.randint(2, 4)
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
    seed_init, seed_connect, seed_rw, seed_shutdown,
    seed_credit, seed_dgram, seed_seqpacket, seed_rx_buffers,
    seed_dma_reflection,
    seed_dma_all_regions,
    seed_dma_reflection_concurrent,
    seed_dma_reset_gadget,
    seed_dma_recursive_notify,
]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-o","--out", default="/tmp/proto_fuzz_run/corpus_vsock")
    p.add_argument("--clean", action="store_true")
    p.add_argument("-n","--count", type=int, default=None)
    p.add_argument("--seed", type=lambda x: int(x,0), default=0xC0FFEE)
    a = p.parse_args()
    os.makedirs(a.out, exist_ok=True)
    if a.clean:
        for f in os.listdir(a.out):
            if f.endswith(".textpb"): os.unlink(os.path.join(a.out, f))
    target = a.count if a.count is not None else len(SEED_BUILDERS)
    rng = random.Random(a.seed)
    base = [b() for b in SEED_BUILDERS]
    seeds = list(base[:target])
    v = 1
    while len(seeds) < target:
        seeds.append(variation(base[(v - 1) % len(base)], v, rng)); v += 1
    n = 0
    for name, c, ops in seeds:
        emit(os.path.join(a.out, name), ops, c)
        n += 1; print("wrote", os.path.join(a.out, name), "(%d ops)" % len(ops))
    print("\n%d seeds written to %s" % (n, a.out))

if __name__ == "__main__":
    sys.exit(main())
