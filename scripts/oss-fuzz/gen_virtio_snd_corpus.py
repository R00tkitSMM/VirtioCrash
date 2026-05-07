#!/usr/bin/env python3
"""
Seed corpus generator for proto-fuzz-virtio-snd.

Seeds:
  * init only
  * JACK_INFO / JACK_REMAP
  * PCM_INFO discovery
  * PCM_SET_PARAMS for stream 0 (S16_LE @ 48kHz, stereo)
  * Full PCM lifecycle: SET_PARAMS -> PREPARE -> START -> STOP -> RELEASE
  * CHMAP_INFO
  * TX with samples
  * RX request
  * Raw control (LPM mutates code freely)
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


def op_get_features():  return "ops { get_features {} }"
def op_set_features(f): return "ops { set_features { features: %d } }" % f
def op_vq_setup(idx, size=64):
    return "ops { vq_setup { vq_idx: %d size: %d } }" % (idx, size)
def op_set_status(bits):
    return "ops { set_status { bits: %d } }" % bits
def op_vq_wait_used(idx):
    return "ops { vq_wait_used { vq_idx: %d } }" % idx



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
    """Bring the device up: ctrl(0), event(1), tx(2), rx(3) queues."""
    return [
        op_get_features(),
        op_set_features(VIRTIO_F_VERSION_1),
        op_vq_setup(0, 64),    # control
        op_vq_setup(1, 64),    # event
        op_vq_setup(2, 64),    # TX
        op_vq_setup(3, 64),    # RX
        op_set_status(STATUS_DRIVER_OK),
    ]


def emit(path, ops, comment):
    body = "# " + comment.strip().replace("\n", "\n# ") + "\n"
    body += "\n".join(ops) + "\n"
    with open(path, "w") as f:
        f.write(body)


def ctrl(block):
    return 'ops { snd_ctrl { vq_idx: 0 %s } }' % block

def jack_info(start=0, count=4):
    return 'jack_info { start_id: %d count: %d }' % (start, count)
def jack_remap(jid=0, assoc=0, seq=0):
    return ('jack_remap { jack_id: %d association: %d sequence: %d }'
            % (jid, assoc, seq))
def pcm_info(start=0, count=4):
    return 'pcm_info { start_id: %d count: %d }' % (start, count)
def pcm_set_params(sid=0, buf=4096, period=1024, feat=0,
                   ch=2, fmt=5, rate=4):
    """Defaults: 2 channels, S16_LE (fmt=5), 48000 Hz (rate=4)."""
    return ('pcm_set_params { stream_id: %d buffer_bytes: %d '
            'period_bytes: %d features: %d channels: %d format: %d '
            'rate: %d }'
            % (sid, buf, period, feat, ch, fmt, rate))
def pcm_cmd(field, sid):
    return '%s { stream_id: %d }' % (field, sid)
def chmap_info(start=0, count=4):
    return 'chmap_info { start_id: %d count: %d }' % (start, count)
def ctrl_raw(code, payload=b"", in_len=256):
    return ('raw { code: %d in_len: %d payload: "%s" }'
            % (code, in_len, escape_bytes(payload)))


def tx_xfer(stream=0, samples=b""):
    return ('ops { snd_pcm_xfer { vq_idx: 2 stream_id: %d samples: "%s" } }'
            % (stream, escape_bytes(samples)))

def rx_xfer(stream=0, in_len=1024):
    return ('ops { snd_pcm_xfer { vq_idx: 3 stream_id: %d in_len: %d } }'
            % (stream, in_len))


# ---- seeds -----------------------------------------------------

def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue: ctrl/event/tx/rx queues + DRIVER_OK.",
            prologue())

def seed_jack():
    ops = prologue()
    ops.append(ctrl(jack_info(0, 4)))
    ops.append(op_vq_wait_used(0))
    ops.append(ctrl(jack_remap(0, 0, 0)))
    ops.append(op_vq_wait_used(0))
    return ("seed_02_jack.textpb",
            "JACK_INFO + JACK_REMAP. Drives the jack-info responder.",
            ops)

def seed_pcm_info():
    ops = prologue()
    ops.append(ctrl(pcm_info(0, 8)))
    ops.append(op_vq_wait_used(0))
    return ("seed_03_pcm_info.textpb",
            "PCM_INFO discovery (start=0, count=8). Standard first step.",
            ops)

def seed_pcm_set_params():
    ops = prologue()
    ops.append(ctrl(pcm_set_params(sid=0, ch=2, fmt=5, rate=4)))
    ops.append(op_vq_wait_used(0))
    return ("seed_04_pcm_set_params.textpb",
            "PCM_SET_PARAMS for stream 0 (S16_LE stereo @ 48kHz).",
            ops)

def seed_pcm_lifecycle():
    """Set params -> prepare -> start -> stop -> release."""
    ops = prologue()
    for c in (pcm_set_params(sid=0),
              pcm_cmd('pcm_prepare', 0),
              pcm_cmd('pcm_start',   0),
              pcm_cmd('pcm_stop',    0),
              pcm_cmd('pcm_release', 0)):
        ops.append(ctrl(c))
        ops.append(op_vq_wait_used(0))
    return ("seed_05_pcm_lifecycle.textpb",
            "Full PCM lifecycle: SET_PARAMS -> PREPARE -> START -> "
            "STOP -> RELEASE on stream 0.",
            ops)

def seed_chmap_info():
    ops = prologue()
    ops.append(ctrl(chmap_info(0, 4)))
    ops.append(op_vq_wait_used(0))
    return ("seed_06_chmap_info.textpb",
            "CHMAP_INFO discovery (channel maps).",
            ops)

def seed_tx_samples():
    """Set up a stream then push samples on the TX queue."""
    ops = prologue()
    ops.append(ctrl(pcm_set_params(sid=0)))
    ops.append(op_vq_wait_used(0))
    ops.append(ctrl(pcm_cmd('pcm_prepare', 0)))
    ops.append(op_vq_wait_used(0))
    ops.append(ctrl(pcm_cmd('pcm_start', 0)))
    ops.append(op_vq_wait_used(0))
    samples = (b"\x00\x80" * 256)        # 256 stereo S16_LE samples
    ops.append(tx_xfer(stream=0, samples=samples))
    ops.append(op_vq_wait_used(2))
    ops.append(ctrl(pcm_cmd('pcm_stop', 0)))
    ops.append(op_vq_wait_used(0))
    return ("seed_07_tx_samples.txtpb".replace(".txtpb", ".textpb"),
            "Set up stream 0 + push 256 stereo S16_LE samples on TX.",
            ops)

def seed_rx_request():
    ops = prologue()
    ops.append(ctrl(pcm_set_params(sid=1)))     # capture stream typically id 1+
    ops.append(op_vq_wait_used(0))
    ops.append(ctrl(pcm_cmd('pcm_prepare', 1)))
    ops.append(op_vq_wait_used(0))
    ops.append(ctrl(pcm_cmd('pcm_start', 1)))
    ops.append(op_vq_wait_used(0))
    ops.append(rx_xfer(stream=1, in_len=1024))
    ops.append(op_vq_wait_used(3))
    return ("seed_08_rx_request.textpb",
            "Set up capture stream 1 + queue an RX buffer.",
            ops)

def seed_raw_unknown_code():
    ops = prologue()
    ops.append(ctrl(ctrl_raw(0x0fff, payload=b"\x00" * 16, in_len=64)))
    ops.append(op_vq_wait_used(0))
    return ("seed_09_raw_unknown.textpb",
            "Raw control with code=0x0fff (unknown). Lets LPM mutate "
            "the code freely.",
            ops)


def variation(base_seed, idx, rng):
    name, comment, ops = base_seed
    new_name = name.replace(".textpb", "_v%03d.textpb" % idx)
    new_comment = comment + " -- variation %d (auto-perturbed)." % idx
    out = list(ops)
    if len(out) >= 2:
        s = rng.choice(["dup", "drop", "shuffle_tail", "repeat_one"])
        if s == "dup":
            i = rng.randrange(len(out));  out.insert(i, out[i])
        elif s == "drop":
            i = rng.randrange(1, len(out));  out.pop(i)
        elif s == "shuffle_tail":
            head_len = min(7, len(out))
            tail = out[head_len:]
            if tail: rng.shuffle(tail); out = out[:head_len] + tail
        elif s == "repeat_one":
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
        op_vq_add_desc(0, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(0, 44, 4, True,  False, exotic_region=2),
        "ops { vq_kick { vq_idx: 0 } }",
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
        op_vq_add_desc(0, 1,  4, False, True,  exotic_region=1),
        op_vq_add_desc(0, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(0, 0,  4, True,  True,  exotic_region=3),
        op_vq_add_desc(0, 0,  4, True,  False, exotic_region=4),
        "ops { vq_kick { vq_idx: 0 } }",
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
        op_vq_add_desc(0, 20, 4, True, True,  exotic_region=2),
        op_vq_add_desc(0, 44, 4, True, False, exotic_region=2),
        "ops { vq_kick { vq_idx: 0 } }",
        b_mmio_corrupt(0x050, 0),
        b_mmio_corrupt(0x070, 0),
        b_vq_add_desc(0, 20, 4, True, False, exotic_region=2),
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
        ops.append(op_vq_add_desc(0, 20, 4, True, True,  exotic_region=2))
    ops.append(op_vq_add_desc(0, 20, 4, True, False, exotic_region=2))
    ops.append("ops { vq_kick { vq_idx: 0 } }")
    return ("seed_dma_recursive_notify.textpb",
            "Endless-recursion test: 9-deep chain of descs all targeting "
            "QueueNotify (buf_id=20 → offset 0x050). Each DMA-write to "
            "QueueNotify may schedule another BH kick → deep recursion. "
            "Exercises QEMU recursion guard or triggers stack overflow.",
            ops)

SEED_BUILDERS = [
    seed_init,
    seed_jack,
    seed_pcm_info,
    seed_pcm_set_params,
    seed_pcm_lifecycle,
    seed_chmap_info,
    seed_tx_samples,
    seed_rx_request,
    seed_raw_unknown_code,
    seed_dma_reflection,
    seed_dma_all_regions,
    seed_dma_reflection_concurrent,
    seed_dma_reset_gadget,
    seed_dma_recursive_notify,
]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-o", "--out", default="/tmp/proto_fuzz_run/corpus_snd",
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
