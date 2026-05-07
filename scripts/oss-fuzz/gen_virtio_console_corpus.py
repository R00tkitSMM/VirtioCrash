#!/usr/bin/env python3
"""Seed corpus generator for proto-fuzz-virtio-console."""

import argparse, os, random, sys

VIRTIO_F_VERSION_1 = 1 << 32
STATUS_DRIVER_OK   = 0x04


def escape_bytes(b):
    out = []
    for x in b:
        if 32 <= x < 127 and x not in (ord('"'), ord('\\')): out.append(chr(x))
        else: out.append('\\%03o' % x)
    return ''.join(out)


def prologue():
    """rx0(0), tx0(1), ctrl-rx(2), ctrl-tx(3), rx1(4), tx1(5)."""
    ops = [
        "ops { get_features {} }",
        "ops { set_features { features: %d } }" % VIRTIO_F_VERSION_1,
    ]
    for v in range(6):
        ops.append("ops { vq_setup { vq_idx: %d size: %d } }" % (v, 64))
    ops.append("ops { set_status { bits: %d } }" % STATUS_DRIVER_OK)
    return ops


def emit(path, ops, comment):
    with open(path, "w") as f:
        f.write("# " + comment.replace("\n", "\n# ") + "\n")
        f.write("\n".join(ops) + "\n")


def tx(port=0, data=b""):
    return ('ops { tx_data { port_id: %d data: "%s" } }'
            % (port, escape_bytes(data)))

def rx(port=0, size=1024):
    return 'ops { rx_buf { port_id: %d size: %d } }' % (port, size)

def ctrl(port_id=0, event=0, value=0, data=b""):
    return ('ops { ctrl_msg { port_id: %d event: %d value: %d data: "%s" } }'
            % (port_id, event, value, escape_bytes(data)))


def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue (rx0/tx0/ctrl-rx/ctrl-tx/port1 rx/tx + DRIVER_OK).",
            prologue())

def seed_ctrl_handshake():
    """The driver-init dance: PORT_READY for port 0 + 1, PORT_OPEN x2."""
    ops = prologue()
    ops.append(rx(port=0, size=1024))      # stage RX before opening
    ops.append(rx(port=1, size=1024))
    # event 3 = PORT_READY, 6 = PORT_OPEN
    for pid in (0, 1):
        ops.append(ctrl(port_id=pid, event=3, value=1))
    for pid in (0, 1):
        ops.append(ctrl(port_id=pid, event=6, value=1))
    ops.append("ops { vq_wait_used { vq_idx: 3 } }")
    return ("seed_02_ctrl_handshake.textpb",
            "PORT_READY + PORT_OPEN for ports 0 and 1.",
            ops)

def seed_tx():
    ops = prologue()
    ops.append(tx(port=0, data=b"hello console\n"))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    ops.append(tx(port=1, data=b"data on port 1\n"))
    ops.append("ops { vq_wait_used { vq_idx: 5 } }")
    return ("seed_03_tx.textpb",
            "TX bytes on port 0 (vq 1) and port 1 (vq 5).",
            ops)

def seed_rx_buffers():
    ops = prologue()
    for _ in range(4):
        ops.append(rx(port=0, size=4096))
    ops.append("ops { vq_wait_used { vq_idx: 0 } }")
    return ("seed_04_rx_buffers.textpb",
            "Stage 4 RX buffers on port 0. Exercises the receive-buffer "
            "publish path.",
            ops)

def seed_resize():
    """RESIZE event has 4-byte rows + 4-byte cols payload."""
    ops = prologue()
    payload = (24).to_bytes(2, 'little') + (80).to_bytes(2, 'little')
    ops.append(ctrl(port_id=0, event=5, value=0, data=payload))
    ops.append("ops { vq_wait_used { vq_idx: 3 } }")
    return ("seed_05_resize.textpb",
            "RESIZE event for port 0 (24x80 terminal). Payload follows "
            "the 8-byte ctrl header.",
            ops)

def seed_port_name():
    """PORT_NAME event has the name string after the header."""
    ops = prologue()
    ops.append(ctrl(port_id=1, event=7, value=0, data=b"hvc1\0"))
    ops.append("ops { vq_wait_used { vq_idx: 3 } }")
    return ("seed_06_port_name.textpb",
            "PORT_NAME event with name=hvc1 for port 1.",
            ops)

def seed_burst_tx():
    ops = prologue()
    for i in range(8):
        ops.append(tx(port=0, data=bytes([0x40 + i]) * 64))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    return ("seed_07_burst_tx.textpb",
            "8 TX bursts of 64 bytes on port 0.",
            ops)


def variation(base, idx, rng):
    name, comment, ops = base
    new_name = name.replace(".textpb", "_v%03d.textpb" % idx)
    out = list(ops)
    if len(out) >= 2:
        s = rng.choice(["dup", "drop", "shuffle", "repeat"])
        if s == "dup":
            i = rng.randrange(len(out)); out.insert(i, out[i])
        elif s == "drop":
            i = rng.randrange(1, len(out)); out.pop(i)
        elif s == "shuffle":
            head = min(8, len(out)); tail = out[head:]
            if tail: rng.shuffle(tail); out = out[:head] + tail
        elif s == "repeat":
            i = rng.randrange(len(out)); n = rng.randint(2, 4)
            out[i:i+1] = [out[i]] * n
    return (new_name, comment + " -- v%d." % idx, out)


SEED_BUILDERS = [
    seed_init, seed_ctrl_handshake, seed_tx, seed_rx_buffers,
    seed_resize, seed_port_name, seed_burst_tx,
]

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-o","--out", default="/tmp/proto_fuzz_run/corpus_console")
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
