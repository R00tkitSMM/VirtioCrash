#!/usr/bin/env python3
"""Seed corpus generator for proto-fuzz-virtio-input."""

import argparse, os, random, sys

VIRTIO_F_VERSION_1 = 1 << 32
STATUS_DRIVER_OK   = 0x04

# evdev event types
EV_SYN = 0; EV_KEY = 1; EV_REL = 2; EV_ABS = 3; EV_LED = 0x11; EV_REP = 0x14

# common keys
KEY_A = 30; KEY_ENTER = 28; KEY_LEFTSHIFT = 42

# LEDs
LED_NUML = 0; LED_CAPSL = 1; LED_SCROLLL = 2


def prologue():
    return [
        "ops { get_features {} }",
        "ops { set_features { features: %d } }" % VIRTIO_F_VERSION_1,
        "ops { vq_setup { vq_idx: 0 size: 64 } }",   # event queue
        "ops { vq_setup { vq_idx: 1 size: 64 } }",   # status queue
        "ops { set_status { bits: %d } }" % STATUS_DRIVER_OK,
    ]


def emit(path, ops, comment):
    with open(path, "w") as f:
        f.write("# " + comment.replace("\n", "\n# ") + "\n")
        f.write("\n".join(ops) + "\n")


def status_event(t, c, v):
    return ('ops { status_event { type: %d code: %d value: %d } }'
            % (t, c, v))

def event_buf(size=64):
    return ('ops { event_buf { size: %d } }' % size)


def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue (event/status queues + DRIVER_OK).",
            prologue())

def seed_event_buffers():
    """Stage event-queue buffers so the device can deliver events."""
    ops = prologue()
    for _ in range(8):
        ops.append(event_buf(size=64))
    ops.append("ops { vq_wait_used { vq_idx: 0 } }")
    return ("seed_02_event_buffers.textpb",
            "Stage 8 event-queue buffers. Device will fill them with "
            "evdev events when something is sent through the QEMU input "
            "subsystem.",
            ops)

def seed_led_status():
    """Send LED status updates on the status queue. virtio-input uses
    these to receive guest LED-state changes."""
    ops = prologue()
    for led in (LED_NUML, LED_CAPSL, LED_SCROLLL):
        ops.append(status_event(EV_LED, led, 1))
        ops.append(status_event(EV_LED, led, 0))
    ops.append(status_event(EV_SYN, 0, 0))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    return ("seed_03_led_status.textpb",
            "Send EV_LED on/off for NUML/CAPSL/SCROLLL on the status "
            "queue, then a SYN_REPORT.",
            ops)

def seed_repeat_config():
    """Set keyboard repeat rate via EV_REP. Some drivers also send "
    "this on the status queue."""
    ops = prologue()
    ops.append(status_event(EV_REP, 0, 250))   # delay
    ops.append(status_event(EV_REP, 1, 33))    # period
    ops.append(status_event(EV_SYN, 0, 0))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    return ("seed_04_rep_config.textpb",
            "EV_REP delay+period (typematic config) on status queue.",
            ops)

def seed_config_probe():
    """Read across the device config space. virtio-input config has
    select/subsel/size + 128-byte abs-info union -- a fuzz hot spot."""
    ops = prologue()
    for off in (0, 1, 2, 4, 8, 16, 24, 32):
        ops.append("ops { config_read { offset: %d size: %d } }"
                   % (off, 4))
    # write into select/subsel to switch the union
    for sel in (0x01, 0x11, 0x12, 0x21):
        ops.append('ops { config_write { offset: 0 data: "%c\\000\\000\\000" } }' % chr(sel))
        ops.append("ops { config_read { offset: 8 size: 4 } }")
    return ("seed_05_config_probe.textpb",
            "Walk the virtio-input config space (select/subsel/size + "
            "128-byte union). Drives the config-decode logic.",
            ops)

def seed_burst_status():
    ops = prologue()
    for v in range(8):
        ops.append(status_event(EV_LED, LED_CAPSL, v & 1))
    ops.append(status_event(EV_SYN, 0, 0))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    return ("seed_06_burst_status.textpb",
            "8 LED toggles + SYN_REPORT on status queue.",
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
            head = min(5, len(out)); tail = out[head:]
            if tail: rng.shuffle(tail); out = out[:head] + tail
        elif s == "repeat":
            i = rng.randrange(len(out)); n = rng.randint(2, 4)
            out[i:i+1] = [out[i]] * n
    return (new_name, comment + " -- v%d." % idx, out)


SEED_BUILDERS = [
    seed_init, seed_event_buffers, seed_led_status, seed_repeat_config,
    seed_config_probe, seed_burst_status,
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("-o","--out", default="/tmp/proto_fuzz_run/corpus_input")
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
