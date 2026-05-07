#!/usr/bin/env python3
"""Seed corpus generator for proto-fuzz-virtio-balloon."""

import argparse, os, random, sys

VIRTIO_F_VERSION_1   = 1 << 32
STATUS_DRIVER_OK     = 0x04
F_STATS_VQ           = 1 << 1
F_FREE_PAGE_HINT     = 1 << 3


def prologue(features=VIRTIO_F_VERSION_1 | F_STATS_VQ | F_FREE_PAGE_HINT):
    return [
        "ops { get_features {} }",
        "ops { set_features { features: %d } }" % features,
        "ops { vq_setup { vq_idx: 0 size: 64 } }",   # inflate
        "ops { vq_setup { vq_idx: 1 size: 64 } }",   # deflate
        "ops { vq_setup { vq_idx: 2 size: 64 } }",   # stats
        "ops { vq_setup { vq_idx: 3 size: 64 } }",   # free-page-hint
        "ops { set_status { bits: %d } }" % STATUS_DRIVER_OK,
    ]


def emit(path, ops, comment):
    with open(path, "w") as f:
        f.write("# " + comment.replace("\n", "\n# ") + "\n")
        f.write("\n".join(ops) + "\n")


def inflate(pfns):
    return ('ops { inflate { %s } }'
            % ' '.join('pfns: %d' % p for p in pfns))

def deflate(pfns):
    return ('ops { deflate { %s } }'
            % ' '.join('pfns: %d' % p for p in pfns))

def stats(entries):
    parts = []
    for tag, val in entries:
        parts.append('entries { tag: %d value: %d }' % (tag, val))
    return 'ops { stats { %s } }' % ' '.join(parts)

def free_page(cmd_id):
    return 'ops { free_page { cmd_id: %d } }' % cmd_id


def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue (inflate/deflate/stats/fph queues + DRIVER_OK).",
            prologue())

def seed_inflate():
    ops = prologue()
    ops.append(inflate([0x4700, 0x4701, 0x4702, 0x4703]))
    ops.append("ops { vq_wait_used { vq_idx: 0 } }")
    return ("seed_02_inflate.textpb",
            "Inflate 4 PFNs.",
            ops)

def seed_deflate():
    ops = prologue()
    ops.append(deflate([0x4700, 0x4701, 0x4702]))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    return ("seed_03_deflate.textpb",
            "Deflate 3 PFNs.",
            ops)

def seed_inflate_burst():
    ops = prologue()
    big = list(range(0x4700, 0x4700 + 256))
    ops.append(inflate(big))
    ops.append("ops { vq_wait_used { vq_idx: 0 } }")
    return ("seed_04_inflate_burst.textpb",
            "Inflate 256 sequential PFNs.",
            ops)

def seed_stats():
    """Common stat tags: SWAP_IN=0, SWAP_OUT=1, MAJFLT=2, MINFLT=3,
    MEMFREE=4, MEMTOT=5, AVAIL=6, CACHES=7, HTLB_PGALLOC=8,
    HTLB_PGFAIL=9. We push a representative blob."""
    ops = prologue()
    ops.append(stats([(0, 100), (1, 200), (4, 1<<28), (5, 1<<30),
                      (6, 1<<29), (7, 1<<24)]))
    ops.append("ops { vq_wait_used { vq_idx: 2 } }")
    return ("seed_05_stats.textpb",
            "Push 6 stats (swap-in/out/memfree/memtot/avail/caches).",
            ops)

def seed_free_page_cycle():
    """The free-page-hint state machine has a cmd_id sequence; LPM
    will mutate it freely from this base."""
    ops = prologue()
    for cmd in (1, 2, 3):
        ops.append(free_page(cmd_id=cmd))
        ops.append("ops { vq_wait_used { vq_idx: 3 } }")
    return ("seed_06_free_page.textpb",
            "Drive a few cmd_id values into the free-page-hint queue.",
            ops)

def seed_oscillate():
    """Inflate then deflate the same pages -- exercises the balloon
    bookkeeping under churn."""
    pfns = [0x4710 + i for i in range(16)]
    ops = prologue()
    ops.append(inflate(pfns))
    ops.append("ops { vq_wait_used { vq_idx: 0 } }")
    ops.append(deflate(pfns))
    ops.append("ops { vq_wait_used { vq_idx: 1 } }")
    return ("seed_07_oscillate.textpb",
            "Inflate 16 PFNs then deflate the same set.",
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
            head = min(7, len(out)); tail = out[head:]
            if tail: rng.shuffle(tail); out = out[:head] + tail
        elif s == "repeat":
            i = rng.randrange(len(out)); n = rng.randint(2, 4)
            out[i:i+1] = [out[i]] * n
    return (new_name, comment + " -- v%d." % idx, out)


SEED_BUILDERS = [
    seed_init, seed_inflate, seed_deflate, seed_inflate_burst,
    seed_stats, seed_free_page_cycle, seed_oscillate,
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("-o","--out", default="/tmp/proto_fuzz_run/corpus_balloon")
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
