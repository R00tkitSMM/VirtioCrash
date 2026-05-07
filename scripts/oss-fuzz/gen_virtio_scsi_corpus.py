#!/usr/bin/env python3
"""
Seed corpus generator for proto-fuzz-virtio-scsi.

Each seed text-format proto is loaded by the harness and dispatched
in-process. LPM mutates them at the field level. Seeds cover the high
bug-surface CDBs and the control-queue (TMF/AN) paths.

Seeds:
  * init only
  * INQUIRY (standard + EVPD)
  * REPORT_LUNS
  * READ_CAPACITY_10/16
  * TEST_UNIT_READY
  * READ_10 (small)
  * WRITE_10 (small)
  * MODE_SENSE_6 (a few page codes)
  * REQUEST_SENSE
  * SYNCHRONIZE_CACHE_10
  * START_STOP_UNIT
  * Raw CDB (vendor-specific opcode space)
  * TMF: ABORT_TASK, LUN_RESET
  * AN_QUERY / AN_SUBSCRIBE
  * Phase B: hammer the request header during a long READ to fish for
    stale-descriptor / TOCTOU bugs.
"""

import argparse
import os
import random
import struct
import sys

VIRTIO_F_VERSION_1 = 1 << 32

STATUS_DRIVER_OK   = 0x04

# virtio-scsi feature bits worth setting:
#   VERSION_1, INOUT, HOTPLUG, CHANGE
VIRTIO_SCSI_F_INOUT      = 1 << 0
VIRTIO_SCSI_F_HOTPLUG    = 1 << 1
VIRTIO_SCSI_F_CHANGE     = 1 << 2

DEFAULT_FEATURES = (
    VIRTIO_F_VERSION_1
    | VIRTIO_SCSI_F_INOUT
    | VIRTIO_SCSI_F_HOTPLUG
    | VIRTIO_SCSI_F_CHANGE
)

# TMF subtypes
TMF_ABORT_TASK         = 1
TMF_ABORT_TASK_SET     = 2
TMF_CLEAR_ACA          = 3
TMF_CLEAR_TASK_SET     = 4
TMF_I_T_NEXUS_RESET    = 5
TMF_LOGICAL_UNIT_RESET = 6
TMF_QUERY_TASK         = 7
TMF_QUERY_TASK_SET     = 8


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


# Prologue: bring the device through ACK -> DRIVER -> features -> queue
# setup for ctrl/event/req0 -> DRIVER_OK.
def prologue(features=DEFAULT_FEATURES):
    return [
        op_get_features(),
        op_set_features(features),
        op_vq_setup(0, 64),    # control queue
        op_vq_setup(1, 64),    # event queue
        op_vq_setup(2, 64),    # request queue 0
        op_set_status(STATUS_DRIVER_OK),
    ]


def emit(path, ops, comment):
    body = "# " + comment.strip().replace("\n", "\n# ") + "\n"
    body += "\n".join(ops) + "\n"
    with open(path, "w") as f:
        f.write(body)


def cmd(target=0, lun=0, tag=1, attr=0, cdb_block=""):
    return ('ops { scsi_cmd { vq_idx: 2 target: %d lun: %d tag: %d '
            'task_attr: %d %s } }') % (target, lun, tag, attr, cdb_block)


# ---- typed CDB helpers ----------------------------------------------

def cdb_inquiry(evpd=False, page=0, alloc=96):
    return ('inquiry { evpd: %s page_code: %d alloc_len: %d }'
            % ('true' if evpd else 'false', page, alloc))

def cdb_test_unit_ready():
    return 'test_unit_ready {}'

def cdb_read_capacity_10(lba=0, pmi=False):
    return ('read_capacity_10 { lba: %d pmi: %s }'
            % (lba, 'true' if pmi else 'false'))

def cdb_read_capacity_16(lba=0, alloc=32, pmi=False):
    return ('read_capacity_16 { lba: %d alloc_len: %d pmi: %s }'
            % (lba, alloc, 'true' if pmi else 'false'))

def cdb_read_10(lba=0, n=1):
    return ('read_10 { lba: %d transfer_len: %d }' % (lba, n))

def cdb_write_10(lba=0, n=1, data=None):
    if data is None:
        data = b"\xa5" * (n * 512)
    return ('write_10 { lba: %d transfer_len: %d data: "%s" }'
            % (lba, n, escape_bytes(data)))

def cdb_mode_sense_6(pc=0, page=0x3f, sub=0, alloc=192):
    return ('mode_sense_6 { pc: %d page_code: %d subpage: %d alloc_len: %d }'
            % (pc, page, sub, alloc))

def cdb_request_sense(alloc=18):
    return ('request_sense { alloc_len: %d }' % alloc)

def cdb_report_luns(select=0, alloc=256):
    return ('report_luns { select_report: %d alloc_len: %d }' % (select, alloc))

def cdb_start_stop_unit(start=True, immed=False):
    return ('start_stop_unit { immed: %s start: %s }'
            % ('true' if immed else 'false',
               'true' if start else 'false'))

def cdb_sync_cache_10(lba=0, num=0):
    return ('sync_cache_10 { lba: %d num_blocks: %d }' % (lba, num))

def cdb_raw(opcode, extra=b"", in_len=0, out_data=b""):
    cdb_bytes = bytes([opcode]) + extra
    cdb_bytes = cdb_bytes[:32]
    return ('raw { cdb_bytes: "%s" in_len: %d out_data: "%s" }'
            % (escape_bytes(cdb_bytes), in_len, escape_bytes(out_data)))


def op_tmf(subtype, target=0, lun=0, tag=1):
    return ('ops { tmf_req { subtype: %d target: %d lun: %d tag: %d } }'
            % (subtype, target, lun, tag))

def op_an(subtype, target=0, lun=0, mask=0xffffffff):
    return ('ops { an_req { subtype: %d target: %d lun: %d '
            'event_requested: %d } }'
            % (subtype, target, lun, mask))


# ---- seeds ----------------------------------------------------------

def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue: ACK+DRIVER, features, ctrl/event/req0 setup, "
            "DRIVER_OK. No I/O.",
            prologue())

def seed_inquiry():
    ops = prologue()
    ops.append(cmd(cdb_block=cdb_inquiry(evpd=False, alloc=96)))
    ops.append(op_vq_wait_used(2))
    # EVPD page 0x00 (supported pages list)
    ops.append(cmd(tag=2, cdb_block=cdb_inquiry(evpd=True, page=0x00, alloc=64)))
    ops.append(op_vq_wait_used(2))
    # EVPD page 0x80 (unit serial number)
    ops.append(cmd(tag=3, cdb_block=cdb_inquiry(evpd=True, page=0x80, alloc=64)))
    ops.append(op_vq_wait_used(2))
    # EVPD page 0x83 (device id)
    ops.append(cmd(tag=4, cdb_block=cdb_inquiry(evpd=True, page=0x83, alloc=128)))
    ops.append(op_vq_wait_used(2))
    return ("seed_02_inquiry.textpb",
            "INQUIRY (standard data + EVPD pages 0x00/0x80/0x83). "
            "Exercises the standard-INQUIRY responder and the EVPD "
            "page formatters.",
            ops)

def seed_report_luns():
    ops = prologue()
    for select in (0, 1, 2):
        ops.append(cmd(tag=10 + select,
                       cdb_block=cdb_report_luns(select=select,
                                                 alloc=512)))
        ops.append(op_vq_wait_used(2))
    return ("seed_03_report_luns.textpb",
            "REPORT LUNS with select_report 0/1/2 over a 512-byte buffer. "
            "Hits the report-luns reply formatter (length-handling CVE "
            "history).",
            ops)

def seed_read_capacity():
    ops = prologue()
    ops.append(cmd(tag=20, cdb_block=cdb_read_capacity_10()))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=21, cdb_block=cdb_read_capacity_16()))
    ops.append(op_vq_wait_used(2))
    return ("seed_04_read_capacity.textpb",
            "READ CAPACITY (10) and (16). Exercises both responders + "
            "the SERVICE ACTION IN dispatcher for the 16-byte form.",
            ops)

def seed_tur():
    ops = prologue()
    for i in range(3):
        ops.append(cmd(tag=30 + i, cdb_block=cdb_test_unit_ready()))
        ops.append(op_vq_wait_used(2))
    return ("seed_05_tur.textpb",
            "TEST UNIT READY x3. Smallest realistic command. Catches "
            "ready-state bookkeeping bugs.",
            ops)

def seed_read10():
    ops = prologue()
    for lba in (0, 1, 16, 0xfff):
        ops.append(cmd(tag=40 + lba, cdb_block=cdb_read_10(lba=lba, n=1)))
        ops.append(op_vq_wait_used(2))
    return ("seed_06_read10.textpb",
            "READ (10) at several LBAs. Exercises the read path and "
            "the response data buffer assembly.",
            ops)

def seed_write10():
    ops = prologue()
    ops.append(cmd(tag=50, cdb_block=cdb_write_10(lba=0, n=1)))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=51, cdb_block=cdb_write_10(lba=1, n=2)))
    ops.append(op_vq_wait_used(2))
    return ("seed_07_write10.textpb",
            "WRITE (10) one and two blocks. Exercises the write path "
            "(with -drive null-co:// the data is dropped, but the "
            "request handling runs).",
            ops)

def seed_mode_sense():
    ops = prologue()
    # All pages, default values
    ops.append(cmd(tag=60, cdb_block=cdb_mode_sense_6(pc=2, page=0x3f, alloc=192)))
    ops.append(op_vq_wait_used(2))
    # Caching mode page, current values
    ops.append(cmd(tag=61, cdb_block=cdb_mode_sense_6(pc=0, page=0x08, alloc=64)))
    ops.append(op_vq_wait_used(2))
    # Control mode page
    ops.append(cmd(tag=62, cdb_block=cdb_mode_sense_6(pc=0, page=0x0a, alloc=64)))
    ops.append(op_vq_wait_used(2))
    return ("seed_08_mode_sense.textpb",
            "MODE SENSE (6) with pc=current/default and several page "
            "codes (caching, control, all-pages). Long bug history.",
            ops)

def seed_request_sense():
    ops = prologue()
    ops.append(cmd(tag=70, cdb_block=cdb_request_sense(alloc=18)))
    ops.append(op_vq_wait_used(2))
    return ("seed_09_request_sense.textpb",
            "REQUEST SENSE (alloc=18). Hits the sense-data assembler.",
            ops)

def seed_sync_cache():
    ops = prologue()
    ops.append(cmd(tag=80, cdb_block=cdb_sync_cache_10(lba=0, num=0)))
    ops.append(op_vq_wait_used(2))
    return ("seed_10_sync_cache.textpb",
            "SYNCHRONIZE CACHE (10) over the whole LU.",
            ops)

def seed_start_stop():
    ops = prologue()
    ops.append(cmd(tag=90, cdb_block=cdb_start_stop_unit(start=False)))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=91, cdb_block=cdb_start_stop_unit(start=True)))
    ops.append(op_vq_wait_used(2))
    return ("seed_11_start_stop.textpb",
            "START STOP UNIT: stop, then start. Drives the LU lifecycle.",
            ops)

def seed_raw_vendor():
    """Vendor-specific opcode (0xC0..0xFF range) with a small in-buffer.
       LPM will mutate the cdb_bytes so this is the entry point for
       reaching unrecognized opcodes."""
    ops = prologue()
    ops.append(cmd(tag=100, cdb_block=cdb_raw(0xc0, b"\x00" * 5,
                                              in_len=64)))
    ops.append(op_vq_wait_used(2))
    return ("seed_12_raw_vendor.textpb",
            "Raw CDB with vendor-specific opcode 0xc0. Lets LPM mutate "
            "the cdb_bytes freely to reach opcodes we don't have typed "
            "coverage for.",
            ops)

def seed_tmf_abort():
    ops = prologue()
    ops.append(cmd(tag=200, cdb_block=cdb_read_10(lba=0, n=64)))  # long-ish
    ops.append(op_tmf(TMF_ABORT_TASK, tag=200))
    ops.append(op_vq_wait_used(0))
    return ("seed_13_tmf_abort.textpb",
            "Submit a longer READ on the request queue, then ABORT_TASK "
            "on the control queue. Drives the TMF dispatch + tag lookup.",
            ops)

def seed_tmf_lun_reset():
    ops = prologue()
    ops.append(op_tmf(TMF_LOGICAL_UNIT_RESET, target=0, lun=0))
    ops.append(op_vq_wait_used(0))
    return ("seed_14_tmf_lun_reset.textpb",
            "LOGICAL UNIT RESET TMF. Hits the LU-reset path.",
            ops)

def seed_an_subscribe():
    ops = prologue()
    ops.append(op_an(subtype=2, target=0, lun=0, mask=0xffffffff))
    ops.append(op_vq_wait_used(0))
    ops.append(op_an(subtype=1, target=0, lun=0, mask=0xffffffff))
    ops.append(op_vq_wait_used(0))
    return ("seed_15_an.textpb",
            "AN_SUBSCRIBE then AN_QUERY for all events. Exercises the "
            "async-notification subscription state.",
            ops)

def seed_full_session():
    ops = prologue()
    ops.append(cmd(tag=300, cdb_block=cdb_test_unit_ready()))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=301, cdb_block=cdb_inquiry(alloc=96)))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=302, cdb_block=cdb_read_capacity_10()))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=303, cdb_block=cdb_read_10(lba=0, n=1)))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=304, cdb_block=cdb_write_10(lba=0, n=1)))
    ops.append(op_vq_wait_used(2))
    ops.append(cmd(tag=305, cdb_block=cdb_sync_cache_10(lba=0, num=0)))
    ops.append(op_vq_wait_used(2))
    return ("seed_16_full_session.textpb",
            "TUR + INQUIRY + READ_CAPACITY + READ + WRITE + SYNC_CACHE. "
            "Long stateful sequence.",
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


SEED_BUILDERS = [
    seed_init,
    seed_inquiry,
    seed_report_luns,
    seed_read_capacity,
    seed_tur,
    seed_read10,
    seed_write10,
    seed_mode_sense,
    seed_request_sense,
    seed_sync_cache,
    seed_start_stop,
    seed_raw_vendor,
    seed_tmf_abort,
    seed_tmf_lun_reset,
    seed_an_subscribe,
    seed_full_session,
]


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-o", "--out", default="/tmp/proto_fuzz_run/corpus_scsi",
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
