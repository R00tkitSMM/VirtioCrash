#!/usr/bin/env python3
"""
Seed corpus generator for proto-fuzz-virtio-gpu.

Each seed exercises a specific virtio-gpu code path. The schema is
state-aware: Create / AttachBacking ops write into a slot, and Use /
Unref / Detach ops reference the same slot to consume the result.
LPM mutates the slot indices and the typed payload fields (formats,
dimensions, scanout ids) while the harness resolves slot references
through its per-iteration table.

Seeds:
  * init only
  * pure-2D pipeline: create -> attach backing -> transfer -> flush
  * scanout binding: create -> set_scanout
  * cursor: small resource -> update_cursor -> move_cursor
  * multi-resource: create N, scanout slot 0, flush slot N-1
  * negative: detach without backing, transfer with no resource, etc.
  * GET_DISPLAY_INFO + GET_EDID probe across scanouts
  * unref + reuse: create slot 0, unref, recreate slot 0
"""

import argparse
import os
import random
import struct
import sys

# virtio-gpu format codes (subset)
FMT_B8G8R8A8_UNORM = 1
FMT_B8G8R8X8_UNORM = 2
FMT_A8R8G8B8_UNORM = 3
FMT_X8R8G8B8_UNORM = 4
FMT_R8G8B8A8_UNORM = 67
FMT_X8B8G8R8_UNORM = 68
FMT_A8B8G8R8_UNORM = 121
FMT_R8G8B8X8_UNORM = 134

VIRTIO_F_VERSION_1 = 1 << 32

STATUS_DRIVER_OK   = 0x04
STATUS_FEATURES_OK = 0x08


def escape_bytes(b: bytes) -> str:
    out = []
    for x in b:
        if 32 <= x < 127 and x not in (ord('"'), ord('\\')):
            out.append(chr(x))
        else:
            out.append('\\%03o' % x)
    return ''.join(out)


# -- common ops ---------------------------------------------------------------

def op_get_features(): return "ops { get_features {} }"
def op_set_features(f): return "ops { set_features { features: %d } }" % f
def op_config_read(offset, size):
    return ("ops { config_read { offset: %d size: %d } }"
            % (offset, size))
def op_config_write(offset, data: bytes):
    return ('ops { config_write { offset: %d data: "%s" } }'
            % (offset, escape_bytes(data)))
def op_vq_select(idx):
    return "ops { vq_select { vq_idx: %d } }" % idx
def op_vq_setup(idx, size=64):
    return "ops { vq_setup { vq_idx: %d size: %d } }" % (idx, size)
def op_set_status(bits): return "ops { set_status { bits: %d } }" % bits
def op_reset(): return "ops { reset {} }"
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
def op_vq_kick(idx): return "ops { vq_kick { vq_idx: %d } }" % idx
def op_vq_wait_used(idx):
    return "ops { vq_wait_used { vq_idx: %d } }" % idx
def op_mem_write_absolute(gpa, data: bytes):
    return ('ops { mem_write_absolute { gpa: %d data: "%s" } }'
            % (gpa, escape_bytes(data)))
def op_mmio_corrupt(offset, value, size=4):
    return ("ops { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))

def b_mmio_corrupt(offset, value, size=4):
    return ("ops_thread_b { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))

# -- gpu-specific ops ---------------------------------------------------------

def op_gpu_create_2d(slot, fmt, w, h):
    return ("ops { gpu_create_2d { resource_slot: %d format: %d "
            "width: %d height: %d } }" % (slot, fmt, w, h))

def op_gpu_unref(slot):
    return "ops { gpu_resource_unref { resource_slot: %d } }" % slot

def op_gpu_attach_backing(r_slot, b_slot, num_entries, entry_size,
                          fill: bytes = b""):
    s = ('ops { gpu_attach_backing { resource_slot: %d backing_slot: %d '
         'num_entries: %d entry_size: %d' % (r_slot, b_slot, num_entries,
                                               entry_size))
    if fill:
        s += ' fill: "%s"' % escape_bytes(fill)
    s += " } }"
    return s

def op_gpu_detach_backing(slot):
    return ("ops { gpu_detach_backing { resource_slot: %d } }" % slot)

def op_gpu_transfer(slot, x, y, w, h, offset):
    return ("ops { gpu_transfer_to_host { resource_slot: %d "
            "x: %d y: %d width: %d height: %d offset: %d } }"
            % (slot, x, y, w, h, offset))

def op_gpu_flush(slot, x, y, w, h):
    return ("ops { gpu_resource_flush { resource_slot: %d "
            "x: %d y: %d width: %d height: %d } }" % (slot, x, y, w, h))

def op_gpu_set_scanout(scanout, slot, x, y, w, h):
    return ("ops { gpu_set_scanout { scanout_id: %d resource_slot: %d "
            "x: %d y: %d width: %d height: %d } }"
            % (scanout, slot, x, y, w, h))

def op_gpu_get_display_info():
    return "ops { gpu_get_display_info {} }"

def op_gpu_get_edid(scanout):
    return "ops { gpu_get_edid { scanout_id: %d } }" % scanout

def op_gpu_update_cursor(scanout, x, y, slot, hot_x, hot_y):
    return ("ops { gpu_update_cursor { scanout_id: %d x: %d y: %d "
            "resource_slot: %d hot_x: %d hot_y: %d } }"
            % (scanout, x, y, slot, hot_x, hot_y))

def op_gpu_move_cursor(scanout, x, y):
    return ("ops { gpu_move_cursor { scanout_id: %d x: %d y: %d } }"
            % (scanout, x, y))

def op_gpu_set_fence(enabled: bool, fence_id: int = 0, ctx_id: int = 0):
    return ("ops { gpu_set_fence_state { enabled: %s fence_id: %d "
            "ctx_id: %d } }"
            % ('true' if enabled else 'false', fence_id, ctx_id))

def op_gpu_create_blob(slot: int, blob_mem: int, blob_flags: int,
                        blob_id: int, size: int, num_entries: int,
                        entry_size: int):
    return ("ops { gpu_create_blob { resource_slot: %d blob_mem: %d "
            "blob_flags: %d blob_id: %d size: %d num_entries: %d "
            "entry_size: %d } }"
            % (slot, blob_mem, blob_flags, blob_id, size,
               num_entries, entry_size))

def op_host_hotplug(console_index: int, w: int, h: int):
    return ("ops { host_hotplug_scanout { console_index: %d "
            "width: %d height: %d } }" % (console_index, w, h))


def prologue():
    """Bring the GPU up: features + cmd queue (0) + cursor queue (1) +
    DRIVER_OK."""
    return [
        op_get_features(),
        op_set_features(VIRTIO_F_VERSION_1),
        op_vq_setup(0, 64),   # control queue
        op_vq_setup(1, 64),   # cursor queue
        op_set_status(STATUS_DRIVER_OK),
    ]


def emit(path, ops, comment):
    body = "# " + comment.strip().replace("\n", "\n# ") + "\n"
    body += "\n".join(ops) + "\n"
    with open(path, "w") as f:
        f.write(body)


# -- seed builders ------------------------------------------------------------

def seed_init():
    return ("seed_01_init.textpb",
            "Bare prologue: features negotiation + cmd/cursor queue "
            "setup + DRIVER_OK. No commands. Lets LPM build outwards.",
            prologue())


def seed_full_2d_pipeline():
    """The canonical 2D session: create, attach backing, fill, transfer,
    flush. State-aware: every op references slot 0 (created in step 1)."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM, w=64, h=64))
    ops.append(op_gpu_attach_backing(r_slot=0, b_slot=0,
                                      num_entries=4, entry_size=4096,
                                      fill=b"\xff" * 16))
    ops.append(op_gpu_transfer(slot=0, x=0, y=0, w=64, h=64, offset=0))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=64, h=64))
    return ("seed_02_full_2d.textpb",
            "Canonical 2D pipeline. CREATE_2D writes the new resource "
            "id into slot 0; ATTACH_BACKING / TRANSFER_TO_HOST_2D / "
            "RESOURCE_FLUSH all read the same slot. LPM can mutate slot "
            "indices to break the dependency, dimensions, formats, etc.",
            ops)


def seed_set_scanout():
    """Bind a resource to scanout 0."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM,
                                 w=1024, h=768))
    ops.append(op_gpu_attach_backing(r_slot=0, b_slot=0,
                                      num_entries=8, entry_size=4096))
    ops.append(op_gpu_set_scanout(scanout=0, slot=0,
                                   x=0, y=0, w=1024, h=768))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=1024, h=768))
    return ("seed_03_set_scanout.textpb",
            "Create a 1024x768 surface and bind it to scanout 0. "
            "Exercises the set_scanout path including resource lookup.",
            ops)


def seed_cursor():
    """Cursor uses a small (max 64x64) resource on the cursor queue."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=1, fmt=FMT_B8G8R8A8_UNORM,
                                 w=64, h=64))
    ops.append(op_gpu_attach_backing(r_slot=1, b_slot=1,
                                      num_entries=1, entry_size=4096))
    ops.append(op_gpu_transfer(slot=1, x=0, y=0, w=64, h=64, offset=0))
    ops.append(op_gpu_update_cursor(scanout=0, x=100, y=100,
                                     slot=1, hot_x=0, hot_y=0))
    ops.append(op_gpu_move_cursor(scanout=0, x=200, y=200))
    ops.append(op_gpu_move_cursor(scanout=0, x=400, y=400))
    return ("seed_04_cursor.textpb",
            "Create a 64x64 cursor resource, bind it via update_cursor "
            "(cursor queue), then move_cursor a few times. Exercises "
            "the cursor queue path -- separate from the control queue.",
            ops)


def seed_multi_resource():
    """Multiple live resources at once. Each in its own slot. Then "
    "flush a non-zero slot to verify slot lookup."""
    ops = prologue()
    for i, (fmt, dim) in enumerate([
            (FMT_B8G8R8A8_UNORM, 64),
            (FMT_R8G8B8A8_UNORM, 128),
            (FMT_X8R8G8B8_UNORM, 256),
            (FMT_A8B8G8R8_UNORM, 512),
    ]):
        ops.append(op_gpu_create_2d(slot=i, fmt=fmt, w=dim, h=dim))
        ops.append(op_gpu_attach_backing(r_slot=i, b_slot=i,
                                          num_entries=2, entry_size=4096))
    # Bind slot 0 to scanout 0; flush slot 3 (the largest)
    ops.append(op_gpu_set_scanout(scanout=0, slot=0,
                                   x=0, y=0, w=64, h=64))
    ops.append(op_gpu_flush(slot=3, x=0, y=0, w=512, h=512))
    return ("seed_05_multi_resource.textpb",
            "Four concurrent resources in slots 0..3 with different "
            "formats and sizes. set_scanout binds slot 0; flush "
            "operates on slot 3. LPM can mix slot references freely.",
            ops)


def seed_unref_recreate():
    """State-aware demonstration: create slot 0 (resource_id assigned),
    unref it (slot becomes empty), then create slot 0 again (a NEW
    resource_id is assigned). The harness's next_resource_id advances
    monotonically, so recreated slots get fresh ids."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM, w=64, h=64))
    ops.append(op_gpu_unref(slot=0))
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_R8G8B8A8_UNORM,
                                 w=128, h=128))
    ops.append(op_gpu_attach_backing(r_slot=0, b_slot=0,
                                      num_entries=2, entry_size=4096))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=128, h=128))
    return ("seed_06_unref_recreate.textpb",
            "Create slot 0 -> unref slot 0 -> create slot 0 again. The "
            "second create assigns a fresh resource_id; subsequent "
            "ops operate on the new resource. Exercises the device's "
            "id-reuse handling.",
            ops)


def seed_negative_no_resource():
    """Reference slot 0 without ever creating it: the harness sees an
    empty slot and emits resource_id=0, which is the 'no resource'
    sentinel. Useful negative test."""
    ops = prologue()
    ops.append(op_gpu_set_scanout(scanout=0, slot=0,
                                   x=0, y=0, w=640, h=480))
    ops.append(op_gpu_transfer(slot=0, x=0, y=0, w=64, h=64, offset=0))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=64, h=64))
    return ("seed_07_negative_no_resource.textpb",
            "Reference slot 0 without creating it. The harness emits "
            "resource_id=0 for every op. Negative-space exploration.",
            ops)


def seed_negative_detach_no_backing():
    """Create a resource, detach backing without attaching. Edge case."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM, w=64, h=64))
    ops.append(op_gpu_detach_backing(slot=0))
    return ("seed_08_negative_detach_no_backing.textpb",
            "DETACH_BACKING on a resource that never had backing. "
            "Exercises the device's defensive parsing.",
            ops)


def seed_transfer_extreme():
    """TRANSFER_TO_HOST_2D with weird dimensions: 0x0, very large, "
    "negative-looking offset. Catches OOB-read bugs in the transfer "
    "rectangle handler."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM,
                                 w=64, h=64))
    ops.append(op_gpu_attach_backing(r_slot=0, b_slot=0,
                                      num_entries=4, entry_size=4096))
    # zero size
    ops.append(op_gpu_transfer(slot=0, x=0, y=0, w=0, h=0, offset=0))
    # very large
    ops.append(op_gpu_transfer(slot=0, x=0, y=0,
                                w=0xffff, h=0xffff, offset=0))
    # offset > backing
    ops.append(op_gpu_transfer(slot=0, x=0, y=0, w=4, h=4,
                                offset=0xffffffff))
    return ("seed_09_transfer_extreme.textpb",
            "Three TRANSFER_TO_HOST_2D commands with extreme width/"
            "height/offset combinations. Targets the rectangle bounds "
            "checks.",
            ops)


def seed_display_info_edid():
    ops = prologue()
    ops.append(op_gpu_get_display_info())
    for sc in range(4):
        ops.append(op_gpu_get_edid(scanout=sc))
    return ("seed_10_display_info_edid.textpb",
            "GET_DISPLAY_INFO + GET_EDID across 4 scanouts. Drives the "
            "info-query path including the EDID generator.",
            ops)


def seed_fenced_pipeline():
    """State-aware: enable fence state, then issue a 2D pipeline. Every
    ctrl_hdr emitted carries VIRTIO_GPU_FLAG_FENCE + fence_id. Exercises
    the device's fence-tracking + signal-on-completion paths."""
    ops = prologue()
    ops.append(op_gpu_set_fence(True, fence_id=0xdeadbeef))
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM, w=64, h=64))
    ops.append(op_gpu_attach_backing(r_slot=0, b_slot=0,
                                      num_entries=4, entry_size=4096))
    ops.append(op_gpu_transfer(slot=0, x=0, y=0, w=64, h=64, offset=0))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=64, h=64))
    ops.append(op_gpu_set_fence(False))
    return ("seed_11_fenced_pipeline.textpb",
            "Enable fence state (id=0xdeadbeef), run a 2D pipeline; "
            "every ctrl_hdr carries VIRTIO_GPU_FLAG_FENCE. Disable.",
            ops)


def seed_blob_resource():
    """RESOURCE_CREATE_BLOB with guest-memory backing."""
    ops = prologue()
    # blob_mem = 0 (VIRTIO_GPU_BLOB_MEM_GUEST), no flags
    ops.append(op_gpu_create_blob(slot=0, blob_mem=0, blob_flags=0,
                                   blob_id=0, size=4096, num_entries=1,
                                   entry_size=4096))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=64, h=64))
    return ("seed_12_blob_resource.textpb",
            "Create a 4KB guest-memory blob resource in slot 0 then "
            "flush it. Exercises VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB.",
            ops)


def seed_host_hotplug():
    """Hotplug: resize console 0 a few times, with intervening flushes
    so the device sees the geometry change at different states."""
    ops = prologue()
    ops.append(op_gpu_create_2d(slot=0, fmt=FMT_B8G8R8A8_UNORM,
                                 w=640, h=480))
    ops.append(op_gpu_attach_backing(r_slot=0, b_slot=0,
                                      num_entries=4, entry_size=4096))
    ops.append(op_gpu_set_scanout(scanout=0, slot=0,
                                   x=0, y=0, w=640, h=480))
    ops.append(op_host_hotplug(console_index=0, w=1024, h=768))
    ops.append(op_gpu_flush(slot=0, x=0, y=0, w=640, h=480))
    ops.append(op_host_hotplug(console_index=0, w=1920, h=1080))
    ops.append(op_gpu_get_display_info())
    return ("seed_13_host_hotplug.textpb",
            "Bind a 640x480 surface to scanout 0, then hotplug-resize "
            "console 0 to 1024x768 and 1920x1080 with flushes between. "
            "Exercises the display-info change path.",
            ops)


def seed_config_probe():
    """ConfigRead/Write + VqSelect over virtio-gpu config space.
    virtio_gpu_config: events_read(4) events_clear(4) num_scanouts(4)
    num_capsets(4) = 16 bytes."""
    ops = prologue()
    ops.append(op_vq_select(0))
    for off in (0, 4, 8, 12):
        ops.append(op_config_read(off, 4))
    ops.append(op_config_read(0, 16))
    # write events_clear to ack any pending events
    ops.append(op_config_write(4, struct.pack("<I", 0xffffffff)))
    return ("seed_14_config_probe.textpb",
            "Init + VqSelect + ConfigRead/Write across virtio-gpu "
            "config space (events_read/events_clear/num_scanouts/"
            "num_capsets).",
            ops)


def seed_fault_injection():
    """MmioCorrupt across the virtio-mmio window + MemwriteAbsolute
    across the harness DRAM pool. Register-decoder + memory-region
    fault injection."""
    ops = prologue()
    ops.append(op_mmio_corrupt(offset=0x01c, value=0xdeadbeef, size=4))
    ops.append(op_mmio_corrupt(offset=0x028, value=0xcafebabe, size=4))
    ops.append(op_mmio_corrupt(offset=0x070, value=0, size=4))
    ops.append(op_mem_write_absolute(0x47000000, b"\xff" * 64))
    ops.append(op_mem_write_absolute(0x4700C000, b"\xaa" * 32))
    return ("seed_15_fault_injection.textpb",
            "Init + MmioCorrupt + MemwriteAbsolute. Fault injection "
            "for the register decoder and DMA-region paths.",
            ops)


def seed_raw_vq_get_display_info():
    """Hand-build a VIRTIO_GPU_CMD_GET_DISPLAY_INFO via raw descriptor
    placement instead of the typed gpu_get_display_info helper.
    Exercises GuestMemWrite + VqAddDesc + VqKick + VqWaitUsed."""
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100
    # virtio_gpu_ctrl_hdr: type(4) flags(4) fence_id(8) ctx_id(4)
    # ring_idx(1) padding(3) = 24 bytes
    hdr = struct.pack("<IIQI4s", VIRTIO_GPU_CMD_GET_DISPLAY_INFO,
                      0, 0, 0, b"\x00" * 4)
    # response: virtio_gpu_resp_display_info (24 hdr + 16 * 24 pmodes)
    resp = b"\x00" * (24 + 16 * 24)
    ops = prologue()
    ops += [
        op_guest_mem_write(buf_id=200, data=hdr),
        op_guest_mem_write(buf_id=201, data=resp),
        op_vq_add_desc(0, 200, len(hdr), False, True),
        op_vq_add_desc(0, 201, len(resp), True,  False),
        op_vq_kick(0),
        op_vq_wait_used(0),
    ]
    return ("seed_16_raw_vq_get_display_info.textpb",
            "Init + manually-built virtio-gpu GET_DISPLAY_INFO via "
            "raw guest_mem_write + vq_add_desc + vq_kick + "
            "vq_wait_used. Mirrors what the typed "
            "gpu_get_display_info helper does, but expressed as raw "
            "vq operations.",
            ops)


def seed_dma_reflection():
    """DMA Reflection: device-writable descs → own MMIO (exotic_region=2).
    buf_id=20 → QueueNotify (offset 0x050); buf_id=28 → QueueDescLow.
    Device DMA-writes land on its own MMIO registers → reentrancy.
    CVE-2024-3446 class."""
    ops = prologue()
    ops += [
        op_vq_add_desc(0, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(0, 44, 4, True,  False, exotic_region=2),
        op_vq_kick(0),
    ]
    return ("seed_dma_reflection.textpb",
            "DMA Reflection (exotic_region=2): device-writable descs target "
            "own MMIO QueueNotify (buf_id=20) and QueueDescLow (buf_id=28). "
            "CVE-2024-3446 class.",
            ops)


def seed_dma_all_regions():
    """All four exotic GPA regions in one chain: UART(1), Reflection(2),
    GIC(3), Refraction(4). Ensures LPM seeds all reentrancy primitives."""
    ops = prologue()
    ops += [
        op_vq_add_desc(0, 1,  4, False, True,  exotic_region=1),
        op_vq_add_desc(0, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(0, 0,  4, True,  True,  exotic_region=3),
        op_vq_add_desc(0, 0,  4, True,  False, exotic_region=4),
        op_vq_kick(0),
    ]
    return ("seed_dma_all_exotic_regions.textpb",
            "All four exotic GPA regions: UART(1), own-MMIO Reflection(2), "
            "GIC(3), virt-mmio Refraction(4). Seeds all reentrancy primitives.",
            ops)


def seed_dma_reflection_concurrent():
    """Concurrent DMA Reflection: primary descs target own QueueNotify;
    secondary thread races with MMIO writes to the same register."""
    ops = prologue()
    ops += [
        op_vq_add_desc(0, 20, 4, True, True,  exotic_region=2),
        op_vq_add_desc(0, 44, 4, True, False, exotic_region=2),
        op_vq_kick(0),
        b_mmio_corrupt(0x050, 0),
        b_mmio_corrupt(0x070, 0),
        b_vq_add_desc(0, 20, 4, True, False, exotic_region=2),
    ]
    return ("seed_dma_reflection_concurrent.textpb",
            "Concurrent DMA Reflection: primary reflection chain + thread_b "
            "racing with QueueNotify MMIO writes. CVE-2024-3446 class.",
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
    seed_full_2d_pipeline,
    seed_set_scanout,
    seed_cursor,
    seed_multi_resource,
    seed_unref_recreate,
    seed_negative_no_resource,
    seed_negative_detach_no_backing,
    seed_transfer_extreme,
    seed_display_info_edid,
    # Phase A addables -----------------------------------------------
    seed_fenced_pipeline,
    seed_blob_resource,
    seed_host_hotplug,
    # Proto-coverage fillers ----------------------------------------
    seed_config_probe,
    seed_fault_injection,
    seed_raw_vq_get_display_info,
    # DMA reentrancy seeds -------------------------------------------
    seed_dma_reflection,
    seed_dma_all_regions,
    seed_dma_reflection_concurrent,
    seed_dma_reset_gadget,
    seed_dma_recursive_notify,
]


def variation(base_seed, idx, rng):
    """Derive a perturbed seed from a base (name, comment, ops) tuple.
    Strategies are deterministic given `rng`: duplicate one op, drop one
    op, shuffle the tail, or repeat one op several times. Lets the
    generator emit any number of seeds even when N > len(SEED_BUILDERS)."""
    name, comment, ops = base_seed
    new_name = name.replace(".textpb", "_v%03d.textpb" % idx)
    new_comment = comment + (" -- variation %d (auto-perturbed)." % idx)
    out = list(ops)
    if len(out) >= 2:
        strategy = rng.choice(["dup", "drop", "shuffle_tail", "repeat_one"])
        if strategy == "dup":
            i = rng.randrange(len(out))
            out.insert(i, out[i])
        elif strategy == "drop":
            i = rng.randrange(1, len(out))   # keep op 0
            out.pop(i)
        elif strategy == "shuffle_tail":
            head_len = min(5, len(out))      # preserve prologue
            tail = out[head_len:]
            if tail:
                rng.shuffle(tail)
                out = out[:head_len] + tail
        elif strategy == "repeat_one":
            i = rng.randrange(len(out))
            n = rng.randint(2, 4)
            out[i:i+1] = [out[i]] * n
    return (new_name, new_comment, out)


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-o", "--out", default="/tmp/proto_fuzz_run/corpus_gpu",
                   help="output directory (default: %(default)s)")
    p.add_argument("--clean", action="store_true",
                   help="remove existing .textpb files before generating")
    p.add_argument("-n", "--count", type=int, default=None,
                   help="number of seeds to emit (default: %d base "
                        "builders). When N > base count, the extras "
                        "are deterministic perturbations of the base "
                        "seeds." % len(SEED_BUILDERS))
    p.add_argument("--seed", type=lambda x: int(x, 0), default=0xC0FFEE,
                   help="rng seed for variation generation "
                        "(default: 0xC0FFEE; reruns produce the same "
                        "corpus)")
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
