/*
 * Structured + state-aware fuzzer for virtio-gpu-device on arm 'virt'.
 *
 * State-aware in the same sense as a real virtio-gpu driver: each
 * iteration walks a sequence of typed device ops, and any reference
 * between ops (e.g. SET_SCANOUT pointing at the resource that
 * RESOURCE_CREATE_2D just made) is a slot-table lookup, not a fixed
 * id baked into the proto. The harness keeps a small per-iteration
 * GpuState struct holding:
 *
 *   slot -> resource_id   (filled by GpuResourceCreate2D)
 *   slot -> width, height (so transfers / flushes can be sized
 *                          relative to the resource)
 *   slot -> backing GPA + size (filled by ATTACH_BACKING)
 *
 * LPM mutates the proto fields (slot indices, formats, dimensions);
 * the harness resolves slots into real values when emitting wire
 * bytes onto the control queue (vq 0) or cursor queue (vq 1).
 */

#include <glib.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_gpu.pb.h"

extern "C" {

typedef struct QTestState QTestState;

uint8_t  qtest_readb (QTestState *s, uint64_t addr);
uint16_t qtest_readw (QTestState *s, uint64_t addr);
uint32_t qtest_readl (QTestState *s, uint64_t addr);
void     qtest_writeb(QTestState *s, uint64_t addr, uint8_t  value);
void     qtest_writew(QTestState *s, uint64_t addr, uint16_t value);
void     qtest_writel(QTestState *s, uint64_t addr, uint32_t value);
void     qtest_memwrite(QTestState *s, uint64_t addr,
                        const void *data, size_t size);
void     qtest_memread (QTestState *s, uint64_t addr,
                        void *data, size_t size);
void     flush_events  (QTestState *s);

/*
 * Display hotplug helpers. Forward-declared rather than #included so we
 * keep `-I..` (QEMU source root) off the C++ command line -- see the
 * top-of-file comment in proto_fuzz_virtio_blk.cc for the rationale.
 */
typedef struct QemuConsole QemuConsole;
QemuConsole *qemu_console_lookup_by_index(int index);
void qemu_console_resize(QemuConsole *con, int width, int height);

typedef enum {
    MODULE_INIT_MIGRATION,
    MODULE_INIT_BLOCK,
    MODULE_INIT_OPTS,
    MODULE_INIT_QOM,
    MODULE_INIT_TRACE,
    MODULE_INIT_XEN_BACKEND,
    MODULE_INIT_LIBQOS,
    MODULE_INIT_FUZZ_TARGET,
    MODULE_INIT_MAX,
} module_init_type;
void register_module_init(void (*fn)(void), module_init_type type);

typedef struct FuzzTarget {
    const char *name;
    const char *description;
    GString *(*get_init_cmdline)(struct FuzzTarget *);
    void (*pre_vm_init)(void);
    void (*pre_fuzz)(QTestState *);
    void (*fuzz)(QTestState *, const unsigned char *, size_t);
    size_t (*crossover)(const uint8_t *, size_t,
                        const uint8_t *, size_t,
                        uint8_t *, size_t, unsigned int);
    size_t (*custom_mutator)(uint8_t *data, size_t size, size_t max_size,
                             unsigned int seed);
    void *opaque;
} FuzzTarget;

void fuzz_add_target(const FuzzTarget *target);

}  /* extern "C" */

namespace {

/* arm-virt fills its 32 virtio-mmio slots from the highest address
 * downwards, so a single `-device virtio-gpu-device` lands at slot 31
 * (0x0a003e00), not slot 0. */
constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;
constexpr uint64_t kExoticGpaBase = 0x09000000ULL; /* PL011 UART, non-RAM MMIO */
constexpr uint32_t kExoticGpaSize = 0x1000;

enum : uint64_t {
    R_DEV_FEATURES     = 0x010,
    R_DEV_FEATURES_SEL = 0x014,
    R_DRV_FEATURES     = 0x020,
    R_DRV_FEATURES_SEL = 0x024,
    R_QUEUE_SEL        = 0x030,
    R_QUEUE_NUM_MAX    = 0x034,
    R_QUEUE_NUM        = 0x038,
    R_QUEUE_READY      = 0x044,
    R_QUEUE_NOTIFY     = 0x050,
    R_INT_STATUS       = 0x060,
    R_INT_ACK          = 0x064,
    R_STATUS           = 0x070,
    R_QDESC_LO         = 0x080,
    R_QDESC_HI         = 0x084,
    R_QDRV_LO          = 0x090,
    R_QDRV_HI          = 0x094,
    R_QDEV_LO          = 0x0a0,
    R_QDEV_HI          = 0x0a4,
    R_CONFIG           = 0x100,
};

constexpr uint32_t kStatusAck         = 0x01;
constexpr uint32_t kStatusDriver      = 0x02;
constexpr uint32_t kStatusDriverOk    = 0x04;
constexpr uint32_t kStatusFeaturesOk  = 0x08;

constexpr uint16_t kDescNext  = 0x1;
constexpr uint16_t kDescWrite = 0x2;

/* virtio-gpu wire-format command codes (subset). */
enum : uint32_t {
    VIRTIO_GPU_CMD_GET_DISPLAY_INFO       = 0x0100,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_2D     = 0x0101,
    VIRTIO_GPU_CMD_RESOURCE_UNREF         = 0x0102,
    VIRTIO_GPU_CMD_SET_SCANOUT            = 0x0103,
    VIRTIO_GPU_CMD_RESOURCE_FLUSH         = 0x0104,
    VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D    = 0x0105,
    VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING = 0x0106,
    VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING = 0x0107,
    VIRTIO_GPU_CMD_GET_CAPSET_INFO        = 0x0108,
    VIRTIO_GPU_CMD_GET_CAPSET             = 0x0109,
    VIRTIO_GPU_CMD_GET_EDID               = 0x010a,
    VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB   = 0x010b,
    VIRTIO_GPU_CMD_SET_SCANOUT_BLOB       = 0x010c,
    VIRTIO_GPU_CMD_UPDATE_CURSOR          = 0x0300,
    VIRTIO_GPU_CMD_MOVE_CURSOR            = 0x0301,

    VIRTIO_GPU_FLAG_FENCE                 = 1 << 0,
};

/*
 * virtio-gpu queues:
 *   0 = control queue
 *   1 = cursor queue
 * we reserve 4 slots in our per-vq state arrays (more than needed).
 */
constexpr uint64_t kPoolBase    = 0x47000000ULL;
constexpr uint32_t kMaxQueues   = 4;
constexpr uint32_t kVqDescSize  = 0x1000;
constexpr uint32_t kVqAvailSize = 0x1000;
constexpr uint32_t kVqUsedSize  = 0x1000;
constexpr uint32_t kVqStride    = kVqDescSize + kVqAvailSize + kVqUsedSize;
constexpr uint64_t kBufPoolBase = kPoolBase + kMaxQueues * kVqStride;
constexpr uint64_t kBufPoolEnd  = 0x47F00000ULL;

constexpr uint32_t kCmdVq    = 0;
constexpr uint32_t kCursorVq = 1;

/* slot table sizes for state-aware references */
constexpr int kResourceSlots = 16;
constexpr int kBackingSlots  = 16;

struct VqState {
    uint64_t desc_gpa;
    uint64_t avail_gpa;
    uint64_t used_gpa;
    uint32_t size;
    uint32_t next_desc_idx;
    uint32_t next_avail_idx;
};

struct Buf {
    uint64_t gpa;
    uint32_t len;
};

/*
 * Resource slot bookkeeping. Filled by RESOURCE_CREATE_2D. Cleared on
 * RESOURCE_UNREF. Read by SET_SCANOUT, RESOURCE_FLUSH, TRANSFER_TO_HOST_2D,
 * UPDATE_CURSOR.
 */
struct ResourceSlot {
    uint32_t resource_id;   /* 0 = empty */
    uint32_t width;
    uint32_t height;
    uint32_t format;
};

/*
 * Backing slot bookkeeping. Filled by RESOURCE_ATTACH_BACKING. Used by
 * (notionally) TRANSFER_TO_HOST_2D's offset bounds. The slot remembers
 * the backing's base GPA so reads from the same memory region are
 * possible later if needed.
 */
struct BackingSlot {
    uint64_t base_gpa;     /* 0 = empty */
    uint32_t total_size;
    uint32_t resource_slot; /* which resource slot this is bound to */
};

struct GpuState {
    QTestState* qts = nullptr;
    VqState vqs[kMaxQueues] = {};
    uint64_t buf_alloc = kBufPoolBase;
    std::unordered_map<uint32_t, Buf> bufs;

    ResourceSlot resources[kResourceSlots] = {};
    BackingSlot  backings[kBackingSlots] = {};
    uint32_t next_resource_id = 1;

    /*
     * Fence state: state-aware decoration applied to all subsequent
     * outgoing ctrl_hdrs until reset or a new GpuSetFenceState. When
     * fence_enabled is true, every op emits flags |=
     * VIRTIO_GPU_FLAG_FENCE and fence_id from this state.
     */
    bool     fence_enabled = false;
    uint64_t fence_id      = 0;
    uint32_t fence_ctx_id  = 0;

    /*
     * One GPA region per vq for staging request + response; we reuse
     * across ops within an iteration by advancing buf_alloc. Reset at
     * iteration start.
     */
};

/* See proto_fuzz_virtio_blk.cc for why this is thread_local. */
thread_local GpuState g_state;

/* ---- mmio + ring helpers (same shape as net.cc/blk.cc) ---- */

inline uint32_t mmio_readl(uint64_t off) {
    return qtest_readl(g_state.qts, kVirtioMmioBase + off);
}
inline void mmio_writel(uint64_t off, uint32_t v) {
    qtest_writel(g_state.qts, kVirtioMmioBase + off, v);
}

void reset_iteration_state() {
    mmio_writel(R_STATUS, 0);
    mmio_writel(R_STATUS, kStatusAck | kStatusDriver);

    for (uint32_t i = 0; i < kMaxQueues; ++i) {
        g_state.vqs[i] = VqState{
            .desc_gpa  = kPoolBase + i * kVqStride,
            .avail_gpa = kPoolBase + i * kVqStride + kVqDescSize,
            .used_gpa  = kPoolBase + i * kVqStride + kVqDescSize + kVqAvailSize,
            .size = 0, .next_desc_idx = 0, .next_avail_idx = 0,
        };
    }
    g_state.buf_alloc = kBufPoolBase;
    g_state.bufs.clear();
    for (auto& r : g_state.resources) r = ResourceSlot{};
    for (auto& b : g_state.backings)  b = BackingSlot{};
    g_state.next_resource_id = 1;
    g_state.fence_enabled = false;
    g_state.fence_id      = 0;
    g_state.fence_ctx_id  = 0;
}

uint64_t alloc_gpa(uint32_t len) {
    if (g_state.buf_alloc + len + 16 > kBufPoolEnd) return 0;
    uint64_t gpa = g_state.buf_alloc;
    g_state.buf_alloc = (g_state.buf_alloc + len + 16) & ~uint64_t{0xf};
    return gpa;
}

void op_vq_setup(uint32_t vq_idx, uint32_t requested_size) {
    if (vq_idx >= kMaxQueues) return;
    auto& q = g_state.vqs[vq_idx];

    mmio_writel(R_QUEUE_SEL, vq_idx);
    uint32_t max = mmio_readl(R_QUEUE_NUM_MAX);
    if (max == 0) return;
    uint32_t size = requested_size ? requested_size : 64;
    if (size > max) size = max;
    while (size && (size & (size - 1))) size &= size - 1;
    if (size == 0) size = 1;

    q.size = size;
    mmio_writel(R_QUEUE_NUM, size);
    mmio_writel(R_QDESC_LO, static_cast<uint32_t>(q.desc_gpa));
    mmio_writel(R_QDESC_HI, static_cast<uint32_t>(q.desc_gpa >> 32));
    mmio_writel(R_QDRV_LO,  static_cast<uint32_t>(q.avail_gpa));
    mmio_writel(R_QDRV_HI,  static_cast<uint32_t>(q.avail_gpa >> 32));
    mmio_writel(R_QDEV_LO,  static_cast<uint32_t>(q.used_gpa));
    mmio_writel(R_QDEV_HI,  static_cast<uint32_t>(q.used_gpa >> 32));
    mmio_writel(R_QUEUE_READY, 1);
}

uint32_t place_desc(uint32_t vq_idx, uint64_t addr, uint32_t len,
                    bool device_writable, bool chain_next) {
    auto& q = g_state.vqs[vq_idx];
    uint32_t idx = q.next_desc_idx % q.size;

    uint16_t flags = 0;
    if (device_writable) flags |= kDescWrite;
    if (chain_next)      flags |= kDescNext;

    uint8_t desc[16];
    uint16_t next = static_cast<uint16_t>((idx + 1) % q.size);
    std::memcpy(desc + 0,  &addr,  8);
    std::memcpy(desc + 8,  &len,   4);
    std::memcpy(desc + 12, &flags, 2);
    std::memcpy(desc + 14, &next,  2);
    qtest_memwrite(g_state.qts, q.desc_gpa + idx * 16, desc, 16);

    uint32_t head = q.next_desc_idx;
    q.next_desc_idx++;
    if (!chain_next) {
        uint16_t hh = static_cast<uint16_t>(head);
        uint64_t ring_slot =
            q.avail_gpa + 4 + (q.next_avail_idx % q.size) * 2;
        qtest_memwrite(g_state.qts, ring_slot, &hh, 2);
        q.next_avail_idx++;
        uint16_t aidx = static_cast<uint16_t>(q.next_avail_idx);
        qtest_memwrite(g_state.qts, q.avail_gpa + 2, &aidx, 2);
    }
    return head;
}

/* ---- virtio-gpu wire packers ---- */

/*
 * struct virtio_gpu_ctrl_hdr (24 bytes):
 *   le32 type, le32 flags, le64 fence_id, le32 ctx_id, le32 padding
 *
 * Reads g_state.fence_{enabled,id,ctx_id} so that any op submitted
 * after a GpuSetFenceState{enabled=true,...} carries the fence flags.
 */
void pack_ctrl_hdr(uint8_t out[24], uint32_t type) {
    uint32_t flags    = g_state.fence_enabled ? VIRTIO_GPU_FLAG_FENCE : 0;
    uint64_t fence_id = g_state.fence_enabled ? g_state.fence_id : 0;
    uint32_t ctx_id   = g_state.fence_enabled ? g_state.fence_ctx_id : 0;
    uint32_t padding  = 0;
    std::memcpy(out + 0,  &type, 4);
    std::memcpy(out + 4,  &flags, 4);
    std::memcpy(out + 8,  &fence_id, 8);
    std::memcpy(out + 16, &ctx_id, 4);
    std::memcpy(out + 20, &padding, 4);
}

/*
 * Submit a request on vq 0 or vq 1: stage `req` bytes in DRAM, stage
 * `resp_len` bytes of response space in DRAM, build a 2-descriptor
 * chain (req out, resp in), kick, flush.
 *
 * Returns the response GPA so the caller can read it (unused here for
 * 2D resource ops since resource_id is guest-assigned, but useful for
 * GET_DISPLAY_INFO and GET_EDID).
 */
uint64_t submit_cmd(uint32_t vq_idx, const void* req, uint32_t req_len,
                    uint32_t resp_len) {
    if (g_state.vqs[vq_idx].size == 0) return 0;
    if (g_state.vqs[vq_idx].next_desc_idx + 2
            >= g_state.vqs[vq_idx].size) return 0;

    uint64_t req_gpa = alloc_gpa(req_len);
    if (!req_gpa) return 0;
    qtest_memwrite(g_state.qts, req_gpa, req, req_len);

    uint64_t resp_gpa = alloc_gpa(resp_len);
    if (!resp_gpa) return 0;
    /* zero-init response area */
    {
        uint8_t zero[64] = {};
        for (uint32_t i = 0; i < resp_len; i += sizeof(zero)) {
            uint32_t n = std::min<uint32_t>(sizeof(zero), resp_len - i);
            qtest_memwrite(g_state.qts, resp_gpa + i, zero, n);
        }
    }

    place_desc(vq_idx, req_gpa,  req_len,  /*write=*/false, /*next=*/true);
    place_desc(vq_idx, resp_gpa, resp_len, /*write=*/true,  /*next=*/false);

    mmio_writel(R_QUEUE_NOTIFY, vq_idx);
    flush_events(g_state.qts);

    uint32_t st = mmio_readl(R_INT_STATUS);
    if (st) mmio_writel(R_INT_ACK, st);
    return resp_gpa;
}

/* ---- per-command dispatchers ---- */

inline uint32_t resource_slot(uint32_t s) { return s % kResourceSlots; }
inline uint32_t backing_slot (uint32_t s) { return s % kBackingSlots; }

/*
 * Build a virtio_gpu_resource_create_2d (24B hdr + 16B body = 40B)
 * for the named slot. Picks a fresh resource_id, writes it into the
 * slot, then ships the request.
 */
void op_create_2d(const qemu::fuzz::gpu::GpuResourceCreate2D& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.next_resource_id++;

    uint8_t buf[40];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    std::memcpy(buf + 24, &rid, 4);
    uint32_t format = m.format();
    uint32_t width  = m.width();
    uint32_t height = m.height();
    std::memcpy(buf + 28, &format, 4);
    std::memcpy(buf + 32, &width,  4);
    std::memcpy(buf + 36, &height, 4);

    submit_cmd(kCmdVq, buf, sizeof(buf), 24 /* resp = ctrl_hdr only */);

    g_state.resources[slot] = ResourceSlot{
        .resource_id = rid,
        .width  = width,
        .height = height,
        .format = format,
    };
}

/*
 * RESOURCE_UNREF (24B hdr + 8B body = 32B): {resource_id, padding}
 */
void op_resource_unref(const qemu::fuzz::gpu::GpuResourceUnref& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.resources[slot].resource_id;

    uint8_t buf[32];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_UNREF);
    std::memcpy(buf + 24, &rid, 4);
    uint32_t pad = 0;
    std::memcpy(buf + 28, &pad, 4);

    submit_cmd(kCmdVq, buf, sizeof(buf), 24);

    /* slot becomes empty after unref */
    g_state.resources[slot] = ResourceSlot{};
}

/*
 * RESOURCE_ATTACH_BACKING:
 *   ctrl_hdr (24)
 *   le32 resource_id
 *   le32 nr_entries
 *   then nr_entries * { le64 addr, le32 length, le32 padding }
 */
void op_attach_backing(const qemu::fuzz::gpu::GpuResourceAttachBacking& m) {
    uint32_t r_slot = resource_slot(m.resource_slot());
    uint32_t b_slot = backing_slot(m.backing_slot());
    uint32_t rid    = g_state.resources[r_slot].resource_id;

    uint32_t nr   = std::clamp<uint32_t>(m.num_entries(), 1, 16);
    uint32_t esz  = std::clamp<uint32_t>(m.entry_size(),  1, 4096);
    uint32_t total = nr * esz;

    /* Allocate one contiguous DRAM region; the SG list points at it
     * with `nr` entries of `esz` each. */
    uint64_t back_gpa = alloc_gpa(total);
    if (!back_gpa) return;

    /* Optionally fill the backing region with `fill` (cycled). */
    const std::string& fill = m.fill();
    if (!fill.empty()) {
        for (uint32_t off = 0; off < total; off += fill.size()) {
            uint32_t n = std::min<uint32_t>(fill.size(), total - off);
            qtest_memwrite(g_state.qts, back_gpa + off, fill.data(), n);
        }
    } else {
        uint8_t zero[64] = {};
        for (uint32_t off = 0; off < total; off += sizeof(zero)) {
            uint32_t n = std::min<uint32_t>(sizeof(zero), total - off);
            qtest_memwrite(g_state.qts, back_gpa + off, zero, n);
        }
    }

    /* Build request: 24 (hdr) + 4 (rid) + 4 (nr) + 16*nr (entries) */
    std::string req(24 + 4 + 4 + 16 * nr, '\0');
    pack_ctrl_hdr(reinterpret_cast<uint8_t*>(req.data()),
                  VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    std::memcpy(req.data() + 24, &rid, 4);
    std::memcpy(req.data() + 28, &nr,  4);
    for (uint32_t i = 0; i < nr; ++i) {
        uint64_t addr = back_gpa + i * esz;
        uint32_t len  = esz;
        uint32_t pad  = 0;
        std::memcpy(req.data() + 32 + i * 16,      &addr, 8);
        std::memcpy(req.data() + 32 + i * 16 + 8,  &len,  4);
        std::memcpy(req.data() + 32 + i * 16 + 12, &pad,  4);
    }

    submit_cmd(kCmdVq, req.data(), req.size(), 24);

    g_state.backings[b_slot] = BackingSlot{
        .base_gpa = back_gpa,
        .total_size = total,
        .resource_slot = r_slot,
    };
}

/*
 * RESOURCE_DETACH_BACKING: 24+8 = 32B, payload = {rid, padding}.
 */
void op_detach_backing(
        const qemu::fuzz::gpu::GpuResourceDetachBacking& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.resources[slot].resource_id;

    uint8_t buf[32];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING);
    std::memcpy(buf + 24, &rid, 4);
    uint32_t pad = 0;
    std::memcpy(buf + 28, &pad, 4);
    submit_cmd(kCmdVq, buf, sizeof(buf), 24);

    /* Backing slots that referenced this resource are no longer valid;
     * we don't aggressively clear them so subsequent ops can also fuzz
     * the post-detach state. */
}

/*
 * TRANSFER_TO_HOST_2D: ctrl_hdr (24) + virtio_gpu_rect (16) + offset (8)
 *                    + resource_id (4) + padding (4) = 56B
 *   rect = {x, y, width, height} all le32
 */
void op_transfer_to_host(
        const qemu::fuzz::gpu::GpuTransferToHost2D& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.resources[slot].resource_id;

    uint8_t buf[56];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    uint32_t x = m.x();
    uint32_t y = m.y();
    uint32_t w = m.width();
    uint32_t h = m.height();
    uint64_t off = m.offset();
    uint32_t pad = 0;
    std::memcpy(buf + 24, &x,   4);
    std::memcpy(buf + 28, &y,   4);
    std::memcpy(buf + 32, &w,   4);
    std::memcpy(buf + 36, &h,   4);
    std::memcpy(buf + 40, &off, 8);
    std::memcpy(buf + 48, &rid, 4);
    std::memcpy(buf + 52, &pad, 4);
    submit_cmd(kCmdVq, buf, sizeof(buf), 24);
}

/*
 * RESOURCE_FLUSH: ctrl_hdr (24) + virtio_gpu_rect (16) + rid (4) + pad (4) = 48B
 */
void op_resource_flush(const qemu::fuzz::gpu::GpuResourceFlush& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.resources[slot].resource_id;

    uint8_t buf[48];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    uint32_t x = m.x(), y = m.y(), w = m.width(), h = m.height();
    uint32_t pad = 0;
    std::memcpy(buf + 24, &x, 4);
    std::memcpy(buf + 28, &y, 4);
    std::memcpy(buf + 32, &w, 4);
    std::memcpy(buf + 36, &h, 4);
    std::memcpy(buf + 40, &rid, 4);
    std::memcpy(buf + 44, &pad, 4);
    submit_cmd(kCmdVq, buf, sizeof(buf), 24);
}

/*
 * SET_SCANOUT: ctrl_hdr (24) + virtio_gpu_rect (16) + scanout_id (4)
 *            + resource_id (4) = 48B
 */
void op_set_scanout(const qemu::fuzz::gpu::GpuSetScanout& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.resources[slot].resource_id;
    /* If resource_slot is 0 and slot 0 is empty, we send rid=0 which is
     * the legitimate "disable scanout" sentinel. That itself is worth
     * fuzzing. */

    uint8_t buf[48];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_SET_SCANOUT);
    uint32_t x = m.x(), y = m.y(), w = m.width(), h = m.height();
    uint32_t scid = m.scanout_id();
    std::memcpy(buf + 24, &x, 4);
    std::memcpy(buf + 28, &y, 4);
    std::memcpy(buf + 32, &w, 4);
    std::memcpy(buf + 36, &h, 4);
    std::memcpy(buf + 40, &scid, 4);
    std::memcpy(buf + 44, &rid,  4);
    submit_cmd(kCmdVq, buf, sizeof(buf), 24);
}

/* GET_DISPLAY_INFO: 24B request, response holds 24 + max_scanouts entries. */
void op_get_display_info() {
    uint8_t buf[24];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    /* Response is sized for up to 16 scanouts × 24B + 24B hdr = 408 */
    submit_cmd(kCmdVq, buf, sizeof(buf), 24 + 16 * 24);
}

/*
 * GET_EDID: ctrl_hdr (24) + scanout_id (4) + padding (4) = 32B request.
 *          Response: ctrl_hdr (24) + size (4) + padding (4) + 1024-byte blob.
 */
void op_get_edid(const qemu::fuzz::gpu::GpuGetEdid& m) {
    uint8_t buf[32];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_GET_EDID);
    uint32_t scid = m.scanout_id();
    uint32_t pad  = 0;
    std::memcpy(buf + 24, &scid, 4);
    std::memcpy(buf + 28, &pad,  4);
    submit_cmd(kCmdVq, buf, sizeof(buf), 24 + 8 + 1024);
}

/*
 * UPDATE_CURSOR (cursor queue): virtio_gpu_update_cursor:
 *   ctrl_hdr (24)
 *   pos (8) = {scanout_id, x, y, padding}
 *   resource_id (4)
 *   hot_x (4), hot_y (4)
 *   padding (4)
 *   = 24 + 8 + 4 + 4 + 4 + 4 = 48B
 */
void op_update_cursor(const qemu::fuzz::gpu::GpuUpdateCursor& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.resources[slot].resource_id;

    uint8_t buf[56];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_UPDATE_CURSOR);
    uint32_t scid = m.scanout_id();
    uint32_t x = m.x(), y = m.y();
    uint32_t pad = 0;
    std::memcpy(buf + 24, &scid, 4);
    std::memcpy(buf + 28, &x,    4);
    std::memcpy(buf + 32, &y,    4);
    std::memcpy(buf + 36, &pad,  4);
    std::memcpy(buf + 40, &rid,  4);
    uint32_t hx = m.hot_x(), hy = m.hot_y();
    std::memcpy(buf + 44, &hx,   4);
    std::memcpy(buf + 48, &hy,   4);
    std::memcpy(buf + 52, &pad,  4);
    submit_cmd(kCursorVq, buf, sizeof(buf), 24);
}

/*
 * GpuSetFenceState: update harness fence state. Subsequent commands
 * pick this up via pack_ctrl_hdr.
 */
void op_set_fence_state(const qemu::fuzz::gpu::GpuSetFenceState& m) {
    g_state.fence_enabled = m.enabled();
    g_state.fence_id      = m.fence_id();
    g_state.fence_ctx_id  = m.ctx_id();
}

/*
 * RESOURCE_CREATE_BLOB: ctrl_hdr (24) + resource_id (4) + blob_mem (4) +
 * blob_flags (4) + nr_entries (4) + blob_id (8) + size (8)
 *                    + nr_entries * { addr(8), length(4), padding(4) }
 *
 * State-aware: the new resource_id is stored in resources[slot] so
 * downstream ops (FLUSH, SET_SCANOUT_BLOB if added) can reference it.
 */
void op_create_blob(const qemu::fuzz::gpu::GpuResourceCreateBlob& m) {
    uint32_t slot = resource_slot(m.resource_slot());
    uint32_t rid  = g_state.next_resource_id++;

    uint32_t nr  = std::clamp<uint32_t>(m.num_entries(), 1, 16);
    uint32_t esz = std::clamp<uint32_t>(m.entry_size(), 16, 4096);
    uint32_t total = nr * esz;

    uint64_t back_gpa = alloc_gpa(total);
    if (!back_gpa) return;

    /* zero-fill backing */
    {
        uint8_t zero[64] = {};
        for (uint32_t off = 0; off < total; off += sizeof(zero)) {
            uint32_t n = std::min<uint32_t>(sizeof(zero), total - off);
            qtest_memwrite(g_state.qts, back_gpa + off, zero, n);
        }
    }

    /* request size: 24 (hdr) + 4*4 + 8*2 + nr*16 = 56 + nr*16 */
    std::string req(56 + nr * 16, '\0');
    pack_ctrl_hdr(reinterpret_cast<uint8_t*>(req.data()),
                  VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB);

    uint32_t blob_mem   = m.blob_mem();
    uint32_t blob_flags = m.blob_flags();
    uint64_t blob_id    = m.blob_id();
    uint64_t blob_size  = m.size();

    std::memcpy(req.data() + 24, &rid,        4);
    std::memcpy(req.data() + 28, &blob_mem,   4);
    std::memcpy(req.data() + 32, &blob_flags, 4);
    std::memcpy(req.data() + 36, &nr,         4);
    std::memcpy(req.data() + 40, &blob_id,    8);
    std::memcpy(req.data() + 48, &blob_size,  8);

    for (uint32_t i = 0; i < nr; ++i) {
        uint64_t addr = back_gpa + i * esz;
        uint32_t len  = esz;
        uint32_t pad  = 0;
        std::memcpy(req.data() + 56 + i * 16,      &addr, 8);
        std::memcpy(req.data() + 56 + i * 16 + 8,  &len,  4);
        std::memcpy(req.data() + 56 + i * 16 + 12, &pad,  4);
    }

    submit_cmd(kCmdVq, req.data(), req.size(), 24);

    /* state-aware: new blob resource lives in slot. width/height are 0
     * because blob resources are linear, not 2D rectangles. */
    g_state.resources[slot] = ResourceSlot{
        .resource_id = rid,
        .width  = 0,
        .height = 0,
        .format = 0,
    };
}

/*
 * MmioCorrupt: register-level fault injection. Writes to any offset
 * in the virtio-mmio window, including reserved / unimplemented /
 * read-only offsets. Decoder fault injection.
 */
void op_mmio_corrupt(const qemu::fuzz::gpu::MmioCorrupt& m) {
    uint32_t off  = m.offset() & 0x1ff;
    uint32_t val  = m.value();
    uint32_t size = m.size();
    uint64_t addr = kVirtioMmioBase + off;
    if      (size == 1) qtest_writeb(g_state.qts, addr, val & 0xff);
    else if (size == 2) qtest_writew(g_state.qts, addr, val & 0xffff);
    else                qtest_writel(g_state.qts, addr, val);
}

/*
 * MemwriteAbsolute: fault-injection primitive. Writes `data` to a
 * fixed GPA inside the harness's reserved DRAM pool (clamped). Used
 * in interleaved mode so a secondary op list can mutate memory
 * regions that primary GPU ops have placed descriptors / blob backing
 * at.
 */
void op_memwrite_absolute(const qemu::fuzz::gpu::MemwriteAbsolute& m) {
    const std::string& d = m.data();
    if (d.empty()) return;
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(d.size(), 4096));
    uint64_t gpa = m.gpa();
    /* Compare against (kBufPoolEnd - len) instead of computing
     * (gpa + len): the latter overflows uint64 for huge LPM-generated
     * gpa values, fails to detect out-of-range, and lets the write
     * escape into low MMIO (pflash mode-toggle thrashing flatviews
     * until host OOM). */
    if (gpa < kBufPoolBase || gpa > kBufPoolEnd - len) {
        uint64_t span = kBufPoolEnd - kBufPoolBase - len;
        if (span == 0) return;
        gpa = kBufPoolBase + (gpa % span);
    }
    qtest_memwrite(g_state.qts, gpa, d.data(), len);
}

/*
 * HostHotplugScanout: drive QEMU to resize a virtio-gpu console.
 * Internally this triggers virtio-gpu's display-info change path and
 * raises a config-change interrupt to the guest.
 */
void op_host_hotplug_scanout(
        const qemu::fuzz::gpu::HostHotplugScanout& m) {
    QemuConsole* con = qemu_console_lookup_by_index(
        m.console_index() & 0x7);
    if (!con) return;
    int w = std::clamp<int>(m.width(),  16, 4096);
    int h = std::clamp<int>(m.height(), 16, 4096);
    qemu_console_resize(con, w, h);
    flush_events(g_state.qts);
}

/* MOVE_CURSOR: same struct as UPDATE_CURSOR but cmd opcode differs. */
void op_move_cursor(const qemu::fuzz::gpu::GpuMoveCursor& m) {
    uint8_t buf[56];
    pack_ctrl_hdr(buf, VIRTIO_GPU_CMD_MOVE_CURSOR);
    uint32_t scid = m.scanout_id();
    uint32_t x = m.x(), y = m.y();
    uint32_t pad = 0, rid = 0, hx = 0, hy = 0;
    std::memcpy(buf + 24, &scid, 4);
    std::memcpy(buf + 28, &x,    4);
    std::memcpy(buf + 32, &y,    4);
    std::memcpy(buf + 36, &pad,  4);
    std::memcpy(buf + 40, &rid,  4);
    std::memcpy(buf + 44, &hx,   4);
    std::memcpy(buf + 48, &hy,   4);
    std::memcpy(buf + 52, &pad,  4);
    submit_cmd(kCursorVq, buf, sizeof(buf), 24);
}

/* ---- common-op handlers (mostly identical to net.cc) ---- */

void op_guest_mem_write(uint32_t buf_id, const std::string& data) {
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(data.size(), 4096));
    uint64_t gpa = alloc_gpa(len);
    if (!gpa) return;
    if (len) qtest_memwrite(g_state.qts, gpa, data.data(), len);
    g_state.bufs[buf_id] = Buf{gpa, len};
}

void op_vq_add_desc(uint32_t vq_idx, uint32_t buf_id, uint32_t len,
                    bool device_writable, bool chain_next,
                    uint32_t exotic_region) {
    if (vq_idx >= kMaxQueues) return;
    if (g_state.vqs[vq_idx].size == 0) return;
    uint64_t gpa; uint32_t dlen;
    if (exotic_region != 0) {
        const uint64_t bases[4] = {
            0x09000000ULL, kVirtioMmioBase, 0x08000000ULL, 0x0a000000ULL };
        const uint32_t sizes[4] = { 0x1000, 0x200, 0x10000, 0x3e00 };
        uint32_t ri = (exotic_region - 1) % 4;
        gpa  = bases[ri] + (buf_id % (sizes[ri] / 4)) * 4;
        dlen = std::min(len, 4u);
    } else {
        auto it = g_state.bufs.find(buf_id);
        if (it == g_state.bufs.end()) return;
        gpa  = it->second.gpa;
        dlen = std::min(len, it->second.len);
    }
    place_desc(vq_idx, gpa, dlen, device_writable, chain_next);
}

void op_vq_kick(uint32_t vq_idx) {
    if (vq_idx >= kMaxQueues) return;
    mmio_writel(R_QUEUE_NOTIFY, vq_idx);
    flush_events(g_state.qts);
}

void op_vq_wait_used(uint32_t /*vq_idx*/) {
    flush_events(g_state.qts);
    uint32_t st = mmio_readl(R_INT_STATUS);
    if (st) mmio_writel(R_INT_ACK, st);
}

void dispatch(const qemu::fuzz::gpu::VirtioOp& op) {
    using qemu::fuzz::gpu::VirtioOp;
    switch (op.op_case()) {
    case VirtioOp::kGetFeatures:
        mmio_writel(R_DEV_FEATURES_SEL, 0); (void)mmio_readl(R_DEV_FEATURES);
        mmio_writel(R_DEV_FEATURES_SEL, 1); (void)mmio_readl(R_DEV_FEATURES);
        break;
    case VirtioOp::kSetFeatures: {
        uint64_t f = op.set_features().features();
        mmio_writel(R_DRV_FEATURES_SEL, 0);
        mmio_writel(R_DRV_FEATURES, static_cast<uint32_t>(f));
        mmio_writel(R_DRV_FEATURES_SEL, 1);
        mmio_writel(R_DRV_FEATURES, static_cast<uint32_t>(f >> 32));
        mmio_writel(R_STATUS, mmio_readl(R_STATUS) | kStatusFeaturesOk);
        break;
    }
    case VirtioOp::kConfigRead: {
        uint32_t off = op.config_read().offset() & 0xff;
        (void)mmio_readl(R_CONFIG + off);
        break;
    }
    case VirtioOp::kConfigWrite: {
        const auto& d = op.config_write().data();
        uint32_t off = op.config_write().offset() & 0xff;
        for (size_t i = 0; i + 4 <= d.size() && off + i + 4 <= 0x100; i += 4) {
            uint32_t v;
            std::memcpy(&v, d.data() + i, 4);
            mmio_writel(R_CONFIG + off + i, v);
        }
        break;
    }
    case VirtioOp::kVqSelect:
        mmio_writel(R_QUEUE_SEL, op.vq_select().vq_idx() & 0xff);
        break;
    case VirtioOp::kVqSetup:
        op_vq_setup(op.vq_setup().vq_idx(), op.vq_setup().size());
        break;
    case VirtioOp::kSetStatus: {
        uint32_t bits = op.set_status().bits();
        if (bits == 0) mmio_writel(R_STATUS, 0);
        else           mmio_writel(R_STATUS, mmio_readl(R_STATUS) | bits);
        break;
    }
    case VirtioOp::kGuestMemWrite:
        op_guest_mem_write(op.guest_mem_write().buf_id(),
                           op.guest_mem_write().data());
        break;
    case VirtioOp::kVqAddDesc: {
        const auto& d = op.vq_add_desc();
        op_vq_add_desc(d.vq_idx(), d.buf_id(), d.len(),
                       d.device_writable(), d.chain_next(),
                       d.exotic_region());
        break;
    }
    case VirtioOp::kVqKick:
        op_vq_kick(op.vq_kick().vq_idx());
        break;
    case VirtioOp::kVqWaitUsed:
        op_vq_wait_used(op.vq_wait_used().vq_idx());
        break;
    case VirtioOp::kReset:
        reset_iteration_state();
        break;

    case VirtioOp::kGpuCreate2D:        op_create_2d(op.gpu_create_2d());           break;
    case VirtioOp::kGpuResourceUnref:   op_resource_unref(op.gpu_resource_unref()); break;
    case VirtioOp::kGpuAttachBacking:   op_attach_backing(op.gpu_attach_backing()); break;
    case VirtioOp::kGpuDetachBacking:   op_detach_backing(op.gpu_detach_backing()); break;
    case VirtioOp::kGpuTransferToHost:  op_transfer_to_host(op.gpu_transfer_to_host()); break;
    case VirtioOp::kGpuResourceFlush:   op_resource_flush(op.gpu_resource_flush()); break;
    case VirtioOp::kGpuSetScanout:      op_set_scanout(op.gpu_set_scanout());       break;
    case VirtioOp::kGpuGetDisplayInfo:  op_get_display_info();                      break;
    case VirtioOp::kGpuGetEdid:         op_get_edid(op.gpu_get_edid());             break;
    case VirtioOp::kGpuUpdateCursor:    op_update_cursor(op.gpu_update_cursor());   break;
    case VirtioOp::kGpuMoveCursor:      op_move_cursor(op.gpu_move_cursor());       break;

    case VirtioOp::kGpuSetFenceState:   op_set_fence_state(op.gpu_set_fence_state()); break;
    case VirtioOp::kGpuCreateBlob:      op_create_blob(op.gpu_create_blob());       break;
    case VirtioOp::kHostHotplugScanout: op_host_hotplug_scanout(op.host_hotplug_scanout()); break;
    case VirtioOp::kMemWriteAbsolute:   op_memwrite_absolute(op.mem_write_absolute()); break;
    case VirtioOp::kMmioCorrupt:        op_mmio_corrupt(op.mmio_corrupt());            break;

    case VirtioOp::OP_NOT_SET:
        break;
    }
}

void proto_fuzz_virtio_gpu_run(QTestState* qts,
                               const unsigned char* data, size_t size) {
    g_state.qts = qts;

    qemu::fuzz::gpu::VirtioGpuProgram prog;
    if (!protobuf_mutator::libfuzzer::LoadProtoInput(
            /*binary=*/false, data, size, &prog)) {
        return;
    }

    reset_iteration_state();

    constexpr int kMaxOps = 256;
    int n = 0;

    if (prog.ops_thread_b_size() == 0) {
        for (const auto& op : prog.ops()) {
            if (n++ >= kMaxOps) break;
            dispatch(op);
        }
    } else {
        QTestState* shared_qts = g_state.qts;
        constexpr uint64_t kBufPoolMid =
            kBufPoolBase + (kBufPoolEnd - kBufPoolBase) / 2;
        uint32_t iter = std::clamp<uint32_t>(prog.thread_b_iter(), 1, 100);
        int bsz = prog.ops_thread_b_size();
        std::atomic<bool> b_stop{false};

        std::thread thread_b([&]() {
            g_state.qts  = shared_qts;
            g_state.buf_alloc = kBufPoolMid;
            for (uint32_t i = 0;
                 i < iter && !b_stop.load(std::memory_order_relaxed); ++i) {
                for (int j = 0; j < bsz; ++j)
                    dispatch(prog.ops_thread_b(j));
            }
        });

        for (const auto& op : prog.ops()) {
            if (n++ >= kMaxOps) break;
            dispatch(op);
        }

        b_stop.store(true, std::memory_order_relaxed);
        thread_b.join();
    }
}

GString* proto_fuzz_virtio_gpu_cmdline(FuzzTarget* /*t*/) {
    GString* s = g_string_new(nullptr);
    /*
     * virtio-gpu-device on arm 'virt'. -m 256 leaves headroom for
     * resource backing allocations. -display none keeps it headless.
     */
    /* force-legacy=false switches virtio-mmio to spec v2 (the layout
     * this harness writes). Without it, QUEUE_READY / QUEUE_DESC_LO/HI
     * etc. are silently dropped and the vrings never get programmed. */
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 256 "
        "-global virtio-mmio.force-legacy=false "
        "-device virtio-gpu-device");
    return s;
}

size_t gpu_proto_mutator(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed) {
    qemu::fuzz::gpu::VirtioGpuProgram input;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(
        /*binary=*/false, data, size, max_size, seed, &input);
}

}  /* anonymous namespace */

extern "C" {

static void register_proto_fuzz_virtio_gpu(void) {
    static const FuzzTarget t = {
        /* .name        = */ "proto-fuzz-virtio-gpu",
        /* .description = */ "LPM-driven state-aware structured fuzzer for virtio-gpu-device on arm virt",
        /* .get_init_cmdline = */ proto_fuzz_virtio_gpu_cmdline,
        /* .pre_vm_init = */ nullptr,
        /* .pre_fuzz    = */ nullptr,
        /* .fuzz        = */ proto_fuzz_virtio_gpu_run,
        /* .crossover   = */ nullptr,
        /* .custom_mutator = */ gpu_proto_mutator,
        /* .opaque      = */ nullptr,
    };
    fuzz_add_target(&t);
}

__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_gpu(void) {
    register_module_init(register_proto_fuzz_virtio_gpu,
                         MODULE_INIT_FUZZ_TARGET);
}

}  /* extern "C" */
