/*
 * Structured (libprotobuf-mutator) fuzzer for virtio-blk-device on the
 * arm 'virt' machine.
 *
 * The proto schema in proto_fuzz_virtio_blk.proto describes the operations
 * a guest virtio-mmio driver makes: feature negotiation, virtqueue setup,
 * descriptor chains, doorbell. Each fuzz iteration deserializes a text-
 * format VirtioBlkProgram and dispatches its ops in-process against the
 * qemu-system-aarch64 machine model that LLVMFuzzerInitialize spun up.
 *
 * After the weak-symbol patch in tests/qtest/libqtest.c, the qtest_writel
 * / qtest_memwrite calls below are direct in-process MemoryRegion / DMA
 * accesses — no socket, no fork, single-threaded. Same code path a real
 * Linux virtio_mmio.c driver hits.
 */

#include <glib.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_blk.pb.h"

/*
 * Forward-declare the small slice of QEMU's ABI we use, instead of
 * #including the QEMU headers. This lets us compile this file without
 * `-I..` (the QEMU source root) on the command line, which is needed
 * because macOS APFS is case-insensitive and `<version>` from libc++
 * collides with QEMU's root `VERSION` file.
 *
 * If FuzzTarget or MODULE_INIT_FUZZ_TARGET ever changes upstream, this
 * block needs to be kept in sync.
 */
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
void     flush_events  (QTestState *s);

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

/*
 * arm 'virt' machine layout used by the cmdline below:
 *   DRAM           @ 0x40000000, -m 128 → ends at 0x48000000
 *   virtio-mmio[0] @ 0x0a000000  (size 0x200) — first attached virtio device
 */
/* arm-virt fills its 32 virtio-mmio slots from the highest address
 * downwards, so a single `-device virtio-blk-device` lands at slot 31
 * (0x0a003e00), not slot 0. */
constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;

/* Non-RAM MMIO target for DMA reentrancy / bounce-buffer testing.
 * PL011 UART @ 0x09000000 on aarch64 virt — always present, safe to
 * read/write, not directly accessible RAM → forces address_space_map()
 * through the bounce-buffer path and triggers MMIO read/write side
 * effects (the DMA reentrancy attack surface, CVE-2024-3446 class). */
constexpr uint64_t kExoticGpaBase = 0x09000000ULL;
constexpr uint32_t kExoticGpaSize = 0x1000;

/* virtio-mmio register offsets (modern, version 2) */
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

/* virtio device-status bits */
constexpr uint32_t kStatusAck         = 0x01;
constexpr uint32_t kStatusDriver      = 0x02;
constexpr uint32_t kStatusDriverOk    = 0x04;
constexpr uint32_t kStatusFeaturesOk  = 0x08;

/* VRING descriptor flags */
constexpr uint16_t kDescNext  = 0x1;
constexpr uint16_t kDescWrite = 0x2;

/*
 * Reserved DRAM region for descriptor tables, rings, and request buffers.
 * Sits at the high end of the 128 MB DRAM so QEMU's machine init won't
 * touch it. Layout per virtqueue:
 *     desc table : kVqDescSize  (4 KB → 256 × 16 B descriptors)
 *     avail ring : kVqAvailSize (4 KB)
 *     used ring  : kVqUsedSize  (4 KB)
 */
constexpr uint64_t kPoolBase    = 0x47000000ULL;
constexpr uint32_t kMaxQueues   = 4;
constexpr uint32_t kVqDescSize  = 0x1000;
constexpr uint32_t kVqAvailSize = 0x1000;
constexpr uint32_t kVqUsedSize  = 0x1000;
constexpr uint32_t kVqStride    = kVqDescSize + kVqAvailSize + kVqUsedSize;
constexpr uint64_t kBufPoolBase = kPoolBase + kMaxQueues * kVqStride;
constexpr uint64_t kBufPoolEnd  = 0x47F00000ULL;

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

struct State {
    QTestState* qts = nullptr;
    VqState vqs[kMaxQueues] = {};
    uint64_t buf_alloc = kBufPoolBase;
    std::unordered_map<uint32_t, Buf> bufs;
};

/*
 * Per-iteration harness state. thread_local is kept so we can switch
 * to a real-pthread mode later without touching the rest of the file,
 * but the current dispatch is single-threaded and deterministic: each
 * primary op from `ops` is followed by `thread_b_iter` operations
 * from `ops_thread_b`, cycling. Determinism is required for libFuzzer
 * crash files to replay. The bug class this finds is stale-descriptor
 * / out-of-order-mutation: a memory write or queue manipulation lands
 * in between two primary ops in a way that the device handler then
 * misinterprets when it later reads guest state.
 */
thread_local State g_state;

inline uint32_t mmio_readl(uint64_t off) {
    return qtest_readl(g_state.qts, kVirtioMmioBase + off);
}
inline void mmio_writel(uint64_t off, uint32_t v) {
    qtest_writel(g_state.qts, kVirtioMmioBase + off, v);
}

/*
 * Reset transient bookkeeping so each fuzz iteration starts from a clean,
 * deterministic state. We don't do a full qemu_system_reset() per input
 * (too slow); instead, drive the virtio device's own reset by writing 0
 * to status, then re-enter the negotiation prologue.
 */
void reset_iteration_state() {
    mmio_writel(R_STATUS, 0);
    mmio_writel(R_STATUS, kStatusAck | kStatusDriver);

    for (uint32_t i = 0; i < kMaxQueues; ++i) {
        g_state.vqs[i] = VqState{
            .desc_gpa  = kPoolBase + i * kVqStride,
            .avail_gpa = kPoolBase + i * kVqStride + kVqDescSize,
            .used_gpa  = kPoolBase + i * kVqStride + kVqDescSize + kVqAvailSize,
            .size = 0,
            .next_desc_idx = 0,
            .next_avail_idx = 0,
        };
    }
    g_state.buf_alloc = kBufPoolBase;
    g_state.bufs.clear();
}

void op_vq_setup(uint32_t vq_idx, uint32_t requested_size) {
    if (vq_idx >= kMaxQueues) return;
    auto& q = g_state.vqs[vq_idx];

    mmio_writel(R_QUEUE_SEL, vq_idx);
    uint32_t max = mmio_readl(R_QUEUE_NUM_MAX);
    if (max == 0) return;

    uint32_t size = requested_size ? requested_size : 64;
    if (size > max) size = max;
    /* Round down to power of two; virtio requires power-of-two sizes. */
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

void op_guest_mem_write(uint32_t buf_id, const std::string& data) {
    /* Cap buffer size to keep the input space bounded. */
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(data.size(), 4096));
    if (g_state.buf_alloc + len + 16 > kBufPoolEnd) return;

    uint64_t gpa = g_state.buf_alloc;
    /* 16-byte align next allocation */
    g_state.buf_alloc = (g_state.buf_alloc + len + 16) & ~uint64_t{0xf};

    if (len) {
        qtest_memwrite(g_state.qts, gpa, data.data(), len);
    }
    g_state.bufs[buf_id] = Buf{gpa, len};
}

void op_vq_add_desc(uint32_t vq_idx, uint32_t buf_id,
                    uint32_t len, bool device_writable, bool chain_next,
                    uint32_t exotic_region) {
    if (vq_idx >= kMaxQueues) return;
    auto& q = g_state.vqs[vq_idx];
    if (q.size == 0) return;

    uint64_t addr;
    uint32_t dlen;
    if (exotic_region != 0) {
        /* Rotate through 4 MMIO regions to exercise recursive-MMIO reentrancy
         * (BH Asia 2022: "Recursive MMIO Flaws in QEMU/KVM").
         * All addresses verified against hw/arm/virt.c base_memmap[]:
         *
         *   1 = PL011 UART0  0x09000000..0x09000fff  (size 0x1000)
         *       virt.c: [VIRT_UART0] = { 0x09000000, 0x00001000 }
         *   2 = own virtio-mmio (DMA Reflection)  kVirtioMmioBase..+0x1ff
         *       virt.c: [VIRT_MMIO] = { 0x0a000000, 0x200 } × 32 slots;
         *               our device is slot 31 = 0x0a003e00
         *   3 = GIC distributor  0x08000000..0x0800ffff  (size 0x10000)
         *       virt.c: [VIRT_GIC_DIST] = { 0x08000000, 0x00010000 }
         *   4 = virtio-mmio bus slots 0..30  0x0a000000..0x0a003dff  (DMA Refraction)
         *       virt.c: [VIRT_MMIO] = { 0x0a000000, 0x200 } × 32 slots
         *
         * Region 2 virtio-mmio register map from
         * include/standard-headers/linux/virtio_mmio.h
         * (gpa = kVirtioMmioBase + (buf_id % 128) * 4):
         *   buf_id=0  → 0x000  VIRTIO_MMIO_MAGIC_VALUE       (R)
         *   buf_id=17 → 0x044  VIRTIO_MMIO_QUEUE_READY       (RW) ← write 0 → disable queue mid-flight
         *   buf_id=20 → 0x050  VIRTIO_MMIO_QUEUE_NOTIFY      (W)  ← kick → BH → reentrancy
         *   buf_id=25 → 0x064  VIRTIO_MMIO_INTERRUPT_ACK     (W)  ← clears interrupt mid-processing
         *   buf_id=28 → 0x070  VIRTIO_MMIO_STATUS            (RW) ← write 0 → virtio_mmio_soft_reset → UAF!
         *   buf_id=32 → 0x080  VIRTIO_MMIO_QUEUE_DESC_LOW    (W)  ← corrupts descriptor table pointer
         *   buf_id=33 → 0x084  VIRTIO_MMIO_QUEUE_DESC_HIGH   (W)  ← corrupts descriptor table pointer (hi)
         *   buf_id=36 → 0x090  VIRTIO_MMIO_QUEUE_AVAIL_LOW   (W)  ← corrupts avail ring (driver area)
         *   buf_id=40 → 0x0a0  VIRTIO_MMIO_QUEUE_USED_LOW    (W)  ← corrupts used ring (device area)
         */
        const uint64_t bases[4] = {
            0x09000000ULL, kVirtioMmioBase, 0x08000000ULL, 0x0a000000ULL };
        const uint32_t sizes[4] = { 0x1000, 0x200, 0x10000, 0x3e00 };
        uint32_t ri = (exotic_region - 1) % 4;
        addr = bases[ri] + (buf_id % (sizes[ri] / 4)) * 4;
        dlen = std::min(len, 4u);
    } else {
        auto it = g_state.bufs.find(buf_id);
        if (it == g_state.bufs.end()) return;
        const Buf& buf = it->second;
        addr = buf.gpa;
        dlen = std::min(len, buf.len);
    }

    uint32_t idx = q.next_desc_idx % q.size;
    uint16_t flags = 0;
    if (device_writable) flags |= kDescWrite;
    if (chain_next)      flags |= kDescNext;

    /* Encode a 16-byte split-virtqueue descriptor:
     *   le64 addr, le32 len, le16 flags, le16 next */
    uint8_t desc[16];
    uint16_t next = static_cast<uint16_t>((idx + 1) % q.size);
    std::memcpy(desc + 0,  &addr,  8);
    std::memcpy(desc + 8,  &dlen,  4);
    std::memcpy(desc + 12, &flags, 2);
    std::memcpy(desc + 14, &next,  2);
    qtest_memwrite(g_state.qts, q.desc_gpa + idx * 16, desc, 16);

    if (!chain_next) {
        /* Tail of a chain: append head index to the avail ring and bump idx.
         * avail layout: u16 flags, u16 idx, u16 ring[size], u16 used_event. */
        uint16_t head = static_cast<uint16_t>(q.next_desc_idx);
        uint64_t ring_slot =
            q.avail_gpa + 4 + (q.next_avail_idx % q.size) * 2;
        qtest_memwrite(g_state.qts, ring_slot, &head, 2);
        q.next_avail_idx++;
        uint16_t aidx = static_cast<uint16_t>(q.next_avail_idx);
        qtest_memwrite(g_state.qts, q.avail_gpa + 2, &aidx, 2);
    }
    q.next_desc_idx++;
}

void op_vq_kick(uint32_t vq_idx) {
    mmio_writel(R_QUEUE_NOTIFY, vq_idx);
    flush_events(g_state.qts);
}

void op_vq_wait_used(uint32_t /*vq_idx*/) {
    /* qtest accelerator runs the device synchronously; we just give bottom
     * halves a chance to fire and acknowledge any pending interrupts. */
    flush_events(g_state.qts);
    uint32_t st = mmio_readl(R_INT_STATUS);
    if (st) mmio_writel(R_INT_ACK, st);
}

/*
 * MmioCorrupt -- write to an arbitrary virtio-mmio register offset.
 * Unlike typed ops that only touch well-formed registers, this can
 * hit reserved / unimplemented offsets, RO registers, etc. Common
 * decoder-bug territory.
 */
void op_mmio_corrupt(const qemu::fuzz::blk::MmioCorrupt& m) {
    uint32_t off  = m.offset() & 0x1ff;     /* keep within MMIO window */
    uint32_t val  = m.value();
    uint32_t size = m.size();
    uint64_t addr = kVirtioMmioBase + off;
    if      (size == 1) qtest_writeb(g_state.qts, addr, val & 0xff);
    else if (size == 2) qtest_writew(g_state.qts, addr, val & 0xffff);
    else                qtest_writel(g_state.qts, addr, val);
}

/*
 * MemwriteAbsolute -- write to a fixed GPA, no buf_id table involved.
 * Used by thread B in multi-thread mode to hammer GPAs that thread A
 * has placed descriptors at, racing against the device's reads. The
 * GPA is clamped into our reserved DRAM region so it can't punch into
 * MMIO areas (those are BQL-serialized so wouldn't race anyway).
 */
void op_memwrite_absolute(const qemu::fuzz::blk::MemwriteAbsolute& m) {
    const std::string& d = m.data();
    if (d.empty()) return;
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(d.size(), 4096));

    uint64_t gpa = m.gpa();
    /* Constrain into our reserved pool so we don't trample machine-init
     * regions or MMIO. Compare against (kBufPoolEnd - len) instead of
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

void dispatch(const qemu::fuzz::blk::VirtioOp& op) {
    using qemu::fuzz::blk::VirtioOp;
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
        uint32_t sz  = op.config_read().size();
        if      (sz >= 4) (void)mmio_readl(R_CONFIG + off);
        else if (sz >= 2) (void)qtest_readw(g_state.qts,
                                            kVirtioMmioBase + R_CONFIG + off);
        else              (void)qtest_readb(g_state.qts,
                                            kVirtioMmioBase + R_CONFIG + off);
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
    case VirtioOp::kMemWriteAbsolute:
        op_memwrite_absolute(op.mem_write_absolute());
        break;
    case VirtioOp::kMmioCorrupt:
        op_mmio_corrupt(op.mmio_corrupt());
        break;
    case VirtioOp::OP_NOT_SET:
        break;
    }
}

void proto_fuzz_virtio_blk_run(QTestState* qts,
                               const unsigned char* data, size_t size) {
    g_state.qts = qts;

    qemu::fuzz::blk::VirtioBlkProgram prog;
    /* LoadProtoInput takes a base protobuf::Message*; pass our typed
     * instance (implicit upcast) and the API parses into it. */
    if (!protobuf_mutator::libfuzzer::LoadProtoInput(
            /*binary=*/false, data, size, &prog)) {
        return;
    }

    reset_iteration_state();

    /* Cap per-iteration ops so a pathological mutation can't run forever. */
    constexpr int kMaxOps = 256;
    int n = 0;

    if (prog.ops_thread_b_size() == 0) {
        /* sequential mode -- the original single-list dispatch */
        for (const auto& op : prog.ops()) {
            if (n++ >= kMaxOps) break;
            dispatch(op);
        }
    } else {
        /*
         * Concurrent mode: thread B loops through ops_thread_b while
         * thread A runs ops.  Both share QEMU's address space; the race
         * window is between thread A's VqKick (device reads descriptor /
         * buffer) and thread B's MemwriteAbsolute (mutates the same GPA).
         * qtest_memwrite is BQL-free so the two writes genuinely overlap.
         *
         * g_state is thread_local, so each thread has independent harness
         * bookkeeping.  Thread B initialises its own copy with the shared
         * QTestState* and a disjoint buffer-pool region (upper half) to
         * avoid GPA collisions with thread A's allocations.
         *
         * Crash files are non-deterministic (scheduling-dependent), but
         * libFuzzer still minimises the input size, which is sufficient
         * for triage.
         */
        QTestState* shared_qts = g_state.qts;
        constexpr uint64_t kBufPoolMid =
            kBufPoolBase + (kBufPoolEnd - kBufPoolBase) / 2;
        uint32_t iter = std::clamp<uint32_t>(prog.thread_b_iter(), 1, 100);
        int bsz = prog.ops_thread_b_size();
        std::atomic<bool> b_stop{false};

        std::thread thread_b([&]() {
            g_state.qts       = shared_qts;
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

GString* proto_fuzz_virtio_blk_cmdline(FuzzTarget* /*t*/) {
    GString* s = g_string_new(nullptr);
    /* force-legacy=false switches virtio-mmio to spec v2 (the layout
     * this harness writes). Without it, QUEUE_READY / QUEUE_DESC_LO/HI
     * etc. are silently dropped and the vrings never get programmed. */
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 128 "
        "-global virtio-mmio.force-legacy=false "
        "-device virtio-blk-device,drive=hd0 "
        "-drive if=none,id=hd0,file=null-co://,file.read-zeroes=on,format=raw");
    return s;
}

}  /* anonymous namespace */

/*
 * Per-target custom mutator: keeps mutations in proto space so the corpus
 * always parses back to a valid VirtioBlkProgram. fuzz.c routes
 * libFuzzer's LLVMFuzzerCustomMutator calls through this when the
 * proto-fuzz-virtio-blk target is selected.
 */
static size_t blk_proto_mutator(uint8_t *data, size_t size, size_t max_size,
                                unsigned int seed) {
    qemu::fuzz::blk::VirtioBlkProgram input;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(
        /*binary=*/false, data, size, max_size, seed, &input);
}

extern "C" {

static void register_proto_fuzz_virtio_blk(void) {
    static const FuzzTarget t = {
        /* .name        = */ "proto-fuzz-virtio-blk",
        /* .description = */ "LPM-driven structured fuzzer for virtio-blk-device on arm virt",
        /* .get_init_cmdline = */ proto_fuzz_virtio_blk_cmdline,
        /* .pre_vm_init = */ nullptr,
        /* .pre_fuzz    = */ nullptr,
        /* .fuzz        = */ proto_fuzz_virtio_blk_run,
        /* .crossover   = */ nullptr,
        /* .custom_mutator = */ blk_proto_mutator,
        /* .opaque      = */ nullptr,
    };
    fuzz_add_target(&t);
}

/*
 * Inline expansion of qemu/module.h's fuzz_target_init() macro. We
 * don't include that header here so we keep the C++ command line free
 * of `-I..` (the QEMU root) — see the long comment near the top of the
 * file for why.
 */
__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_blk(void) {
    register_module_init(register_proto_fuzz_virtio_blk,
                         MODULE_INIT_FUZZ_TARGET);
}

}  /* extern "C" */
