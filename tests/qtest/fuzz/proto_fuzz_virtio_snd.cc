/*
 * proto-fuzz-virtio-snd
 *
 * In-process LPM-driven structured fuzzer for QEMU's virtio-sound-device
 * on the arm-virt machine. Same overall shape as the other proto_fuzz_*
 * targets; device-specific bits handle the four-queue layout and the
 * virtio_snd_hdr-prefixed control protocol.
 */

#include <glib.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_snd.pb.h"

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

constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;
constexpr uint64_t kExoticGpaBase = 0x09000000ULL; /* PL011 UART, non-RAM MMIO */
constexpr uint32_t kExoticGpaSize = 0x1000;

enum : uint64_t {
    R_DEV_FEATURES     = 0x010, R_DEV_FEATURES_SEL = 0x014,
    R_DRV_FEATURES     = 0x020, R_DRV_FEATURES_SEL = 0x024,
    R_QUEUE_SEL        = 0x030,
    R_QUEUE_NUM_MAX    = 0x034,
    R_QUEUE_NUM        = 0x038,
    R_QUEUE_READY      = 0x044,
    R_QUEUE_NOTIFY     = 0x050,
    R_STATUS           = 0x070,
    R_QDESC_LO         = 0x080, R_QDESC_HI = 0x084,
    R_QDRV_LO          = 0x090, R_QDRV_HI  = 0x094,
    R_QDEV_LO          = 0x0a0, R_QDEV_HI  = 0x0a4,
    R_CONFIG           = 0x100,
};

constexpr uint32_t kStatusAck         = 0x01;
constexpr uint32_t kStatusDriver      = 0x02;
constexpr uint32_t kStatusDriverOk    = 0x04;
constexpr uint32_t kStatusFeaturesOk  = 0x08;

constexpr uint16_t kDescNext  = 0x0001;
constexpr uint16_t kDescWrite = 0x0002;

constexpr uint32_t kMaxQueues   = 8;
constexpr uint32_t kVqDescSize  = 0x1000;
constexpr uint32_t kVqAvailSize = 0x1000;
constexpr uint32_t kVqUsedSize  = 0x1000;
constexpr uint32_t kVqStride    = kVqDescSize + kVqAvailSize + kVqUsedSize;

constexpr uint64_t kPoolBase    = 0x47000000ULL;
constexpr uint64_t kBufPoolBase = kPoolBase + kMaxQueues * kVqStride;
constexpr uint64_t kBufPoolEnd  = 0x47F00000ULL;

/* virtio_snd opcodes */
constexpr uint32_t VIRTIO_SND_R_JACK_INFO       = 0x0001;
constexpr uint32_t VIRTIO_SND_R_JACK_REMAP      = 0x0002;
constexpr uint32_t VIRTIO_SND_R_PCM_INFO        = 0x0100;
constexpr uint32_t VIRTIO_SND_R_PCM_SET_PARAMS  = 0x0101;
constexpr uint32_t VIRTIO_SND_R_PCM_PREPARE     = 0x0102;
constexpr uint32_t VIRTIO_SND_R_PCM_RELEASE     = 0x0103;
constexpr uint32_t VIRTIO_SND_R_PCM_START       = 0x0104;
constexpr uint32_t VIRTIO_SND_R_PCM_STOP        = 0x0105;
constexpr uint32_t VIRTIO_SND_R_CHMAP_INFO      = 0x0200;

struct Buf { uint64_t gpa; uint32_t len; };
struct VqState {
    uint64_t desc_gpa, avail_gpa, used_gpa;
    uint32_t size, next_desc_idx, next_avail_idx;
};

struct GlobalState {
    QTestState* qts;
    VqState     vqs[kMaxQueues] = {};
    uint64_t    buf_alloc;
    std::unordered_map<uint32_t, Buf> bufs;
    uint32_t    synth_buf_id;
};
thread_local GlobalState g_state;

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
            kPoolBase + i * kVqStride,
            kPoolBase + i * kVqStride + kVqDescSize,
            kPoolBase + i * kVqStride + kVqDescSize + kVqAvailSize,
            0, 0, 0,
        };
    }
    g_state.buf_alloc = kBufPoolBase;
    g_state.bufs.clear();
    g_state.synth_buf_id = 0x80000000u;
}

uint32_t alloc_buf(const void* bytes, uint32_t len) {
    if (g_state.buf_alloc + len + 16 > kBufPoolEnd) return 0;
    uint64_t gpa = g_state.buf_alloc;
    g_state.buf_alloc = (g_state.buf_alloc + len + 16) & ~uint64_t{0xf};
    if (len) qtest_memwrite(g_state.qts, gpa, bytes, len);
    uint32_t id = g_state.synth_buf_id++;
    g_state.bufs[id] = Buf{gpa, len};
    return id;
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

void op_guest_mem_write(uint32_t buf_id, const std::string& data) {
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(data.size(), 4096));
    if (g_state.buf_alloc + len + 16 > kBufPoolEnd) return;
    uint64_t gpa = g_state.buf_alloc;
    g_state.buf_alloc = (g_state.buf_alloc + len + 16) & ~uint64_t{0xf};
    if (len) qtest_memwrite(g_state.qts, gpa, data.data(), len);
    g_state.bufs[buf_id] = Buf{gpa, len};
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
        uint64_t ring_slot = q.avail_gpa + 4 + (q.next_avail_idx % q.size) * 2;
        qtest_memwrite(g_state.qts, ring_slot, &hh, 2);
        q.next_avail_idx++;
        uint16_t aidx = static_cast<uint16_t>(q.next_avail_idx);
        qtest_memwrite(g_state.qts, q.avail_gpa + 2, &aidx, 2);
    }
    return head;
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
        dlen = std::max(std::min(len, 4u), 1u);
    } else {
        auto it = g_state.bufs.find(buf_id);
        if (it == g_state.bufs.end()) return;
        const Buf& buf = it->second;
        gpa  = buf.gpa;
        dlen = std::min(len, buf.len);
        if (dlen == 0) dlen = 1;
    }
    place_desc(vq_idx, gpa, dlen, device_writable, chain_next);
}

void op_mem_write_absolute(const qemu::fuzz::snd::MemwriteAbsolute& m) {
    const std::string& d = m.data();
    if (d.empty()) return;
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(d.size(), 4096));
    uint64_t gpa = m.gpa();
    if (gpa < kBufPoolBase || gpa > kBufPoolEnd - len) {
        uint64_t span = kBufPoolEnd - kBufPoolBase - len;
        if (span == 0) return;
        gpa = kBufPoolBase + (gpa % span);
    }
    qtest_memwrite(g_state.qts, gpa, d.data(), len);
}

void op_mmio_corrupt(const qemu::fuzz::snd::MmioCorrupt& m) {
    uint32_t off = m.offset() & 0x1ff;
    qtest_writel(g_state.qts, kVirtioMmioBase + off, m.value());
}

/* --- control queue helpers --------------------------------------- */

void append_le32(std::string& s, uint32_t v) {
    char b[4]; std::memcpy(b, &v, 4); s.append(b, 4);
}

/*
 * Submit a request on the control queue:
 *   [out: virtio_snd_hdr+payload] [in: response]
 * Most responses include a virtio_snd_hdr (4 bytes: status code) plus
 * an info block. 256 bytes of in-buffer covers the typed responses we
 * exercise.
 */
void submit_ctrl(uint32_t vq, uint32_t code, const std::string& payload,
                 uint32_t in_len) {
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 3 >= g_state.vqs[vq].size) return;

    std::string out;
    append_le32(out, code);
    out.append(payload);

    if (in_len < 16) in_len = 16;
    if (in_len > 4096) in_len = 4096;
    std::string in_buf(in_len, '\0');

    uint32_t out_id = alloc_buf(out.data(), out.size());
    if (!out_id) return;
    uint32_t in_id  = alloc_buf(in_buf.data(), in_buf.size());
    if (!in_id) return;

    auto& ob = g_state.bufs[out_id];
    auto& ib = g_state.bufs[in_id];
    place_desc(vq, ob.gpa, ob.len, false, true);
    place_desc(vq, ib.gpa, ib.len, true,  false);

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

void submit_snd_ctrl(const qemu::fuzz::snd::SndCtrl& c) {
    uint32_t vq = c.vq_idx() % kMaxQueues;
    if (vq != 0) vq = 0;     /* control queue */

    using S = qemu::fuzz::snd::SndCtrl;
    std::string p;

    switch (c.cmd_case()) {
    case S::kJackInfo: {
        const auto& m = c.jack_info();
        append_le32(p, m.start_id());
        append_le32(p, m.count());
        append_le32(p, 0);   /* size */
        submit_ctrl(vq, VIRTIO_SND_R_JACK_INFO, p, 256 + 32 * m.count());
        break;
    }
    case S::kJackRemap: {
        const auto& m = c.jack_remap();
        append_le32(p, 0); append_le32(p, m.jack_id());
        append_le32(p, m.association()); append_le32(p, m.sequence());
        submit_ctrl(vq, VIRTIO_SND_R_JACK_REMAP, p, 4);
        break;
    }
    case S::kPcmInfo: {
        const auto& m = c.pcm_info();
        append_le32(p, m.start_id());
        append_le32(p, m.count());
        append_le32(p, 0);
        submit_ctrl(vq, VIRTIO_SND_R_PCM_INFO, p, 256 + 64 * m.count());
        break;
    }
    case S::kPcmSetParams: {
        const auto& m = c.pcm_set_params();
        /* virtio_snd_pcm_set_params: hdr.stream_id(4) buffer_bytes(4)
         * period_bytes(4) features(4) channels(1) format(1) rate(1)
         * padding(1) */
        append_le32(p, 0); append_le32(p, m.stream_id());
        append_le32(p, m.buffer_bytes());
        append_le32(p, m.period_bytes());
        append_le32(p, m.features());
        char b[4] = {
            static_cast<char>(m.channels() & 0xff),
            static_cast<char>(m.format() & 0xff),
            static_cast<char>(m.rate() & 0xff),
            0
        };
        p.append(b, 4);
        submit_ctrl(vq, VIRTIO_SND_R_PCM_SET_PARAMS, p, 4);
        break;
    }
    case S::kPcmPrepare: {
        const auto& m = c.pcm_prepare();
        append_le32(p, 0); append_le32(p, m.stream_id());
        submit_ctrl(vq, VIRTIO_SND_R_PCM_PREPARE, p, 4);
        break;
    }
    case S::kPcmRelease: {
        const auto& m = c.pcm_release();
        append_le32(p, 0); append_le32(p, m.stream_id());
        submit_ctrl(vq, VIRTIO_SND_R_PCM_RELEASE, p, 4);
        break;
    }
    case S::kPcmStart: {
        const auto& m = c.pcm_start();
        append_le32(p, 0); append_le32(p, m.stream_id());
        submit_ctrl(vq, VIRTIO_SND_R_PCM_START, p, 4);
        break;
    }
    case S::kPcmStop: {
        const auto& m = c.pcm_stop();
        append_le32(p, 0); append_le32(p, m.stream_id());
        submit_ctrl(vq, VIRTIO_SND_R_PCM_STOP, p, 4);
        break;
    }
    case S::kChmapInfo: {
        const auto& m = c.chmap_info();
        append_le32(p, m.start_id());
        append_le32(p, m.count());
        append_le32(p, 0);
        submit_ctrl(vq, VIRTIO_SND_R_CHMAP_INFO, p, 256 + 64 * m.count());
        break;
    }
    case S::kRaw: {
        const auto& m = c.raw();
        size_t n = std::min<size_t>(m.payload().size(), 4096);
        if (n) p.append(m.payload().data(), n);
        uint32_t in_len = m.in_len() ? m.in_len() : 256;
        submit_ctrl(vq, m.code(), p, in_len);
        break;
    }
    default:
        break;
    }
}

/* --- TX/RX queue: PCM data transfers ----------------------------- */

void submit_pcm_xfer(const qemu::fuzz::snd::SndPcmXfer& x) {
    uint32_t vq = x.vq_idx() % kMaxQueues;
    if (vq != 2 && vq != 3) vq = 2;
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 4 >= g_state.vqs[vq].size) return;

    /* virtio_snd_pcm_xfer: u32 stream_id */
    std::string xfer;
    append_le32(xfer, x.stream_id());

    /* TX (vq 2): out = xfer header + samples; in = status (28 bytes). */
    /* RX (vq 3): out = xfer header;          in = status + samples. */

    if (vq == 2) {
        std::string out = xfer;
        const std::string& s = x.samples();
        size_t n = std::min<size_t>(s.size(), 4096);
        if (n) out.append(s.data(), n);

        std::string status(28, '\0');     /* virtio_snd_pcm_status */

        uint32_t out_id = alloc_buf(out.data(), out.size());
        if (!out_id) return;
        uint32_t in_id  = alloc_buf(status.data(), status.size());
        if (!in_id) return;
        auto& ob = g_state.bufs[out_id];
        auto& ib = g_state.bufs[in_id];
        place_desc(vq, ob.gpa, ob.len, false, true);
        place_desc(vq, ib.gpa, ib.len, true,  false);
    } else {
        std::string out = xfer;
        uint32_t in_len = x.in_len() ? x.in_len() : 1024;
        if (in_len > 4096) in_len = 4096;
        if (in_len < 28)   in_len = 28;
        std::string in_buf(in_len, '\0');

        uint32_t out_id = alloc_buf(out.data(), out.size());
        if (!out_id) return;
        uint32_t in_id  = alloc_buf(in_buf.data(), in_buf.size());
        if (!in_id) return;
        auto& ob = g_state.bufs[out_id];
        auto& ib = g_state.bufs[in_id];
        place_desc(vq, ob.gpa, ob.len, false, true);
        place_desc(vq, ib.gpa, ib.len, true,  false);
    }
    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/* --- dispatch ---------------------------------------------------- */

void dispatch(const qemu::fuzz::snd::VirtioOp& op) {
    using qemu::fuzz::snd::VirtioOp;
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
    case VirtioOp::kConfigRead:
        (void)mmio_readl(R_CONFIG + (op.config_read().offset() & 0xff));
        break;
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
        mmio_writel(R_QUEUE_NOTIFY, op.vq_kick().vq_idx());
        break;
    case VirtioOp::kVqWaitUsed:
        flush_events(g_state.qts);
        break;
    case VirtioOp::kReset:
        reset_iteration_state();
        break;
    case VirtioOp::kSndCtrl:
        submit_snd_ctrl(op.snd_ctrl());
        break;
    case VirtioOp::kSndPcmXfer:
        submit_pcm_xfer(op.snd_pcm_xfer());
        break;
    case VirtioOp::kMemWriteAbsolute:
        op_mem_write_absolute(op.mem_write_absolute());
        break;
    case VirtioOp::kMmioCorrupt:
        op_mmio_corrupt(op.mmio_corrupt());
        break;
    case VirtioOp::OP_NOT_SET:
        break;
    }
}

void proto_fuzz_virtio_snd_run(QTestState* qts,
                               const unsigned char* data, size_t size) {
    g_state.qts = qts;

    qemu::fuzz::snd::VirtioSndProgram prog;
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

GString* proto_fuzz_virtio_snd_cmdline(FuzzTarget* /*t*/) {
    GString* s = g_string_new(nullptr);
    /* virtio-sound-device backed by the "none" audiodev so streams can
     * "play" without touching real hardware. */
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 128 "
        "-global virtio-mmio.force-legacy=false "
        "-audiodev none,id=snd0 "
        "-device virtio-sound-device,audiodev=snd0");
    return s;
}

size_t snd_proto_mutator(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed) {
    qemu::fuzz::snd::VirtioSndProgram input;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(
        /*binary=*/false, data, size, max_size, seed, &input);
}

static void register_proto_fuzz_virtio_snd(void) {
    static const FuzzTarget t = {
        /* .name        = */ "proto-fuzz-virtio-snd",
        /* .description = */ "LPM-driven structured fuzzer for virtio-sound-device on arm virt",
        /* .get_init_cmdline = */ proto_fuzz_virtio_snd_cmdline,
        /* .pre_vm_init = */ nullptr,
        /* .pre_fuzz    = */ nullptr,
        /* .fuzz        = */ proto_fuzz_virtio_snd_run,
        /* .crossover   = */ nullptr,
        /* .custom_mutator = */ snd_proto_mutator,
        /* .opaque      = */ nullptr,
    };
    fuzz_add_target(&t);
}

}  /* anonymous namespace */

extern "C" {

__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_snd(void) {
    register_module_init(register_proto_fuzz_virtio_snd,
                         MODULE_INIT_FUZZ_TARGET);
}

}  /* extern "C" */
