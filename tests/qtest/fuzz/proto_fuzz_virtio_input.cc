/* proto-fuzz-virtio-input -- virtio-keyboard-device on arm-virt. */

#include <glib.h>
#include <algorithm>
#include <atomic>
#include <thread>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_input.pb.h"

extern "C" {
typedef struct QTestState QTestState;
uint32_t qtest_readl (QTestState *s, uint64_t addr);
void     qtest_writel(QTestState *s, uint64_t addr, uint32_t value);
void     qtest_memwrite(QTestState *s, uint64_t addr, const void *data, size_t size);
void     flush_events(QTestState *s);
typedef enum {
    MODULE_INIT_MIGRATION, MODULE_INIT_BLOCK, MODULE_INIT_OPTS,
    MODULE_INIT_QOM, MODULE_INIT_TRACE, MODULE_INIT_XEN_BACKEND,
    MODULE_INIT_LIBQOS, MODULE_INIT_FUZZ_TARGET, MODULE_INIT_MAX,
} module_init_type;
void register_module_init(void (*fn)(void), module_init_type type);
typedef struct FuzzTarget {
    const char *name; const char *description;
    GString *(*get_init_cmdline)(struct FuzzTarget *);
    void (*pre_vm_init)(void); void (*pre_fuzz)(QTestState *);
    void (*fuzz)(QTestState *, const unsigned char *, size_t);
    size_t (*crossover)(const uint8_t *, size_t, const uint8_t *, size_t,
                        uint8_t *, size_t, unsigned int);
    size_t (*custom_mutator)(uint8_t *, size_t, size_t, unsigned int);
    void *opaque;
} FuzzTarget;
void fuzz_add_target(const FuzzTarget *target);
}

namespace {
constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;
constexpr uint64_t kExoticGpaBase = 0x09000000ULL; /* PL011 UART, non-RAM MMIO */
constexpr uint32_t kExoticGpaSize = 0x1000;
enum : uint64_t {
    R_DEV_FEATURES=0x010, R_DEV_FEATURES_SEL=0x014,
    R_DRV_FEATURES=0x020, R_DRV_FEATURES_SEL=0x024,
    R_QUEUE_SEL=0x030, R_QUEUE_NUM_MAX=0x034, R_QUEUE_NUM=0x038,
    R_QUEUE_READY=0x044, R_QUEUE_NOTIFY=0x050, R_STATUS=0x070,
    R_QDESC_LO=0x080, R_QDESC_HI=0x084,
    R_QDRV_LO=0x090,  R_QDRV_HI=0x094,
    R_QDEV_LO=0x0a0,  R_QDEV_HI=0x0a4, R_CONFIG=0x100,
};
constexpr uint32_t kAck=0x01, kDriver=0x02, kFeaturesOk=0x08;
constexpr uint16_t kDescNext=0x0001, kDescWrite=0x0002;
constexpr uint32_t kMaxQueues=4;
constexpr uint32_t kVqStride=0x3000;
constexpr uint64_t kPoolBase=0x47000000ULL;
constexpr uint64_t kBufPoolBase=kPoolBase + kMaxQueues*kVqStride;
constexpr uint64_t kBufPoolEnd =0x47F00000ULL;

struct Buf { uint64_t gpa; uint32_t len; };
struct Vq { uint64_t desc_gpa, avail_gpa, used_gpa;
            uint32_t size, next_desc_idx, next_avail_idx; };
struct G { QTestState* qts; Vq vqs[kMaxQueues]={};
           uint64_t buf_alloc; std::unordered_map<uint32_t,Buf> bufs;
           uint32_t synth_buf_id; };
thread_local G g;
inline uint32_t mr(uint64_t off) { return qtest_readl(g.qts, kVirtioMmioBase+off); }
inline void     mw(uint64_t off, uint32_t v) { qtest_writel(g.qts, kVirtioMmioBase+off, v); }

void reset_iter() {
    mw(R_STATUS,0); mw(R_STATUS, kAck|kDriver);
    for (uint32_t i = 0; i < kMaxQueues; ++i)
        g.vqs[i] = Vq{ kPoolBase+i*kVqStride,
                       kPoolBase+i*kVqStride+0x1000,
                       kPoolBase+i*kVqStride+0x2000, 0,0,0 };
    g.buf_alloc = kBufPoolBase;
    g.bufs.clear();
    g.synth_buf_id = 0x80000000u;
}

uint32_t alloc_buf(const void* bytes, uint32_t len) {
    if (g.buf_alloc + len + 16 > kBufPoolEnd) return 0;
    uint64_t gpa = g.buf_alloc;
    g.buf_alloc = (g.buf_alloc + len + 16) & ~uint64_t{0xf};
    if (len) qtest_memwrite(g.qts, gpa, bytes, len);
    uint32_t id = g.synth_buf_id++;
    g.bufs[id] = Buf{gpa, len};
    return id;
}

void op_vq_setup(uint32_t vq, uint32_t req_sz) {
    if (vq >= kMaxQueues) return;
    auto& q = g.vqs[vq];
    mw(R_QUEUE_SEL, vq);
    uint32_t max = mr(R_QUEUE_NUM_MAX);
    if (max == 0) return;
    uint32_t size = req_sz ? req_sz : 64;
    if (size > max) size = max;
    while (size && (size & (size - 1))) size &= size - 1;
    if (size == 0) size = 1;
    q.size = size;
    mw(R_QUEUE_NUM, size);
    mw(R_QDESC_LO, (uint32_t)q.desc_gpa);  mw(R_QDESC_HI, (uint32_t)(q.desc_gpa>>32));
    mw(R_QDRV_LO,  (uint32_t)q.avail_gpa); mw(R_QDRV_HI,  (uint32_t)(q.avail_gpa>>32));
    mw(R_QDEV_LO,  (uint32_t)q.used_gpa);  mw(R_QDEV_HI,  (uint32_t)(q.used_gpa>>32));
    mw(R_QUEUE_READY, 1);
}

uint32_t place_desc(uint32_t vq, uint64_t addr, uint32_t len,
                    bool dw, bool chain) {
    auto& q = g.vqs[vq];
    uint32_t idx = q.next_desc_idx % q.size;
    uint16_t flags = (dw ? kDescWrite : 0) | (chain ? kDescNext : 0);
    uint8_t d[16];
    uint16_t next = (uint16_t)((idx + 1) % q.size);
    std::memcpy(d+0, &addr, 8); std::memcpy(d+8, &len, 4);
    std::memcpy(d+12, &flags, 2); std::memcpy(d+14, &next, 2);
    qtest_memwrite(g.qts, q.desc_gpa + idx*16, d, 16);
    uint32_t head = q.next_desc_idx++;
    if (!chain) {
        uint16_t hh = (uint16_t)head;
        uint64_t ring = q.avail_gpa + 4 + (q.next_avail_idx % q.size) * 2;
        qtest_memwrite(g.qts, ring, &hh, 2);
        q.next_avail_idx++;
        uint16_t aidx = (uint16_t)q.next_avail_idx;
        qtest_memwrite(g.qts, q.avail_gpa + 2, &aidx, 2);
    }
    return head;
}

void submit_status(const qemu::fuzz::input::StatusEvent& m) {
    constexpr uint32_t STATUS_VQ = 1;
    if (g.vqs[STATUS_VQ].size == 0) return;
    if (g.vqs[STATUS_VQ].next_desc_idx + 1 >= g.vqs[STATUS_VQ].size) return;
    /* virtio_input_event: type(2) code(2) value(4) */
    uint8_t b[8];
    uint16_t t = (uint16_t)m.type(), c = (uint16_t)m.code();
    uint32_t v = m.value();
    std::memcpy(b+0, &t, 2); std::memcpy(b+2, &c, 2); std::memcpy(b+4, &v, 4);
    uint32_t id = alloc_buf(b, 8);
    if (!id) return;
    auto& bb = g.bufs[id];
    place_desc(STATUS_VQ, bb.gpa, bb.len, false, false);
    mw(R_QUEUE_NOTIFY, STATUS_VQ);
    flush_events(g.qts);
}

void submit_event_buf(const qemu::fuzz::input::EventBuf& m) {
    constexpr uint32_t EVENT_VQ = 0;
    if (g.vqs[EVENT_VQ].size == 0) return;
    if (g.vqs[EVENT_VQ].next_desc_idx + 1 >= g.vqs[EVENT_VQ].size) return;
    uint32_t sz = m.size() ? m.size() : 64;
    if (sz < 8)    sz = 8;
    if (sz > 4096) sz = 4096;
    std::string buf(sz, '\0');
    uint32_t id = alloc_buf(buf.data(), sz);
    if (!id) return;
    auto& bb = g.bufs[id];
    place_desc(EVENT_VQ, bb.gpa, bb.len, true, false);
    mw(R_QUEUE_NOTIFY, EVENT_VQ);
    flush_events(g.qts);
}

void op_mem_write_absolute(const qemu::fuzz::input::MemwriteAbsolute& m) {
    const std::string& d = m.data();
    if (d.empty()) return;
    uint32_t len = (uint32_t)std::min<size_t>(d.size(), 4096);
    uint64_t gpa = m.gpa();
    if (gpa < kBufPoolBase || gpa > kBufPoolEnd - len) {
        uint64_t span = kBufPoolEnd - kBufPoolBase - len;
        if (span == 0) return;
        gpa = kBufPoolBase + (gpa % span);
    }
    qtest_memwrite(g.qts, gpa, d.data(), len);
}

void dispatch(const qemu::fuzz::input::VirtioOp& op) {
    using V = qemu::fuzz::input::VirtioOp;
    switch (op.op_case()) {
    case V::kGetFeatures:
        mw(R_DEV_FEATURES_SEL, 0); (void)mr(R_DEV_FEATURES);
        mw(R_DEV_FEATURES_SEL, 1); (void)mr(R_DEV_FEATURES); break;
    case V::kSetFeatures: {
        uint64_t f = op.set_features().features();
        mw(R_DRV_FEATURES_SEL, 0); mw(R_DRV_FEATURES, (uint32_t)f);
        mw(R_DRV_FEATURES_SEL, 1); mw(R_DRV_FEATURES, (uint32_t)(f>>32));
        mw(R_STATUS, mr(R_STATUS) | kFeaturesOk); break;
    }
    case V::kConfigRead:
        (void)mr(R_CONFIG + (op.config_read().offset() & 0xff)); break;
    case V::kConfigWrite: {
        const auto& d = op.config_write().data();
        uint32_t off = op.config_write().offset() & 0xff;
        for (size_t i=0; i+4<=d.size() && off+i+4<=0x100; i+=4) {
            uint32_t v; std::memcpy(&v, d.data()+i, 4);
            mw(R_CONFIG + off + i, v);
        }
        break;
    }
    case V::kVqSelect: mw(R_QUEUE_SEL, op.vq_select().vq_idx() & 0xff); break;
    case V::kVqSetup: op_vq_setup(op.vq_setup().vq_idx(), op.vq_setup().size()); break;
    case V::kSetStatus: {
        uint32_t b = op.set_status().bits();
        if (b == 0) mw(R_STATUS, 0); else mw(R_STATUS, mr(R_STATUS) | b);
        break;
    }
    case V::kGuestMemWrite: {
        const auto& mm = op.guest_mem_write();
        uint32_t len = (uint32_t)std::min<size_t>(mm.data().size(), 4096);
        if (g.buf_alloc + len + 16 > kBufPoolEnd) break;
        uint64_t gpa = g.buf_alloc;
        g.buf_alloc = (g.buf_alloc + len + 16) & ~uint64_t{0xf};
        if (len) qtest_memwrite(g.qts, gpa, mm.data().data(), len);
        g.bufs[mm.buf_id()] = Buf{gpa, len};
        break;
    }
    case V::kVqAddDesc: {
        const auto& d = op.vq_add_desc();
        if (d.vq_idx() >= kMaxQueues) break;
        if (g.vqs[d.vq_idx()].size == 0) break;
        uint64_t gpa; uint32_t dl;
        if (d.exotic_region() != 0) {
            const uint64_t bases[4] = {
                0x09000000ULL, kVirtioMmioBase, 0x08000000ULL, 0x0a000000ULL };
            const uint32_t sizes[4] = { 0x1000, 0x200, 0x10000, 0x3e00 };
            uint32_t ri = (d.exotic_region() - 1) % 4;
            gpa = bases[ri] + (d.buf_id() % (sizes[ri] / 4)) * 4;
            dl = std::max<uint32_t>(std::min<uint32_t>(d.len(), 4u), 1u);
        } else {
            auto it = g.bufs.find(d.buf_id());
            if (it == g.bufs.end()) break;
            gpa = it->second.gpa;
            dl = std::min<uint32_t>(d.len(), it->second.len);
            if (!dl) dl = 1;
        }
        place_desc(d.vq_idx(), gpa, dl, d.device_writable(), d.chain_next());
        break;
    }
    case V::kVqKick: mw(R_QUEUE_NOTIFY, op.vq_kick().vq_idx()); break;
    case V::kVqWaitUsed: flush_events(g.qts); break;
    case V::kReset: reset_iter(); break;
    case V::kStatusEvent: submit_status(op.status_event()); break;
    case V::kEventBuf: submit_event_buf(op.event_buf()); break;
    case V::kMemWriteAbsolute: op_mem_write_absolute(op.mem_write_absolute()); break;
    case V::kMmioCorrupt: {
        const auto& m = op.mmio_corrupt();
        qtest_writel(g.qts, kVirtioMmioBase + (m.offset() & 0x1ff), m.value());
        break;
    }
    case V::OP_NOT_SET: break;
    }
}

void run(QTestState* qts, const unsigned char* data, size_t size) {
    g.qts = qts;
    qemu::fuzz::input::VirtioInputProgram prog;
    if (!protobuf_mutator::libfuzzer::LoadProtoInput(false, data, size, &prog))
        return;
    reset_iter();
    constexpr int kMaxOps = 256;
    int n = 0;
    if (prog.ops_thread_b_size() == 0) {
        for (const auto& op : prog.ops()) {
            if (n++ >= kMaxOps) break;
            dispatch(op);
        }
    } else {
        QTestState* shared_qts = g.qts;
        constexpr uint64_t kBufPoolMid =
            kBufPoolBase + (kBufPoolEnd - kBufPoolBase) / 2;
        uint32_t iter = std::clamp<uint32_t>(prog.thread_b_iter(), 1, 100);
        int bsz = prog.ops_thread_b_size();
        std::atomic<bool> b_stop{false};

        std::thread thread_b([&]() {
            g.qts  = shared_qts;
            g.buf_alloc = kBufPoolMid;
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

GString* cmdline(FuzzTarget*) {
    GString* s = g_string_new(nullptr);
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 128 "
        "-global virtio-mmio.force-legacy=false "
        "-device virtio-keyboard-device");
    return s;
}

size_t mutator(uint8_t* d, size_t s, size_t max, unsigned int seed) {
    qemu::fuzz::input::VirtioInputProgram in;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(false, d, s, max, seed, &in);
}

static void register_target(void) {
    static const FuzzTarget t = {
        "proto-fuzz-virtio-input",
        "LPM-driven structured fuzzer for virtio-keyboard-device on arm virt",
        cmdline, nullptr, nullptr, run, nullptr, mutator, nullptr,
    };
    fuzz_add_target(&t);
}
}  /* anonymous namespace */

extern "C" {
__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_input(void) {
    register_module_init(register_target, MODULE_INIT_FUZZ_TARGET);
}
}
