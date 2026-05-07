/*
 * proto-fuzz-virtio-vsock
 *
 * In-process LPM-driven fuzzer for QEMU's vhost-vsock-device on
 * arm-virt. vhost-vsock requires /dev/vhost-vsock (Linux kernel
 * module), so this target is Linux-only at runtime; on macOS it
 * registers and links but QEMU launch fails with "vhost-vsock-device
 * not a valid device model".
 */

#include <glib.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_vsock.pb.h"

extern "C" {
typedef struct QTestState QTestState;
uint32_t qtest_readl (QTestState *s, uint64_t addr);
void     qtest_writel(QTestState *s, uint64_t addr, uint32_t value);
void     qtest_memwrite(QTestState *s, uint64_t addr,
                        const void *data, size_t size);
void     flush_events  (QTestState *s);
typedef enum {
    MODULE_INIT_MIGRATION, MODULE_INIT_BLOCK, MODULE_INIT_OPTS,
    MODULE_INIT_QOM, MODULE_INIT_TRACE, MODULE_INIT_XEN_BACKEND,
    MODULE_INIT_LIBQOS, MODULE_INIT_FUZZ_TARGET, MODULE_INIT_MAX,
} module_init_type;
void register_module_init(void (*fn)(void), module_init_type type);
typedef struct FuzzTarget {
    const char *name; const char *description;
    GString *(*get_init_cmdline)(struct FuzzTarget *);
    void (*pre_vm_init)(void);
    void (*pre_fuzz)(QTestState *);
    void (*fuzz)(QTestState *, const unsigned char *, size_t);
    size_t (*crossover)(const uint8_t *, size_t, const uint8_t *, size_t,
                        uint8_t *, size_t, unsigned int);
    size_t (*custom_mutator)(uint8_t *data, size_t size, size_t max_size,
                             unsigned int seed);
    void *opaque;
} FuzzTarget;
void fuzz_add_target(const FuzzTarget *target);
}

namespace {

constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;
enum : uint64_t {
    R_DEV_FEATURES=0x010, R_DEV_FEATURES_SEL=0x014,
    R_DRV_FEATURES=0x020, R_DRV_FEATURES_SEL=0x024,
    R_QUEUE_SEL=0x030, R_QUEUE_NUM_MAX=0x034, R_QUEUE_NUM=0x038,
    R_QUEUE_READY=0x044, R_QUEUE_NOTIFY=0x050, R_STATUS=0x070,
    R_QDESC_LO=0x080, R_QDESC_HI=0x084,
    R_QDRV_LO=0x090,  R_QDRV_HI=0x094,
    R_QDEV_LO=0x0a0,  R_QDEV_HI=0x0a4,
    R_CONFIG=0x100,
};
constexpr uint32_t kAck=0x01, kDriver=0x02, kDriverOk=0x04, kFeaturesOk=0x08;
constexpr uint16_t kDescNext=0x0001, kDescWrite=0x0002;
constexpr uint32_t kMaxQueues=8, kVqDescSize=0x1000, kVqAvailSize=0x1000;
constexpr uint32_t kVqUsedSize=0x1000;
constexpr uint32_t kVqStride = kVqDescSize + kVqAvailSize + kVqUsedSize;
constexpr uint64_t kPoolBase=0x47000000ULL;
constexpr uint64_t kBufPoolBase = kPoolBase + kMaxQueues * kVqStride;
constexpr uint64_t kBufPoolEnd  = 0x47F00000ULL;

struct Buf { uint64_t gpa; uint32_t len; };
struct Vq  { uint64_t desc_gpa, avail_gpa, used_gpa;
             uint32_t size, next_desc_idx, next_avail_idx; };

struct G { QTestState* qts; Vq vqs[kMaxQueues]={};
           uint64_t buf_alloc; std::unordered_map<uint32_t,Buf> bufs;
           uint32_t synth_buf_id; } g;

inline uint32_t mr(uint64_t off) { return qtest_readl(g.qts, kVirtioMmioBase+off); }
inline void     mw(uint64_t off, uint32_t v) { qtest_writel(g.qts, kVirtioMmioBase+off, v); }

void reset_iter() {
    mw(R_STATUS,0); mw(R_STATUS, kAck|kDriver);
    for (uint32_t i = 0; i < kMaxQueues; ++i)
        g.vqs[i] = Vq{ kPoolBase+i*kVqStride,
                       kPoolBase+i*kVqStride+kVqDescSize,
                       kPoolBase+i*kVqStride+kVqDescSize+kVqAvailSize,
                       0,0,0 };
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

uint32_t place_desc(uint32_t vq_idx, uint64_t addr, uint32_t len,
                    bool dev_writable, bool chain) {
    auto& q = g.vqs[vq_idx];
    uint32_t idx = q.next_desc_idx % q.size;
    uint16_t flags = (dev_writable ? kDescWrite : 0) | (chain ? kDescNext : 0);
    uint8_t desc[16];
    uint16_t next = (uint16_t)((idx + 1) % q.size);
    std::memcpy(desc+0,  &addr,  8);
    std::memcpy(desc+8,  &len,   4);
    std::memcpy(desc+12, &flags, 2);
    std::memcpy(desc+14, &next,  2);
    qtest_memwrite(g.qts, q.desc_gpa + idx*16, desc, 16);
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

void append_le32(std::string& s, uint32_t v) { char b[4]; std::memcpy(b,&v,4); s.append(b,4); }
void append_le64(std::string& s, uint64_t v) { char b[8]; std::memcpy(b,&v,8); s.append(b,8); }
void append_le16(std::string& s, uint16_t v) { char b[2]; std::memcpy(b,&v,2); s.append(b,2); }

/* TX (vq 1): out-only descriptor with hdr+payload */
void submit_tx(const qemu::fuzz::vsock::VsockPacket& p) {
    constexpr uint32_t TX = 1;
    if (g.vqs[TX].size == 0) return;
    if (g.vqs[TX].next_desc_idx + 1 >= g.vqs[TX].size) return;

    std::string out;
    append_le64(out, p.src_cid()); append_le64(out, p.dst_cid());
    append_le32(out, p.src_port()); append_le32(out, p.dst_port());
    append_le32(out, (uint32_t)p.payload().size());
    append_le16(out, (uint16_t)p.type());
    append_le16(out, (uint16_t)p.op());
    append_le32(out, p.flags());
    append_le32(out, p.buf_alloc());
    append_le32(out, p.fwd_cnt());

    size_t pn = std::min<size_t>(p.payload().size(), 4096);
    if (pn) out.append(p.payload().data(), pn);

    uint32_t id = alloc_buf(out.data(), (uint32_t)out.size());
    if (!id) return;
    auto& b = g.bufs[id];
    place_desc(TX, b.gpa, b.len, false, false);
    mw(R_QUEUE_NOTIFY, TX);
    flush_events(g.qts);
}

/* RX (vq 0): in-only descriptor for the device to fill */
void submit_rx_buf(const qemu::fuzz::vsock::VsockRxBuf& r) {
    constexpr uint32_t RX = 0;
    if (g.vqs[RX].size == 0) return;
    if (g.vqs[RX].next_desc_idx + 1 >= g.vqs[RX].size) return;

    uint32_t sz = r.size() ? r.size() : 1024;
    if (sz < 44)   sz = 44;
    if (sz > 4096) sz = 4096;
    std::string buf(sz, '\0');
    uint32_t id = alloc_buf(buf.data(), sz);
    if (!id) return;
    auto& b = g.bufs[id];
    place_desc(RX, b.gpa, b.len, true, false);
    mw(R_QUEUE_NOTIFY, RX);
    flush_events(g.qts);
}

void op_mem_write_absolute(const qemu::fuzz::vsock::MemwriteAbsolute& m) {
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

void dispatch(const qemu::fuzz::vsock::VirtioOp& op) {
    using V = qemu::fuzz::vsock::VirtioOp;
    switch (op.op_case()) {
    case V::kGetFeatures:
        mw(R_DEV_FEATURES_SEL, 0); (void)mr(R_DEV_FEATURES);
        mw(R_DEV_FEATURES_SEL, 1); (void)mr(R_DEV_FEATURES);
        break;
    case V::kSetFeatures: {
        uint64_t f = op.set_features().features();
        mw(R_DRV_FEATURES_SEL, 0); mw(R_DRV_FEATURES, (uint32_t)f);
        mw(R_DRV_FEATURES_SEL, 1); mw(R_DRV_FEATURES, (uint32_t)(f>>32));
        mw(R_STATUS, mr(R_STATUS) | kFeaturesOk);
        break;
    }
    case V::kConfigRead:
        (void)mr(R_CONFIG + (op.config_read().offset() & 0xff));
        break;
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
    case V::kVqSetup:  op_vq_setup(op.vq_setup().vq_idx(), op.vq_setup().size()); break;
    case V::kSetStatus: {
        uint32_t b = op.set_status().bits();
        if (b == 0) mw(R_STATUS, 0); else mw(R_STATUS, mr(R_STATUS) | b);
        break;
    }
    case V::kGuestMemWrite: {
        const auto& m = op.guest_mem_write();
        uint32_t len = (uint32_t)std::min<size_t>(m.data().size(), 4096);
        if (g.buf_alloc + len + 16 > kBufPoolEnd) break;
        uint64_t gpa = g.buf_alloc;
        g.buf_alloc = (g.buf_alloc + len + 16) & ~uint64_t{0xf};
        if (len) qtest_memwrite(g.qts, gpa, m.data().data(), len);
        g.bufs[m.buf_id()] = Buf{gpa, len};
        break;
    }
    case V::kVqAddDesc: {
        const auto& d = op.vq_add_desc();
        if (d.vq_idx() >= kMaxQueues) break;
        if (g.vqs[d.vq_idx()].size == 0) break;
        auto it = g.bufs.find(d.buf_id());
        if (it == g.bufs.end()) break;
        uint32_t dl = std::min<uint32_t>(d.len(), it->second.len);
        if (!dl) dl = 1;
        place_desc(d.vq_idx(), it->second.gpa, dl, d.device_writable(), d.chain_next());
        break;
    }
    case V::kVqKick: mw(R_QUEUE_NOTIFY, op.vq_kick().vq_idx()); break;
    case V::kVqWaitUsed: flush_events(g.qts); break;
    case V::kReset: reset_iter(); break;
    case V::kVsockTx: submit_tx(op.vsock_tx().pkt()); break;
    case V::kVsockRxBuf: submit_rx_buf(op.vsock_rx_buf()); break;
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
    qemu::fuzz::vsock::VirtioVsockProgram prog;
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
        uint32_t iter = std::clamp<uint32_t>(prog.thread_b_iter(), 1, 8);
        int bsz = prog.ops_thread_b_size(), bidx = 0;
        for (const auto& op : prog.ops()) {
            if (n++ >= kMaxOps) break;
            dispatch(op);
            for (uint32_t i = 0; i < iter; ++i) {
                if (n++ >= kMaxOps) break;
                dispatch(prog.ops_thread_b(bidx));
                bidx = (bidx + 1) % bsz;
            }
        }
    }
}

GString* cmdline(FuzzTarget*) {
    GString* s = g_string_new(nullptr);
    /* vhost-vsock requires /dev/vhost-vsock (Linux). guest-cid=3 is
     * the smallest valid value (>2). On macOS this fails at launch. */
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 128 "
        "-global virtio-mmio.force-legacy=false "
        "-device vhost-vsock-device,guest-cid=3");
    return s;
}

size_t mutator(uint8_t* d, size_t s, size_t max, unsigned int seed) {
    qemu::fuzz::vsock::VirtioVsockProgram in;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(false, d, s, max, seed, &in);
}

static void register_target(void) {
    static const FuzzTarget t = {
        "proto-fuzz-virtio-vsock",
        "LPM-driven structured fuzzer for vhost-vsock-device on arm virt (Linux only)",
        cmdline, nullptr, nullptr, run, nullptr, mutator, nullptr,
    };
    fuzz_add_target(&t);
}

}  /* anonymous namespace */

extern "C" {
__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_vsock(void) {
    register_module_init(register_target, MODULE_INIT_FUZZ_TARGET);
}
}
