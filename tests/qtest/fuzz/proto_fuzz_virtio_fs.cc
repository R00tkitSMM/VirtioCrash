/*
 * proto-fuzz-virtio-fs
 *
 * In-process LPM-driven structured fuzzer for QEMU's vhost-user-fs
 * device on the arm-virt machine.
 *
 * virtio-fs is vhost-user-only: the QEMU device just proxies to a
 * unix-domain backend (normally virtiofsd). To make this target self-
 * contained, the harness ships a *minimal mock vhost-user backend* in
 * a background thread. The mock accepts the chardev-socket connection
 * QEMU initiates, acks every vhost-user message, and stores any kick/
 * call eventfds it receives so the device's queue setup completes.
 *
 * What this exercises in QEMU itself:
 *   - virtio-mmio register decode + queue setup (same as the other
 *     proto-fuzz targets)
 *   - vhost-user message handling on the QEMU side: VHOST_USER_GET/SET_*
 *     codepaths in hw/virtio/vhost-user.c
 *   - vhost-user-fs frontend: virtio_fs_handle_vq, the slave-protocol
 *     handler, DAX window handlers (when configured)
 *   - virtqueue forwarding to the (mock) backend
 *
 * What it does NOT exercise:
 *   - actual FUSE protocol parsing (that lives in virtiofsd, not QEMU)
 *   - DAX cache-window data plane beyond what QEMU's frontend touches
 */

#include <glib.h>

#include <algorithm>
#include <atomic>
#include <thread>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <pthread.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_fs.pb.h"

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

/* ===== virtio-mmio side ===================================== */

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

void op_mem_write_absolute(const qemu::fuzz::fs::MemwriteAbsolute& m) {
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

void op_mmio_corrupt(const qemu::fuzz::fs::MmioCorrupt& m) {
    uint32_t off = m.offset() & 0x1ff;
    uint32_t val = m.value();
    qtest_writel(g_state.qts, kVirtioMmioBase + off, val);
}

/* ===== FUSE request packing ================================== */

constexpr uint32_t FUSE_LOOKUP      = 1;
constexpr uint32_t FUSE_FORGET      = 2;
constexpr uint32_t FUSE_GETATTR     = 3;
constexpr uint32_t FUSE_SETATTR     = 4;
constexpr uint32_t FUSE_MKDIR       = 9;
constexpr uint32_t FUSE_UNLINK      = 10;
constexpr uint32_t FUSE_RMDIR       = 11;
constexpr uint32_t FUSE_OPEN        = 14;
constexpr uint32_t FUSE_READ        = 15;
constexpr uint32_t FUSE_WRITE       = 16;
constexpr uint32_t FUSE_RELEASE     = 18;
constexpr uint32_t FUSE_FLUSH       = 25;
constexpr uint32_t FUSE_INIT        = 26;
constexpr uint32_t FUSE_GETXATTR    = 22;
constexpr uint32_t FUSE_SETXATTR    = 21;
constexpr uint32_t FUSE_LISTXATTR   = 23;
constexpr uint32_t FUSE_REMOVEXATTR = 24;
constexpr uint32_t FUSE_IOCTL       = 39;

void append_le32(std::string& s, uint32_t v) {
    char b[4]; std::memcpy(b, &v, 4); s.append(b, 4);
}
void append_le64(std::string& s, uint64_t v) {
    char b[8]; std::memcpy(b, &v, 8); s.append(b, 8);
}

void build_in_header(std::string& s, uint32_t opcode, uint64_t unique,
                     uint64_t nodeid, uint32_t uid, uint32_t gid,
                     uint32_t pid, uint32_t total_len) {
    /* fuse_in_header: len(4) opcode(4) unique(8) nodeid(8) uid(4) gid(4) pid(4) padding(4) */
    append_le32(s, total_len);
    append_le32(s, opcode);
    append_le64(s, unique);
    append_le64(s, nodeid);
    append_le32(s, uid);
    append_le32(s, gid);
    append_le32(s, pid);
    append_le32(s, 0);
}

/*
 * Submit a typed FUSE request as a 2-descriptor chain on the chosen
 * request queue:
 *   [out: fuse_in_header + opcode args | in: response buffer]
 */
void submit_fuse(const qemu::fuzz::fs::FuseRequest& r) {
    uint32_t vq = r.vq_idx() % kMaxQueues;
    if (vq < 2) vq = 2;                /* default to first request queue */
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 3 >= g_state.vqs[vq].size) return;

    std::string out;
    out.reserve(256);

    /* Reserve space for the in-header; we'll fix up `len` once we know
     * the total request size. */
    out.assign(40, '\0');

    uint32_t opcode = 0;
    using F = qemu::fuzz::fs::FuseRequest;
    switch (r.op_case()) {
    case F::kInit: {
        opcode = FUSE_INIT;
        const auto& m = r.init();
        append_le32(out, m.major());
        append_le32(out, m.minor());
        append_le32(out, m.max_readahead());
        append_le32(out, m.flags());
        break;
    }
    case F::kLookup: {
        opcode = FUSE_LOOKUP;
        const auto& m = r.lookup();
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        break;
    }
    case F::kGetattr: {
        opcode = FUSE_GETATTR;
        const auto& m = r.getattr();
        append_le32(out, m.getattr_flags());
        append_le32(out, 0);
        append_le64(out, m.fh());
        break;
    }
    case F::kSetattr: {
        opcode = FUSE_SETATTR;
        const auto& m = r.setattr();
        append_le32(out, m.valid());
        append_le32(out, 0);
        append_le64(out, m.fh());
        append_le64(out, m.size());
        append_le64(out, m.lock_owner());
        append_le64(out, m.atime());
        append_le64(out, m.mtime());
        append_le64(out, m.ctime());
        append_le32(out, 0);  /* atimensec */
        append_le32(out, 0);  /* mtimensec */
        append_le32(out, 0);  /* ctimensec */
        append_le32(out, m.mode());
        append_le32(out, 0);  /* unused */
        append_le32(out, m.uid());
        append_le32(out, m.gid());
        break;
    }
    case F::kOpen: {
        opcode = FUSE_OPEN;
        const auto& m = r.open();
        append_le32(out, m.flags());
        append_le32(out, m.open_flags());
        break;
    }
    case F::kRead: {
        opcode = FUSE_READ;
        const auto& m = r.read();
        append_le64(out, m.fh());
        append_le64(out, m.offset());
        append_le32(out, m.size());
        append_le32(out, m.read_flags());
        append_le64(out, m.lock_owner());
        append_le32(out, m.flags());
        append_le32(out, 0); /* padding */
        break;
    }
    case F::kWrite: {
        opcode = FUSE_WRITE;
        const auto& m = r.write();
        append_le64(out, m.fh());
        append_le64(out, m.offset());
        append_le32(out, m.size());
        append_le32(out, m.write_flags());
        append_le64(out, m.lock_owner());
        append_le32(out, m.flags());
        append_le32(out, 0);  /* padding */
        const std::string& d = m.data();
        size_t n = std::min<size_t>(d.size(), 4096);
        if (n) out.append(d.data(), n);
        break;
    }
    case F::kRelease: {
        opcode = FUSE_RELEASE;
        const auto& m = r.release();
        append_le64(out, m.fh());
        append_le32(out, m.flags());
        append_le32(out, m.release_flags());
        append_le64(out, m.lock_owner());
        break;
    }
    case F::kMkdir: {
        opcode = FUSE_MKDIR;
        const auto& m = r.mkdir();
        append_le32(out, m.mode());
        append_le32(out, m.umask());
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        break;
    }
    case F::kUnlink: {
        opcode = FUSE_UNLINK;
        const auto& m = r.unlink();
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        break;
    }
    case F::kRmdir: {
        opcode = FUSE_RMDIR;
        const auto& m = r.rmdir();
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        break;
    }
    case F::kFlush: {
        opcode = FUSE_FLUSH;
        const auto& m = r.flush();
        append_le64(out, m.fh());
        append_le32(out, m.unused());
        append_le32(out, m.padding());
        append_le64(out, m.lock_owner());
        break;
    }
    case F::kGetxattr: {
        opcode = FUSE_GETXATTR;
        const auto& m = r.getxattr();
        append_le32(out, m.size());
        append_le32(out, 0);  /* padding */
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        break;
    }
    case F::kSetxattr: {
        opcode = FUSE_SETXATTR;
        const auto& m = r.setxattr();
        const std::string& v = m.value();
        uint32_t vlen = static_cast<uint32_t>(std::min<size_t>(v.size(), 4096));
        append_le32(out, vlen);
        append_le32(out, m.flags());
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        out.append(v.data(), vlen);
        break;
    }
    case F::kListxattr: {
        opcode = FUSE_LISTXATTR;
        const auto& m = r.listxattr();
        append_le32(out, m.size());
        append_le32(out, 0); /* padding */
        break;
    }
    case F::kRemovexattr: {
        opcode = FUSE_REMOVEXATTR;
        const auto& m = r.removexattr();
        size_t n = std::min<size_t>(m.name().size(), 256);
        out.append(m.name().data(), n);
        if (n == 0 || m.name()[n - 1] != '\0') out.push_back('\0');
        break;
    }
    case F::kIoctl: {
        opcode = FUSE_IOCTL;
        const auto& m = r.ioctl();
        append_le64(out, m.fh());
        append_le32(out, m.flags());
        append_le32(out, m.cmd());
        append_le64(out, m.arg());
        append_le32(out, m.in_size());
        append_le32(out, m.out_size());
        const std::string& d = m.in_data();
        size_t n = std::min<size_t>(d.size(), 4096);
        if (n) out.append(d.data(), n);
        break;
    }
    case F::kRaw: {
        opcode = r.raw().opcode();
        const std::string& p = r.raw().payload();
        size_t n = std::min<size_t>(p.size(), 4096);
        if (n) out.append(p.data(), n);
        break;
    }
    default:
        opcode = FUSE_INIT;
        append_le32(out, 7);
        append_le32(out, 38);
        append_le32(out, 0);
        append_le32(out, 0);
        break;
    }

    /* Fix up fuse_in_header.len now that we know the total size */
    uint32_t total_len = static_cast<uint32_t>(out.size());
    std::string hdr;
    build_in_header(hdr, opcode, r.unique(), r.nodeid(),
                    r.uid(), r.gid(), r.pid(), total_len);
    std::memcpy(&out[0], hdr.data(), 40);

    /* Response buffer (in). Default 1024, capped 4096. */
    uint32_t in_len = r.in_buf_size() ? r.in_buf_size() : 1024;
    if (in_len > 4096) in_len = 4096;
    if (in_len < 16)   in_len = 16;
    std::string in_buf(in_len, '\0');

    /* Place the chain. */
    uint32_t out_id = alloc_buf(out.data(), out.size());
    if (!out_id) return;
    uint32_t in_id  = alloc_buf(in_buf.data(), in_buf.size());
    if (!in_id) return;
    auto& ob = g_state.bufs[out_id];
    auto& ib = g_state.bufs[in_id];
    place_desc(vq, ob.gpa, ob.len, /*writable=*/false, /*chain=*/true);
    place_desc(vq, ib.gpa, ib.len, /*writable=*/true,  /*chain=*/false);

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/*
 * High-priority queue (vq 0) op: FORGET / BATCH_FORGET / INTERRUPT.
 * One out-only descriptor.
 */
void submit_fuse_hp(const qemu::fuzz::fs::FuseHpReq& m) {
    uint32_t vq = 0;
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 1 >= g_state.vqs[vq].size) return;

    std::string out(40, '\0');
    const std::string& p = m.payload();
    size_t n = std::min<size_t>(p.size(), 256);
    if (n) out.append(p.data(), n);

    std::string hdr;
    build_in_header(hdr, m.opcode(), m.unique(), m.nodeid(),
                    0, 0, 0, static_cast<uint32_t>(out.size()));
    std::memcpy(&out[0], hdr.data(), 40);

    uint32_t out_id = alloc_buf(out.data(), out.size());
    if (!out_id) return;
    auto& ob = g_state.bufs[out_id];
    place_desc(vq, ob.gpa, ob.len, false, false);
    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/* ===== mock vhost-user-fs backend ============================ */

/*
 * Minimal vhost-user backend: accept the chardev-socket connection
 * QEMU initiates, ack every message, return zeroed values where a
 * reply payload is required. Just enough to let the QEMU device
 * complete vhost-user negotiation and reach DRIVER_OK.
 */

constexpr uint32_t VHOST_USER_GET_FEATURES         = 1;
constexpr uint32_t VHOST_USER_SET_FEATURES         = 2;
constexpr uint32_t VHOST_USER_SET_OWNER            = 3;
constexpr uint32_t VHOST_USER_RESET_OWNER          = 4;
constexpr uint32_t VHOST_USER_SET_MEM_TABLE        = 5;
constexpr uint32_t VHOST_USER_SET_LOG_BASE         = 6;
constexpr uint32_t VHOST_USER_SET_LOG_FD           = 7;
constexpr uint32_t VHOST_USER_SET_VRING_NUM        = 8;
constexpr uint32_t VHOST_USER_SET_VRING_ADDR       = 9;
constexpr uint32_t VHOST_USER_SET_VRING_BASE       = 10;
constexpr uint32_t VHOST_USER_GET_VRING_BASE       = 11;
constexpr uint32_t VHOST_USER_SET_VRING_KICK       = 12;
constexpr uint32_t VHOST_USER_SET_VRING_CALL       = 13;
constexpr uint32_t VHOST_USER_SET_VRING_ERR        = 14;
constexpr uint32_t VHOST_USER_GET_PROTOCOL_FEATURES = 15;
constexpr uint32_t VHOST_USER_SET_PROTOCOL_FEATURES = 16;
constexpr uint32_t VHOST_USER_GET_QUEUE_NUM        = 17;
constexpr uint32_t VHOST_USER_SET_VRING_ENABLE     = 18;

constexpr uint32_t VHOST_USER_FLAG_REPLY = 0x4;
constexpr uint32_t VHOST_USER_VERSION    = 0x1;

/*
 * Features we advertise. We don't enable any vhost-user-fs-specific
 * features beyond the base virtio set: the harness drives the device
 * directly, it doesn't need a real filesystem behind it.
 */
constexpr uint64_t kBackendFeatures         = (1ULL << 32);   // VIRTIO_F_VERSION_1
constexpr uint64_t kBackendProtocolFeatures = 0;
constexpr uint64_t kBackendQueueNum         = 1024;

struct VhostUserHdr {
    uint32_t request;
    uint32_t flags;
    uint32_t size;
} __attribute__((packed));

std::atomic<int>     g_backend_listen_fd{-1};
std::atomic<int>     g_backend_client_fd{-1};
std::atomic<bool>    g_backend_run{true};
pthread_t            g_backend_thread;
char                 g_backend_path[256] = {0};

ssize_t recv_all(int fd, void* buf, size_t n) {
    char* p = static_cast<char*>(buf);
    size_t got = 0;
    while (got < n) {
        ssize_t r = ::recv(fd, p + got, n - got, 0);
        if (r <= 0) return r;
        got += r;
    }
    return got;
}

bool send_reply(int fd, uint32_t request, const void* payload, uint32_t size) {
    VhostUserHdr h{};
    h.request = request;
    h.flags   = VHOST_USER_VERSION | VHOST_USER_FLAG_REPLY;
    h.size    = size;
    iovec iov[2];
    iov[0].iov_base = &h;
    iov[0].iov_len  = sizeof(h);
    iov[1].iov_base = const_cast<void*>(payload);
    iov[1].iov_len  = size;
    msghdr m{};
    m.msg_iov    = iov;
    m.msg_iovlen = size ? 2 : 1;
    return ::sendmsg(fd, &m, 0) > 0;
}

/* Drain any fds passed via SCM_RIGHTS so we don't leak them. */
void close_passed_fds(msghdr* m) {
    for (cmsghdr* c = CMSG_FIRSTHDR(m); c; c = CMSG_NXTHDR(m, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
        int n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int* fds = reinterpret_cast<int*>(CMSG_DATA(c));
        for (int i = 0; i < n; i++) ::close(fds[i]);
    }
}

void* backend_main(void* /*arg*/) {
    int lfd = g_backend_listen_fd.load();
    if (lfd < 0) return nullptr;

    while (g_backend_run.load()) {
        int cfd = ::accept(lfd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            return nullptr;
        }
        g_backend_client_fd.store(cfd);

        for (;;) {
            VhostUserHdr h;
            char ctrl[CMSG_SPACE(sizeof(int) * 16)] = {0};
            iovec iov{};
            iov.iov_base = &h;
            iov.iov_len  = sizeof(h);
            msghdr mh{};
            mh.msg_iov     = &iov;
            mh.msg_iovlen  = 1;
            mh.msg_control = ctrl;
            mh.msg_controllen = sizeof(ctrl);

            ssize_t n = ::recvmsg(cfd, &mh, 0);
            if (n <= 0) break;
            close_passed_fds(&mh);
            if (n != sizeof(h)) break;

            char payload[4096];
            uint32_t sz = h.size;
            if (sz > sizeof(payload)) sz = sizeof(payload);
            if (sz) {
                msghdr pm{};
                iovec piov{};
                piov.iov_base = payload;
                piov.iov_len  = sz;
                pm.msg_iov    = &piov;
                pm.msg_iovlen = 1;
                pm.msg_control = ctrl;
                pm.msg_controllen = sizeof(ctrl);
                ssize_t pn = ::recvmsg(cfd, &pm, 0);
                close_passed_fds(&pm);
                if (pn <= 0) break;
            }

            switch (h.request) {
            case VHOST_USER_GET_FEATURES: {
                send_reply(cfd, h.request, &kBackendFeatures, 8);
                break;
            }
            case VHOST_USER_GET_PROTOCOL_FEATURES: {
                send_reply(cfd, h.request, &kBackendProtocolFeatures, 8);
                break;
            }
            case VHOST_USER_GET_QUEUE_NUM: {
                send_reply(cfd, h.request, &kBackendQueueNum, 8);
                break;
            }
            case VHOST_USER_GET_VRING_BASE: {
                /* Reply with vring_state (idx, num=0). Layout matches
                 * what was sent in the request. */
                struct { uint32_t idx, num; } reply{};
                if (sz >= sizeof(reply)) std::memcpy(&reply, payload, sizeof(reply));
                reply.num = 0;
                send_reply(cfd, h.request, &reply, sizeof(reply));
                break;
            }
            default:
                /* SET_*, RESET_OWNER, SET_OWNER, etc. -- ack only when
                 * the request flagged need-reply. We don't track
                 * REPLY_ACK protocol feature so just always ack on a
                 * conservative subset. */
                if (h.request == VHOST_USER_SET_FEATURES ||
                    h.request == VHOST_USER_SET_PROTOCOL_FEATURES ||
                    h.request == VHOST_USER_SET_OWNER ||
                    h.request == VHOST_USER_SET_MEM_TABLE ||
                    h.request == VHOST_USER_SET_VRING_NUM ||
                    h.request == VHOST_USER_SET_VRING_ADDR ||
                    h.request == VHOST_USER_SET_VRING_BASE ||
                    h.request == VHOST_USER_SET_VRING_KICK ||
                    h.request == VHOST_USER_SET_VRING_CALL ||
                    h.request == VHOST_USER_SET_VRING_ERR ||
                    h.request == VHOST_USER_SET_VRING_ENABLE ||
                    h.request == VHOST_USER_SET_LOG_BASE ||
                    h.request == VHOST_USER_SET_LOG_FD ||
                    h.request == VHOST_USER_RESET_OWNER) {
                    /* No reply unless REPLY_ACK is on (which we don't
                     * advertise). Just continue. */
                }
                break;
            }
        }
        ::close(cfd);
        g_backend_client_fd.store(-1);
    }
    return nullptr;
}

void start_mock_backend() {
    /* Build a unique unix socket path under /tmp. */
    snprintf(g_backend_path, sizeof(g_backend_path),
             "/tmp/vhost-fs-mock-%d-%ld",
             (int)getpid(), (long)std::time(nullptr));
    ::unlink(g_backend_path);

    int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, g_backend_path, sizeof(addr.sun_path) - 1);
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(s); return;
    }
    if (::listen(s, 1) < 0) {
        ::close(s); ::unlink(g_backend_path); return;
    }
    g_backend_listen_fd.store(s);
    pthread_create(&g_backend_thread, nullptr, backend_main, nullptr);
}

/* ===== fuzz target plumbing ================================== */

void proto_fuzz_virtio_fs_pre_vm_init(void) {
    start_mock_backend();
}

void dispatch(const qemu::fuzz::fs::VirtioOp& op) {
    using qemu::fuzz::fs::VirtioOp;
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
    case VirtioOp::kFuseRequest:
        submit_fuse(op.fuse_request());
        break;
    case VirtioOp::kFuseHpReq:
        submit_fuse_hp(op.fuse_hp_req());
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

void proto_fuzz_virtio_fs_run(QTestState* qts,
                              const unsigned char* data, size_t size) {
    g_state.qts = qts;

    qemu::fuzz::fs::VirtioFsProgram prog;
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

GString* proto_fuzz_virtio_fs_cmdline(FuzzTarget* /*t*/) {
    GString* s = g_string_new(nullptr);
    /* Use the mock-backend socket path the harness set up in pre_vm_init.
     * Falls back to /dev/null if pre_vm_init didn't run (which would
     * cause vhost-user setup to fail; better than a path collision). */
    const char* path = g_backend_path[0] ? g_backend_path : "/dev/null";
    g_string_printf(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 256 "
        "-global virtio-mmio.force-legacy=false "
        "-chardev socket,id=vhostfs0,path=%s "
        "-device vhost-user-fs-device,chardev=vhostfs0,tag=fuzz",
        path);
    return s;
}

size_t fs_proto_mutator(uint8_t* data, size_t size, size_t max_size,
                        unsigned int seed) {
    qemu::fuzz::fs::VirtioFsProgram input;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(
        /*binary=*/false, data, size, max_size, seed, &input);
}

static void register_proto_fuzz_virtio_fs(void) {
    static const FuzzTarget t = {
        /* .name        = */ "proto-fuzz-virtio-fs",
        /* .description = */ "LPM-driven structured fuzzer for vhost-user-fs-device on arm virt (with in-process mock backend)",
        /* .get_init_cmdline = */ proto_fuzz_virtio_fs_cmdline,
        /* .pre_vm_init = */ proto_fuzz_virtio_fs_pre_vm_init,
        /* .pre_fuzz    = */ nullptr,
        /* .fuzz        = */ proto_fuzz_virtio_fs_run,
        /* .crossover   = */ nullptr,
        /* .custom_mutator = */ fs_proto_mutator,
        /* .opaque      = */ nullptr,
    };
    fuzz_add_target(&t);
}

}  /* anonymous namespace */

extern "C" {

__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_fs(void) {
    register_module_init(register_proto_fuzz_virtio_fs,
                         MODULE_INIT_FUZZ_TARGET);
}

}  /* extern "C" */
