/*
 * proto-fuzz-virtio-scsi
 *
 * In-process LPM-driven structured fuzzer for QEMU's virtio-scsi-device
 * on the arm-virt machine. Mirrors the architecture of proto_fuzz_virtio_*
 * (in-process qtest, virtio-mmio v2, slot-keyed device state).
 *
 * Hooked up to a single virtio-scsi-pci-... no, we use virtio-scsi-device
 * on virtio-mmio. One target (id=0), with a single LUN backed by
 * file.read-zeroes=on so reads always succeed and writes are no-ops.
 */

#include <glib.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_scsi.pb.h"

/*
 * Forward-declare the slice of QEMU's ABI we use, instead of including
 * QEMU headers. Same trick as the other proto_fuzz_* harnesses: keeps
 * `-I..` (the QEMU source root) off the C++ command line and so avoids
 * the macOS APFS case-insensitive `<version>` vs root `VERSION`
 * collision.
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

/* arm-virt fills its 32 virtio-mmio slots from the high address down,
 * so a single -device virtio-scsi-device lands at slot 31. */
constexpr uint64_t kVirtioMmioBase = 0x0a003e00ULL;

enum : uint64_t {
    R_MAGIC            = 0x000,
    R_VERSION          = 0x004,
    R_DEVICE_ID        = 0x008,
    R_DEV_FEATURES     = 0x010,
    R_DEV_FEATURES_SEL = 0x014,
    R_DRV_FEATURES     = 0x020,
    R_DRV_FEATURES_SEL = 0x024,
    R_QUEUE_SEL        = 0x030,
    R_QUEUE_NUM_MAX    = 0x034,
    R_QUEUE_NUM        = 0x038,
    R_QUEUE_READY      = 0x044,
    R_QUEUE_NOTIFY     = 0x050,
    R_INTERRUPT_STATUS = 0x060,
    R_INTERRUPT_ACK    = 0x064,
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

constexpr uint32_t kMaxQueues   = 8;     // ctrl + event + up to 6 request queues
constexpr uint32_t kVqDescSize  = 0x1000;
constexpr uint32_t kVqAvailSize = 0x1000;
constexpr uint32_t kVqUsedSize  = 0x1000;
constexpr uint32_t kVqStride    = kVqDescSize + kVqAvailSize + kVqUsedSize;

constexpr uint64_t kPoolBase    = 0x47000000ULL;
constexpr uint64_t kBufPoolBase = kPoolBase + kMaxQueues * kVqStride;
constexpr uint64_t kBufPoolEnd  = 0x47F00000ULL;

/* virtio-scsi default sizes (changeable via config space, not done here) */
constexpr uint32_t kCdbSize   = 32;
constexpr uint32_t kSenseSize = 96;

struct Buf {
    uint64_t gpa;
    uint32_t len;
};

struct VqState {
    uint64_t desc_gpa;
    uint64_t avail_gpa;
    uint64_t used_gpa;
    uint32_t size;
    uint32_t next_desc_idx;
    uint32_t next_avail_idx;
};

struct GlobalState {
    QTestState* qts;
    VqState     vqs[kMaxQueues] = {};
    uint64_t    buf_alloc;
    std::unordered_map<uint32_t, Buf> bufs;
    uint32_t    synth_buf_id;
} g_state;

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
                    bool device_writable, bool chain_next) {
    if (vq_idx >= kMaxQueues) return;
    if (g_state.vqs[vq_idx].size == 0) return;
    auto it = g_state.bufs.find(buf_id);
    if (it == g_state.bufs.end()) return;
    const Buf& buf = it->second;
    uint32_t dlen = std::min(len, buf.len);
    if (dlen == 0) dlen = 1;
    place_desc(vq_idx, buf.gpa, dlen, device_writable, chain_next);
}

void op_vq_kick(uint32_t vq_idx) {
    mmio_writel(R_QUEUE_NOTIFY, vq_idx);
}

void op_vq_wait_used(uint32_t vq_idx) {
    /* simple drain: process pending events for a few iterations */
    (void)vq_idx;
    flush_events(g_state.qts);
}

void op_mem_write_absolute(const qemu::fuzz::scsi::MemwriteAbsolute& m) {
    const std::string& d = m.data();
    if (d.empty()) return;
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(d.size(), 4096));
    uint64_t gpa = m.gpa();
    /* Compare against (kBufPoolEnd - len), not (gpa + len), to avoid
     * uint64 overflow letting writes escape into low MMIO. */
    if (gpa < kBufPoolBase || gpa > kBufPoolEnd - len) {
        uint64_t span = kBufPoolEnd - kBufPoolBase - len;
        if (span == 0) return;
        gpa = kBufPoolBase + (gpa % span);
    }
    qtest_memwrite(g_state.qts, gpa, d.data(), len);
}

void op_mmio_corrupt(const qemu::fuzz::scsi::MmioCorrupt& m) {
    uint32_t off = m.offset() & 0x1ff;
    uint32_t val = m.value();
    uint64_t addr = kVirtioMmioBase + off;
    uint32_t size = m.size();
    if      (size == 1) qtest_writel(g_state.qts, addr, val & 0xff);
    else if (size == 2) qtest_writel(g_state.qts, addr, val & 0xffff);
    else                qtest_writel(g_state.qts, addr, val);
}

/* --- LUN encoding ------------------------------------------------ */

void encode_lun(uint8_t lun8[8], uint32_t target, uint32_t lun) {
    /* virtio-scsi single-level LUN encoding:
     *   lun8[0] = 1 (always)
     *   lun8[1] = target (0..255)
     *   lun8[2] = 0x40 | (lun & 0x3f)   single-level
     *   lun8[3] = lun & 0xff (extended) -- upper bits
     *   lun8[4..7] = 0
     */
    lun8[0] = 1;
    lun8[1] = target & 0xff;
    lun8[2] = 0x40 | (lun & 0x3f);
    lun8[3] = (lun >> 8) & 0xff;
    lun8[4] = lun8[5] = lun8[6] = lun8[7] = 0;
}

/* --- CDB packing ------------------------------------------------- */

/* All CDB packers write into out[0..cdb_size). Big-endian where the
 * SCSI spec calls for it. */

void pack_be32(uint8_t* p, uint32_t v) {
    p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff;
    p[2] = (v >>  8) & 0xff; p[3] = v & 0xff;
}
void pack_be16(uint8_t* p, uint16_t v) {
    p[0] = (v >> 8) & 0xff; p[1] = v & 0xff;
}
void pack_be64(uint8_t* p, uint64_t v) {
    pack_be32(p,     v >> 32);
    pack_be32(p + 4, v & 0xffffffff);
}

/*
 * Returns (in_data_len, out_data_len). Most reads have in_data_len > 0,
 * most writes have out_data_len > 0, TUR/SYNCHRONIZE_CACHE have both 0.
 */

void pack_inquiry(uint8_t* cdb, const qemu::fuzz::scsi::CdbInquiry& m,
                  uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x12;                   // INQUIRY
    cdb[1] = m.evpd() ? 1 : 0;
    cdb[2] = m.page_code() & 0xff;
    pack_be16(cdb + 3, m.alloc_len() & 0xffff);
    cdb[5] = 0;                       // control byte
    *in_len  = m.alloc_len() & 0xffff;
    *out_len = 0;
}

void pack_test_unit_ready(uint8_t* cdb,
                          uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x00;                    // TEST UNIT READY
    *in_len = *out_len = 0;
}

void pack_read_capacity_10(uint8_t* cdb,
                           const qemu::fuzz::scsi::CdbReadCapacity10& m,
                           uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x25;                    // READ CAPACITY (10)
    cdb[1] = 0;
    pack_be32(cdb + 2, m.lba());
    cdb[6] = 0; cdb[7] = 0;
    cdb[8] = m.pmi() ? 1 : 0;
    *in_len  = 8;
    *out_len = 0;
}

void pack_read_capacity_16(uint8_t* cdb,
                           const qemu::fuzz::scsi::CdbReadCapacity16& m,
                           uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x9e;                    // SERVICE ACTION IN (16)
    cdb[1] = 0x10;                    // READ CAPACITY (16)
    pack_be64(cdb + 2, m.lba());
    pack_be32(cdb + 10, m.alloc_len());
    cdb[14] = m.pmi() ? 1 : 0;
    *in_len  = m.alloc_len();
    *out_len = 0;
}

void pack_read_10(uint8_t* cdb, const qemu::fuzz::scsi::CdbRead10& m,
                  uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x28;                    // READ (10)
    cdb[1] = (m.dpo() ? 0x10 : 0) | (m.fua() ? 0x08 : 0);
    pack_be32(cdb + 2, m.lba());
    cdb[6] = m.group() & 0x1f;
    pack_be16(cdb + 7, m.transfer_len() & 0xffff);
    cdb[9] = 0;
    *in_len  = (m.transfer_len() & 0xffff) * 512;
    *out_len = 0;
}

void pack_write_10(uint8_t* cdb, const qemu::fuzz::scsi::CdbWrite10& m,
                   uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x2a;                    // WRITE (10)
    cdb[1] = (m.dpo() ? 0x10 : 0) | (m.fua() ? 0x08 : 0);
    pack_be32(cdb + 2, m.lba());
    cdb[6] = m.group() & 0x1f;
    pack_be16(cdb + 7, m.transfer_len() & 0xffff);
    cdb[9] = 0;
    *in_len  = 0;
    *out_len = (m.transfer_len() & 0xffff) * 512;
}

void pack_read_16(uint8_t* cdb, const qemu::fuzz::scsi::CdbRead16& m,
                  uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x88;                    // READ (16)
    cdb[1] = (m.dpo() ? 0x10 : 0) | (m.fua() ? 0x08 : 0);
    pack_be64(cdb + 2, m.lba());
    pack_be32(cdb + 10, m.transfer_len());
    cdb[14] = m.group() & 0x1f;
    cdb[15] = 0;
    *in_len  = m.transfer_len() * 512;
    *out_len = 0;
}

void pack_write_16(uint8_t* cdb, const qemu::fuzz::scsi::CdbWrite16& m,
                   uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x8a;                    // WRITE (16)
    cdb[1] = (m.dpo() ? 0x10 : 0) | (m.fua() ? 0x08 : 0);
    pack_be64(cdb + 2, m.lba());
    pack_be32(cdb + 10, m.transfer_len());
    cdb[14] = m.group() & 0x1f;
    cdb[15] = 0;
    *in_len  = 0;
    *out_len = m.transfer_len() * 512;
}

void pack_mode_sense_6(uint8_t* cdb, const qemu::fuzz::scsi::CdbModeSense6& m,
                       uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x1a;                    // MODE SENSE (6)
    cdb[1] = m.dbd() ? 0x08 : 0;
    cdb[2] = ((m.pc() & 0x3) << 6) | (m.page_code() & 0x3f);
    cdb[3] = m.subpage() & 0xff;
    cdb[4] = m.alloc_len() & 0xff;
    cdb[5] = 0;
    *in_len  = m.alloc_len() & 0xff;
    *out_len = 0;
}

void pack_mode_select_6(uint8_t* cdb, const qemu::fuzz::scsi::CdbModeSelect6& m,
                        uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x15;                    // MODE SELECT (6)
    cdb[1] = (m.pf() ? 0x10 : 0) | (m.sp() ? 0x01 : 0);
    cdb[2] = 0; cdb[3] = 0;
    cdb[4] = m.param_len() & 0xff;
    cdb[5] = 0;
    *in_len  = 0;
    *out_len = m.param_len() & 0xff;
}

void pack_request_sense(uint8_t* cdb, const qemu::fuzz::scsi::CdbRequestSense& m,
                        uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x03;                    // REQUEST SENSE
    cdb[1] = m.desc() ? 1 : 0;
    cdb[2] = 0; cdb[3] = 0;
    cdb[4] = m.alloc_len() & 0xff;
    cdb[5] = 0;
    *in_len  = m.alloc_len() & 0xff;
    *out_len = 0;
}

void pack_report_luns(uint8_t* cdb, const qemu::fuzz::scsi::CdbReportLuns& m,
                      uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0xa0;                    // REPORT LUNS
    cdb[1] = 0;
    cdb[2] = m.select_report() & 0xff;
    cdb[3] = cdb[4] = cdb[5] = 0;
    pack_be32(cdb + 6, m.alloc_len());
    cdb[10] = 0; cdb[11] = 0;
    *in_len  = m.alloc_len();
    *out_len = 0;
}

void pack_start_stop_unit(uint8_t* cdb, const qemu::fuzz::scsi::CdbStartStopUnit& m,
                          uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x1b;                    // START STOP UNIT
    cdb[1] = m.immed() ? 1 : 0;
    cdb[2] = 0;
    cdb[3] = 0;
    cdb[4] = ((m.power() & 0xf) << 4) |
             (m.loej() ? 0x02 : 0) |
             (m.start() ? 0x01 : 0);
    cdb[5] = 0;
    *in_len = *out_len = 0;
}

void pack_sync_cache_10(uint8_t* cdb,
                        const qemu::fuzz::scsi::CdbSynchronizeCache10& m,
                        uint32_t* in_len, uint32_t* out_len) {
    cdb[0] = 0x35;                    // SYNCHRONIZE CACHE (10)
    cdb[1] = m.immed() ? 0x02 : 0;
    pack_be32(cdb + 2, m.lba());
    cdb[6] = 0;
    pack_be16(cdb + 7, m.num_blocks() & 0xffff);
    cdb[9] = 0;
    *in_len = *out_len = 0;
}

void pack_raw(uint8_t* cdb, const qemu::fuzz::scsi::CdbRaw& m,
              uint32_t* in_len, uint32_t* out_len) {
    const std::string& bytes = m.cdb_bytes();
    size_t n = std::min<size_t>(bytes.size(), kCdbSize);
    if (n) std::memcpy(cdb, bytes.data(), n);
    *in_len  = std::min<uint32_t>(m.in_len(), 4096);
    *out_len = static_cast<uint32_t>(
        std::min<size_t>(m.out_data().size(), 4096));
}

/* --- request submission ----------------------------------------- */

/*
 * Build and submit a virtio-scsi request:
 *   1. virtio_scsi_cmd_req     (out)   -- LUN, tag, attrs, CDB
 *   2. (optional) data buffer  (out)   -- WRITE-class data
 *   3. virtio_scsi_cmd_resp    (in)    -- sense_len/resid/status/sense
 *   4. (optional) data buffer  (in)    -- READ-class data
 *
 * Returns silently if the queue isn't set up.
 */
void submit_scsi_cmd(const qemu::fuzz::scsi::ScsiCmd& c) {
    uint32_t vq = c.vq_idx() % kMaxQueues;
    if (g_state.vqs[vq].size == 0) return;
    /* Need up to 4 descriptors + 1 slack */
    if (g_state.vqs[vq].next_desc_idx + 5 >= g_state.vqs[vq].size) return;

    /* Build the request header */
    uint8_t req[8 + 8 + 1 + 1 + 1 + 1 + kCdbSize] = {};
    encode_lun(req + 0, c.target(), c.lun());
    uint64_t tag_le = c.tag();
    std::memcpy(req + 8, &tag_le, 8);
    req[16] = c.task_attr() & 0x07;
    req[17] = c.prio() & 0xff;
    req[18] = c.crn() & 0xff;
    req[19] = 0;                          // reserved
    uint8_t* cdb = req + 20;

    uint32_t in_len = 0, out_len = 0;
    std::string out_data;

    using CdbCase = qemu::fuzz::scsi::ScsiCmd::CdbCase;
    switch (c.cdb_case()) {
    case CdbCase::kInquiry:
        pack_inquiry(cdb, c.inquiry(), &in_len, &out_len); break;
    case CdbCase::kTestUnitReady:
        pack_test_unit_ready(cdb, &in_len, &out_len); break;
    case CdbCase::kReadCapacity10:
        pack_read_capacity_10(cdb, c.read_capacity_10(), &in_len, &out_len); break;
    case CdbCase::kReadCapacity16:
        pack_read_capacity_16(cdb, c.read_capacity_16(), &in_len, &out_len); break;
    case CdbCase::kRead10:
        pack_read_10(cdb, c.read_10(), &in_len, &out_len); break;
    case CdbCase::kWrite10:
        pack_write_10(cdb, c.write_10(), &in_len, &out_len);
        out_data = c.write_10().data();
        break;
    case CdbCase::kRead16:
        pack_read_16(cdb, c.read_16(), &in_len, &out_len); break;
    case CdbCase::kWrite16:
        pack_write_16(cdb, c.write_16(), &in_len, &out_len);
        out_data = c.write_16().data();
        break;
    case CdbCase::kModeSense6:
        pack_mode_sense_6(cdb, c.mode_sense_6(), &in_len, &out_len); break;
    case CdbCase::kModeSelect6:
        pack_mode_select_6(cdb, c.mode_select_6(), &in_len, &out_len);
        out_data = c.mode_select_6().parameters();
        break;
    case CdbCase::kRequestSense:
        pack_request_sense(cdb, c.request_sense(), &in_len, &out_len); break;
    case CdbCase::kReportLuns:
        pack_report_luns(cdb, c.report_luns(), &in_len, &out_len); break;
    case CdbCase::kStartStopUnit:
        pack_start_stop_unit(cdb, c.start_stop_unit(), &in_len, &out_len); break;
    case CdbCase::kSyncCache10:
        pack_sync_cache_10(cdb, c.sync_cache_10(), &in_len, &out_len); break;
    case CdbCase::kRaw:
        pack_raw(cdb, c.raw(), &in_len, &out_len);
        out_data = c.raw().out_data();
        break;
    default:
        /* No CDB selected. Send a default TUR-shaped CDB so the queue
         * still sees an op. */
        pack_test_unit_ready(cdb, &in_len, &out_len);
        break;
    }

    /* Cap data lengths -- LPM can request giant transfers */
    if (in_len  > 4096) in_len  = 4096;
    if (out_len > 4096) out_len = 4096;

    /* Allocate the four buffers */
    uint32_t req_id = alloc_buf(req, sizeof(req));
    if (!req_id) return;

    uint32_t out_id = 0;
    if (out_len > 0) {
        size_t n = std::min<size_t>(out_data.size(), out_len);
        if (n < out_len) {
            std::string padded(out_len, '\0');
            if (n) std::memcpy(&padded[0], out_data.data(), n);
            out_id = alloc_buf(padded.data(), out_len);
        } else {
            out_id = alloc_buf(out_data.data(), out_len);
        }
        if (!out_id) return;
    }

    uint8_t resp[4 + 4 + 2 + 1 + 1 + kSenseSize] = {};
    uint32_t resp_id = alloc_buf(resp, sizeof(resp));
    if (!resp_id) return;

    uint32_t in_id = 0;
    if (in_len > 0) {
        std::string zero(in_len, '\0');
        in_id = alloc_buf(zero.data(), in_len);
        if (!in_id) return;
    }

    /* Place descriptors. Out-direction first (req+optional data),
     * then in-direction (resp + optional data). */
    auto& rb = g_state.bufs[req_id];

    bool more_after_req = (out_len > 0) || true;  // always at least resp follows
    place_desc(vq, rb.gpa, rb.len, /*device_writable=*/false,
               /*chain_next=*/more_after_req);

    if (out_len > 0) {
        auto& ob = g_state.bufs[out_id];
        place_desc(vq, ob.gpa, ob.len, false, /*chain_next=*/true);
    }

    auto& pb = g_state.bufs[resp_id];
    bool more_after_resp = (in_len > 0);
    place_desc(vq, pb.gpa, pb.len, /*device_writable=*/true,
               /*chain_next=*/more_after_resp);

    if (in_len > 0) {
        auto& ib = g_state.bufs[in_id];
        place_desc(vq, ib.gpa, ib.len, /*device_writable=*/true,
                   /*chain_next=*/false);
    }

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/* --- task management on ctrl queue (vq 0) ------------------------ */

void submit_tmf(const qemu::fuzz::scsi::TmfReq& m) {
    uint32_t vq = 0;
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 3 >= g_state.vqs[vq].size) return;

    /* virtio_scsi_ctrl_tmf_req: type(4) subtype(4) lun(8) tag(8) */
    uint8_t req[4 + 4 + 8 + 8] = {};
    uint32_t type = 0;       /* VIRTIO_SCSI_T_TMF */
    uint32_t subtype = m.subtype();
    std::memcpy(req + 0, &type, 4);
    std::memcpy(req + 4, &subtype, 4);
    encode_lun(req + 8, m.target(), m.lun());
    uint64_t tag = m.tag();
    std::memcpy(req + 16, &tag, 8);

    uint8_t resp[1] = { 0 };

    uint32_t req_id  = alloc_buf(req, sizeof(req));
    if (!req_id) return;
    uint32_t resp_id = alloc_buf(resp, sizeof(resp));
    if (!resp_id) return;

    auto& rb = g_state.bufs[req_id];
    auto& sb = g_state.bufs[resp_id];
    place_desc(vq, rb.gpa, rb.len, false, /*chain_next=*/true);
    place_desc(vq, sb.gpa, sb.len, /*device_writable=*/true,
               /*chain_next=*/false);

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

void submit_an(const qemu::fuzz::scsi::AnReq& m) {
    uint32_t vq = 0;
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 3 >= g_state.vqs[vq].size) return;

    /* virtio_scsi_ctrl_an_req: type(4) lun(8) event_requested(4) */
    uint8_t req[4 + 8 + 4] = {};
    uint32_t type = m.subtype() == 1 ? 1u : 2u;     /* AN_QUERY=1, AN_SUBSCRIBE=2 */
    std::memcpy(req + 0, &type, 4);
    encode_lun(req + 4, m.target(), m.lun());
    uint32_t evreq = m.event_requested();
    std::memcpy(req + 12, &evreq, 4);

    /* virtio_scsi_ctrl_an_resp: event_actual(4) response(1) */
    uint8_t resp[5] = { 0 };

    uint32_t req_id  = alloc_buf(req, sizeof(req));
    if (!req_id) return;
    uint32_t resp_id = alloc_buf(resp, sizeof(resp));
    if (!resp_id) return;

    auto& rb = g_state.bufs[req_id];
    auto& sb = g_state.bufs[resp_id];
    place_desc(vq, rb.gpa, rb.len, false, /*chain_next=*/true);
    place_desc(vq, sb.gpa, sb.len, /*device_writable=*/true,
               /*chain_next=*/false);

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/* --- dispatch ---------------------------------------------------- */

void dispatch(const qemu::fuzz::scsi::VirtioOp& op) {
    using qemu::fuzz::scsi::VirtioOp;
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
                       d.device_writable(), d.chain_next());
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
    case VirtioOp::kScsiCmd:
        submit_scsi_cmd(op.scsi_cmd());
        break;
    case VirtioOp::kTmfReq:
        submit_tmf(op.tmf_req());
        break;
    case VirtioOp::kAnReq:
        submit_an(op.an_req());
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

void proto_fuzz_virtio_scsi_run(QTestState* qts,
                                const unsigned char* data, size_t size) {
    g_state.qts = qts;

    qemu::fuzz::scsi::VirtioScsiProgram prog;
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
        uint32_t iter = std::clamp<uint32_t>(prog.thread_b_iter(), 1, 8);
        int      bsz  = prog.ops_thread_b_size();
        int      bidx = 0;
        for (const auto& op : prog.ops()) {
            if (n++ >= kMaxOps) break;
            dispatch(op);
            for (uint32_t i = 0; i < iter; ++i) {
                if (n++ >= kMaxOps) break;
                const auto& bop = prog.ops_thread_b(bidx);
                bidx = (bidx + 1) % bsz;
                dispatch(bop);
            }
        }
    }
}

GString* proto_fuzz_virtio_scsi_cmdline(FuzzTarget* /*t*/) {
    GString* s = g_string_new(nullptr);
    /* Single virtio-scsi-device with one LUN backed by null-co://
     * (writes are no-ops, reads return zeroes). force-legacy=false
     * for the v2 register layout the harness writes. */
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 128 "
        "-global virtio-mmio.force-legacy=false "
        "-device virtio-scsi-device,id=scsi0 "
        "-device scsi-hd,drive=hd0,bus=scsi0.0 "
        "-drive if=none,id=hd0,file=null-co://,file.read-zeroes=on,format=raw");
    return s;
}

size_t scsi_proto_mutator(uint8_t* data, size_t size, size_t max_size,
                          unsigned int seed) {
    qemu::fuzz::scsi::VirtioScsiProgram input;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(
        /*binary=*/false, data, size, max_size, seed, &input);
}

static void register_proto_fuzz_virtio_scsi(void) {
    static const FuzzTarget t = {
        /* .name        = */ "proto-fuzz-virtio-scsi",
        /* .description = */ "LPM-driven structured fuzzer for virtio-scsi-device on arm virt",
        /* .get_init_cmdline = */ proto_fuzz_virtio_scsi_cmdline,
        /* .pre_vm_init = */ nullptr,
        /* .pre_fuzz    = */ nullptr,
        /* .fuzz        = */ proto_fuzz_virtio_scsi_run,
        /* .crossover   = */ nullptr,
        /* .custom_mutator = */ scsi_proto_mutator,
        /* .opaque      = */ nullptr,
    };
    fuzz_add_target(&t);
}

}  /* anonymous namespace */

extern "C" {

__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_scsi(void) {
    register_module_init(register_proto_fuzz_virtio_scsi,
                         MODULE_INIT_FUZZ_TARGET);
}

}  /* extern "C" */
