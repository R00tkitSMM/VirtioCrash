/*
 * Structured (libprotobuf-mutator) fuzzer for virtio-net-device on the
 * arm 'virt' machine.
 *
 * Same shape as proto_fuzz_virtio_blk.cc: a proto schema describes a
 * sequence of guest virtio-mmio operations; LoadProtoInput parses the
 * fuzzer input as a VirtioNetProgram; the dispatcher walks the ops and
 * issues real in-process MMIO writes / DMA writes via qtest_*. After
 * the weak-symbol patch in libqtest.c those land directly in
 * hw/virtio/virtio-mmio.c, hw/virtio/virtio.c, and hw/net/virtio-net.c
 * with no socket, no fork, single-threaded.
 *
 * In addition to the common-virtio ops (GetFeatures, SetFeatures,
 * VqSetup, VqAddDesc, VqKick, ...), this schema adds two device-aware
 * helpers:
 *
 *   TxPacket  -- builds a 2-descriptor TX chain (virtio_net_hdr + frame)
 *                and kicks the queue.
 *   CtrlCmd   -- builds a 3-descriptor CVQ chain (class+cmd header,
 *                payload, 1-byte ack) and kicks. CVQ is the high-CVE
 *                surface (RX filter, MAC, VLAN, MQ, guest-offloads).
 */

#include <glib.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "libfuzzer/libfuzzer_macro.h"
#include "proto_fuzz_virtio_net.pb.h"

/*
 * Forward-declare just the slice of QEMU's ABI we use, instead of
 * including QEMU headers. Same trick as proto_fuzz_virtio_blk.cc: this
 * keeps `-I..` (the QEMU source root) off the C++ command line and so
 * avoids the macOS APFS case-insensitive `<version>` vs root `VERSION`
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

/*
 * Minimal slice of QEMU's QMP/error API for the host-side actions.
 * Forward-declared rather than #included to keep `-I..` off our C++
 * command line (the macOS APFS <version> vs VERSION case-collision
 * problem).
 */
typedef struct Error Error;
void qmp_set_link(const char *name, bool up, Error **errp);

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
 * arm 'virt' machine: DRAM @ 0x40000000 (-m 128 → ends at 0x48000000),
 * first virtio-mmio slot @ 0x0a000000. The first attached virtio device
 * lands at slot 0; with `-device virtio-net-device,...` that is the
 * virtio-net device.
 */
/* arm-virt fills its 32 virtio-mmio slots from the highest address
 * downwards, so a `-device virtio-net-device,...` lands at slot 31
 * (0x0a003e00), not slot 0. We discover the right base at first use
 * by scanning for magic="virt" + DEVICE_ID==1 (virtio-net). */
uint64_t kVirtioMmioBase = 0x0a003e00ULL;
constexpr uint32_t kVirtioNetDeviceId = 1;

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

constexpr uint32_t kStatusAck         = 0x01;
constexpr uint32_t kStatusDriver      = 0x02;
constexpr uint32_t kStatusDriverOk    = 0x04;
constexpr uint32_t kStatusFeaturesOk  = 0x08;

constexpr uint16_t kDescNext  = 0x1;
constexpr uint16_t kDescWrite = 0x2;

/*
 * Reserved DRAM region for descriptor tables, rings, and request
 * buffers. virtio-net needs more queues than blk: at minimum RX (vq 0)
 * + TX (vq 1) + control (vq 2 with VIRTIO_NET_F_CTRL_VQ); with
 * multi-queue + CVQ we want headroom for several pairs. Reserve 8.
 */
constexpr uint64_t kPoolBase    = 0x47000000ULL;
constexpr uint32_t kMaxQueues   = 8;
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

/*
 * Per-iteration device state. The "state-aware" part: when an earlier
 * op produces a result (active queue-pair count, a remembered VID, a
 * remembered MAC list), it lands in one of these slots, and a later op
 * can reference the same slot by index to consume that result.
 */
constexpr int kVlanSlots    = 16;
constexpr int kMacListSlots = 4;

struct MacList {
    std::vector<std::string> unicast;
    std::vector<std::string> multicast;
};

struct State {
    QTestState* qts = nullptr;
    VqState vqs[kMaxQueues] = {};
    uint64_t buf_alloc = kBufPoolBase;
    std::unordered_map<uint32_t, Buf> bufs;
    /*
     * Synthetic buf_id allocator for TxPacket / CtrlCmd: their
     * convenience messages don't reference user-visible buf_ids, so we
     * mint internal ones in the upper half of the 32-bit space to
     * avoid colliding with user-supplied GuestMemWrite buf_ids.
     */
    uint32_t synth_buf_id = 0x80000000u;

    /* device-aware state */
    uint32_t  active_pairs   = 1;        /* updated by CtrlMqVqPairsSet */
    uint8_t   current_mac[6] = {};       /* updated by CtrlMacAddrSet */
    uint16_t  vlan_slots[kVlanSlots] = {0};
    bool      vlan_slot_valid[kVlanSlots] = {false};
    MacList   mac_list_slots[kMacListSlots];
};

/* See proto_fuzz_virtio_blk.cc for why this is thread_local. */
thread_local State g_state;

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
            .size = 0,
            .next_desc_idx = 0,
            .next_avail_idx = 0,
        };
    }
    g_state.buf_alloc = kBufPoolBase;
    g_state.bufs.clear();
    g_state.synth_buf_id = 0x80000000u;

    /* device-aware state */
    g_state.active_pairs = 1;
    std::memset(g_state.current_mac, 0, sizeof(g_state.current_mac));
    for (int i = 0; i < kVlanSlots; ++i) {
        g_state.vlan_slots[i] = 0;
        g_state.vlan_slot_valid[i] = false;
    }
    for (int i = 0; i < kMacListSlots; ++i) {
        g_state.mac_list_slots[i] = MacList{};
    }
}

/*
 * Allocate a chunk of guest DRAM, write `bytes` to it, return the buf_id
 * under which the caller can later add a descriptor. Returns 0 on
 * failure (empty buffer or pool exhausted). buf_id 0 is reserved.
 */
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

/*
 * Place a single descriptor into a queue's descriptor table, optionally
 * appending the head index to the avail ring when the chain ends.
 *
 * Returns the head index of this descriptor (useful for callers that
 * want to assemble multi-descriptor chains explicitly).
 */
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

void op_vq_add_desc(uint32_t vq_idx, uint32_t buf_id, uint32_t len,
                    bool device_writable, bool chain_next) {
    if (vq_idx >= kMaxQueues) return;
    if (g_state.vqs[vq_idx].size == 0) return;

    auto it = g_state.bufs.find(buf_id);
    if (it == g_state.bufs.end()) return;
    const Buf& buf = it->second;
    uint32_t dlen = std::min(len, buf.len);

    place_desc(vq_idx, buf.gpa, dlen, device_writable, chain_next);
}

void op_vq_kick(uint32_t vq_idx) {
    mmio_writel(R_QUEUE_NOTIFY, vq_idx);
    flush_events(g_state.qts);
}

void op_vq_wait_used(uint32_t /*vq_idx*/) {
    flush_events(g_state.qts);
    uint32_t st = mmio_readl(R_INT_STATUS);
    if (st) mmio_writel(R_INT_ACK, st);
}

/*
 * Pack the modern 12-byte virtio_net_hdr into the supplied buffer.
 */
void pack_net_hdr(uint8_t out[12], const qemu::fuzz::net::TxPacket& p) {
    out[0]  = static_cast<uint8_t>(p.hdr_flags());
    out[1]  = static_cast<uint8_t>(p.gso_type());
    uint16_t hdr_len     = static_cast<uint16_t>(p.hdr_len());
    uint16_t gso_size    = static_cast<uint16_t>(p.gso_size());
    uint16_t csum_start  = static_cast<uint16_t>(p.csum_start());
    uint16_t csum_offset = static_cast<uint16_t>(p.csum_offset());
    uint16_t num_buffers = static_cast<uint16_t>(p.num_buffers());
    std::memcpy(out + 2,  &hdr_len,     2);
    std::memcpy(out + 4,  &gso_size,    2);
    std::memcpy(out + 6,  &csum_start,  2);
    std::memcpy(out + 8,  &csum_offset, 2);
    std::memcpy(out + 10, &num_buffers, 2);
}

/*
 * TxPacket: stage a virtio_net_hdr + payload in guest DRAM, build a
 * 2-descriptor chain (both out, header chain_next=true), bump avail,
 * kick.
 *
 * If vlan_tci is non-zero, splice a 4-byte 802.1Q tag (TPID 0x8100,
 * TCI = vlan_tci & 0xffff) between the src MAC and the existing
 * EtherType field of `payload`. The frame must be at least 14 bytes
 * (eth header) for the splice to apply; shorter payloads pass
 * through unchanged so LPM can still mutate small frames.
 */
void op_tx_packet(const qemu::fuzz::net::TxPacket& p) {
    uint32_t vq = p.vq_idx() % kMaxQueues;
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 2 >= g_state.vqs[vq].size) return;

    uint8_t hdr[12];
    pack_net_hdr(hdr, p);

    uint32_t hdr_id = alloc_buf(hdr, sizeof(hdr));
    if (!hdr_id) return;

    /* Cap payload size to keep input space bounded. */
    const std::string& pl_in = p.payload();
    std::string pl;
    pl.reserve(std::min<size_t>(pl_in.size() + 4, 9018));

    uint32_t vlan_tci = p.vlan_tci();
    if (vlan_tci != 0 && pl_in.size() >= 14) {
        /* eth: dst(6) src(6) type(2)
         * 802.1Q tagged: dst(6) src(6) TPID(2)=0x8100 TCI(2) type(2) ... */
        pl.append(pl_in.data(), 12);                 /* dst + src */
        uint8_t tag[4] = {0x81, 0x00,
                          static_cast<uint8_t>((vlan_tci >> 8) & 0xff),
                          static_cast<uint8_t>(vlan_tci & 0xff)};
        pl.append(reinterpret_cast<char*>(tag), 4);
        pl.append(pl_in.data() + 12, pl_in.size() - 12);
    } else {
        pl.assign(pl_in);
    }

    uint32_t plen = static_cast<uint32_t>(std::min<size_t>(pl.size(), 9018));
    uint32_t pay_id = alloc_buf(pl.data(), plen);
    if (!pay_id) return;

    auto& hb = g_state.bufs[hdr_id];
    auto& pb = g_state.bufs[pay_id];

    place_desc(vq, hb.gpa, hb.len, /*device_writable=*/false,
               /*chain_next=*/plen > 0);
    if (plen > 0) {
        place_desc(vq, pb.gpa, pb.len, /*device_writable=*/false,
                   /*chain_next=*/false);
    }

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/*
 * HostSetLink: ask QEMU to flip the netdev link state. virtio-net's
 * link_status_changed callback updates the Status config field and (with
 * VIRTIO_NET_F_STATUS) raises a config-change interrupt. Exercises the
 * device's link-event path which is otherwise unreachable from a guest
 * driver alone.
 */
void op_host_set_link(const qemu::fuzz::net::HostSetLink& m) {
    qmp_set_link("user0", m.up(), nullptr);
    flush_events(g_state.qts);
}

/*
 * MmioCorrupt: register-level fault injection. Writes to any offset
 * in the virtio-mmio window, including reserved / unimplemented /
 * read-only offsets. Decoder fault injection.
 */
void op_mmio_corrupt(const qemu::fuzz::net::MmioCorrupt& m) {
    uint32_t off  = m.offset() & 0x1ff;
    uint32_t val  = m.value();
    uint32_t size = m.size();
    uint64_t addr = kVirtioMmioBase + off;
    if      (size == 1) qtest_writeb(g_state.qts, addr, val & 0xff);
    else if (size == 2) qtest_writew(g_state.qts, addr, val & 0xffff);
    else                qtest_writel(g_state.qts, addr, val);
}

/*
 * MemwriteAbsolute: fault-injection primitive. Writes raw bytes to a
 * fixed GPA, bypassing the buf_id table. Used in interleaved mode so
 * a secondary op list can mutate memory regions that primary ops have
 * placed descriptors at. GPA is clamped into the harness's reserved
 * pool to avoid trampling MMIO regions.
 */
void op_memwrite_absolute(const qemu::fuzz::net::MemwriteAbsolute& m) {
    const std::string& d = m.data();
    if (d.empty()) return;
    uint32_t len = static_cast<uint32_t>(std::min<size_t>(d.size(), 4096));
    uint64_t gpa = m.gpa();
    /* Compare against (kBufPoolEnd - len) instead of (gpa + len): the
     * latter overflows uint64 for huge LPM-generated gpa values, fails
     * to detect out-of-range, and lets the write escape into low MMIO
     * (pflash mode-toggle thrashing flatviews until host OOM). */
    if (gpa < kBufPoolBase || gpa > kBufPoolEnd - len) {
        uint64_t span = kBufPoolEnd - kBufPoolBase - len;
        if (span == 0) return;
        gpa = kBufPoolBase + (gpa % span);
    }
    qtest_memwrite(g_state.qts, gpa, d.data(), len);
}

/*
 * CtrlCmd: stage a 2-byte class+cmd header, the payload, and a 1-byte
 * ack region in guest DRAM, build a 3-descriptor chain on the CVQ:
 *   [ class+cmd (out) | data (out, optional) | ack (in) ]
 * kick, flush.
 */
void op_ctrl_cmd(const qemu::fuzz::net::CtrlCmd& c) {
    uint32_t vq = c.vq_idx() % kMaxQueues;
    if (g_state.vqs[vq].size == 0) return;
    if (g_state.vqs[vq].next_desc_idx + 3 >= g_state.vqs[vq].size) return;

    uint8_t ctrl_hdr[2] = {
        static_cast<uint8_t>(c.vclass()),
        static_cast<uint8_t>(c.cmd()),
    };
    uint32_t ch_id = alloc_buf(ctrl_hdr, sizeof(ctrl_hdr));
    if (!ch_id) return;

    const std::string& d = c.data();
    uint32_t dlen = static_cast<uint32_t>(std::min<size_t>(d.size(), 1024));
    uint32_t d_id = 0;
    if (dlen > 0) {
        d_id = alloc_buf(d.data(), dlen);
        if (!d_id) return;
    }

    uint8_t ack = 0xff;
    uint32_t ack_id = alloc_buf(&ack, 1);
    if (!ack_id) return;

    auto& cb = g_state.bufs[ch_id];
    auto& ab = g_state.bufs[ack_id];

    place_desc(vq, cb.gpa, cb.len, /*device_writable=*/false,
               /*chain_next=*/true);
    if (dlen > 0) {
        auto& db = g_state.bufs[d_id];
        place_desc(vq, db.gpa, db.len, /*device_writable=*/false,
                   /*chain_next=*/true);
    }
    place_desc(vq, ab.gpa, ab.len, /*device_writable=*/true,
               /*chain_next=*/false);

    mmio_writel(R_QUEUE_NOTIFY, vq);
    flush_events(g_state.qts);
}

/*
 * Submit a typed CVQ command on the control queue: build a 3-descriptor
 * chain [class+cmd hdr (out) | payload (out) | 1-byte ack (in)] and
 * kick. Centralizes the wire-format plumbing so the per-class handlers
 * just say "what's my class, my cmd, my payload bytes".
 */
void submit_ctrl(uint32_t vq_idx, uint8_t vclass, uint8_t cmd,
                 const std::string& payload) {
    if (vq_idx >= kMaxQueues) return;
    if (g_state.vqs[vq_idx].size == 0) return;
    if (g_state.vqs[vq_idx].next_desc_idx + 3
            >= g_state.vqs[vq_idx].size) return;

    uint8_t ctrl_hdr[2] = { vclass, cmd };
    uint32_t ch_id = alloc_buf(ctrl_hdr, sizeof(ctrl_hdr));
    if (!ch_id) return;
    uint32_t d_id = 0;
    if (!payload.empty()) {
        d_id = alloc_buf(payload.data(),
                         std::min<uint32_t>(payload.size(), 2048));
        if (!d_id) return;
    }
    uint8_t ack = 0xff;
    uint32_t a_id = alloc_buf(&ack, 1);
    if (!a_id) return;

    auto& cb = g_state.bufs[ch_id];
    auto& ab = g_state.bufs[a_id];
    place_desc(vq_idx, cb.gpa, cb.len, /*write=*/false, /*next=*/true);
    if (d_id) {
        auto& db = g_state.bufs[d_id];
        place_desc(vq_idx, db.gpa, db.len, /*write=*/false, /*next=*/true);
    }
    place_desc(vq_idx, ab.gpa, ab.len, /*write=*/true,  /*next=*/false);

    mmio_writel(R_QUEUE_NOTIFY, vq_idx);
    flush_events(g_state.qts);
}

/*
 * cvq() returns the canonical CVQ index given the current active_pairs.
 * Layout: [rx0, tx0, rx1, tx1, ..., rxN-1, txN-1, ctrl] -> ctrl = 2N.
 */
uint32_t cvq() { return 2 * g_state.active_pairs; }

/* VIRTIO_NET_CTRL_RX: 1-byte enable payload. */
void op_ctrl_rx(const qemu::fuzz::net::CtrlRx& m) {
    uint8_t en = static_cast<uint8_t>(m.enable() & 0xff);
    submit_ctrl(cvq(), /*vclass=*/0 /*VIRTIO_NET_CTRL_RX*/,
                static_cast<uint8_t>(m.cmd() & 0xff),
                std::string(reinterpret_cast<const char*>(&en), 1));
}

/* VIRTIO_NET_CTRL_MAC_ADDR_SET: 6-byte MAC payload. */
void op_ctrl_mac_addr_set(const qemu::fuzz::net::CtrlMacAddrSet& m) {
    std::string mac = m.mac();
    mac.resize(6, 0);
    submit_ctrl(cvq(), /*vclass=*/1, /*cmd=*/1,
                mac.substr(0, 6));
    /* state-aware: remember the MAC so future ops can read it back */
    std::memcpy(g_state.current_mac, mac.data(), 6);
}

/*
 * VIRTIO_NET_CTRL_MAC_TABLE_SET payload:
 *   le32 unicast_count, unicast_count*6B macs,
 *   le32 multicast_count, multicast_count*6B macs.
 *
 * State-aware: store the lists in a slot so a future op could refer
 * back to the same set (we don't currently emit such an op, but the
 * slot is there for the next iteration of the schema).
 */
void op_ctrl_mac_table_set(const qemu::fuzz::net::CtrlMacTableSet& m) {
    uint32_t slot = m.macs_slot() % kMacListSlots;
    MacList& ml = g_state.mac_list_slots[slot];
    ml.unicast.clear();
    ml.multicast.clear();
    for (const auto& mac : m.unicast_macs())   ml.unicast.push_back(mac);
    for (const auto& mac : m.multicast_macs()) ml.multicast.push_back(mac);

    auto pad6 = [](std::string s) {
        s.resize(6, 0);
        return s.substr(0, 6);
    };

    std::string payload;
    uint32_t uni_n = static_cast<uint32_t>(ml.unicast.size());
    payload.append(reinterpret_cast<const char*>(&uni_n), 4);
    for (const auto& mac : ml.unicast) payload += pad6(mac);
    uint32_t mul_n = static_cast<uint32_t>(ml.multicast.size());
    payload.append(reinterpret_cast<const char*>(&mul_n), 4);
    for (const auto& mac : ml.multicast) payload += pad6(mac);

    submit_ctrl(cvq(), /*vclass=*/1, /*cmd=*/0, payload);
}

/* VIRTIO_NET_CTRL_VLAN_ADD: u16 VID. State-aware: remember VID in slot. */
void op_ctrl_vlan_add(const qemu::fuzz::net::CtrlVlanAdd& m) {
    uint16_t vid = static_cast<uint16_t>(m.vid() & 0x0fff);
    uint32_t slot = m.vlan_slot() % kVlanSlots;
    g_state.vlan_slots[slot] = vid;
    g_state.vlan_slot_valid[slot] = true;

    submit_ctrl(cvq(), /*vclass=*/2, /*cmd=*/0,
                std::string(reinterpret_cast<const char*>(&vid), 2));
}

/*
 * VIRTIO_NET_CTRL_VLAN_DEL: u16 VID. State-aware: if use_slot is set,
 * read the VID stored by an earlier CtrlVlanAdd (so the proto can say
 * "delete the VLAN I added two ops ago"). Otherwise use the literal vid.
 */
void op_ctrl_vlan_del(const qemu::fuzz::net::CtrlVlanDel& m) {
    uint16_t vid;
    if (m.use_slot()) {
        uint32_t slot = m.vlan_slot() % kVlanSlots;
        vid = g_state.vlan_slot_valid[slot]
              ? g_state.vlan_slots[slot]
              : 0;
        if (g_state.vlan_slot_valid[slot]) {
            g_state.vlan_slot_valid[slot] = false;
        }
    } else {
        vid = static_cast<uint16_t>(m.vid() & 0x0fff);
    }
    submit_ctrl(cvq(), /*vclass=*/2, /*cmd=*/1,
                std::string(reinterpret_cast<const char*>(&vid), 2));
}

/* VIRTIO_NET_CTRL_ANNOUNCE_ACK: empty payload. */
void op_ctrl_announce_ack() {
    submit_ctrl(cvq(), /*vclass=*/3, /*cmd=*/0, std::string());
}

/*
 * VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u16 pair count.
 *
 * State-aware: bump active_pairs so subsequent cvq() calls find the
 * right control queue index. (After MQ activation the CVQ moves to
 * 2 * active_pairs.)
 */
void op_ctrl_mq_vq_pairs_set(const qemu::fuzz::net::CtrlMqVqPairsSet& m) {
    uint16_t pairs = static_cast<uint16_t>(
        std::clamp<uint32_t>(m.pair_count(), 1, kMaxQueues / 2 - 1));
    submit_ctrl(cvq(), /*vclass=*/4, /*cmd=*/0,
                std::string(reinterpret_cast<const char*>(&pairs), 2));
    /* update only after the device has had a chance to ACK */
    g_state.active_pairs = pairs;
}

/* VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET: u64 offloads. */
void op_ctrl_guest_offloads(const qemu::fuzz::net::CtrlGuestOffloads& m) {
    uint64_t off = m.offloads();
    submit_ctrl(cvq(), /*vclass=*/5, /*cmd=*/0,
                std::string(reinterpret_cast<const char*>(&off), 8));
}

/*
 * VIRTIO_NET_CTRL_RSS_CONFIG payload (heavy CVE history):
 *   le32 hash_types
 *   le16 indirection_table_mask
 *   le16 unclassified_queue
 *   indirection_table_mask + 1 * le16 entries
 *   le16 max_tx_vq
 *   u8 hash_key_length
 *   hash_key bytes
 */
void op_ctrl_rss_config(const qemu::fuzz::net::CtrlRssConfig& m) {
    std::string payload;
    uint32_t ht = m.hash_types();
    payload.append(reinterpret_cast<const char*>(&ht), 4);
    /* clamp mask to a sane range so we don't overflow the buf pool */
    uint16_t mask = static_cast<uint16_t>(m.indirection_table_mask() & 0x7f);
    payload.append(reinterpret_cast<const char*>(&mask), 2);
    uint16_t uq = static_cast<uint16_t>(m.unclassified_queue());
    payload.append(reinterpret_cast<const char*>(&uq), 2);
    /* indirection table: take the user-supplied bytes, pad/truncate to
     * exactly (mask+1)*2 bytes */
    uint32_t want = (uint32_t)(mask + 1) * 2;
    std::string it = m.indirection_table();
    if (it.size() < want) it.resize(want, 0);
    else                  it.resize(want);
    payload += it;
    uint16_t max_tx = static_cast<uint16_t>(m.max_tx_vq());
    payload.append(reinterpret_cast<const char*>(&max_tx), 2);
    /* hash key (cap at 40 bytes) */
    std::string hk = m.hash_key();
    if (hk.size() > 40) hk.resize(40);
    uint8_t hk_len = static_cast<uint8_t>(hk.size());
    payload.append(reinterpret_cast<const char*>(&hk_len), 1);
    payload += hk;

    submit_ctrl(cvq(), /*vclass=*/4 /*VIRTIO_NET_CTRL_MQ*/,
                /*cmd=*/1 /*VIRTIO_NET_CTRL_MQ_RSS_CONFIG*/, payload);
}

void dispatch(const qemu::fuzz::net::VirtioOp& op) {
    using qemu::fuzz::net::VirtioOp;
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
    case VirtioOp::kTxPacket:
        op_tx_packet(op.tx_packet());
        break;
    case VirtioOp::kCtrlCmd:
        op_ctrl_cmd(op.ctrl_cmd());
        break;
    case VirtioOp::kCtrlRx:
        op_ctrl_rx(op.ctrl_rx());
        break;
    case VirtioOp::kCtrlMacAddrSet:
        op_ctrl_mac_addr_set(op.ctrl_mac_addr_set());
        break;
    case VirtioOp::kCtrlMacTableSet:
        op_ctrl_mac_table_set(op.ctrl_mac_table_set());
        break;
    case VirtioOp::kCtrlVlanAdd:
        op_ctrl_vlan_add(op.ctrl_vlan_add());
        break;
    case VirtioOp::kCtrlVlanDel:
        op_ctrl_vlan_del(op.ctrl_vlan_del());
        break;
    case VirtioOp::kCtrlAnnounceAck:
        op_ctrl_announce_ack();
        break;
    case VirtioOp::kCtrlMqVqPairsSet:
        op_ctrl_mq_vq_pairs_set(op.ctrl_mq_vq_pairs_set());
        break;
    case VirtioOp::kCtrlGuestOffloads:
        op_ctrl_guest_offloads(op.ctrl_guest_offloads());
        break;
    case VirtioOp::kCtrlRssConfig:
        op_ctrl_rss_config(op.ctrl_rss_config());
        break;
    case VirtioOp::kHostSetLink:
        op_host_set_link(op.host_set_link());
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

void proto_fuzz_virtio_net_run(QTestState* qts,
                               const unsigned char* data, size_t size) {
    g_state.qts = qts;

    qemu::fuzz::net::VirtioNetProgram prog;
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
        /* Deterministic interleaved mode -- see proto_fuzz_virtio_blk.cc
         * for the design notes on why this is single-threaded. */
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

GString* proto_fuzz_virtio_net_cmdline(FuzzTarget* /*t*/) {
    GString* s = g_string_new(nullptr);
    /*
     * Single TX/RX queue pair + control queue: VIRTIO_NET_F_CTRL_VQ is
     * provided by virtio-net by default. Use slirp (-netdev user) so the
     * device's full TX/RX path runs without needing a tap/host bridge.
     */
    /* force-legacy=false switches virtio-mmio to spec v2; the v2
     * register layout (QUEUE_DESC_LO/HI, QUEUE_AVAIL_LO/HI, QUEUE_USED_LO/HI,
     * QUEUE_READY) is what this harness writes. With the default
     * force-legacy=true, those writes are silently dropped and the
     * vrings never get programmed. */
    g_string_assign(s,
        "qemu-system-aarch64 -display none -machine virt -nodefaults -m 128 "
        "-global virtio-mmio.force-legacy=false "
        "-device virtio-net-device,netdev=user0 "
        "-netdev user,id=user0");
    return s;
}

size_t net_proto_mutator(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed) {
    qemu::fuzz::net::VirtioNetProgram input;
    return protobuf_mutator::libfuzzer::CustomProtoMutator(
        /*binary=*/false, data, size, max_size, seed, &input);
}

}  /* anonymous namespace */

extern "C" {

static void register_proto_fuzz_virtio_net(void) {
    static const FuzzTarget t = {
        /* .name        = */ "proto-fuzz-virtio-net",
        /* .description = */ "LPM-driven structured fuzzer for virtio-net-device on arm virt",
        /* .get_init_cmdline = */ proto_fuzz_virtio_net_cmdline,
        /* .pre_vm_init = */ nullptr,
        /* .pre_fuzz    = */ nullptr,
        /* .fuzz        = */ proto_fuzz_virtio_net_run,
        /* .crossover   = */ nullptr,
        /* .custom_mutator = */ net_proto_mutator,
        /* .opaque      = */ nullptr,
    };
    fuzz_add_target(&t);
}

__attribute__((constructor))
static void do_qemu_init_register_proto_fuzz_virtio_net(void) {
    register_module_init(register_proto_fuzz_virtio_net,
                         MODULE_INIT_FUZZ_TARGET);
}

}  /* extern "C" */
