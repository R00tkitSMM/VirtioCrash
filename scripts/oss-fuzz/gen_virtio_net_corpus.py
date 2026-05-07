#!/usr/bin/env python3
"""
Seed corpus generator for proto-fuzz-virtio-net.

Emits a set of hand-crafted text-format VirtioNetProgram messages -- one
per file -- into a target directory. The harness in
tests/qtest/fuzz/proto_fuzz_virtio_net.cc parses each file with
LoadProtoInput(binary=false, ...) and dispatches the ops in-process.

LPM (libprotobuf-mutator) takes over from there: every seed becomes the
starting point for an arbitrary number of structured mutations that
preserve proto shape. So the corpus does not need to be exhaustive; it
just needs to plant the harness in enough distinct code paths that
libFuzzer can branch out from there.

Seeds covered:
  * init only                         -- bare prologue
  * plain TX (small ethernet frame)
  * TX with checksum offload metadata
  * TX with GSO (TCPv4, large hdr_len)
  * CVQ: VIRTIO_NET_CTRL_RX (promisc on/off, allmulti, alluni, nobcast)
  * CVQ: VIRTIO_NET_CTRL_MAC_ADDR_SET   -- MAC set
  * CVQ: VIRTIO_NET_CTRL_MAC_TABLE_SET  -- MAC unicast/multicast tables
  * CVQ: VIRTIO_NET_CTRL_VLAN_ADD/DEL   -- VLAN filter management
  * CVQ: VIRTIO_NET_CTRL_ANNOUNCE_ACK
  * CVQ: VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET (multi-queue)
  * CVQ: VIRTIO_NET_CTRL_GUEST_OFFLOADS
  * RX-prepared buffers
  * full-session combo

Each seed sets DRIVER_OK before doing anything else, so the device
emulation actually runs the code paths we care about. Without
DRIVER_OK most CVQ commands are silently rejected.
"""

import argparse
import os
import random
import struct
import sys
from textwrap import dedent

# -- virtio-net feature bits (linux/virtio_net.h) -----------------------------

VIRTIO_F_VERSION_1            = 1 << 32

VIRTIO_NET_F_CSUM             = 1 << 0
VIRTIO_NET_F_GUEST_CSUM       = 1 << 1
VIRTIO_NET_F_MAC              = 1 << 5
VIRTIO_NET_F_GUEST_TSO4       = 1 << 7
VIRTIO_NET_F_GUEST_TSO6       = 1 << 8
VIRTIO_NET_F_GUEST_ECN        = 1 << 9
VIRTIO_NET_F_GUEST_UFO        = 1 << 10
VIRTIO_NET_F_HOST_TSO4        = 1 << 11
VIRTIO_NET_F_HOST_TSO6        = 1 << 12
VIRTIO_NET_F_HOST_ECN         = 1 << 13
VIRTIO_NET_F_HOST_UFO         = 1 << 14
VIRTIO_NET_F_MRG_RXBUF        = 1 << 15
VIRTIO_NET_F_STATUS           = 1 << 16
VIRTIO_NET_F_CTRL_VQ          = 1 << 17
VIRTIO_NET_F_CTRL_RX          = 1 << 18
VIRTIO_NET_F_CTRL_VLAN        = 1 << 19
VIRTIO_NET_F_CTRL_RX_EXTRA    = 1 << 20
VIRTIO_NET_F_GUEST_ANNOUNCE   = 1 << 21
VIRTIO_NET_F_MQ               = 1 << 22
VIRTIO_NET_F_CTRL_MAC_ADDR    = 1 << 23

# A reasonable feature set: VERSION_1 + MAC + STATUS + CTRL_VQ + CTRL_RX +
# CTRL_VLAN + GUEST_ANNOUNCE + MQ + CTRL_MAC_ADDR + CSUM/HOST_TSO4/HOST_TSO6
# so the device offers the full surface we want to exercise.
DEFAULT_FEATURES = (
    VIRTIO_F_VERSION_1
    | VIRTIO_NET_F_CSUM
    | VIRTIO_NET_F_MAC
    | VIRTIO_NET_F_HOST_TSO4
    | VIRTIO_NET_F_HOST_TSO6
    | VIRTIO_NET_F_MRG_RXBUF
    | VIRTIO_NET_F_STATUS
    | VIRTIO_NET_F_CTRL_VQ
    | VIRTIO_NET_F_CTRL_RX
    | VIRTIO_NET_F_CTRL_VLAN
    | VIRTIO_NET_F_GUEST_ANNOUNCE
    | VIRTIO_NET_F_MQ
    | VIRTIO_NET_F_CTRL_MAC_ADDR
)

# -- virtio status bits --------------------------------------------------------

STATUS_DRIVER_OK   = 0x04
STATUS_FEATURES_OK = 0x08

# -- VIRTIO_NET_CTRL_* classes and commands ------------------------------------

CTRL_RX     = 0
CTRL_RX_PROMISC      = 0
CTRL_RX_ALLMULTI     = 1
CTRL_RX_ALLUNI       = 2
CTRL_RX_NOMULTI      = 3
CTRL_RX_NOUNI        = 4
CTRL_RX_NOBCAST      = 5

CTRL_MAC    = 1
CTRL_MAC_TABLE_SET   = 0
CTRL_MAC_ADDR_SET    = 1

CTRL_VLAN   = 2
CTRL_VLAN_ADD        = 0
CTRL_VLAN_DEL        = 1

CTRL_ANNOUNCE = 3
CTRL_ANNOUNCE_ACK    = 0

CTRL_MQ     = 4
CTRL_MQ_VQ_PAIRS_SET = 0

CTRL_GUEST_OFFLOADS = 5
CTRL_GUEST_OFFLOADS_SET = 0

# -- text-proto helpers --------------------------------------------------------

def escape_bytes(b: bytes) -> str:
    """Encode bytes as a C-style escaped string for a proto bytes field."""
    out = []
    for x in b:
        if 32 <= x < 127 and x not in (ord('"'), ord('\\')):
            out.append(chr(x))
        else:
            out.append('\\%03o' % x)
    return ''.join(out)


def op_get_features() -> str:
    return "ops { get_features {} }"

def op_set_features(features: int) -> str:
    return "ops { set_features { features: %d } }" % features

def op_vq_setup(vq_idx: int, size: int = 64) -> str:
    return "ops { vq_setup { vq_idx: %d size: %d } }" % (vq_idx, size)

def op_vq_select(vq_idx: int) -> str:
    return "ops { vq_select { vq_idx: %d } }" % vq_idx

def op_set_status(bits: int) -> str:
    return "ops { set_status { bits: %d } }" % bits

def op_reset() -> str:
    return "ops { reset {} }"

def op_config_read(offset: int, size: int) -> str:
    return ("ops { config_read { offset: %d size: %d } }"
            % (offset, size))

def op_config_write(offset: int, data: bytes) -> str:
    return ('ops { config_write { offset: %d data: "%s" } }'
            % (offset, escape_bytes(data)))

def op_guest_mem_write(buf_id: int, data: bytes) -> str:
    return ('ops { guest_mem_write { buf_id: %d data: "%s" } }'
            % (buf_id, escape_bytes(data)))

def op_vq_add_desc(vq_idx: int, buf_id: int, length: int,
                   device_writable: bool, chain_next: bool,
                   exotic_region: int = 0) -> str:
    s = ("ops { vq_add_desc { vq_idx: %d buf_id: %d len: %d "
         "device_writable: %s chain_next: %s"
         % (vq_idx, buf_id, length,
            'true' if device_writable else 'false',
            'true' if chain_next else 'false'))
    if exotic_region:
        s += " exotic_region: %d" % exotic_region
    return s + " } }"

def b_vq_add_desc(vq_idx: int, buf_id: int, length: int,
                  device_writable: bool, chain_next: bool,
                  exotic_region: int = 0) -> str:
    s = ("ops_thread_b { vq_add_desc { vq_idx: %d buf_id: %d len: %d "
         "device_writable: %s chain_next: %s"
         % (vq_idx, buf_id, length,
            'true' if device_writable else 'false',
            'true' if chain_next else 'false'))
    if exotic_region:
        s += " exotic_region: %d" % exotic_region
    return s + " } }"

def op_vq_kick(vq_idx: int) -> str:
    return "ops { vq_kick { vq_idx: %d } }" % vq_idx

def op_vq_wait_used(vq_idx: int) -> str:
    return "ops { vq_wait_used { vq_idx: %d } }" % vq_idx

def op_tx_packet(vq_idx: int, payload: bytes,
                 hdr_flags: int = 0, gso_type: int = 0,
                 hdr_len: int = 0, gso_size: int = 0,
                 csum_start: int = 0, csum_offset: int = 0,
                 num_buffers: int = 0) -> str:
    return (
        "ops { tx_packet { "
        "vq_idx: %d hdr_flags: %d gso_type: %d hdr_len: %d gso_size: %d "
        'csum_start: %d csum_offset: %d num_buffers: %d payload: "%s" } }'
        % (vq_idx, hdr_flags, gso_type, hdr_len, gso_size,
           csum_start, csum_offset, num_buffers, escape_bytes(payload)))

def op_ctrl_cmd(vq_idx: int, vclass: int, cmd: int, data: bytes) -> str:
    return (
        'ops { ctrl_cmd { vq_idx: %d vclass: %d cmd: %d data: "%s" } }'
        % (vq_idx, vclass, cmd, escape_bytes(data)))

# -- typed CVQ ops (device-aware + state-aware) -------------------------------

def op_ctrl_rx(cmd: int, enable: int) -> str:
    return ("ops { ctrl_rx { cmd: %d enable: %d } }" % (cmd, enable))

def op_ctrl_mac_addr_set(mac: bytes) -> str:
    return ('ops { ctrl_mac_addr_set { mac: "%s" } }' % escape_bytes(mac))

def op_ctrl_mac_table_set(slot: int, unicast: list, multicast: list) -> str:
    parts = ['macs_slot: %d' % slot]
    for m in unicast:
        parts.append('unicast_macs: "%s"' % escape_bytes(m))
    for m in multicast:
        parts.append('multicast_macs: "%s"' % escape_bytes(m))
    return ("ops { ctrl_mac_table_set { %s } }" % ' '.join(parts))

def op_ctrl_vlan_add(slot: int, vid: int) -> str:
    return ("ops { ctrl_vlan_add { vlan_slot: %d vid: %d } }"
            % (slot, vid))

def op_ctrl_vlan_del_slot(slot: int) -> str:
    """state-aware: delete the VID stored in slot by an earlier add"""
    return ("ops { ctrl_vlan_del { vlan_slot: %d use_slot: true } }" % slot)

def op_ctrl_vlan_del_vid(vid: int) -> str:
    return ("ops { ctrl_vlan_del { use_slot: false vid: %d } }" % vid)

def op_ctrl_announce_ack() -> str:
    return "ops { ctrl_announce_ack {} }"

def op_ctrl_mq_vq_pairs_set(pair_count: int) -> str:
    return ("ops { ctrl_mq_vq_pairs_set { pair_count: %d } }" % pair_count)

def op_ctrl_guest_offloads(offloads: int) -> str:
    return ("ops { ctrl_guest_offloads { offloads: %d } }" % offloads)

def op_ctrl_rss_config(hash_types: int, mask: int, unclassified: int,
                       indir: bytes, max_tx: int, hash_key: bytes) -> str:
    return ('ops { ctrl_rss_config { hash_types: %d '
            'indirection_table_mask: %d unclassified_queue: %d '
            'indirection_table: "%s" max_tx_vq: %d hash_key: "%s" } }'
            % (hash_types, mask, unclassified, escape_bytes(indir),
               max_tx, escape_bytes(hash_key)))

def op_host_set_link(up: bool) -> str:
    return ("ops { host_set_link { up: %s } }"
            % ('true' if up else 'false'))

def op_mem_write_absolute(gpa: int, data: bytes) -> str:
    return ('ops { mem_write_absolute { gpa: %d data: "%s" } }'
            % (gpa, escape_bytes(data)))

def op_mmio_corrupt(offset: int, value: int, size: int = 4) -> str:
    return ("ops { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))

def b_mmio_corrupt(offset: int, value: int, size: int = 4) -> str:
    return ("ops_thread_b { mmio_corrupt { offset: %d value: %d size: %d } }"
            % (offset, value, size))

def op_tx_packet_vlan(vq_idx: int, payload: bytes, vlan_tci: int) -> str:
    return (
        'ops { tx_packet { vq_idx: %d hdr_flags: 0 gso_type: 0 hdr_len: 0 '
        'gso_size: 0 csum_start: 0 csum_offset: 0 num_buffers: 0 '
        'vlan_tci: %d payload: "%s" } }'
        % (vq_idx, vlan_tci, escape_bytes(payload)))

# -- prologue: bring the device up to DRIVER_OK with N queues -------------

def prologue(features: int = DEFAULT_FEATURES,
             num_qpairs: int = 1,
             have_ctrl: bool = True) -> list:
    """
    Bring the device through the standard init dance:
      get_features -> set_features (sets FEATURES_OK) ->
      vq_setup for every queue -> set_status DRIVER_OK
    """
    ops = []
    ops.append(op_get_features())
    ops.append(op_set_features(features))
    # rxN, txN, ..., ctrl
    for q in range(2 * num_qpairs):
        ops.append(op_vq_setup(q, 64))
    if have_ctrl:
        ops.append(op_vq_setup(2 * num_qpairs, 64))
    ops.append(op_set_status(STATUS_DRIVER_OK))
    return ops


def emit(path: str, ops: list, header_comment: str):
    body = "# " + header_comment.strip().replace("\n", "\n# ") + "\n"
    body += "\n".join(ops) + "\n"
    with open(path, "w") as f:
        f.write(body)


# -- frame builders ------------------------------------------------------------

def eth_frame(dst_mac: bytes, src_mac: bytes,
              ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", ethertype) + payload


def arp_request(src_mac: bytes, src_ip: bytes,
                dst_ip: bytes) -> bytes:
    return struct.pack(
        "!HHBBH",
        0x0001,    # htype: ethernet
        0x0800,    # ptype: IPv4
        6, 4,      # hlen, plen
        0x0001,    # opcode: request
    ) + src_mac + src_ip + b"\x00" * 6 + dst_ip


def ipv4_tcp_payload() -> bytes:
    # Minimal IPv4 + TCP header, contents do not need to be
    # routable -- we just want the device to parse it.
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,        # ver/IHL
        0x00,        # tos
        20 + 20,     # total length
        0xbeef,      # id
        0x0000,      # flags+frag
        64,          # ttl
        6,           # proto: TCP
        0xdead,      # checksum (deliberately wrong; csum offload would fix)
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        12345, 80,   # src, dst port
        0,           # seq
        0,           # ack
        0x50,        # data offset
        0x02,        # flags: SYN
        0xffff,      # window
        0x0000,      # checksum (wrong on purpose)
        0,           # urgent
    )
    return ip + tcp


# -- seed builders -------------------------------------------------------------

def seed_init_only() -> tuple:
    return ("seed_01_init_only.textpb",
            "Bare init prologue: features negotiation + queue setup + "
            "DRIVER_OK. No I/O. Lets LPM mutate the prologue itself "
            "(skip steps, reorder, change feature bits, etc.).",
            prologue())


def seed_tx_arp() -> tuple:
    src_mac = b"\x52\x54\x00\x12\x34\x56"
    dst_mac = b"\xff\xff\xff\xff\xff\xff"
    payload = eth_frame(
        dst_mac, src_mac, 0x0806,
        arp_request(src_mac, b"\x0a\x00\x00\x02", b"\x0a\x00\x00\x01"))
    ops = prologue()
    ops.append(op_tx_packet(vq_idx=1, payload=payload))
    ops.append(op_vq_wait_used(1))
    return ("seed_02_tx_arp.textpb",
            "Init + send one ARP request. Smallest realistic ethernet "
            "frame; exercises virtio-net TX without any offload metadata.",
            ops)


def seed_tx_csum_offload() -> tuple:
    src_mac = b"\x52\x54\x00\x12\x34\x56"
    dst_mac = b"\x52\x54\x00\xab\xcd\xef"
    payload = eth_frame(dst_mac, src_mac, 0x0800, ipv4_tcp_payload())
    ops = prologue()
    ops.append(op_tx_packet(
        vq_idx=1, payload=payload,
        hdr_flags=1,        # VIRTIO_NET_HDR_F_NEEDS_CSUM
        csum_start=14 + 20, # eth + ip header bytes
        csum_offset=16))    # tcp checksum offset
    ops.append(op_vq_wait_used(1))
    return ("seed_03_tx_csum_offload.textpb",
            "Init + IPv4/TCP frame with VIRTIO_NET_HDR_F_NEEDS_CSUM and a "
            "valid csum_start/csum_offset. Drives the device's "
            "virtio_net_hdr_swap + checksum-offload path.",
            ops)


def seed_tx_gso() -> tuple:
    """
    A larger TCP segment with VIRTIO_NET_HDR_GSO_TCPV4. The device's
    GSO segmentation path was a recurring source of bugs upstream.
    """
    src_mac = b"\x52\x54\x00\x12\x34\x56"
    dst_mac = b"\x52\x54\x00\xab\xcd\xef"
    big = ipv4_tcp_payload() + b"\xaa" * 4096   # >MTU, will need GSO
    payload = eth_frame(dst_mac, src_mac, 0x0800, big)
    ops = prologue()
    ops.append(op_tx_packet(
        vq_idx=1, payload=payload,
        hdr_flags=1,        # VIRTIO_NET_HDR_F_NEEDS_CSUM
        gso_type=1,         # VIRTIO_NET_HDR_GSO_TCPV4
        hdr_len=14 + 20 + 20,   # eth + ip + tcp
        gso_size=1448,
        csum_start=14 + 20,
        csum_offset=16))
    ops.append(op_vq_wait_used(1))
    return ("seed_04_tx_gso_tcpv4.textpb",
            "Init + large TCPv4 frame with VIRTIO_NET_HDR_GSO_TCPV4. "
            "Hits the device's GSO segmentation logic.",
            ops)


def seed_ctrl_rx_promisc() -> tuple:
    ops = prologue()
    # promisc on
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_RX, cmd=CTRL_RX_PROMISC,
                           data=b"\x01"))
    ops.append(op_vq_wait_used(2))
    # promisc off
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_RX, cmd=CTRL_RX_PROMISC,
                           data=b"\x00"))
    ops.append(op_vq_wait_used(2))
    # allmulti / alluni / nobcast for completeness
    for cmd in (CTRL_RX_ALLMULTI, CTRL_RX_ALLUNI, CTRL_RX_NOBCAST):
        ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_RX, cmd=cmd,
                               data=b"\x01"))
        ops.append(op_vq_wait_used(2))
    return ("seed_05_ctrl_rx.textpb",
            "Init + several VIRTIO_NET_CTRL_RX subcommands "
            "(promisc/allmulti/alluni/nobcast on and off). Exercises the "
            "RX filter state machine.",
            ops)


def seed_ctrl_mac_addr() -> tuple:
    ops = prologue()
    new_mac = b"\x52\x54\xde\xad\xbe\xef"
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_MAC,
                           cmd=CTRL_MAC_ADDR_SET, data=new_mac))
    ops.append(op_vq_wait_used(2))
    return ("seed_06_ctrl_mac_addr_set.textpb",
            "Init + VIRTIO_NET_CTRL_MAC_ADDR_SET. Hits the new-MAC "
            "configuration path including the host backend's filter "
            "update.",
            ops)


def seed_ctrl_mac_table() -> tuple:
    """
    VIRTIO_NET_CTRL_MAC_TABLE_SET payload:
      le32 unicast_count, then unicast_count * 6 bytes of MACs,
      le32 multicast_count, then multicast_count * 6 bytes of MACs.
    """
    macs_uni = [b"\x52\x54\x00\xaa\xbb\x01",
                b"\x52\x54\x00\xaa\xbb\x02",
                b"\x52\x54\x00\xaa\xbb\x03"]
    macs_mul = [b"\x33\x33\x00\x00\x00\x01",
                b"\x01\x00\x5e\x00\x00\xfb"]
    data = (struct.pack("<I", len(macs_uni))
            + b"".join(macs_uni)
            + struct.pack("<I", len(macs_mul))
            + b"".join(macs_mul))
    ops = prologue()
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_MAC,
                           cmd=CTRL_MAC_TABLE_SET, data=data))
    ops.append(op_vq_wait_used(2))
    return ("seed_07_ctrl_mac_table.textpb",
            "Init + VIRTIO_NET_CTRL_MAC_TABLE_SET with three unicast "
            "and two multicast addresses. Drives the device's MAC table "
            "parser, which has had length-handling bugs in the past.",
            ops)


def seed_ctrl_vlan() -> tuple:
    ops = prologue()
    for vlan in (100, 200, 300):
        ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_VLAN,
                               cmd=CTRL_VLAN_ADD,
                               data=struct.pack("<H", vlan)))
        ops.append(op_vq_wait_used(2))
    # delete one
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_VLAN,
                           cmd=CTRL_VLAN_DEL,
                           data=struct.pack("<H", 200)))
    ops.append(op_vq_wait_used(2))
    return ("seed_08_ctrl_vlan.textpb",
            "Init + several VIRTIO_NET_CTRL_VLAN add/del commands. "
            "Exercises the VLAN filter bitmap.",
            ops)


def seed_ctrl_announce() -> tuple:
    ops = prologue()
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_ANNOUNCE,
                           cmd=CTRL_ANNOUNCE_ACK, data=b""))
    ops.append(op_vq_wait_used(2))
    return ("seed_09_ctrl_announce.textpb",
            "Init + VIRTIO_NET_CTRL_ANNOUNCE_ACK. Tiny path but worth "
            "covering.",
            ops)


def seed_ctrl_mq() -> tuple:
    """
    Multi-queue: set up 2 qpairs, then ask the device to switch to 2.
    """
    ops = prologue(num_qpairs=2)   # rx0,tx0,rx1,tx1,ctrl
    # CTRL_MQ_VQ_PAIRS_SET payload is a u16 pair count
    ops.append(op_ctrl_cmd(vq_idx=4, vclass=CTRL_MQ,
                           cmd=CTRL_MQ_VQ_PAIRS_SET,
                           data=struct.pack("<H", 2)))
    ops.append(op_vq_wait_used(4))
    return ("seed_10_ctrl_mq_vq_pairs.textpb",
            "Init with 2 queue pairs + VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET. "
            "Drives the multi-queue activation path.",
            ops)


def seed_ctrl_guest_offloads() -> tuple:
    """
    GUEST_OFFLOADS payload is a u64 of feature bits.
    """
    offloads = (VIRTIO_NET_F_GUEST_CSUM
                | VIRTIO_NET_F_GUEST_TSO4
                | VIRTIO_NET_F_GUEST_TSO6
                | VIRTIO_NET_F_GUEST_UFO
                | VIRTIO_NET_F_GUEST_ECN)
    ops = prologue()
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_GUEST_OFFLOADS,
                           cmd=CTRL_GUEST_OFFLOADS_SET,
                           data=struct.pack("<Q", offloads)))
    ops.append(op_vq_wait_used(2))
    return ("seed_11_ctrl_guest_offloads.textpb",
            "Init + VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET. Toggles the "
            "guest-side offload bits at runtime; relatively new code.",
            ops)


def seed_rx_buffers() -> tuple:
    """
    Stage receive buffers: write zero-filled buffers, add device-writable
    descriptors to RX queue 0, then poll. The device waits for actual
    network input which slirp may or may not synthesize, but the descriptor
    setup path is exercised regardless.
    """
    ops = prologue()
    for i in range(8):
        ops.append(op_guest_mem_write(buf_id=100 + i,
                                      data=b"\x00" * 1518))
        ops.append(op_vq_add_desc(vq_idx=0, buf_id=100 + i, length=1518,
                                  device_writable=True, chain_next=False))
    ops.append(op_vq_kick(0))
    ops.append(op_vq_wait_used(0))
    return ("seed_12_rx_buffers.textpb",
            "Init + 8 RX buffers added to receiveq[0]. Exercises the RX "
            "descriptor-publish path (bumping avail.idx for incoming "
            "packets).",
            ops)


def seed_full_session() -> tuple:
    """
    A combined session: multiple TX, multiple CVQ commands, ending with
    a reset. Long inputs help libFuzzer find sequence-dependent bugs.
    """
    src_mac = b"\x52\x54\x00\x12\x34\x56"
    dst_mac = b"\x52\x54\x00\xab\xcd\xef"
    ops = prologue()
    # reconfigure RX filter, then send some packets, then change MAC
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_RX,
                           cmd=CTRL_RX_PROMISC, data=b"\x01"))
    ops.append(op_vq_wait_used(2))
    for i in range(3):
        payload = eth_frame(dst_mac, src_mac, 0x0800,
                            ipv4_tcp_payload() + bytes([i]) * 32)
        ops.append(op_tx_packet(vq_idx=1, payload=payload))
        ops.append(op_vq_wait_used(1))
    ops.append(op_ctrl_cmd(vq_idx=2, vclass=CTRL_MAC,
                           cmd=CTRL_MAC_ADDR_SET,
                           data=b"\x52\x54\xde\xad\xbe\xef"))
    ops.append(op_vq_wait_used(2))
    payload = eth_frame(dst_mac, b"\x52\x54\xde\xad\xbe\xef",
                        0x0800, ipv4_tcp_payload())
    ops.append(op_tx_packet(vq_idx=1, payload=payload))
    ops.append(op_vq_wait_used(1))
    # finally, reset and re-init -- verifies clean teardown
    ops.append(op_reset())
    ops.append(op_set_status(STATUS_DRIVER_OK))
    return ("seed_13_full_session.textpb",
            "Init + RX filter change + 3 TX + MAC change + 1 TX + reset + "
            "re-init. Long stateful sequence.",
            ops)


def seed_minimal_no_features() -> tuple:
    """
    Only VIRTIO_F_VERSION_1: no CTRL_VQ, no MAC config etc. Negative
    space exploration -- what does the device do with a bare-minimum
    feature set.
    """
    ops = []
    ops.append(op_get_features())
    ops.append(op_set_features(VIRTIO_F_VERSION_1))
    ops.append(op_vq_setup(0, 64))
    ops.append(op_vq_setup(1, 64))
    ops.append(op_set_status(STATUS_DRIVER_OK))
    src_mac = b"\x52\x54\x00\x00\x00\x01"
    payload = eth_frame(b"\xff" * 6, src_mac, 0x0806,
                        arp_request(src_mac, b"\x00" * 4, b"\x00" * 4))
    ops.append(op_tx_packet(vq_idx=1, payload=payload))
    ops.append(op_vq_wait_used(1))
    return ("seed_14_minimal_no_ctrl_vq.textpb",
            "Init with ONLY VIRTIO_F_VERSION_1 -- no CTRL_VQ, no MAC, "
            "no MQ. Then send an ARP. Exercises the device's no-extras "
            "code path.",
            ops)


def seed_config_probe() -> tuple:
    """
    Bare prologue + repeated reads of device config space at varying
    offsets/sizes. The device config space holds MAC, status, MQ
    pair count, MTU, RSS-related fields. Bug-friendly area.
    """
    ops = prologue()
    for off in (0, 4, 6, 8, 10, 12, 16, 20):
        ops.append(op_config_read(off, 4))
    ops.append(op_config_read(0, 1))
    ops.append(op_config_read(0, 2))
    return ("seed_15_config_probe.textpb",
            "Init + many reads across the device config space (MAC, "
            "status, MQ, MTU, ...). Exercises virtio-net's "
            "config-readb/w/l handlers.",
            ops)


# -- main ---------------------------------------------------------------------

def seed_typed_rx_filter() -> tuple:
    """Typed CtrlRx: same coverage as the raw-bytes seed but LPM mutates
    the cmd / enable as typed ints, not as opaque payload bytes."""
    ops = prologue()
    for cmd in (CTRL_RX_PROMISC, CTRL_RX_ALLMULTI, CTRL_RX_ALLUNI,
                CTRL_RX_NOBCAST):
        ops.append(op_ctrl_rx(cmd, 1))
        ops.append(op_vq_wait_used(2))
        ops.append(op_ctrl_rx(cmd, 0))
        ops.append(op_vq_wait_used(2))
    return ("seed_16_typed_ctrl_rx.textpb",
            "Init + typed CtrlRx for every subcommand. LPM mutates cmd "
            "and enable as typed integers; sub-byte fuzzing of the RX "
            "filter state machine.",
            ops)


def seed_typed_mac_addr_set() -> tuple:
    ops = prologue()
    ops.append(op_ctrl_mac_addr_set(b"\x52\x54\xde\xad\xbe\xef"))
    ops.append(op_vq_wait_used(2))
    return ("seed_17_typed_mac_addr_set.textpb",
            "Init + typed CtrlMacAddrSet. The 6-byte MAC is now a typed "
            "field; LPM mutates it as bytes but inside a known-shaped "
            "envelope.",
            ops)


def seed_typed_mac_table() -> tuple:
    ops = prologue()
    ops.append(op_ctrl_mac_table_set(
        slot=0,
        unicast=[b"\x52\x54\x00\xaa\xbb\x01",
                 b"\x52\x54\x00\xaa\xbb\x02",
                 b"\x52\x54\x00\xaa\xbb\x03"],
        multicast=[b"\x33\x33\x00\x00\x00\x01",
                   b"\x01\x00\x5e\x00\x00\xfb"]))
    ops.append(op_vq_wait_used(2))
    return ("seed_18_typed_mac_table.textpb",
            "Init + typed CtrlMacTableSet with repeated bytes fields. "
            "LPM mutates list shape (add/remove MACs) and individual "
            "MAC bytes -- shape and byte fuzzing in one schema.",
            ops)


def seed_typed_vlan_state_aware() -> tuple:
    """STATE-AWARE example: add a VLAN into slot 0, then ask Del to
    consume slot 0. The VID isn't repeated in the Del op -- it's
    resolved through the harness's slot table at dispatch time."""
    ops = prologue()
    # add VID 100 into slot 0
    ops.append(op_ctrl_vlan_add(slot=0, vid=100))
    ops.append(op_vq_wait_used(2))
    # add VID 200 into slot 1
    ops.append(op_ctrl_vlan_add(slot=1, vid=200))
    ops.append(op_vq_wait_used(2))
    # delete via slot 0 (resolves to 100)
    ops.append(op_ctrl_vlan_del_slot(0))
    ops.append(op_vq_wait_used(2))
    # delete via raw VID
    ops.append(op_ctrl_vlan_del_vid(200))
    ops.append(op_vq_wait_used(2))
    return ("seed_19_typed_vlan_state_aware.textpb",
            "Init + Add(slot=0,vid=100), Add(slot=1,vid=200), "
            "Del(slot=0) which resolves to 100, Del(vid=200). "
            "Demonstrates the slot-aware dependency: the second add "
            "writes slot 1, the Del reads slot 0 -- LPM can mutate "
            "either independently, including 'add to slot N then del "
            "slot M' which usually produces 'delete VID 0' (a useful "
            "edge case).",
            ops)


def seed_typed_mq_pair_set() -> tuple:
    ops = prologue(num_qpairs=2)
    ops.append(op_ctrl_mq_vq_pairs_set(2))
    ops.append(op_vq_wait_used(4))
    return ("seed_20_typed_mq.textpb",
            "Init with 2 qpairs + typed CtrlMqVqPairsSet(2). The "
            "harness updates active_pairs after this, so subsequent "
            "ctrl_* ops automatically target the correct CVQ index.",
            ops)


def seed_typed_guest_offloads() -> tuple:
    offloads = (VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_GUEST_TSO4
                | VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_UFO
                | VIRTIO_NET_F_GUEST_ECN)
    ops = prologue()
    ops.append(op_ctrl_guest_offloads(offloads))
    ops.append(op_vq_wait_used(2))
    return ("seed_21_typed_guest_offloads.textpb",
            "Init + typed CtrlGuestOffloads(features). LPM mutates "
            "the u64 as a typed integer.",
            ops)


def seed_typed_rss_config() -> tuple:
    """RSS config: 16-entry indirection table mapping hashes to "
    "queue indices."""
    indir = b''
    for q in (0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0):
        indir += struct.pack("<H", q)
    hash_key = b"\x6d\x5a" * 20  # 40-byte hash key
    ops = prologue(num_qpairs=2)
    ops.append(op_ctrl_rss_config(
        hash_types=0x3f,        # all common types
        mask=15,                # 16-entry table (mask = N - 1)
        unclassified=0,
        indir=indir,
        max_tx=2,
        hash_key=hash_key))
    ops.append(op_vq_wait_used(4))
    return ("seed_22_typed_rss_config.textpb",
            "Init with 2 qpairs + typed CtrlRssConfig: 16-entry "
            "indirection table + 40-byte hash key. The RSS path is "
            "high-CVE; LPM mutates table shape, mask, hash bytes, "
            "etc., as typed fields.",
            ops)


def seed_typed_announce() -> tuple:
    ops = prologue()
    ops.append(op_ctrl_announce_ack())
    ops.append(op_vq_wait_used(2))
    return ("seed_23_typed_announce.textpb",
            "Init + typed CtrlAnnounceAck (empty payload).",
            ops)


def seed_dma_reflection() -> tuple:
    """DMA Reflection on TX queue: device-writable descs → own MMIO.
    buf_id=20 → QueueNotify (offset 0x050); buf_id=28 → QueueDescLow.
    Device DMA-writes to its own MMIO registers during TX processing.
    CVE-2024-3446 class."""
    ops = prologue()
    ops += [
        op_vq_add_desc(1, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(1, 44, 4, True,  False, exotic_region=2),
        op_vq_kick(1),
    ]
    return ("seed_dma_reflection.textpb",
            "DMA Reflection (TX queue, exotic_region=2): device-writable descs "
            "target own MMIO QueueNotify (buf_id=20) and QueueDescLow (buf_id=28). "
            "CVE-2024-3446 class.",
            ops)


def seed_dma_all_regions() -> tuple:
    """All four exotic GPA regions in one chain on the TX queue."""
    ops = prologue()
    ops += [
        op_vq_add_desc(1, 1,  4, False, True,  exotic_region=1),
        op_vq_add_desc(1, 20, 4, True,  True,  exotic_region=2),
        op_vq_add_desc(1, 0,  4, True,  True,  exotic_region=3),
        op_vq_add_desc(1, 0,  4, True,  False, exotic_region=4),
        op_vq_kick(1),
    ]
    return ("seed_dma_all_exotic_regions.textpb",
            "All four exotic GPA regions on TX queue: UART(1), own-MMIO "
            "Reflection(2), GIC(3), virt-mmio Refraction(4).",
            ops)


def seed_dma_reflection_concurrent() -> tuple:
    """Concurrent DMA Reflection: primary descs target own QueueNotify;
    secondary thread races with MMIO writes to the same register."""
    ops = prologue()
    ops += [
        op_vq_add_desc(1, 20, 4, True, True,  exotic_region=2),
        op_vq_add_desc(1, 44, 4, True, False, exotic_region=2),
        op_vq_kick(1),
        b_mmio_corrupt(0x050, 0),
        b_mmio_corrupt(0x070, 0),
        b_vq_add_desc(1, 20, 4, True, False, exotic_region=2),
    ]
    return ("seed_dma_reflection_concurrent.textpb",
            "Concurrent DMA Reflection (TX queue): primary reflection chain + "
            "thread_b racing with QueueNotify MMIO writes. CVE-2024-3446 class.",
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
        op_vq_add_desc(1, 0,   4, False, True,  exotic_region=2),
        # body: device WRITES to own Status register → potential soft-reset
        op_vq_add_desc(1, 28,  4, True,  True,  exotic_region=2),
        # tail: device continues with (possibly freed) state → UAF path
        op_vq_add_desc(1, 0,   4, True,  False, exotic_region=2),
        "ops { vq_kick { vq_idx: 1 } }",
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
        ops.append(op_vq_add_desc(1, 20, 4, True, True,  exotic_region=2))
    ops.append(op_vq_add_desc(1, 20, 4, True, False, exotic_region=2))
    ops.append("ops { vq_kick { vq_idx: 1 } }")
    return ("seed_dma_recursive_notify.textpb",
            "Endless-recursion test: 9-deep chain of descs all targeting "
            "QueueNotify (buf_id=20 → offset 0x050). Each DMA-write to "
            "QueueNotify may schedule another BH kick → deep recursion. "
            "Exercises QEMU recursion guard or triggers stack overflow.",
            ops)

SEED_BUILDERS = [
    seed_init_only,
    seed_tx_arp,
    seed_tx_csum_offload,
    seed_tx_gso,
    seed_ctrl_rx_promisc,
    seed_ctrl_mac_addr,
    seed_ctrl_mac_table,
    seed_ctrl_vlan,
    seed_ctrl_announce,
    seed_ctrl_mq,
    seed_ctrl_guest_offloads,
    seed_rx_buffers,
    seed_full_session,
    seed_minimal_no_features,
    seed_config_probe,
    # Typed CVQ seeds (device-aware, some state-aware) -------------
    seed_typed_rx_filter,
    seed_typed_mac_addr_set,
    seed_typed_mac_table,
    seed_typed_vlan_state_aware,
    seed_typed_mq_pair_set,
    seed_typed_guest_offloads,
    seed_typed_rss_config,
    seed_typed_announce,
    # Phase A addables -----------------------------------------------
    lambda: ("seed_24_host_set_link.textpb",
             "Init + flip the netdev link down then up via "
             "qmp_set_link. Drives the link_status_changed callback "
             "and the config-change interrupt path.",
             prologue() + [op_host_set_link(False),
                           op_host_set_link(True)]),
    lambda: ("seed_25_tx_vlan_tagged.textpb",
             "Init + send an 802.1Q-tagged frame via TxPacket.vlan_tci "
             "(harness inserts the 4-byte tag for us). Exercises the "
             "device's VLAN-tag stripping/forwarding logic.",
             prologue() + [
                 op_tx_packet_vlan(
                     vq_idx=1,
                     payload=eth_frame(b"\xff" * 6,
                                        b"\x52\x54\x00\x12\x34\x56",
                                        0x0800,
                                        ipv4_tcp_payload()),
                     vlan_tci=100),
                 op_vq_wait_used(1),
             ]),
    lambda: ("seed_26_fault_injection.textpb",
             "Init + MmioCorrupt across the virtio-mmio window + "
             "MemwriteAbsolute across the harness DRAM pool. "
             "Register-decoder and DMA-region fault injection.",
             prologue() + [
                 op_mmio_corrupt(offset=0x01c, value=0xdeadbeef, size=4),
                 op_mmio_corrupt(offset=0x028, value=0xcafebabe, size=4),
                 op_mmio_corrupt(offset=0x070, value=0, size=4),
                 op_mem_write_absolute(0x47000000, b"\xff" * 64),
                 op_mem_write_absolute(0x4700C000, b"\xaa" * 32),
             ]),
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
            i = rng.randrange(1, len(out))
            out.pop(i)
        elif strategy == "shuffle_tail":
            head_len = min(7, len(out))      # preserve prologue + 1-2 ops
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
    p.add_argument("-o", "--out", default="/tmp/proto_fuzz_run/corpus_net",
                   help="output directory (default: %(default)s)")
    p.add_argument("--clean", action="store_true",
                   help="remove existing files in the output directory "
                        "before generating")
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
