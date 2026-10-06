/*!
# Linux Offload Support Module

This module provides Generic Receive Offload (GRO) and Generic Segmentation Offload (GSO)
support for Linux TUN devices. These mechanisms can reduce per-packet processing overhead for
TCP and UDP traffic; the actual performance effect is workload- and host-dependent.

## Overview

Modern network cards and drivers use offload techniques to reduce CPU overhead:

- **GSO (Generic Segmentation Offload)**: Allows sending large packets that are segmented by
  the kernel/driver, reducing per-packet processing overhead.

- **GRO (Generic Receive Offload)**: Coalesces multiple received packets into larger segments,
  reducing the number of packets passed to the application.

This module implements GRO/GSO for TUN devices using the `virtio_net` header format, compatible
with the Linux kernel's TUN/TAP driver offload capabilities.

## Performance Characteristics

Offload reduces the number of packet-sized operations visible to userspace and can reduce
per-packet CPU/syscall overhead. Throughput and CPU improvement are deliberately not specified
as fixed ratios; they depend on workload, kernel, transport state, and host capabilities.

## Usage

Enable offload when building a device:

```no_run
# #[cfg(target_os = "linux")]
# {
use tun_rs::{DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};

let dev = DeviceBuilder::new()
    .offload(true)  // Enable offload
    .ipv4("10.0.0.1", 24, None)
    .build_sync()?;

// Allocate buffers for batch operations
let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
let mut sizes = vec![0; IDEAL_BATCH_SIZE];

// Create GRO table for coalescing
let mut gro_table = GROTable::default();

loop {
    // Receive multiple packets at once
    let num = dev.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)?;

    for i in 0..num {
        // Process each packet
        println!("Packet {}: {} bytes", i, sizes[i]);
    }
}
# }
# Ok::<(), std::io::Error>(())
```

## Key Types

- [`VirtioNetHdr`]: Header structure for virtio network offload
- [`GROTable`]: Manages TCP and UDP flow coalescing for GRO
- [`TcpGROTable`]: TCP-specific GRO state
- [`UdpGROTable`]: UDP-specific GRO state

## Key Functions

- [`handle_gro`]: Process received packets and perform GRO coalescing
- [`gso_split`]: Split a GSO packet into multiple segments
- [`apply_tcp_coalesce_accounting`]: Update TCP headers after coalescing

## Constants

- [`VIRTIO_NET_HDR_LEN`]: Size of the virtio network header (10 bytes)
- [`IDEAL_BATCH_SIZE`]: Recommended batch size for packet operations (128)
- [`VIRTIO_NET_HDR_GSO_NONE`], [`VIRTIO_NET_HDR_GSO_TCPV4`], etc.: GSO type constants

## References

- [Linux virtio_net.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_net.h)
- [WireGuard-go offload implementation](https://github.com/WireGuard/wireguard-go/blob/master/tun/offload_linux.go)

## Platform Requirements

- Linux kernel with TUN/TAP driver
- Kernel support for `IFF_VNET_HDR` (available since Linux 2.6.32)
- Root privileges to create TUN devices with offload enabled
*/

/// <https://github.com/WireGuard/wireguard-go/blob/master/tun/offload_linux.go>
use crate::platform::linux::checksum::{checksum, pseudo_header_checksum_no_fold};
use bytes::BytesMut;
use libc::{IPPROTO_TCP, IPPROTO_UDP};
use std::io;

#[inline]
const fn read_be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

#[inline]
const fn read_be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[inline]
fn write_be_u16(bytes: &mut [u8], value: u16) {
    bytes[..2].copy_from_slice(&value.to_be_bytes());
}

#[inline]
fn write_be_u32(bytes: &mut [u8], value: u32) {
    bytes[..4].copy_from_slice(&value.to_be_bytes());
}

/// GSO type: Not a GSO frame (normal packet).
///
/// This indicates a regular packet without Generic Segmentation Offload applied.
/// See: <https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_net.h>
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;

const GRO_FLOW_TABLE_SLOTS: usize = IDEAL_BATCH_SIZE * 2;

const fn mix_flow_word(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn mix_flow_bytes(bytes: &[u8; 16]) -> u64 {
    let lo = u64::from_ne_bytes(bytes[..8].try_into().unwrap_or_default());
    let hi = u64::from_ne_bytes(bytes[8..].try_into().unwrap_or_default());
    mix_flow_word(lo ^ hi.rotate_left(23))
}

trait GroFlowKey: Copy + Eq {
    fn flow_hash(self) -> u64;
}

enum GroLookup {
    Occupied(usize),
    Vacant(usize),
    Full,
}

struct GroFlowTable<K, I> {
    slots: Vec<Option<(K, Vec<I>)>>,
    occupied: Vec<usize>,
    items_pool: Vec<Vec<I>>,
}

impl<K: GroFlowKey, I> GroFlowTable<K, I> {
    fn empty_slots(count: usize) -> Vec<Option<(K, Vec<I>)>> {
        let mut slots = Vec::with_capacity(count);
        slots.resize_with(count, || None);
        slots
    }

    fn new() -> Self {
        let mut items_pool = Vec::with_capacity(IDEAL_BATCH_SIZE);
        for _ in 0..IDEAL_BATCH_SIZE {
            items_pool.push(Vec::with_capacity(IDEAL_BATCH_SIZE));
        }
        Self {
            slots: Self::empty_slots(GRO_FLOW_TABLE_SLOTS),
            occupied: Vec::with_capacity(IDEAL_BATCH_SIZE),
            items_pool,
        }
    }

    fn find(&self, key: K) -> GroLookup {
        let mask = self.slots.len() - 1;
        let hash = key.flow_hash().to_le_bytes();
        let start = usize::from(u16::from_le_bytes([hash[0], hash[1]])) & mask;
        for probe in 0..self.slots.len() {
            let index = (start + probe) & mask;
            match &self.slots[index] {
                Some((existing, _)) if *existing == key => return GroLookup::Occupied(index),
                Some(_) => {}
                None => return GroLookup::Vacant(index),
            }
        }
        GroLookup::Full
    }

    fn grow(&mut self) {
        let new_len = self.slots.len().saturating_mul(2);
        let old_slots = std::mem::replace(&mut self.slots, Self::empty_slots(new_len));
        self.occupied.clear();
        for entry in old_slots.into_iter().flatten() {
            let index = match self.find(entry.0) {
                GroLookup::Vacant(index) => index,
                GroLookup::Occupied(_) | GroLookup::Full => {
                    unreachable!("freshly grown GRO flow table must have a vacant slot")
                }
            };
            self.slots[index] = Some(entry);
            self.occupied.push(index);
        }
    }

    fn lookup_or_insert(&mut self, key: K, item: I) -> Option<&mut Vec<I>> {
        let index = loop {
            match self.find(key) {
                GroLookup::Occupied(index) => {
                    return self.slots[index].as_mut().map(|(_, items)| items);
                }
                GroLookup::Vacant(index) => break index,
                GroLookup::Full => self.grow(),
            }
        };
        let mut items = self.items_pool.pop().unwrap_or_default();
        items.push(item);
        self.slots[index] = Some((key, items));
        self.occupied.push(index);
        None
    }

    fn insert(&mut self, key: K, item: I) {
        let index = loop {
            match self.find(key) {
                GroLookup::Occupied(index) | GroLookup::Vacant(index) => break index,
                GroLookup::Full => self.grow(),
            }
        };
        if self.slots[index].is_none() {
            let items = self.items_pool.pop().unwrap_or_default();
            self.slots[index] = Some((key, items));
            self.occupied.push(index);
        }
        if let Some((_, items)) = &mut self.slots[index] {
            items.push(item);
        }
    }

    fn reset(&mut self) {
        for index in self.occupied.drain(..) {
            if let Some((_, mut items)) = self.slots[index].take() {
                items.clear();
                self.items_pool.push(items);
            }
        }
    }

    fn values(&self) -> impl Iterator<Item = &Vec<I>> {
        self.occupied
            .iter()
            .filter_map(|&index| self.slots[index].as_ref().map(|(_, items)| items))
    }
}

/// Flag: Use `csum_start` and `csum_offset` fields for checksum calculation.
///
/// When this flag is set, the packet requires checksum calculation.
/// The `csum_start` field indicates where checksumming should begin,
/// and `csum_offset` indicates where to write the checksum.
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

/// GSO type: IPv4 TCP segmentation (TSO - TCP Segmentation Offload).
///
/// Large TCP packets can be sent and will be segmented by the kernel/driver.
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;

/// GSO type: IPv6 TCP segmentation (TSO).
///
/// Similar to TCPV4 but for IPv6 packets.
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;

/// GSO type: UDP segmentation for IPv4 and IPv6 (USO - UDP Segmentation Offload).
///
/// Available in newer Linux kernels for UDP packet segmentation.
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;

/// Flag combined with a TCP GSO type when Explicit Congestion Notification is active.
///
/// Linux masks this bit before identifying the base GSO type and maps it to
/// `SKB_GSO_TCP_ECN`. It is not a standalone GSO type.
pub const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Recommended batch size for packet operations with offload.
///
/// This is the crate's default batch-size heuristic for `recv_multiple`/`send_multiple`,
/// inherited from WireGuard-go rather than a Linux ABI requirement. It balances:
/// - Amortizing system call overhead
/// - Keeping latency reasonable
/// - Memory usage for packet buffers
///
/// Based on WireGuard-go's implementation.
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::IDEAL_BATCH_SIZE;
///
/// // Allocate buffers for batch operations
/// let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
/// let mut sizes = vec![0; IDEAL_BATCH_SIZE];
/// # }
/// ```
///
/// See: <https://github.com/WireGuard/wireguard-go/blob/master/conn/conn.go#L19>
pub const IDEAL_BATCH_SIZE: usize = 128;

const TCP_FLAGS_OFFSET: usize = 13;

const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_PSH: u8 = 0x08;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_CWR: u8 = 0x80;

#[expect(
    clippy::cast_possible_truncation,
    reason = "libc IPPROTO_TCP and IPPROTO_UDP are ABI constants 6 and 17"
)]
const IPPROTO_TCP_U8: u8 = IPPROTO_TCP as u8;
#[expect(
    clippy::cast_possible_truncation,
    reason = "libc IPPROTO_TCP and IPPROTO_UDP are ABI constants 6 and 17"
)]
pub(super) const IPPROTO_UDP_U8: u8 = IPPROTO_UDP as u8;

fn checked_u16_len(value: usize, message: &'static str) -> io::Result<u16> {
    u16::try_from(value).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, message))
}

/// Virtio network header for offload support.
///
/// This structure precedes each packet when offload is enabled on a Linux TUN device.
/// It provides metadata about Generic Segmentation Offload (GSO) and checksum requirements,
/// allowing the kernel to perform hardware-accelerated operations.
///
/// The header matches the Linux kernel's `virtio_net_hdr` structure defined in
/// `include/uapi/linux/virtio_net.h`.
///
/// # Memory Layout
///
/// The legacy Linux `struct virtio_net_hdr` represented here is 10 bytes
/// ([`VIRTIO_NET_HDR_LEN`]). The crate's TUN path leaves the cross-endian
/// `TUNSETVNETLE`/`TUNSETVNETBE` modes unset, so the kernel uses legacy host
/// endianness and these helpers encode/decode multi-byte fields with native endianness.
/// They must not be used unchanged for a TUN file descriptor explicitly configured for
/// cross-endian vnet headers.
///
/// # Usage
///
/// When reading from a TUN device with offload enabled:
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::{VirtioNetHdr, VIRTIO_NET_HDR_LEN};
///
/// let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + 1500];
/// // let n = dev.recv(&mut buf)?;
///
/// // Decode the header
/// // let hdr = VirtioNetHdr::decode(&buf[..VIRTIO_NET_HDR_LEN])?;
/// // let packet = &buf[VIRTIO_NET_HDR_LEN..n];
/// # }
/// ```
///
/// # Fields
///
/// - `flags`: Bit flags for header processing (e.g., [`VIRTIO_NET_HDR_F_NEEDS_CSUM`])
/// - `gso_type`: Type of GSO applied (e.g., [`VIRTIO_NET_HDR_GSO_TCPV4`])
/// - `hdr_len`: Length of packet headers (Ethernet + IP + TCP/UDP)
/// - `gso_size`: Maximum segment size for GSO
/// - `csum_start`: Offset to start checksum calculation
/// - `csum_offset`: Offset within checksum area to store the checksum
///
/// # References
///
/// - [Linux virtio_net.h](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_net.h)
///
/// See: <https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_net.h>
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct VirtioNetHdr {
    // #define VIRTIO_NET_HDR_F_NEEDS_CSUM	1	/* Use csum_start, csum_offset */
    // #define VIRTIO_NET_HDR_F_DATA_VALID	2	/* Csum is valid */
    // #define VIRTIO_NET_HDR_F_RSC_INFO	4	/* rsc info in csum_ fields */
    pub flags: u8,
    // #define VIRTIO_NET_HDR_GSO_NONE		0	/* Not a GSO frame */
    // #define VIRTIO_NET_HDR_GSO_TCPV4	1	/* GSO frame, IPv4 TCP (TSO) */
    // #define VIRTIO_NET_HDR_GSO_UDP		3	/* GSO frame, IPv4 UDP (UFO) */
    // #define VIRTIO_NET_HDR_GSO_TCPV6	4	/* GSO frame, IPv6 TCP */
    // #define VIRTIO_NET_HDR_GSO_UDP_L4	5	/* GSO frame, IPv4& IPv6 UDP (USO) */
    // #define VIRTIO_NET_HDR_GSO_ECN		0x80	/* TCP has ECN set */
    pub gso_type: u8,
    // Ethernet + IP + tcp/udp hdrs
    pub hdr_len: u16,
    // Bytes to append to hdr_len per frame
    pub gso_size: u16,
    // Checksum calculation
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VirtioNetHdr {
    /// Decode a virtio network header from a byte buffer.
    ///
    /// Reads the first [`VIRTIO_NET_HDR_LEN`] bytes from the buffer and interprets
    /// them as a `VirtioNetHdr` structure.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short (less than [`VIRTIO_NET_HDR_LEN`] bytes).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(target_os = "linux")]
    /// # {
    /// use tun_rs::{VirtioNetHdr, VIRTIO_NET_HDR_LEN};
    ///
    /// let buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 1500];
    /// let header = VirtioNetHdr::decode(&buffer)?;
    /// println!("GSO type: {:?}", header.gso_type);
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn decode(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < VIRTIO_NET_HDR_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "too short"));
        }
        Ok(Self {
            flags: buf[0],
            gso_type: buf[1],
            hdr_len: u16::from_ne_bytes([buf[2], buf[3]]),
            gso_size: u16::from_ne_bytes([buf[4], buf[5]]),
            csum_start: u16::from_ne_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_ne_bytes([buf[8], buf[9]]),
        })
    }

    /// Encode a virtio network header into a byte buffer.
    ///
    /// Writes this header into the first [`VIRTIO_NET_HDR_LEN`] bytes of the buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too short (less than [`VIRTIO_NET_HDR_LEN`] bytes).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(target_os = "linux")]
    /// # {
    /// use tun_rs::{VirtioNetHdr, VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN};
    ///
    /// let header = VirtioNetHdr {
    ///     gso_type: VIRTIO_NET_HDR_GSO_NONE,
    ///     ..Default::default()
    /// };
    ///
    /// let mut buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 1500];
    /// header.encode(&mut buffer)?;
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn encode(&self, buf: &mut [u8]) -> io::Result<()> {
        if buf.len() < VIRTIO_NET_HDR_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "too short"));
        }
        buf[0] = self.flags;
        buf[1] = self.gso_type;
        buf[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        buf[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        buf[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        buf[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        Ok(())
    }
}

/// Size of the virtio network header in bytes (10 bytes).
///
/// This constant is the size of the legacy `VirtioNetHdr` represented by this crate.
/// Linux TUN initializes its vnet-header size to this legacy structure size; Linux also
/// exposes ioctls for larger/newer header layouts, which this type does not model.
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::VIRTIO_NET_HDR_LEN;
///
/// // Allocate buffer with space for header + packet
/// let mut buffer = vec![0u8; VIRTIO_NET_HDR_LEN + 1500];
///
/// // Header is at the start
/// // let header_bytes = &buffer[..VIRTIO_NET_HDR_LEN];
/// // Packet data follows the header
/// // let packet_data = &buffer[VIRTIO_NET_HDR_LEN..];
/// # }
/// ```
pub const VIRTIO_NET_HDR_LEN: usize = std::mem::size_of::<VirtioNetHdr>();

/// Identifier for a TCP flow used in Generic Receive Offload (GRO).
///
/// This structure uniquely identifies a TCP connection for packet coalescing.
/// Packets belonging to the same flow can be coalesced into larger segments,
/// reducing per-packet processing overhead.
///
/// # Fields
///
/// The flow is identified by:
/// - Source and destination IP addresses (IPv4 or IPv6)
/// - Source and destination ports
/// - TCP acknowledgment number (to avoid coalescing segments with different ACKs)
/// - IP version flag
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct TcpFlowKey {
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
    src_port: u16,
    dst_port: u16,
    rx_ack: u32, // varying ack values should not be coalesced. Treat them as separate flows.
    is_v6: bool,
}

/// TCP Generic Receive Offload (GRO) table.
///
/// Manages the coalescing of TCP packets belonging to the same flow into larger segments.
/// This reduces the number of packets that need to be processed by the application,
/// improving throughput and reducing CPU usage.
///
/// # How TCP GRO Works
///
/// 1. Packets are received from the TUN device
/// 2. The GRO table identifies packets belonging to the same TCP flow
/// 3. Consecutive packets in the same flow are coalesced into a single large segment
/// 4. The coalesced segment is passed to the application
///
/// # Usage
///
/// The GRO table is typically used in conjunction with [`handle_gro`]:
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::GROTable;
///
/// let mut gro_table = GROTable::default();
///
/// // Process received packets
/// // handle_gro(..., &mut gro_table, ...)?;
/// # }
/// ```
///
/// # Performance Considerations
///
/// - Maintains a compact open-addressed table of active flows
/// - Preallocates buffers for [`IDEAL_BATCH_SIZE`] flows
/// - Memory pooling reduces allocations
/// - State is maintained across multiple `recv_multiple` calls
pub struct TcpGROTable {
    items_by_flow: GroFlowTable<TcpFlowKey, TcpGROItem>,
}

impl Default for TcpGROTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpGROTable {
    fn new() -> Self {
        Self {
            items_by_flow: GroFlowTable::new(),
        }
    }
}

impl TcpFlowKey {
    fn new(pkt: &[u8], src_addr_offset: usize, dst_addr_offset: usize, tcph_offset: usize) -> Self {
        let mut key = Self {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
            rx_ack: 0,
            is_v6: false,
        };

        let addr_size = dst_addr_offset - src_addr_offset;
        key.src_addr[..addr_size].copy_from_slice(&pkt[src_addr_offset..dst_addr_offset]);
        key.dst_addr[..addr_size]
            .copy_from_slice(&pkt[dst_addr_offset..dst_addr_offset + addr_size]);
        key.src_port = read_be_u16(&pkt[tcph_offset..]);
        key.dst_port = read_be_u16(&pkt[tcph_offset + 2..]);
        key.rx_ack = read_be_u32(&pkt[tcph_offset + 8..]);
        key.is_v6 = addr_size == 16;
        key
    }
}

impl GroFlowKey for TcpFlowKey {
    fn flow_hash(self) -> u64 {
        let ports = (u64::from(self.src_port) << 48)
            | (u64::from(self.dst_port) << 32)
            | u64::from(self.rx_ack);
        let version = u64::from(self.is_v6);
        let hash = mix_flow_bytes(&self.src_addr)
            ^ mix_flow_bytes(&self.dst_addr).rotate_left(17)
            ^ mix_flow_word(ports ^ version);
        mix_flow_word(hash)
    }
}

impl TcpGROTable {
    /// Looks up the flow for `item`, inserting it when the flow is new.
    ///
    /// Returns the existing items for an occupied flow, or `None` after
    /// inserting the first item for a new flow.
    fn lookup_or_insert(&mut self, item: TcpGROItem) -> Option<&mut Vec<TcpGROItem>> {
        self.items_by_flow.lookup_or_insert(item.key, item)
    }

    /// Inserts an additional item for an existing or newly recreated flow.
    fn insert(&mut self, item: TcpGROItem) {
        self.items_by_flow.insert(item.key, item);
    }
}
// func (t *tcpGROTable) updateAt(item tcpGROItem, i int) {
// 	items, _ := t.itemsByFlow[item.key]
// 	items[i] = item
// }
//
// func (t *tcpGROTable) deleteAt(key tcpFlowKey, i int) {
// 	items, _ := t.itemsByFlow[key]
// 	items = append(items[:i], items[i+1:]...)
// 	t.itemsByFlow[key] = items
// }

/// tcpGROItem represents bookkeeping data for a TCP packet during the lifetime
/// of a GRO evaluation across a vector of packets.
#[derive(Debug, Clone, Copy)]
pub struct TcpGROItem {
    key: TcpFlowKey,
    sent_seq: u32,   // the sequence number
    bufs_index: u16, // the index into the original bufs slice
    num_merged: u16, // the number of packets merged into this item
    gso_size: u16,   // payload size
    iph_len: u8,     // ip header len
    tcph_len: u8,    // tcp header len
    psh_set: bool,   // psh flag is set
}

// func (t *tcpGROTable) newItems() []tcpGROItem {
// 	var items []tcpGROItem
// 	items, t.itemsPool = t.itemsPool[len(t.itemsPool)-1], t.itemsPool[:len(t.itemsPool)-1]
// 	return items
// }
impl TcpGROTable {
    fn reset(&mut self) {
        self.items_by_flow.reset();
    }
}

/// udpFlowKey represents the key for a UDP flow.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct UdpFlowKey {
    src_addr: [u8; 16], // srcAddr
    dst_addr: [u8; 16], // dstAddr
    src_port: u16,      // srcPort
    dst_port: u16,      // dstPort
    is_v6: bool,        // isV6
}

///  udpGROTable holds flow and coalescing information for the purposes of UDP GRO.
pub struct UdpGROTable {
    items_by_flow: GroFlowTable<UdpFlowKey, UdpGROItem>,
}

impl Default for UdpGROTable {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpGROTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            items_by_flow: GroFlowTable::new(),
        }
    }
}

impl UdpFlowKey {
    #[must_use]
    pub fn new(
        pkt: &[u8],
        src_addr_offset: usize,
        dst_addr_offset: usize,
        udph_offset: usize,
    ) -> Self {
        let mut key = Self {
            src_addr: [0; 16],
            dst_addr: [0; 16],
            src_port: 0,
            dst_port: 0,
            is_v6: false,
        };
        let addr_size = dst_addr_offset - src_addr_offset;
        key.src_addr[..addr_size].copy_from_slice(&pkt[src_addr_offset..dst_addr_offset]);
        key.dst_addr[..addr_size]
            .copy_from_slice(&pkt[dst_addr_offset..dst_addr_offset + addr_size]);
        key.src_port = read_be_u16(&pkt[udph_offset..]);
        key.dst_port = read_be_u16(&pkt[udph_offset + 2..]);
        key.is_v6 = addr_size == 16;
        key
    }
}

impl GroFlowKey for UdpFlowKey {
    fn flow_hash(self) -> u64 {
        let ports = (u64::from(self.src_port) << 16) | u64::from(self.dst_port);
        let version = u64::from(self.is_v6);
        let hash = mix_flow_bytes(&self.src_addr)
            ^ mix_flow_bytes(&self.dst_addr).rotate_left(17)
            ^ mix_flow_word(ports ^ version);
        mix_flow_word(hash)
    }
}

impl UdpGROTable {
    /// Looks up the flow for `item`, inserting it when the flow is new.
    ///
    /// Returns the existing items for an occupied flow, or `None` after
    /// inserting the first item for a new flow.
    fn lookup_or_insert(&mut self, item: UdpGROItem) -> Option<&mut Vec<UdpGROItem>> {
        self.items_by_flow.lookup_or_insert(item.key, item)
    }

    /// Inserts an additional item for an existing or newly recreated flow.
    fn insert(&mut self, item: UdpGROItem) {
        self.items_by_flow.insert(item.key, item);
    }
}
// func (u *udpGROTable) updateAt(item udpGROItem, i int) {
// 	items, _ := u.itemsByFlow[item.key]
// 	items[i] = item
// }

/// udpGROItem represents bookkeeping data for a UDP packet during the lifetime
/// of a GRO evaluation across a vector of packets.
#[derive(Debug, Clone, Copy)]
pub struct UdpGROItem {
    key: UdpFlowKey,           // udpFlowKey
    bufs_index: u16,           // the index into the original bufs slice
    num_merged: u16,           // the number of packets merged into this item
    gso_size: u16,             // payload size
    iph_len: u8,               // ip header len
    c_sum_known_invalid: bool, // UDP header checksum validity; a false value DOES NOT imply valid, just unknown.
}
// func (u *udpGROTable) newItems() []udpGROItem {
// 	var items []udpGROItem
// 	items, u.itemsPool = u.itemsPool[len(u.itemsPool)-1], u.itemsPool[:len(u.itemsPool)-1]
// 	return items
// }

impl UdpGROTable {
    fn reset(&mut self) {
        self.items_by_flow.reset();
    }
}

/// canCoalesce represents the outcome of checking if two TCP packets are
/// candidates for coalescing.
#[derive(Copy, Clone, Eq, PartialEq)]
enum CanCoalesce {
    Prepend,
    Unavailable,
    Append,
}

/// ipHeadersCanCoalesce returns true if the IP headers found in pktA and pktB
/// meet all requirements to be merged as part of a GRO operation, otherwise it
/// returns false.
const fn ip_headers_can_coalesce(pkt_a: &[u8], pkt_b: &[u8]) -> bool {
    if pkt_a.len() < 9 || pkt_b.len() < 9 {
        return false;
    }

    if pkt_a[0] >> 4 == 6 {
        if pkt_a[0] != pkt_b[0] || pkt_a[1] >> 4 != pkt_b[1] >> 4 {
            // cannot coalesce with unequal Traffic class values
            return false;
        }
        if pkt_a[7] != pkt_b[7] {
            // cannot coalesce with unequal Hop limit values
            return false;
        }
    } else {
        if pkt_a[1] != pkt_b[1] {
            // cannot coalesce with unequal ToS values
            return false;
        }
        if pkt_a[6] >> 5 != pkt_b[6] >> 5 {
            // cannot coalesce with unequal DF or reserved bits. MF is checked
            // further up the stack.
            return false;
        }
        if pkt_a[8] != pkt_b[8] {
            // cannot coalesce with unequal TTL values
            return false;
        }
    }

    true
}

/// udpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
/// described by item. iphLen and gsoSize describe pkt. bufs is the vector of
/// packets involved in the current GRO evaluation. bufsOffset is the offset at
/// which packet data begins within bufs.
fn udp_packets_can_coalesce(
    pkt: &[u8],
    iph_len: u8,
    gso_size: u16,
    item: &UdpGROItem,
    pkt_target: &[u8],
) -> CanCoalesce {
    if !ip_headers_can_coalesce(pkt, pkt_target) {
        return CanCoalesce::Unavailable;
    }
    if !pkt_target[(usize::from(iph_len) + UDP_H_LEN)..]
        .len()
        .is_multiple_of(usize::from(item.gso_size))
    {
        // A smaller than gsoSize packet has been appended previously.
        // Nothing can come after a smaller packet on the end.
        return CanCoalesce::Unavailable;
    }
    if gso_size > item.gso_size {
        // We cannot have a larger packet following a smaller one.
        return CanCoalesce::Unavailable;
    }
    CanCoalesce::Append
}

/// tcpPacketsCanCoalesce evaluates if pkt can be coalesced with the packet
/// described by item. This function makes considerations that match the kernel's
/// GRO self tests, which can be found in tools/testing/selftests/net/gro.c.
#[expect(
    clippy::too_many_arguments,
    reason = "the GRO predicate mirrors independent TCP coalescing constraints"
)]
fn tcp_packets_can_coalesce(
    pkt: &[u8],
    iph_len: u8,
    tcph_len: u8,
    seq: u32,
    psh_set: bool,
    gso_size: u16,
    item: &TcpGROItem,
    pkt_target: &[u8],
) -> CanCoalesce {
    if tcph_len != item.tcph_len {
        // cannot coalesce with unequal tcp options len
        return CanCoalesce::Unavailable;
    }

    if tcph_len > 20
        && pkt[usize::from(iph_len) + 20..usize::from(iph_len) + usize::from(tcph_len)]
            != pkt_target
                [usize::from(item.iph_len) + 20..usize::from(item.iph_len) + usize::from(tcph_len)]
    {
        // cannot coalesce with unequal tcp options
        return CanCoalesce::Unavailable;
    }

    if !ip_headers_can_coalesce(pkt, pkt_target) {
        return CanCoalesce::Unavailable;
    }

    // seq adjacency
    let lhs_len = u32::from(item.gso_size) * (u32::from(item.num_merged) + 1);

    if seq == item.sent_seq.wrapping_add(lhs_len) {
        // pkt aligns following item from a seq num perspective
        if item.psh_set {
            // We cannot append to a segment that has the PSH flag set, PSH
            // can only be set on the final segment in a reassembled group.
            return CanCoalesce::Unavailable;
        }

        if !pkt_target[usize::from(iph_len) + usize::from(tcph_len)..]
            .len()
            .is_multiple_of(usize::from(item.gso_size))
        {
            // A smaller than gsoSize packet has been appended previously.
            // Nothing can come after a smaller packet on the end.
            return CanCoalesce::Unavailable;
        }

        if gso_size > item.gso_size {
            // We cannot have a larger packet following a smaller one.
            return CanCoalesce::Unavailable;
        }

        return CanCoalesce::Append;
    }

    if seq.wrapping_add(u32::from(gso_size)) == item.sent_seq {
        // pkt aligns in front of item from a seq num perspective
        if psh_set {
            // We cannot prepend with a segment that has the PSH flag set,
            // which can only appear on the final segment.
            return CanCoalesce::Unavailable;
        }

        if gso_size < item.gso_size {
            // We cannot have a larger packet following a smaller one.
            return CanCoalesce::Unavailable;
        }

        if gso_size > item.gso_size && item.num_merged > 0 {
            // Multiple smaller packets may not trail a larger prepend.
            return CanCoalesce::Unavailable;
        }

        return CanCoalesce::Prepend;
    }

    CanCoalesce::Unavailable
}

fn checksum_valid(pkt: &[u8], iph_len: u8, proto: u8, is_v6: bool) -> bool {
    let (src_addr_at, addr_size) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };
    let iph_len = usize::from(iph_len);
    let Some(addresses_end) = src_addr_at.checked_add(addr_size * 2) else {
        return false;
    };
    if iph_len > pkt.len() || addresses_end > pkt.len() {
        return false;
    }

    let Ok(pkt_len) = u16::try_from(pkt.len()) else {
        return false;
    };
    let Ok(iph_len_u16) = u16::try_from(iph_len) else {
        return false;
    };
    let Some(len_for_pseudo) = pkt_len.checked_sub(iph_len_u16) else {
        return false;
    };

    let c_sum = pseudo_header_checksum_no_fold(
        proto,
        &pkt[src_addr_at..src_addr_at + addr_size],
        &pkt[src_addr_at + addr_size..addresses_end],
        len_for_pseudo,
    );

    (!checksum(&pkt[iph_len..], c_sum)) == 0
}

/// coalesceResult represents the result of attempting to coalesce two TCP
/// packets.
enum CoalesceResult {
    InsufficientCap,
    PSHEnding,
    ItemInvalidCSum,
    PktInvalidCSum,
    Success,
}

/// coalesceUDPPackets attempts to coalesce pkt with the packet described by
/// item, and returns the outcome.
fn coalesce_udp_packets<B: ExpandBuffer>(
    current: &B,
    target: &mut B,
    item: &mut UdpGROItem,
    bufs_offset: usize,
    is_v6: bool,
) -> CoalesceResult {
    let pkt = &current.as_ref()[bufs_offset..];
    let target_packet = &target.as_ref()[bufs_offset..];
    let headers_len = usize::from(item.iph_len) + UDP_H_LEN;
    let coalesced_len = target_packet.len() + pkt.len() - headers_len;
    if target.buf_capacity() < bufs_offset * 2 + coalesced_len {
        return CoalesceResult::InsufficientCap;
    }

    if item.num_merged == 0
        && (item.c_sum_known_invalid
            || !checksum_valid(target_packet, item.iph_len, IPPROTO_UDP_U8, is_v6))
    {
        return CoalesceResult::ItemInvalidCSum;
    }

    if !checksum_valid(pkt, item.iph_len, IPPROTO_UDP_U8, is_v6) {
        return CoalesceResult::PktInvalidCSum;
    }
    target.buf_extend_from_slice(&pkt[headers_len..]);
    item.num_merged += 1;
    CoalesceResult::Success
}

/// coalesceTCPPackets attempts to coalesce pkt with the packet described by
/// item, and returns the outcome. This function may swap bufs elements in the
/// event of a prepend as item's bufs index is already being tracked for writing
/// to a Device.
#[expect(
    clippy::too_many_arguments,
    reason = "coalescing needs packet metadata already parsed by tcp_gro"
)]
fn coalesce_tcp_packets<B: ExpandBuffer>(
    mode: CanCoalesce,
    current: &mut B,
    target: &mut B,
    gso_size: u16,
    seq: u32,
    psh_set: bool,
    item: &mut TcpGROItem,
    bufs_offset: usize,
    is_v6: bool,
) -> CoalesceResult {
    let headers_len = usize::from(item.iph_len) + usize::from(item.tcph_len);
    let pkt_len = current.as_ref()[bufs_offset..].len();
    let coalesced_len = target.as_ref()[bufs_offset..].len() + pkt_len - headers_len;

    if target.buf_capacity() < 2 * bufs_offset + coalesced_len {
        return CoalesceResult::InsufficientCap;
    }

    if mode == CanCoalesce::Prepend && current.buf_capacity() < 2 * bufs_offset + coalesced_len {
        return CoalesceResult::InsufficientCap;
    }
    if mode == CanCoalesce::Prepend && psh_set {
        return CoalesceResult::PSHEnding;
    }

    if item.num_merged == 0
        && !checksum_valid(
            &target.as_ref()[bufs_offset..],
            item.iph_len,
            IPPROTO_TCP_U8,
            is_v6,
        )
    {
        return CoalesceResult::ItemInvalidCSum;
    }
    if !checksum_valid(
        &current.as_ref()[bufs_offset..],
        item.iph_len,
        IPPROTO_TCP_U8,
        is_v6,
    ) {
        return CoalesceResult::PktInvalidCSum;
    }

    if mode == CanCoalesce::Prepend {
        item.sent_seq = seq;
        let extend_by = coalesced_len - pkt_len;
        let current_len = current.as_ref().len();
        current.buf_resize(current_len + extend_by, 0);
        let source_start = bufs_offset + headers_len;
        let source_end = source_start + extend_by;
        let destination_start = bufs_offset + pkt_len;
        let destination_end = destination_start + extend_by;
        current.as_mut()[destination_start..destination_end]
            .copy_from_slice(&target.as_ref()[source_start..source_end]);
        std::mem::swap(current, target);
    } else {
        if psh_set {
            item.psh_set = true;
            target.as_mut()[bufs_offset + usize::from(item.iph_len) + TCP_FLAGS_OFFSET] |=
                TCP_FLAG_PSH;
        }
        target.buf_extend_from_slice(&current.as_ref()[bufs_offset + headers_len..]);
    }

    item.gso_size = item.gso_size.max(gso_size);
    item.num_merged += 1;
    CoalesceResult::Success
}

const IPV4_FLAG_MORE_FRAGMENTS: u8 = 0x20;

const IPV4_SRC_ADDR_OFFSET: usize = 12;
const IPV6_SRC_ADDR_OFFSET: usize = 8;
// maxUint16         = 1<<16 - 1

#[derive(PartialEq, Eq)]
enum GroResult {
    Noop,
    TableInsert,
    Coalesced,
}

/// tcpGRO evaluates the TCP packet at pktI in bufs for coalescing with
/// existing packets tracked in table. It returns a groResultNoop when no
/// action was taken, groResultTableInsert when the evaluated packet was
/// inserted into table, and groResultCoalesced when the evaluated packet was
/// coalesced with another packet in table.
#[expect(
    clippy::too_many_lines,
    reason = "TCP GRO is a linear protocol state machine; splitting it would scatter packet-validation invariants"
)]
fn tcp_gro<B: ExpandBuffer>(
    bufs: &mut [B],
    offset: usize,
    pkt_i: usize,
    table: &mut TcpGROTable,
    is_v6: bool,
) -> GroResult {
    let (earlier, current_and_later) = bufs.split_at_mut(pkt_i);
    let Some((current, _later)) = current_and_later.split_first_mut() else {
        return GroResult::Noop;
    };

    let pkt = &current.as_ref()[offset..];
    if pkt.len() > usize::from(u16::MAX) {
        return GroResult::Noop;
    }

    let mut iph_len = usize::from((pkt[0] & 0x0F) * 4);
    if is_v6 {
        iph_len = 40;
        let ipv6_h_payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
        if ipv6_h_payload_len != pkt.len() - iph_len {
            return GroResult::Noop;
        }
    } else {
        let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        if total_len != pkt.len() {
            return GroResult::Noop;
        }
    }

    if pkt.len() < iph_len + TCP_FLAGS_OFFSET + 1 {
        return GroResult::Noop;
    }

    let tcph_len = usize::from((pkt[iph_len + 12] >> 4) * 4);
    if !(20..=60).contains(&tcph_len) || pkt.len() < iph_len + tcph_len {
        return GroResult::Noop;
    }

    if !is_v6 && (pkt[6] & IPV4_FLAG_MORE_FRAGMENTS != 0 || pkt[6] << 3 != 0 || pkt[7] != 0) {
        return GroResult::Noop;
    }

    let tcp_flags = pkt[iph_len + TCP_FLAGS_OFFSET];
    let psh_set = if tcp_flags == TCP_FLAG_ACK {
        false
    } else if tcp_flags == TCP_FLAG_ACK | TCP_FLAG_PSH {
        true
    } else {
        return GroResult::Noop;
    };

    let payload_len = pkt.len() - tcph_len - iph_len;
    let Ok(gso_size) = u16::try_from(payload_len) else {
        return GroResult::Noop;
    };
    if gso_size == 0 {
        return GroResult::Noop;
    }

    let seq = u32::from_be_bytes([
        pkt[iph_len + 4],
        pkt[iph_len + 5],
        pkt[iph_len + 6],
        pkt[iph_len + 7],
    ]);

    let (src_addr_offset, addr_len) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };
    let Ok(iph_len_u8) = u8::try_from(iph_len) else {
        return GroResult::Noop;
    };
    let Ok(tcph_len_u8) = u8::try_from(tcph_len) else {
        return GroResult::Noop;
    };

    let Ok(bufs_index) = u16::try_from(pkt_i) else {
        return GroResult::Noop;
    };
    let candidate = TcpGROItem {
        key: TcpFlowKey::new(pkt, src_addr_offset, src_addr_offset + addr_len, iph_len),
        sent_seq: seq,
        bufs_index,
        num_merged: 0,
        gso_size,
        iph_len: iph_len_u8,
        tcph_len: tcph_len_u8,
        psh_set,
    };

    let Some(items) = table.lookup_or_insert(candidate) else {
        return GroResult::TableInsert;
    };

    for i in (0..items.len()).rev() {
        let item = &mut items[i];
        let target_index = usize::from(item.bufs_index);
        let Some(target) = earlier.get_mut(target_index) else {
            return GroResult::Noop;
        };

        let can = tcp_packets_can_coalesce(
            &current.as_ref()[offset..],
            iph_len_u8,
            tcph_len_u8,
            seq,
            psh_set,
            gso_size,
            item,
            &target.as_ref()[offset..],
        );

        if can == CanCoalesce::Unavailable {
            continue;
        }

        match coalesce_tcp_packets(
            can, current, target, gso_size, seq, psh_set, item, offset, is_v6,
        ) {
            CoalesceResult::Success => return GroResult::Coalesced,
            CoalesceResult::ItemInvalidCSum => {
                target.as_mut()[offset - VIRTIO_NET_HDR_LEN..offset].fill(0);
                items.remove(i);
            }
            CoalesceResult::PktInvalidCSum => return GroResult::Noop,
            CoalesceResult::InsufficientCap | CoalesceResult::PSHEnding => {}
        }
    }

    table.insert(candidate);
    GroResult::TableInsert
}

/// Update packet headers after TCP packet coalescing.
///
/// After [`handle_gro`] coalesces multiple TCP packets into larger segments,
/// this function updates the packet headers to reflect the coalesced state.
/// It writes virtio headers with GSO information and updates IP/TCP headers.
///
/// # Arguments
///
/// * `bufs` - Mutable slice of packet buffers that were processed by GRO
/// * `offset` - Offset where packet data begins (typically [`VIRTIO_NET_HDR_LEN`])
/// * `table` - The TCP GRO table containing coalescing metadata
///
/// # What It Does
///
/// For each coalesced packet:
/// 1. Creates a virtio header with GSO type set to TCP (v4 or v6)
/// 2. Sets the segment size (`gso_size`) for future segmentation
/// 3. Calculates and stores the pseudo-header checksum for TCP
/// 4. Updates IP total length field
/// 5. Recalculates IPv4 header checksum if needed
///
/// The resulting packets can be efficiently segmented by the kernel when transmitted.
///
/// # Usage
///
/// This function is typically called automatically by [`handle_gro`] after packet
/// coalescing is complete. You usually don't need to call it directly.
///
/// # Errors
///
/// Returns an error if:
/// - Buffer sizes are incorrect
/// - Header encoding fails
/// - Packet structure is invalid
///
/// # See Also
///
/// - [`handle_gro`] - Main GRO processing function that calls this
/// - [`TcpGROTable`] - Maintains TCP flow state for coalescing
pub fn apply_tcp_coalesce_accounting<B: ExpandBuffer>(
    bufs: &mut [B],
    offset: usize,
    table: &TcpGROTable,
) -> io::Result<()> {
    for items in table.items_by_flow.values() {
        for item in items {
            if item.num_merged > 0 {
                let mut hdr = VirtioNetHdr {
                    flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    hdr_len: u16::from(item.iph_len + item.tcph_len),
                    gso_size: item.gso_size,
                    csum_start: u16::from(item.iph_len),
                    csum_offset: 16,
                    gso_type: 0, // Will be set later
                };
                let buf = bufs[item.bufs_index as usize].as_mut();
                let pkt = &mut buf[offset..];
                let pkt_len = pkt.len();
                let pkt_len_u16 = checked_u16_len(
                    pkt_len,
                    "coalesced TCP packet length exceeds 16-bit IP length field",
                )?;
                let transport_len = pkt_len_u16
                    .checked_sub(u16::from(item.iph_len))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TCP packet shorter than IP header",
                        )
                    })?;

                // Calculate the pseudo header checksum and place it at the TCP
                // checksum offset. Downstream checksum offloading will combine
                // this with computation of the tcp header and payload checksum.
                let addr_len = if item.key.is_v6 { 16 } else { 4 };
                let src_addr_at = if item.key.is_v6 {
                    IPV6_SRC_ADDR_OFFSET
                } else {
                    IPV4_SRC_ADDR_OFFSET
                };

                let mut src_addr = [0u8; 16];
                let mut dst_addr = [0u8; 16];
                src_addr[..addr_len].copy_from_slice(&pkt[src_addr_at..src_addr_at + addr_len]);
                dst_addr[..addr_len]
                    .copy_from_slice(&pkt[src_addr_at + addr_len..src_addr_at + addr_len * 2]);
                // Recalculate the total len (IPv4) or payload len (IPv6).
                // Recalculate the (IPv4) header checksum.
                if item.key.is_v6 {
                    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
                    write_be_u16(&mut pkt[4..6], transport_len);
                } else {
                    hdr.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
                    pkt[10] = 0;
                    pkt[11] = 0;
                    write_be_u16(&mut pkt[2..4], pkt_len_u16);
                    let iph_csum = !checksum(&pkt[..item.iph_len as usize], 0);
                    write_be_u16(&mut pkt[10..12], iph_csum);
                }

                hdr.encode(&mut buf[offset - VIRTIO_NET_HDR_LEN..])?;

                let pkt = &mut buf[offset..];

                let psum = pseudo_header_checksum_no_fold(
                    IPPROTO_TCP_U8,
                    &src_addr[..addr_len],
                    &dst_addr[..addr_len],
                    transport_len,
                );
                let tcp_csum = checksum(&[], psum);
                write_be_u16(
                    &mut pkt[(hdr.csum_start + hdr.csum_offset) as usize..],
                    tcp_csum,
                );
            } else {
                let hdr = VirtioNetHdr::default();
                hdr.encode(
                    &mut bufs[item.bufs_index as usize].as_mut()[offset - VIRTIO_NET_HDR_LEN..],
                )?;
            }
        }
    }
    Ok(())
}

// applyUDPCoalesceAccounting updates bufs to account for coalescing based on the
// metadata found in table.
///
/// # Errors
///
/// Returns an error if packet buffers or offload metadata are invalid, or if header encoding fails.
pub fn apply_udp_coalesce_accounting<B: ExpandBuffer>(
    bufs: &mut [B],
    offset: usize,
    table: &UdpGROTable,
) -> io::Result<()> {
    for items in table.items_by_flow.values() {
        for item in items {
            if item.num_merged > 0 {
                let hdr = VirtioNetHdr {
                    flags: VIRTIO_NET_HDR_F_NEEDS_CSUM, // this turns into CHECKSUM_PARTIAL in the skb
                    hdr_len: u16::from(item.iph_len) + 8,
                    gso_size: item.gso_size,
                    csum_start: u16::from(item.iph_len),
                    csum_offset: 6,
                    gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
                };

                let buf = bufs[item.bufs_index as usize].as_mut();
                let pkt = &mut buf[offset..];
                let pkt_len = pkt.len();
                let pkt_len_u16 = checked_u16_len(
                    pkt_len,
                    "coalesced UDP packet length exceeds 16-bit IP length field",
                )?;
                let transport_len = pkt_len_u16
                    .checked_sub(u16::from(item.iph_len))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "UDP packet shorter than IP header",
                        )
                    })?;

                // Calculate the pseudo header checksum and place it at the UDP
                // checksum offset. Downstream checksum offloading will combine
                // this with computation of the udp header and payload checksum.
                let (addr_len, src_addr_at) = if item.key.is_v6 {
                    (16, IPV6_SRC_ADDR_OFFSET)
                } else {
                    (4, IPV4_SRC_ADDR_OFFSET)
                };

                let mut src_addr = [0u8; 16];
                let mut dst_addr = [0u8; 16];
                src_addr[..addr_len].copy_from_slice(&pkt[src_addr_at..src_addr_at + addr_len]);
                dst_addr[..addr_len]
                    .copy_from_slice(&pkt[src_addr_at + addr_len..src_addr_at + addr_len * 2]);

                // Recalculate the total len (IPv4) or payload len (IPv6).
                // Recalculate the (IPv4) header checksum.
                if item.key.is_v6 {
                    write_be_u16(&mut pkt[4..6], transport_len);
                    // set new IPv6 header payload len
                } else {
                    pkt[10] = 0;
                    pkt[11] = 0;
                    write_be_u16(&mut pkt[2..4], pkt_len_u16); // set new total length
                    let iph_csum = !checksum(&pkt[..item.iph_len as usize], 0);
                    write_be_u16(&mut pkt[10..12], iph_csum); // set IPv4 header checksum field
                }

                hdr.encode(&mut buf[offset - VIRTIO_NET_HDR_LEN..])?;
                let pkt = &mut buf[offset..];
                // Recalculate the UDP len field value
                write_be_u16(
                    &mut pkt[(item.iph_len as usize + 4)..(item.iph_len as usize + 6)],
                    transport_len,
                );

                let psum = pseudo_header_checksum_no_fold(
                    IPPROTO_UDP_U8,
                    &src_addr[..addr_len],
                    &dst_addr[..addr_len],
                    transport_len,
                );

                let udp_csum = checksum(&[], psum);
                write_be_u16(
                    &mut pkt[(hdr.csum_start + hdr.csum_offset) as usize..],
                    udp_csum,
                );
            } else {
                let hdr = VirtioNetHdr::default();
                hdr.encode(
                    &mut bufs[item.bufs_index as usize].as_mut()[offset - VIRTIO_NET_HDR_LEN..],
                )?;
            }
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
pub enum GroCandidateType {
    NotGRO,
    Tcp4GRO,
    Tcp6GRO,
    Udp4GRO,
    Udp6GRO,
}

#[must_use]
pub const fn packet_is_gro_candidate(b: &[u8], can_udp_gro: bool) -> GroCandidateType {
    if b.len() < 28 {
        return GroCandidateType::NotGRO;
    }
    if b[0] >> 4 == 4 {
        if b[0] & 0x0F != 5 {
            // IPv4 packets w/IP options do not coalesce
            return GroCandidateType::NotGRO;
        }
        match b[9] {
            6 if b.len() >= 40 => return GroCandidateType::Tcp4GRO,
            17 if can_udp_gro => return GroCandidateType::Udp4GRO,
            _ => {}
        }
    } else if b[0] >> 4 == 6 {
        match b[6] {
            6 if b.len() >= 60 => return GroCandidateType::Tcp6GRO,
            17 if b.len() >= 48 && can_udp_gro => return GroCandidateType::Udp6GRO,
            _ => {}
        }
    }
    GroCandidateType::NotGRO
}

const UDP_H_LEN: usize = 8;

/// udpGRO evaluates the UDP packet at pktI in bufs for coalescing with
/// existing packets tracked in table. It returns a groResultNoop when no
/// action was taken, groResultTableInsert when the evaluated packet was
/// inserted into table, and groResultCoalesced when the evaluated packet was
/// coalesced with another packet in table.
fn udp_gro<B: ExpandBuffer>(
    bufs: &mut [B],
    offset: usize,
    pkt_i: usize,
    table: &mut UdpGROTable,
    is_v6: bool,
) -> GroResult {
    let (earlier, current_and_later) = bufs.split_at_mut(pkt_i);
    let Some((current, _later)) = current_and_later.split_first_mut() else {
        return GroResult::Noop;
    };

    let pkt = &current.as_ref()[offset..];
    if pkt.len() > usize::from(u16::MAX) {
        return GroResult::Noop;
    }

    let mut iph_len = usize::from((pkt[0] & 0x0F) * 4);
    if is_v6 {
        iph_len = 40;
        let ipv6_payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
        if ipv6_payload_len != pkt.len() - iph_len {
            return GroResult::Noop;
        }
    } else {
        let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
        if total_len != pkt.len() {
            return GroResult::Noop;
        }
    }

    if pkt.len() < iph_len + UDP_H_LEN {
        return GroResult::Noop;
    }

    if !is_v6 && (pkt[6] & IPV4_FLAG_MORE_FRAGMENTS != 0 || pkt[6] << 3 != 0 || pkt[7] != 0) {
        return GroResult::Noop;
    }

    let payload_len = pkt.len() - UDP_H_LEN - iph_len;
    let Ok(gso_size) = u16::try_from(payload_len) else {
        return GroResult::Noop;
    };
    if gso_size == 0 {
        return GroResult::Noop;
    }

    let (src_addr_offset, addr_len) = if is_v6 {
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        (IPV4_SRC_ADDR_OFFSET, 4)
    };
    let Ok(iph_len_u8) = u8::try_from(iph_len) else {
        return GroResult::Noop;
    };

    let Ok(bufs_index) = u16::try_from(pkt_i) else {
        return GroResult::Noop;
    };
    let mut candidate = UdpGROItem {
        key: UdpFlowKey::new(pkt, src_addr_offset, src_addr_offset + addr_len, iph_len),
        bufs_index,
        num_merged: 0,
        gso_size,
        iph_len: iph_len_u8,
        c_sum_known_invalid: false,
    };

    let Some(items) = table.lookup_or_insert(candidate) else {
        return GroResult::TableInsert;
    };

    let Some(item) = items.last_mut() else {
        return GroResult::Noop;
    };
    let target_index = usize::from(item.bufs_index);
    let Some(target) = earlier.get_mut(target_index) else {
        return GroResult::Noop;
    };

    let can = udp_packets_can_coalesce(
        &current.as_ref()[offset..],
        iph_len_u8,
        gso_size,
        item,
        &target.as_ref()[offset..],
    );
    let mut pkt_csum_known_invalid = false;

    if can == CanCoalesce::Append {
        match coalesce_udp_packets(current, target, item, offset, is_v6) {
            CoalesceResult::Success => return GroResult::Coalesced,
            CoalesceResult::PktInvalidCSum => pkt_csum_known_invalid = true,
            CoalesceResult::ItemInvalidCSum
            | CoalesceResult::InsufficientCap
            | CoalesceResult::PSHEnding => {}
        }
    }

    candidate.c_sum_known_invalid = pkt_csum_known_invalid;
    table.insert(candidate);
    GroResult::TableInsert
}

/// handleGRO evaluates bufs for GRO, and writes the indices of the resulting
/// Process received packets and apply Generic Receive Offload (GRO) coalescing.
///
/// This function examines a batch of received packets and coalesces packets belonging
/// to the same TCP or UDP flow into larger segments, reducing per-packet overhead.
///
/// # Arguments
///
/// * `bufs` - Mutable slice of packet buffers. Each buffer should contain a full packet
///   starting at `offset` (with space before offset for the virtio header).
/// * `offset` - Offset where packet data begins (typically [`VIRTIO_NET_HDR_LEN`]).
///   The virtio header will be written before this offset.
/// * `tcp_table` - TCP GRO table for tracking TCP flows.
/// * `udp_table` - UDP GRO table for tracking UDP flows.
/// * `can_udp_gro` - Whether UDP GRO is supported (kernel feature).
/// * `to_write` - Output vector that will be filled with indices of packets to write.
///   Initially should be empty.
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if packet processing fails.
///
/// # Behavior
///
/// 1. Examines each packet to determine if it's a GRO candidate (TCP or UDP)
/// 2. Attempts to coalesce the packet with previous packets in the same flow
/// 3. Writes indices of final packets (coalesced or standalone) to `to_write`
/// 4. Updates packet headers with appropriate virtio headers
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::{handle_gro, GROTable, VIRTIO_NET_HDR_LEN};
///
/// let mut gro_table = GROTable::default();
/// let mut bufs = vec![vec![0u8; 1500]; 128];
/// let mut to_write = Vec::<usize>::new();
///
/// // After receiving packets into bufs with recv_multiple:
/// // handle_gro(
/// //     &mut bufs,
/// //     VIRTIO_NET_HDR_LEN,
/// //     &mut gro_table.tcp_table,
/// //     &mut gro_table.udp_table,
/// //     true,  // UDP GRO supported
/// //     &mut to_write
/// // )?;
///
/// // to_write now contains indices of packets to process
/// // for idx in &to_write {
/// //     let packet = &bufs[*idx];
/// //     // process packet...
/// // }
/// # }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Performance
///
/// - Coalescing reduces the number of packets passed to the application.
/// - Effectiveness depends on flow continuity, packet sizes, and transport state.
///
/// # See Also
///
/// - [`GROTable`] for managing GRO state
/// - [`apply_tcp_coalesce_accounting`] for updating TCP headers after coalescing
///
/// # Errors
///
/// Returns an error if packet buffers or offload metadata are invalid, or if header encoding fails.
pub fn handle_gro<B: ExpandBuffer>(
    bufs: &mut [B],
    offset: usize,
    tcp_table: &mut TcpGROTable,
    udp_table: &mut UdpGROTable,
    can_udp_gro: bool,
    to_write: &mut Vec<usize>,
) -> io::Result<()> {
    if bufs.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many packet buffers",
        ));
    }
    let bufs_len = bufs.len();
    for i in 0..bufs_len {
        if offset < VIRTIO_NET_HDR_LEN || offset >= bufs[i].as_ref().len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid offset",
            ));
        }

        let result = match packet_is_gro_candidate(&bufs[i].as_ref()[offset..], can_udp_gro) {
            GroCandidateType::Tcp4GRO => tcp_gro(bufs, offset, i, tcp_table, false),
            GroCandidateType::Tcp6GRO => tcp_gro(bufs, offset, i, tcp_table, true),
            GroCandidateType::Udp4GRO => udp_gro(bufs, offset, i, udp_table, false),
            GroCandidateType::Udp6GRO => udp_gro(bufs, offset, i, udp_table, true),
            GroCandidateType::NotGRO => GroResult::Noop,
        };

        match result {
            GroResult::Noop => {
                let hdr = VirtioNetHdr::default();
                hdr.encode(&mut bufs[i].as_mut()[offset - VIRTIO_NET_HDR_LEN..offset])?;
                // Fallthrough intended
                to_write.push(i);
            }
            GroResult::TableInsert => {
                to_write.push(i);
            }
            GroResult::Coalesced => {}
        }
    }

    let err_tcp = apply_tcp_coalesce_accounting(bufs, offset, tcp_table);
    let err_udp = apply_udp_coalesce_accounting(bufs, offset, udp_table);
    err_tcp?;
    err_udp?;
    Ok(())
}

pub(super) fn gso_transport_protocol(gso_type: u8, is_v6: bool) -> io::Result<u8> {
    let has_ecn = gso_type & VIRTIO_NET_HDR_GSO_ECN != 0;
    let base_type = gso_type & !VIRTIO_NET_HDR_GSO_ECN;
    match base_type {
        VIRTIO_NET_HDR_GSO_TCPV4 if !is_v6 => Ok(IPPROTO_TCP_U8),
        VIRTIO_NET_HDR_GSO_TCPV6 if is_v6 => Ok(IPPROTO_TCP_U8),
        VIRTIO_NET_HDR_GSO_UDP_L4 if !has_ecn => Ok(IPPROTO_UDP_U8),
        VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6 => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtio GSO type does not match IP version",
        )),
        VIRTIO_NET_HDR_GSO_UDP_L4 => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "VIRTIO_NET_HDR_GSO_ECN is only valid for TCP GSO",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported virtio GSO type: {gso_type}"),
        )),
    }
}

/// Split a GSO (Generic Segmentation Offload) packet into multiple smaller packets.
///
/// Splits a large packet described by virtio GSO metadata into ordinary protocol-correct
/// packets whose payload chunks are at most `hdr.gso_size`. This is the userspace
/// segmentation step used when reading a GSO packet from a Linux TUN device.
///
/// # Arguments
///
/// * `input` - The IP packet bytes **after** the virtio header. The caller decodes/removes
///   the virtio header separately and passes its metadata as `hdr`.
/// * `hdr` - The already-decoded virtio network header describing `input`.
/// * `out_bufs` - Output buffers where segmented packets will be written.
/// * `sizes` - Output array where the size of each segmented packet will be written.
/// * `out_offset` - Offset in output buffers where packet data should start.
/// * `is_v6` - Whether this is an IPv6 packet (affects header offsets).
///
/// # Returns
///
/// Returns the number of output buffers populated (number of segments created),
/// or an error if segmentation fails.
///
/// # How GSO Splitting Works
///
/// For a large TCP packet with GSO metadata:
/// 1. The packet headers are validated (IP + TCP)
/// 2. The payload is split into chunks of at most `hdr.gso_size`
/// 3. New packets are created with copied headers and updated fields:
///    - IP length field
///    - IP checksum (for IPv4)
///    - TCP sequence number (incremented for each segment)
///    - TCP checksum
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::{gso_split, VirtioNetHdr, VIRTIO_NET_HDR_LEN};
///
/// let mut large_packet = vec![0u8; 65536];
/// let hdr = VirtioNetHdr::default();
/// let mut out_bufs = vec![vec![0u8; 1500]; 128];
/// let mut sizes = vec![0; 128];
///
/// // Split the GSO packet
/// // let num_segments = gso_split(
/// //     &mut large_packet,
/// //     hdr,
/// //     &mut out_bufs,
/// //     &mut sizes,
/// //     VIRTIO_NET_HDR_LEN,
/// //     false  // IPv4
/// // )?;
///
/// // Now out_bufs[0..num_segments] contain the segmented packets
/// # }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Supported Protocols
///
/// - TCP over IPv4 (GSO type: [`VIRTIO_NET_HDR_GSO_TCPV4`])
/// - TCP over IPv6 (GSO type: [`VIRTIO_NET_HDR_GSO_TCPV6`])
/// - UDP (GSO type: [`VIRTIO_NET_HDR_GSO_UDP_L4`])
///
/// # Performance
///
/// GSO allows userspace to process larger packets that are split into protocol-correct
/// segments before delivery. This can reduce userspace per-packet work; no fixed throughput
/// or CPU improvement is part of this API's correctness contract.
///
/// # Errors
///
/// Returns an error if packet buffers or offload metadata are invalid, or if header encoding fails.
#[expect(
    clippy::too_many_lines,
    reason = "GSO segmentation is a linear header-validation and rewrite pipeline whose invariants are easier to audit together"
)]
pub fn gso_split<B: AsRef<[u8]> + AsMut<[u8]>>(
    input: &mut [u8],
    hdr: VirtioNetHdr,
    out_bufs: &mut [B],
    sizes: &mut [usize],
    out_offset: usize,
    is_v6: bool,
) -> io::Result<usize> {
    if sizes.len() < out_bufs.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sizes must be at least as long as out_bufs",
        ));
    }
    if out_bufs.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many packet buffers",
        ));
    }
    if hdr.gso_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtioNetHdr.gsoSize must be non-zero",
        ));
    }
    let protocol = gso_transport_protocol(hdr.gso_type, is_v6)?;
    if hdr.hdr_len < hdr.csum_start {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtioNetHdr.hdrLen is smaller than csumStart",
        ));
    }
    let min_iph_len = if is_v6 { 40 } else { 20 };
    if (hdr.csum_start as usize) < min_iph_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtioNetHdr.csumStart is smaller than the IP header",
        ));
    }
    if input.len() < hdr.hdr_len as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input shorter than virtioNetHdr.hdrLen",
        ));
    }
    let iph_len = hdr.csum_start as usize;
    let (src_addr_offset, addr_len) = if is_v6 {
        if input.len() < 40 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 packet is too short",
            ));
        }
        (IPV6_SRC_ADDR_OFFSET, 16)
    } else {
        if input.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 packet is too short",
            ));
        }
        input[10] = 0;
        input[11] = 0; // clear IPv4 header checksum
        (IPV4_SRC_ADDR_OFFSET, 4)
    };

    let transport_csum_at = usize::from(hdr.csum_start)
        .checked_add(usize::from(hdr.csum_offset))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "checksum offset overflow"))?;
    if transport_csum_at
        .checked_add(2)
        .is_none_or(|end| end > input.len())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "checksum offset exceeds input length",
        ));
    }
    input[transport_csum_at] = 0;
    input[transport_csum_at + 1] = 0; // clear TCP/UDP checksum

    let first_tcp_seq_num = if protocol == IPPROTO_TCP_U8 {
        if (hdr.hdr_len as usize) < hdr.csum_start as usize + 20
            || hdr.csum_start as usize + TCP_FLAGS_OFFSET + 1 > input.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP header is too short",
            ));
        }
        read_be_u32(&input[hdr.csum_start as usize + 4..])
    } else {
        if (hdr.hdr_len as usize) < hdr.csum_start as usize + UDP_H_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP header is too short",
            ));
        }
        0
    };

    if src_addr_offset + 2 * addr_len > input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet addresses exceed input length",
        ));
    }
    let src_addr_bytes = &input[src_addr_offset..src_addr_offset + addr_len];
    let dst_addr_bytes = &input[src_addr_offset + addr_len..src_addr_offset + 2 * addr_len];
    let transport_header_len = usize::from(hdr.hdr_len - hdr.csum_start);

    let nonlast_segment_data_len = usize::from(hdr.gso_size);
    let nonlast_len_for_pseudo = checked_u16_len(
        transport_header_len + nonlast_segment_data_len,
        "GSO transport segment exceeds 16-bit pseudo-header length",
    )?;
    let nonlast_total_len = usize::from(hdr.hdr_len) + nonlast_segment_data_len;

    let nonlast_transport_csum_no_fold = pseudo_header_checksum_no_fold(
        protocol,
        src_addr_bytes,
        dst_addr_bytes,
        nonlast_len_for_pseudo,
    );

    let payload_len = input.len() - usize::from(hdr.hdr_len);
    let segment_count = if payload_len == 0 {
        0
    } else {
        (payload_len - 1) / usize::from(hdr.gso_size) + 1
    };
    if segment_count > out_bufs.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many GSO segments",
        ));
    }
    for out_buf in &out_bufs[..segment_count] {
        let out_len = out_buf.as_ref().len();
        if out_offset > out_len || out_len - out_offset < nonlast_total_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output buffer too small",
            ));
        }
    }

    let mut next_segment_data_at = usize::from(hdr.hdr_len);
    let mut i = 0;

    while next_segment_data_at < input.len() {
        let next_segment_end = next_segment_data_at + usize::from(hdr.gso_size);
        let (next_segment_end, segment_data_len, total_len, transport_csum_no_fold) =
            if next_segment_end > input.len() {
                let last_segment_data_len = input.len() - next_segment_data_at;
                let last_len_for_pseudo = checked_u16_len(
                    transport_header_len + last_segment_data_len,
                    "GSO final transport segment exceeds 16-bit pseudo-header length",
                )?;

                let last_total_len = hdr.hdr_len as usize + last_segment_data_len;
                let last_transport_csum_no_fold = pseudo_header_checksum_no_fold(
                    protocol,
                    src_addr_bytes,
                    dst_addr_bytes,
                    last_len_for_pseudo,
                );
                (
                    input.len(),
                    last_segment_data_len,
                    last_total_len,
                    last_transport_csum_no_fold,
                )
            } else {
                (
                    next_segment_end,
                    usize::from(hdr.gso_size),
                    nonlast_total_len,
                    nonlast_transport_csum_no_fold,
                )
            };

        sizes[i] = total_len;
        let out = &mut out_bufs[i].as_mut()[out_offset..];

        out[..iph_len].copy_from_slice(&input[..iph_len]);

        if is_v6 {
            // For IPv6 we are responsible for updating the payload length field.
            // IPv6 extensions are not checksumed, but included in the payload length.
            const IPV6_FIXED_HDR_LEN: usize = 40;
            let payload_len = total_len - IPV6_FIXED_HDR_LEN;
            let payload_len = checked_u16_len(
                payload_len,
                "segmented IPv6 payload exceeds 16-bit payload length",
            )?;
            write_be_u16(&mut out[4..6], payload_len);
        } else {
            // For IPv4 we are responsible for incrementing the ID field,
            // updating the total len field, and recalculating the header
            // checksum.
            if i > 0 {
                let segment_index = u16::try_from(i).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "too many GSO segments")
                })?;
                let id = read_be_u16(&out[4..]).wrapping_add(segment_index);
                write_be_u16(&mut out[4..6], id);
            }
            let total_len_u16 = checked_u16_len(
                total_len,
                "segmented IPv4 packet exceeds 16-bit total length",
            )?;
            write_be_u16(&mut out[2..4], total_len_u16);
            let ipv4_csum = !checksum(&out[..iph_len], 0);
            write_be_u16(&mut out[10..12], ipv4_csum);
        }

        out[hdr.csum_start as usize..hdr.hdr_len as usize]
            .copy_from_slice(&input[hdr.csum_start as usize..hdr.hdr_len as usize]);

        if protocol == IPPROTO_TCP_U8 {
            let segment_index = u32::try_from(i).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "too many GSO segments")
            })?;
            let tcp_seq = first_tcp_seq_num.wrapping_add(u32::from(hdr.gso_size) * segment_index);
            write_be_u32(
                &mut out[(hdr.csum_start + 4) as usize..(hdr.csum_start + 8) as usize],
                tcp_seq,
            );
            let tcp_flags = &mut out[hdr.csum_start as usize + TCP_FLAGS_OFFSET];
            if i > 0 {
                // Linux TCP GSO keeps legacy CWR only on the first segment.
                *tcp_flags &= !TCP_FLAG_CWR;
            }
            if next_segment_end != input.len() {
                // FIN and PSH belong only to the final segment.
                *tcp_flags &= !(TCP_FLAG_FIN | TCP_FLAG_PSH);
            }
        } else {
            let udp_len = checked_u16_len(
                segment_data_len + usize::from(hdr.hdr_len - hdr.csum_start),
                "segmented UDP datagram exceeds 16-bit UDP length",
            )?;
            write_be_u16(
                &mut out[(hdr.csum_start + 4) as usize..(hdr.csum_start + 6) as usize],
                udp_len,
            );
        }

        out[hdr.hdr_len as usize..total_len]
            .as_mut()
            .copy_from_slice(&input[next_segment_data_at..next_segment_end]);

        let transport_csum = !checksum(
            &out[hdr.csum_start as usize..total_len],
            transport_csum_no_fold,
        );
        write_be_u16(
            &mut out[transport_csum_at..transport_csum_at + 2],
            transport_csum,
        );

        next_segment_data_at += usize::from(hdr.gso_size);
        i += 1;
    }

    Ok(i)
}

/// Calculate checksum for packets without GSO.
///
/// This function computes and writes the transport layer (TCP/UDP) checksum for
/// packets that don't use Generic Segmentation Offload.
///
/// # Arguments
///
/// * `in_buf` - The packet buffer (mutable)
/// * `csum_start` - Offset where checksum calculation should begin
/// * `csum_offset` - Offset within the checksummed area where the checksum should be written
///
/// # Behavior
///
/// 1. Reads the initial checksum value (typically the pseudo-header checksum)
/// 2. Clears the checksum field
/// 3. Calculates the checksum over the transport header and data
/// 4. Writes the final checksum back to the buffer
///
/// This is used when [`VIRTIO_NET_HDR_F_NEEDS_CSUM`] flag is set but [`VIRTIO_NET_HDR_GSO_NONE`]
/// is the GSO type.
///
/// # Panics
///
/// Panics if `csum_start + csum_offset` does not identify two bytes within `in_buf`,
/// or if `csum_start` lies beyond the end of `in_buf`. High-level device receive paths
/// validate these offsets before calling this low-level helper.
pub fn gso_none_checksum(in_buf: &mut [u8], csum_start: u16, csum_offset: u16) {
    let csum_at = usize::from(csum_start) + usize::from(csum_offset);
    // The initial value at the checksum offset should be summed with the
    // checksum we compute. This is typically the pseudo-header checksum.
    let initial = read_be_u16(&in_buf[csum_at..]);
    in_buf[csum_at] = 0;
    in_buf[csum_at + 1] = 0;
    let computed_checksum = checksum(&in_buf[csum_start as usize..], u64::from(initial));
    write_be_u16(&mut in_buf[csum_at..], !computed_checksum);
}

/// Generic Receive Offload (GRO) table for managing packet coalescing.
///
/// This structure maintains the state needed to coalesce multiple received packets
/// into larger segments, reducing per-packet processing overhead. It combines both
/// TCP and UDP GRO capabilities.
///
/// # Purpose
///
/// When receiving many small packets of the same flow, GRO can combine them into
/// fewer, larger packets. This provides significant performance benefits:
///
/// - Reduces the number of packets passed to the application
/// - Fewer context switches and system calls
/// - Better cache utilization
/// - Lower CPU usage per gigabit of traffic
///
/// # Usage
///
/// Create a `GROTable` and reuse it across multiple `recv_multiple` calls:
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use tun_rs::{DeviceBuilder, GROTable, IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN};
///
/// let dev = DeviceBuilder::new()
///     .offload(true)
///     .ipv4("10.0.0.1", 24, None)
///     .build_sync()?;
///
/// let mut gro_table = GROTable::default();
/// let mut original_buffer = vec![0; VIRTIO_NET_HDR_LEN + 65535];
/// let mut bufs = vec![vec![0u8; 1500]; IDEAL_BATCH_SIZE];
/// let mut sizes = vec![0; IDEAL_BATCH_SIZE];
///
/// loop {
///     let num = dev.recv_multiple(&mut original_buffer, &mut bufs, &mut sizes, 0)?;
///
///     // GRO table is automatically used by recv_multiple
///     // to coalesce packets
///     for i in 0..num {
///         println!("Packet: {} bytes", sizes[i]);
///     }
/// }
/// # }
/// # Ok::<(), std::io::Error>(())
/// ```
///
/// # Fields
///
/// - `tcp_gro_table`: State for TCP packet coalescing
/// - `udp_gro_table`: State for UDP packet coalescing (if supported by kernel)
/// - `to_write`: Internal buffer tracking which packets to emit
///
/// # Performance
///
/// The GRO table maintains internal state across calls, including:
/// - Hash map of active flows (preallocated for [`IDEAL_BATCH_SIZE`] flows)
/// - Memory pools to reduce allocations
/// - Per-flow coalescing state
///
///
/// # Thread Safety
///
/// `GROTable` is not thread-safe. Use one instance per thread or protect with a mutex.
#[derive(Default)]
pub struct GROTable {
    pub(crate) to_write: Vec<usize>,
    pub(crate) tcp_gro_table: TcpGROTable,
    pub(crate) udp_gro_table: UdpGROTable,
}

impl GROTable {
    #[must_use]
    pub fn new() -> Self {
        Self {
            to_write: Vec::with_capacity(IDEAL_BATCH_SIZE),
            tcp_gro_table: TcpGROTable::new(),
            udp_gro_table: UdpGROTable::new(),
        }
    }
    pub(crate) fn reset(&mut self) {
        self.to_write.clear();
        self.tcp_gro_table.reset();
        self.udp_gro_table.reset();
    }

    #[doc(hidden)]
    ///
    /// # Errors
    ///
    /// Returns an error if packet buffers or offload metadata are invalid, or if header encoding fails.
    pub fn apply_gro<B: ExpandBuffer>(
        &mut self,
        bufs: &mut [B],
        offset: usize,
        can_udp_gro: bool,
    ) -> io::Result<()> {
        self.reset();
        handle_gro(
            bufs,
            offset,
            &mut self.tcp_gro_table,
            &mut self.udp_gro_table,
            can_udp_gro,
            &mut self.to_write,
        )
    }
}

/// A trait for buffers that can be expanded and resized for offload operations.
///
/// This trait extends basic buffer operations (`AsRef<[u8]>` and `AsMut<[u8]>`)
/// with methods needed for efficient packet processing with GRO/GSO offload support.
/// It allows buffers to grow dynamically as needed during packet coalescing and
/// segmentation operations.
///
/// # Required Methods
///
/// - `buf_capacity()` - Returns the current capacity of the buffer
/// - `buf_resize()` - Resizes the buffer to a new length, filling with a value
/// - `buf_extend_from_slice()` - Extends the buffer with data from a slice
///
/// # Implementations
///
/// This trait is implemented for:
/// - `BytesMut` - The primary buffer type for async operations
/// - `&mut BytesMut` - Mutable reference to `BytesMut`
/// - `Vec<u8>` - Standard Rust vector
/// - `&mut Vec<u8>` - Mutable reference to Vec
///
/// # Example
///
/// ```no_run
/// # #[cfg(target_os = "linux")]
/// # {
/// use bytes::BytesMut;
/// use tun_rs::ExpandBuffer;
///
/// let mut buffer = BytesMut::with_capacity(1500);
/// buffer.buf_resize(20, 0); // Resize to 20 bytes, filled with zeros
/// buffer.buf_extend_from_slice(b"packet data"); // Append data
/// assert!(buffer.buf_capacity() >= buffer.len());
/// # }
/// ```
pub trait ExpandBuffer: AsRef<[u8]> + AsMut<[u8]> {
    /// Returns the current capacity of the buffer in bytes.
    ///
    /// The capacity is the total amount of memory allocated, which may be
    /// greater than the current length of the buffer.
    fn buf_capacity(&self) -> usize;

    /// Resizes the buffer to the specified length, filling new space with the given value.
    ///
    /// If `new_len` is greater than the current length, the buffer is extended
    /// and new bytes are initialized to `value`. If `new_len` is less than the
    /// current length, the buffer is truncated.
    ///
    /// # Arguments
    ///
    /// * `new_len` - The new length of the buffer
    /// * `value` - The byte value to fill any new space with
    fn buf_resize(&mut self, new_len: usize, value: u8);

    /// Extends the buffer by appending data from a slice.
    ///
    /// This method appends all bytes from `src` to the end of the buffer,
    /// growing the buffer as necessary.
    ///
    /// # Arguments
    ///
    /// * `src` - The slice of bytes to append to the buffer
    fn buf_extend_from_slice(&mut self, src: &[u8]);
}

impl ExpandBuffer for BytesMut {
    fn buf_capacity(&self) -> usize {
        self.capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        self.resize(new_len, value);
    }

    fn buf_extend_from_slice(&mut self, extend: &[u8]) {
        self.extend_from_slice(extend);
    }
}

impl ExpandBuffer for &mut BytesMut {
    fn buf_capacity(&self) -> usize {
        self.capacity()
    }
    fn buf_resize(&mut self, new_len: usize, value: u8) {
        self.resize(new_len, value);
    }

    fn buf_extend_from_slice(&mut self, extend: &[u8]) {
        self.extend_from_slice(extend);
    }
}
impl ExpandBuffer for Vec<u8> {
    fn buf_capacity(&self) -> usize {
        self.capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        self.resize(new_len, value);
    }

    fn buf_extend_from_slice(&mut self, extend: &[u8]) {
        self.extend_from_slice(extend);
    }
}
impl ExpandBuffer for &mut Vec<u8> {
    fn buf_capacity(&self) -> usize {
        self.capacity()
    }

    fn buf_resize(&mut self, new_len: usize, value: u8) {
        self.resize(new_len, value);
    }

    fn buf_extend_from_slice(&mut self, extend: &[u8]) {
        self.extend_from_slice(extend);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct CollidingFlowKey(u16);

    impl GroFlowKey for CollidingFlowKey {
        fn flow_hash(self) -> u64 {
            0
        }
    }

    #[test]
    fn flow_table_resolves_collisions_and_grows() -> TestResult {
        let mut table = GroFlowTable::<CollidingFlowKey, u16>::new();
        let batch_size = u16::try_from(GRO_FLOW_TABLE_SLOTS + 17)?;
        for value in 0..batch_size {
            assert!(table
                .lookup_or_insert(CollidingFlowKey(value), value)
                .is_none());
        }
        assert_eq!(table.values().count(), usize::from(batch_size));

        for value in 0..batch_size {
            let items = table
                .lookup_or_insert(CollidingFlowKey(value), u16::MAX)
                .ok_or("existing colliding flow disappeared after table growth")?;
            assert_eq!(items.as_slice(), &[value]);
        }

        table.reset();
        assert_eq!(table.values().count(), 0);
        assert!(table.lookup_or_insert(CollidingFlowKey(7), 7).is_none());
        Ok(())
    }

    fn make_ipv4_tcp_packet(seq: u32, payload_len: usize) -> TestResult<Vec<u8>> {
        const IPH_LEN: usize = 20;
        const TCPH_LEN: usize = 20;

        let total_len = IPH_LEN + TCPH_LEN + payload_len;
        let mut pkt = vec![0u8; total_len];

        pkt[0] = 0x45;
        let total_len = u16::try_from(total_len)?;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = IPPROTO_TCP_U8;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);

        pkt[IPH_LEN..IPH_LEN + 2].copy_from_slice(&10000u16.to_be_bytes());
        pkt[IPH_LEN + 2..IPH_LEN + 4].copy_from_slice(&10001u16.to_be_bytes());
        pkt[IPH_LEN + 4..IPH_LEN + 8].copy_from_slice(&seq.to_be_bytes());
        pkt[IPH_LEN + 8..IPH_LEN + 12].copy_from_slice(&1u32.to_be_bytes());
        pkt[IPH_LEN + 12] = 5 << 4;
        pkt[IPH_LEN + 13] = TCP_FLAG_ACK;
        pkt[IPH_LEN + 14..IPH_LEN + 16].copy_from_slice(&4096u16.to_be_bytes());

        for (idx, byte) in pkt[IPH_LEN + TCPH_LEN..].iter_mut().enumerate() {
            *byte = u8::try_from(idx % 256)?;
        }

        let ip_checksum = !checksum(&pkt[..IPH_LEN], 0);
        pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        let pseudo = pseudo_header_checksum_no_fold(
            IPPROTO_TCP_U8,
            &pkt[12..16],
            &pkt[16..20],
            u16::try_from(TCPH_LEN + payload_len)?,
        );
        let tcp_checksum = !checksum(&pkt[IPH_LEN..], pseudo);
        pkt[IPH_LEN + 16..IPH_LEN + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        Ok(pkt)
    }

    fn make_ipv6_tcp_packet(seq: u32, payload_len: usize) -> TestResult<Vec<u8>> {
        const IPH_LEN: usize = 40;
        const TCPH_LEN: usize = 20;

        let mut pkt = vec![0u8; IPH_LEN + TCPH_LEN + payload_len];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&u16::try_from(TCPH_LEN + payload_len)?.to_be_bytes());
        pkt[6] = IPPROTO_TCP_U8;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        pkt[IPH_LEN..IPH_LEN + 2].copy_from_slice(&10000u16.to_be_bytes());
        pkt[IPH_LEN + 2..IPH_LEN + 4].copy_from_slice(&10001u16.to_be_bytes());
        pkt[IPH_LEN + 4..IPH_LEN + 8].copy_from_slice(&seq.to_be_bytes());
        pkt[IPH_LEN + 8..IPH_LEN + 12].copy_from_slice(&1u32.to_be_bytes());
        pkt[IPH_LEN + 12] = 5 << 4;
        pkt[IPH_LEN + 13] = TCP_FLAG_ACK;
        pkt[IPH_LEN + 14..IPH_LEN + 16].copy_from_slice(&4096u16.to_be_bytes());
        for (idx, byte) in pkt[IPH_LEN + TCPH_LEN..].iter_mut().enumerate() {
            *byte = u8::try_from(idx % 256)?;
        }

        let pseudo = pseudo_header_checksum_no_fold(
            IPPROTO_TCP_U8,
            &pkt[8..24],
            &pkt[24..40],
            u16::try_from(TCPH_LEN + payload_len)?,
        );
        let tcp_checksum = !checksum(&pkt[IPH_LEN..], pseudo);
        pkt[IPH_LEN + 16..IPH_LEN + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
        Ok(pkt)
    }

    #[test]
    fn miri_handle_gro_rejects_invalid_offset() -> TestResult {
        let mut table = GROTable::new();
        let mut bufs = vec![vec![0u8; VIRTIO_NET_HDR_LEN]];
        let Err(err) = table.apply_gro(&mut bufs, VIRTIO_NET_HDR_LEN, false) else {
            return Err("invalid GRO offset unexpectedly succeeded".into());
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn handle_gro_ignores_truncated_tcp_header_without_panic() -> TestResult {
        let mut table = GROTable::new();
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN];
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x4f;
        pkt[2..4].copy_from_slice(&60u16.to_be_bytes());
        pkt[9] = IPPROTO_TCP_U8;
        buf.extend_from_slice(&pkt);
        let mut bufs = vec![buf];

        table.apply_gro(&mut bufs, VIRTIO_NET_HDR_LEN, false)?;
        Ok(())
    }

    #[test]
    fn gso_split_rejects_zero_gso_size() -> TestResult {
        let mut input = make_ipv4_tcp_packet(1, 128)?;
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; 1500]; 2];
        let mut sizes = vec![0usize; 2];

        let Err(err) = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false) else {
            return Err("zero GSO size unexpectedly succeeded".into());
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn gso_split_rejects_small_output_buffer() -> TestResult {
        let mut input = make_ipv4_tcp_packet(1, 512)?;
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 256,
            csum_start: 20,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; 64]; 4];
        let mut sizes = vec![0usize; 4];

        let Err(err) = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false) else {
            return Err("undersized GSO output buffer unexpectedly succeeded".into());
        };

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn gso_split_tcp_ipv4_preserves_payload_and_updates_segment_headers() -> TestResult {
        const PAYLOAD_LEN: usize = 300;
        const GSO_SIZE: u16 = 128;
        const HEADER_LEN: usize = 40;
        let mut input = make_ipv4_tcp_packet(1000, PAYLOAD_LEN)?;
        let original_payload = input[HEADER_LEN..].to_vec();
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: u16::try_from(HEADER_LEN)?,
            gso_size: GSO_SIZE,
            csum_start: 20,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; HEADER_LEN + usize::from(GSO_SIZE)]; 3];
        let mut sizes = vec![0usize; 3];

        let count = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false)?;
        assert_eq!(count, 3);
        assert_eq!(sizes, [168, 168, 84]);

        let mut reconstructed = Vec::with_capacity(PAYLOAD_LEN);
        for (index, (packet, &size)) in out.iter().zip(&sizes).enumerate() {
            let packet = &packet[..size];
            assert_eq!(
                usize::from(u16::from_be_bytes([packet[2], packet[3]])),
                size
            );
            assert_eq!(checksum(&packet[..20], 0), u16::MAX);
            assert_eq!(
                u32::from_be_bytes(packet[24..28].try_into().map_err(io::Error::other)?),
                1000 + u32::from(GSO_SIZE) * u32::try_from(index)?
            );
            let pseudo = pseudo_header_checksum_no_fold(
                IPPROTO_TCP_U8,
                &packet[12..16],
                &packet[16..20],
                u16::try_from(size - 20)?,
            );
            assert_eq!(checksum(&packet[20..], pseudo), u16::MAX);
            reconstructed.extend_from_slice(&packet[HEADER_LEN..]);
        }
        assert_eq!(reconstructed, original_payload);
        Ok(())
    }

    #[test]
    fn gso_split_tcp_ipv6_preserves_payload_sequence_and_payload_length() -> TestResult {
        const PAYLOAD_LEN: usize = 300;
        const GSO_SIZE: u16 = 128;
        const IPV6_HEADER_LEN: usize = 40;
        const HEADER_LEN: usize = 60;
        let mut input = make_ipv6_tcp_packet(2000, PAYLOAD_LEN)?;
        let original_payload = input[HEADER_LEN..].to_vec();
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: u16::try_from(HEADER_LEN)?,
            gso_size: GSO_SIZE,
            csum_start: u16::try_from(IPV6_HEADER_LEN)?,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; HEADER_LEN + usize::from(GSO_SIZE)]; 3];
        let mut sizes = vec![0usize; 3];

        let count = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, true)?;
        assert_eq!(count, 3);
        assert_eq!(sizes, [188, 188, 104]);

        let mut reconstructed = Vec::with_capacity(PAYLOAD_LEN);
        for (index, (packet, &size)) in out.iter().zip(&sizes).enumerate() {
            let packet = &packet[..size];
            assert_eq!(
                usize::from(u16::from_be_bytes([packet[4], packet[5]])),
                size - IPV6_HEADER_LEN
            );
            assert_eq!(
                u32::from_be_bytes(packet[44..48].try_into().map_err(io::Error::other)?),
                2000 + u32::from(GSO_SIZE) * u32::try_from(index)?
            );
            let pseudo = pseudo_header_checksum_no_fold(
                IPPROTO_TCP_U8,
                &packet[8..24],
                &packet[24..40],
                u16::try_from(size - IPV6_HEADER_LEN)?,
            );
            assert_eq!(checksum(&packet[IPV6_HEADER_LEN..], pseudo), u16::MAX);
            reconstructed.extend_from_slice(&packet[HEADER_LEN..]);
        }
        assert_eq!(reconstructed, original_payload);
        Ok(())
    }

    #[test]
    fn gso_split_tcp_ecn_matches_linux_segment_flag_semantics() -> TestResult {
        const PAYLOAD_LEN: usize = 300;
        const GSO_SIZE: u16 = 128;
        const HEADER_LEN: usize = 40;
        let mut input = make_ipv4_tcp_packet(1000, PAYLOAD_LEN)?;
        input[20 + TCP_FLAGS_OFFSET] = TCP_FLAG_ACK | TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH;
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN,
            hdr_len: u16::try_from(HEADER_LEN)?,
            gso_size: GSO_SIZE,
            csum_start: 20,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; HEADER_LEN + usize::from(GSO_SIZE)]; 3];
        let mut sizes = vec![0usize; 3];

        assert_eq!(
            gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false)?,
            3
        );
        let first_flags = out[0][20 + TCP_FLAGS_OFFSET];
        let middle_flags = out[1][20 + TCP_FLAGS_OFFSET];
        let last_flags = out[2][20 + TCP_FLAGS_OFFSET];
        assert_eq!(first_flags & TCP_FLAG_CWR, TCP_FLAG_CWR);
        assert_eq!(first_flags & (TCP_FLAG_FIN | TCP_FLAG_PSH), 0);
        assert_eq!(
            middle_flags & (TCP_FLAG_CWR | TCP_FLAG_FIN | TCP_FLAG_PSH),
            0
        );
        assert_eq!(last_flags & TCP_FLAG_CWR, 0);
        assert_eq!(
            last_flags & (TCP_FLAG_FIN | TCP_FLAG_PSH),
            TCP_FLAG_FIN | TCP_FLAG_PSH
        );
        Ok(())
    }

    #[test]
    fn gso_split_rejects_invalid_gso_type_combinations() -> TestResult {
        let mut input = make_ipv4_tcp_packet(1, 128)?;
        let template = VirtioNetHdr {
            hdr_len: 40,
            gso_size: 64,
            csum_start: 20,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; 128]; 2];
        let mut sizes = vec![0usize; 2];

        for gso_type in [
            VIRTIO_NET_HDR_GSO_TCPV6,
            VIRTIO_NET_HDR_GSO_UDP_L4 | VIRTIO_NET_HDR_GSO_ECN,
            3, // VIRTIO_NET_HDR_GSO_UDP/UFO is intentionally unsupported.
            0x7f,
        ] {
            let hdr = VirtioNetHdr {
                gso_type,
                ..template
            };
            assert!(gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false).is_err());
        }
        Ok(())
    }

    #[test]
    fn gso_split_udp_ipv4_preserves_payload_and_updates_datagram_lengths() -> TestResult {
        const PAYLOAD_LEN: usize = 150;
        const GSO_SIZE: u16 = 64;
        const HEADER_LEN: usize = 28;
        let gro_buf = make_gro_udp_buffer(0, PAYLOAD_LEN)?;
        let mut input = gro_buf[VIRTIO_NET_HDR_LEN..].to_vec();
        for (index, byte) in input[HEADER_LEN..].iter_mut().enumerate() {
            *byte = u8::try_from(index % 251)?;
        }
        let original_payload = input[HEADER_LEN..].to_vec();
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_UDP_L4,
            hdr_len: u16::try_from(HEADER_LEN)?,
            gso_size: GSO_SIZE,
            csum_start: 20,
            csum_offset: 6,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; HEADER_LEN + usize::from(GSO_SIZE)]; 3];
        let mut sizes = vec![0usize; 3];

        let count = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false)?;
        assert_eq!(count, 3);
        assert_eq!(sizes, [92, 92, 50]);

        let mut reconstructed = Vec::with_capacity(PAYLOAD_LEN);
        for (packet, &size) in out.iter().zip(&sizes) {
            let packet = &packet[..size];
            assert_eq!(
                usize::from(u16::from_be_bytes([packet[2], packet[3]])),
                size
            );
            assert_eq!(
                usize::from(u16::from_be_bytes([packet[24], packet[25]])),
                size - 20
            );
            assert_eq!(checksum(&packet[..20], 0), u16::MAX);
            let pseudo = pseudo_header_checksum_no_fold(
                IPPROTO_UDP_U8,
                &packet[12..16],
                &packet[16..20],
                u16::try_from(size - 20)?,
            );
            assert_eq!(checksum(&packet[20..], pseudo), u16::MAX);
            reconstructed.extend_from_slice(&packet[HEADER_LEN..]);
        }
        assert_eq!(reconstructed, original_payload);
        Ok(())
    }

    #[test]
    fn gso_split_rejects_checksum_offset_overflow_instead_of_panicking() -> TestResult {
        let mut input = vec![0u8; usize::from(u16::MAX)];
        input[0] = 0x45;
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: u16::MAX,
            gso_size: 1,
            csum_start: u16::MAX - 1,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; 65_535]; 1];
        let mut sizes = vec![0usize; 1];
        let error = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false)
            .err()
            .ok_or_else(|| io::Error::other("overflowing checksum offset was accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn gso_split_ignores_unused_output_buffers() -> TestResult {
        let mut input = make_ipv4_tcp_packet(1, 512)?;
        let hdr = VirtioNetHdr {
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 256,
            csum_start: 20,
            csum_offset: 16,
            ..Default::default()
        };
        let mut out = vec![vec![0u8; 296], vec![0u8; 296], vec![]];
        let mut sizes = vec![0usize; 3];

        let count = gso_split(&mut input, hdr, &mut out, &mut sizes, 0, false)?;

        assert_eq!(count, 2);
        assert_eq!(&sizes[..count], &[296, 296]);
        Ok(())
    }

    fn make_gro_tcp_buffer(seq: u32, payload_byte: u8, payload_len: usize) -> TestResult<Vec<u8>> {
        const IPH_LEN: usize = 20;
        const TCPH_LEN: usize = 20;
        let mut pkt = make_ipv4_tcp_packet(seq, payload_len)?;
        pkt[IPH_LEN + TCPH_LEN..].fill(payload_byte);
        pkt[IPH_LEN + 16..IPH_LEN + 18].fill(0);
        let pseudo = pseudo_header_checksum_no_fold(
            IPPROTO_TCP_U8,
            &pkt[12..16],
            &pkt[16..20],
            u16::try_from(TCPH_LEN + payload_len)?,
        );
        let tcp_checksum = !checksum(&pkt[IPH_LEN..], pseudo);
        pkt[IPH_LEN + 16..IPH_LEN + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + 65_536);
        buf.resize(VIRTIO_NET_HDR_LEN, 0);
        buf.extend_from_slice(&pkt);
        Ok(buf)
    }

    fn make_gro_udp_buffer(payload_byte: u8, payload_len: usize) -> TestResult<Vec<u8>> {
        const IPH_LEN: usize = 20;
        const UDPH_LEN: usize = 8;
        let total_len = IPH_LEN + UDPH_LEN + payload_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        let total_len = u16::try_from(total_len)?;
        pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = IPPROTO_UDP_U8;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[IPH_LEN..IPH_LEN + 2].copy_from_slice(&10_000u16.to_be_bytes());
        pkt[IPH_LEN + 2..IPH_LEN + 4].copy_from_slice(&10_001u16.to_be_bytes());
        pkt[IPH_LEN + 4..IPH_LEN + 6]
            .copy_from_slice(&u16::try_from(UDPH_LEN + payload_len)?.to_be_bytes());
        pkt[IPH_LEN + UDPH_LEN..].fill(payload_byte);

        let ip_checksum = !checksum(&pkt[..IPH_LEN], 0);
        pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
        let pseudo = pseudo_header_checksum_no_fold(
            IPPROTO_UDP_U8,
            &pkt[12..16],
            &pkt[16..20],
            u16::try_from(UDPH_LEN + payload_len)?,
        );
        let udp_checksum = !checksum(&pkt[IPH_LEN..], pseudo);
        pkt[IPH_LEN + 6..IPH_LEN + 8].copy_from_slice(&udp_checksum.to_be_bytes());

        let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + 65_536);
        buf.resize(VIRTIO_NET_HDR_LEN, 0);
        buf.extend_from_slice(&pkt);
        Ok(buf)
    }

    #[test]
    fn virtio_header_abi_size_and_short_buffer_errors_are_stable() -> TestResult {
        assert_eq!(VIRTIO_NET_HDR_LEN, 10);

        let mut short = vec![0u8; VIRTIO_NET_HDR_LEN - 1];
        let decode_error = VirtioNetHdr::decode(&short)
            .err()
            .ok_or_else(|| io::Error::other("short virtio header decoded successfully"))?;
        assert_eq!(decode_error.kind(), io::ErrorKind::InvalidInput);

        let encode_error = VirtioNetHdr::default()
            .encode(&mut short)
            .err()
            .ok_or_else(|| io::Error::other("short virtio header accepted an encode"))?;
        assert_eq!(encode_error.kind(), io::ErrorKind::InvalidInput);
        Ok(())
    }

    #[test]
    fn gro_candidate_classification_matches_protocol_and_feature_rules() {
        let mut tcp4 = vec![0u8; 40];
        tcp4[0] = 0x45;
        tcp4[9] = IPPROTO_TCP_U8;
        assert!(matches!(
            packet_is_gro_candidate(&tcp4, false),
            GroCandidateType::Tcp4GRO
        ));

        let mut udp4 = vec![0u8; 28];
        udp4[0] = 0x45;
        udp4[9] = IPPROTO_UDP_U8;
        assert!(matches!(
            packet_is_gro_candidate(&udp4, true),
            GroCandidateType::Udp4GRO
        ));
        assert!(matches!(
            packet_is_gro_candidate(&udp4, false),
            GroCandidateType::NotGRO
        ));

        let mut tcp6 = vec![0u8; 60];
        tcp6[0] = 0x60;
        tcp6[6] = IPPROTO_TCP_U8;
        assert!(matches!(
            packet_is_gro_candidate(&tcp6, false),
            GroCandidateType::Tcp6GRO
        ));

        let mut udp6 = vec![0u8; 48];
        udp6[0] = 0x60;
        udp6[6] = IPPROTO_UDP_U8;
        assert!(matches!(
            packet_is_gro_candidate(&udp6, true),
            GroCandidateType::Udp6GRO
        ));

        let mut ipv4_with_options = tcp4.clone();
        ipv4_with_options[0] = 0x46;
        assert!(matches!(
            packet_is_gro_candidate(&ipv4_with_options, true),
            GroCandidateType::NotGRO
        ));
        assert!(matches!(
            packet_is_gro_candidate(&[0u8; 27], true),
            GroCandidateType::NotGRO
        ));
    }

    #[test]
    fn miri_virtio_header_round_trips_wire_fields() -> TestResult {
        let expected = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: 1_440,
            csum_start: 20,
            csum_offset: 16,
        };
        let mut wire = [0u8; VIRTIO_NET_HDR_LEN];
        expected.encode(&mut wire)?;
        assert_eq!(VirtioNetHdr::decode(&wire)?, expected);
        assert_eq!(&wire[2..4], &expected.hdr_len.to_ne_bytes());
        assert_eq!(&wire[4..6], &expected.gso_size.to_ne_bytes());
        Ok(())
    }

    #[test]
    fn tcp_gro_appends_sequential_payload_without_reordering() -> TestResult {
        const PAYLOAD_LEN: usize = 64;
        const HEADER_LEN: usize = 40;
        let mut table = GROTable::new();
        let mut bufs = vec![
            make_gro_tcp_buffer(1, 0xA1, PAYLOAD_LEN)?,
            make_gro_tcp_buffer(1 + u32::try_from(PAYLOAD_LEN)?, 0xB2, PAYLOAD_LEN)?,
        ];

        table.apply_gro(&mut bufs, VIRTIO_NET_HDR_LEN, false)?;
        assert_eq!(table.to_write, [0]);
        let packet = &bufs[0][VIRTIO_NET_HDR_LEN..];
        assert_eq!(
            u32::from_be_bytes(packet[24..28].try_into().map_err(io::Error::other)?),
            1
        );
        assert_eq!(
            &packet[HEADER_LEN..HEADER_LEN + PAYLOAD_LEN],
            &[0xA1; PAYLOAD_LEN]
        );
        assert_eq!(&packet[HEADER_LEN + PAYLOAD_LEN..], &[0xB2; PAYLOAD_LEN]);
        let hdr = VirtioNetHdr::decode(&bufs[0])?;
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(hdr.gso_size, u16::try_from(PAYLOAD_LEN)?);
        Ok(())
    }

    #[test]
    fn tcp_gro_prepends_out_of_order_payload_without_reordering() -> TestResult {
        const PAYLOAD_LEN: usize = 64;
        const HEADER_LEN: usize = 40;
        let mut table = GROTable::new();
        let mut bufs = vec![
            make_gro_tcp_buffer(1 + u32::try_from(PAYLOAD_LEN)?, 0xB2, PAYLOAD_LEN)?,
            make_gro_tcp_buffer(1, 0xA1, PAYLOAD_LEN)?,
        ];

        table.apply_gro(&mut bufs, VIRTIO_NET_HDR_LEN, false)?;
        assert_eq!(table.to_write, [0]);
        let packet = &bufs[0][VIRTIO_NET_HDR_LEN..];
        assert_eq!(
            u32::from_be_bytes(packet[24..28].try_into().map_err(io::Error::other)?),
            1
        );
        assert_eq!(
            &packet[HEADER_LEN..HEADER_LEN + PAYLOAD_LEN],
            &[0xA1; PAYLOAD_LEN]
        );
        assert_eq!(&packet[HEADER_LEN + PAYLOAD_LEN..], &[0xB2; PAYLOAD_LEN]);
        Ok(())
    }

    #[test]
    fn udp_gro_preserves_datagram_payload_order() -> TestResult {
        const PAYLOAD_LEN: usize = 64;
        const HEADER_LEN: usize = 28;
        let mut table = GROTable::new();
        let mut bufs = vec![
            make_gro_udp_buffer(0xA1, PAYLOAD_LEN)?,
            make_gro_udp_buffer(0xB2, PAYLOAD_LEN)?,
        ];

        table.apply_gro(&mut bufs, VIRTIO_NET_HDR_LEN, true)?;
        assert_eq!(table.to_write, [0]);
        let packet = &bufs[0][VIRTIO_NET_HDR_LEN..];
        assert_eq!(
            &packet[HEADER_LEN..HEADER_LEN + PAYLOAD_LEN],
            &[0xA1; PAYLOAD_LEN]
        );
        assert_eq!(&packet[HEADER_LEN + PAYLOAD_LEN..], &[0xB2; PAYLOAD_LEN]);
        let hdr = VirtioNetHdr::decode(&bufs[0])?;
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_UDP_L4);
        assert_eq!(hdr.gso_size, u16::try_from(PAYLOAD_LEN)?);
        Ok(())
    }
}
