mod sys;

mod checksum;
mod device;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) mod offload;
#[doc(hidden)]
pub use checksum::{checksum, checksum_no_fold};
pub use device::DeviceImpl;
pub use offload::ExpandBuffer;
pub use offload::GROTable;
pub use offload::IDEAL_BATCH_SIZE;
pub use offload::VIRTIO_NET_HDR_LEN;
#[doc(hidden)]
pub use offload::{
    gso_split, handle_gro, VirtioNetHdr, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
    VIRTIO_NET_HDR_GSO_UDP_L4,
};
