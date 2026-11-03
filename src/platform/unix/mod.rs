mod sockaddr;
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) use sockaddr::sockaddr_union;

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[cfg_attr(
    not(all(target_os = "linux", not(target_env = "ohos"))),
    expect(
        unused_imports,
        reason = "only the Linux backend imports this shared sockaddr conversion helper"
    )
)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) use sockaddr::ipaddr_to_sockaddr;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) use sockaddr::sockaddr_v4_to_rs_addr;

mod fd;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) use self::fd::Fd;
#[cfg(feature = "interruptible")]
mod interrupt;
#[cfg(feature = "interruptible")]
pub use interrupt::InterruptEvent;
mod tun;
#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) use self::tun::Tun;

#[expect(
    clippy::redundant_pub_crate,
    reason = "crate-only visibility is intentional and prevents accidental public API expansion through re-exports"
)]
pub(crate) mod device;

#[cfg(all(
    unix,
    not(any(
        target_os = "windows",
        target_os = "macos",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))
))]
/// A TUN device for Android/iOS/...
pub struct DeviceImpl {
    pub(crate) tun: Tun,
    #[cfg_attr(
        any(target_os = "android", all(target_os = "linux", target_env = "ohos")),
        expect(
            dead_code,
            reason = "generic Android and OHOS backends do not expose operations that take the device lock"
        )
    )]
    pub(crate) op_lock: std::sync::RwLock<()>,
}
#[cfg(all(
    unix,
    not(any(
        target_os = "windows",
        target_os = "macos",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))
))]
impl DeviceImpl {
    pub(crate) fn from_tun(tun: Tun) -> std::io::Result<Self> {
        Ok(Self {
            tun,
            op_lock: std::sync::RwLock::new(()),
        })
    }
}
