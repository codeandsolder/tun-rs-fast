#![expect(
    unsafe_code,
    reason = "this module adapts raw Unix TUN/TAP descriptors and ioctl control sockets"
)]

use crate::platform::unix::{Fd, Tun};
use crate::platform::DeviceImpl;
#[cfg(any(feature = "async_tokio", feature = "async_io"))]
use bytes::buf::UninitSlice;
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
use libc::{AF_INET, AF_INET6, SOCK_DGRAM};
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};

impl FromRawFd for DeviceImpl {
    /// # Safety
    ///
    /// The caller must ensure that `fd` is a valid, open file descriptor for a TUN/TAP device.
    ///
    /// If the descriptor violates this unsafe contract, construction aborts the process rather
    /// than returning a partially initialized device.
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        // SAFETY: FromRawFd's documented contract guarantees fd is valid and ownership is transferred to this DeviceImpl.
        unsafe { Self::from_fd(fd).unwrap_or_else(|_| std::process::abort()) }
    }
}
impl AsRawFd for DeviceImpl {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}
impl AsFd for DeviceImpl {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: self keeps the underlying descriptor alive for at least the lifetime of the returned BorrowedFd.
        unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
    }
}
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd", target_os = "openbsd")))]
impl std::os::unix::io::IntoRawFd for DeviceImpl {
    fn into_raw_fd(self) -> RawFd {
        self.tun.into_raw_fd()
    }
}
impl DeviceImpl {
    /// # Safety
    /// The fd passed in must be an owned file descriptor; in particular, it must be open.
    pub(crate) unsafe fn from_fd(fd: RawFd) -> io::Result<Self> {
        // SAFETY: from_fd's contract transfers ownership of a valid open descriptor, so constructing an owning Fd is valid.
        unsafe {
            let tun = Fd::new_unchecked(fd);
            Self::from_tun(Tun::new(tun))
        }
    }
    /// # Safety
    /// The fd passed in must be a valid, open file descriptor.
    /// Unlike [`from_fd`], this function does **not** take ownership of `fd`,
    /// and therefore will not close it when dropped.\
    /// The caller is responsible for ensuring the lifetime and eventual closure of `fd`.
    pub(crate) unsafe fn borrow_raw(fd: RawFd) -> io::Result<Self> {
        // SAFETY: borrow_raw's contract guarantees fd stays valid externally; the Fd wrapper is explicitly marked borrowed and will not close it.
        unsafe {
            let tun = Fd::new_unchecked_with_borrow(fd, true);
            Self::from_tun(Tun::new(tun))
        }
    }
    pub(crate) fn is_nonblocking(&self) -> io::Result<bool> {
        self.tun.is_nonblocking()
    }
    /// Moves this Device into or out of nonblocking mode.
    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.tun.set_nonblocking(nonblocking)
    }

    /// Recv a packet from tun device
    #[inline]
    pub(crate) fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.recv(buf)
    }
    #[inline]
    #[cfg(any(feature = "async_tokio", feature = "async_io"))]
    pub(crate) fn recv_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        self.tun.recv_uninit(buf)
    }
    #[inline]
    pub(crate) fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.tun.recv_vectored(bufs)
    }

    /// Send a packet to tun device
    #[inline]
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.tun.send(buf)
    }
    #[inline]
    pub(crate) fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.tun.send_vectored(bufs)
    }
    #[cfg(feature = "interruptible")]
    pub(crate) fn read_interruptible(
        &self,
        buf: &mut [u8],
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<usize> {
        self.tun.read_interruptible(buf, event, timeout)
    }
    #[cfg(feature = "interruptible")]
    pub(crate) fn readv_interruptible(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<usize> {
        self.tun.readv_interruptible(bufs, event, timeout)
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn wait_readable_interruptible(
        &self,
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        self.tun.wait_readable_interruptible(event, timeout)
    }
    #[cfg(feature = "interruptible")]
    pub(crate) fn write_interruptible(
        &self,
        buf: &[u8],
        event: &crate::InterruptEvent,
    ) -> io::Result<usize> {
        self.tun.write_interruptible(buf, event)
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn writev_interruptible(
        &self,
        bufs: &[IoSlice<'_>],
        event: &crate::InterruptEvent,
    ) -> io::Result<usize> {
        self.tun.writev_interruptible(bufs, event)
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn wait_writable_interruptible(
        &self,
        event: &crate::InterruptEvent,
    ) -> io::Result<()> {
        self.tun.wait_writable_interruptible(event)
    }
}
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn if_name_to_index(if_name: &std::ffi::CStr) -> io::Result<u32> {
    // SAFETY: CStr guarantees a NUL-terminated name pointer that remains live
    // for the synchronous if_nametoindex call.
    let index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index)
    }
}

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
impl DeviceImpl {
    /// Retrieves the interface index for the network interface.
    ///
    /// This function converts the interface name (obtained via `self.name()`) into a
    /// C-compatible string (`CString`) and then calls the libc function `if_nametoindex`
    /// to retrieve the corresponding interface index.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the underlying descriptor or interface operation fails.
    pub fn if_index(&self) -> io::Result<u32> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.if_index_impl()
    }
    pub(crate) fn if_index_impl(&self) -> io::Result<u32> {
        let if_name = std::ffi::CString::new(self.name_impl()?)?;
        if_name_to_index(&if_name)
    }
    /// Retrieves all IP addresses associated with the network interface.
    ///
    /// This function calls `getifaddrs` with the interface name,
    /// then iterates over the returned list of interface addresses, extracting and collecting
    /// the IP addresses into a vector.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the underlying descriptor or interface operation fails.
    #[cfg(any(not(target_os = "linux"), feature = "address-management"))]
    pub fn addresses(&self) -> io::Result<Vec<std::net::IpAddr>> {
        Ok(crate::platform::get_if_addrs_by_name(&self.name_impl()?)?
            .iter()
            .filter_map(|v| v.address.ip_addr())
            .collect())
    }
}
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos",))]
impl DeviceImpl {
    /// Returns whether the TUN device is set to ignore packet information (PI).
    ///
    /// When enabled, the device does not prepend the `struct tun_pi` header
    /// to packets, which can simplify packet processing in some cases.
    ///
    /// # Returns
    /// * `true` - The TUN device ignores packet information.
    /// * `false` - The TUN device includes packet information.
    /// # Note
    /// Retrieve whether the packet is ignored for the TUN Device; The TAP device always returns `false`.
    pub fn ignore_packet_info(&self) -> bool {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.tun.ignore_packet_info()
    }
    /// Sets whether the TUN device should ignore packet information (PI).
    ///
    /// When `ignore_packet_info` is set to `true`, the TUN device does not
    /// prepend the `struct tun_pi` header to packets. This can be useful
    /// if the additional metadata is not needed.
    ///
    /// # Parameters
    /// * `ign` - If `true`, the TUN device will ignore packet information.
    ///   `  ` If `false`, it will include packet information.
    /// # Note
    /// This only works for a TUN device; The invocation will be ignored if the device is a TAP.
    pub fn set_ignore_packet_info(&self, ign: bool) {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.tun.set_ignore_packet_info(ign);
    }
}
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub(in crate::platform) fn ctl() -> io::Result<Fd> {
    // SAFETY: socket returns either a new owned descriptor or a negative errno sentinel; Fd::new validates the latter before taking ownership.
    unsafe { Fd::new(libc::socket(AF_INET, SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)) }
}
#[cfg(target_os = "macos")]
pub(in crate::platform) fn ctl() -> io::Result<Fd> {
    // SAFETY: socket returns either a new owned descriptor or a negative errno sentinel;
    // Fd::new validates the latter before taking ownership.
    let fd = unsafe { Fd::new(libc::socket(AF_INET, SOCK_DGRAM, 0))? };
    fd.set_cloexec()?;
    Ok(fd)
}
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub(in crate::platform) fn ctl_v6() -> io::Result<Fd> {
    // SAFETY: socket returns either a new owned descriptor or a negative errno sentinel; Fd::new validates the latter before taking ownership.
    unsafe { Fd::new(libc::socket(AF_INET6, SOCK_DGRAM | libc::SOCK_CLOEXEC, 0)) }
}
#[cfg(target_os = "macos")]
pub(in crate::platform) fn ctl_v6() -> io::Result<Fd> {
    // SAFETY: socket returns either a new owned descriptor or a negative errno sentinel;
    // Fd::new validates the latter before taking ownership.
    let fd = unsafe { Fd::new(libc::socket(AF_INET6, SOCK_DGRAM, 0))? };
    fd.set_cloexec()?;
    Ok(fd)
}

/// Copies an interface name into a BSD C name array.
///
/// The destination must have room for the trailing NUL byte. It is cleared
/// before copying so successful calls always produce a NUL-terminated name.
#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
pub(crate) fn copy_device_name(name: &str, dest: &mut [libc::c_char]) -> io::Result<()> {
    if name.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains NUL",
        ));
    }
    if name.len() >= dest.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name exceeds platform IFNAMSIZ",
        ));
    }
    dest.fill(0);
    for (out, byte) in dest.iter_mut().zip(name.bytes()) {
        *out = byte.cast_signed();
    }
    Ok(())
}

#[cfg(all(
    test,
    any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    )
))]
mod if_index_tests {
    use super::if_name_to_index;

    #[test]
    fn missing_interface_is_an_error_not_index_zero() {
        assert!(if_name_to_index(c"tun-rs/invalid").is_err());
    }
}

#[cfg(all(
    test,
    any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")
))]
mod bsd_device_name_tests {
    use super::copy_device_name;
    use std::io;

    #[test]
    fn copy_device_name_enforces_c_string_contract() {
        let mut dest = [1; 4];
        assert!(copy_device_name("abc", &mut dest).is_ok());
        assert_eq!(dest[3], 0);

        assert!(matches!(
            copy_device_name("abcd", &mut dest),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(matches!(
            copy_device_name("a\0b", &mut dest),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }
}
