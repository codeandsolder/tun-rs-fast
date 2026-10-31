#[cfg(unix)]
pub(crate) mod unix;

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
pub use self::unix::DeviceImpl;
#[cfg(unix)]
#[cfg(feature = "interruptible")]
pub use unix::InterruptEvent;
#[cfg(windows)]
#[cfg(feature = "interruptible")]
pub use windows::InterruptEvent;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) mod linux;
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub use self::linux::*;

#[cfg(target_os = "freebsd")]
pub(crate) mod freebsd;
#[cfg(target_os = "freebsd")]
pub use self::freebsd::DeviceImpl;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::DeviceImpl;
#[cfg(target_os = "openbsd")]
pub(crate) mod openbsd;
#[cfg(target_os = "openbsd")]
pub use self::openbsd::DeviceImpl;

#[cfg(target_os = "netbsd")]
pub(crate) mod netbsd;
#[cfg(target_os = "netbsd")]
pub use self::netbsd::DeviceImpl;

#[cfg(target_os = "windows")]
pub(crate) mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::DeviceImpl;

#[cfg(target_vendor = "apple")]
pub mod apple;

#[cfg(any(not(target_os = "linux"), feature = "address-management"))]
use getifaddrs::Interface;
#[cfg(unix)]
use std::io::{IoSlice, IoSliceMut};
use std::ops::Deref;

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "windows",
))]
pub(crate) fn read_operation_lock(
    lock: &std::sync::RwLock<()>,
) -> std::sync::RwLockReadGuard<'_, ()> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "windows",
))]
pub(crate) fn write_operation_lock(
    lock: &std::sync::RwLock<()>,
) -> std::sync::RwLockWriteGuard<'_, ()> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(all(
    test,
    any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "windows",
    )
))]
mod operation_lock_tests {
    use super::{read_operation_lock, write_operation_lock};
    use std::sync::RwLock;

    #[test]
    fn operation_locks_recover_after_writer_panics() {
        let lock = RwLock::new(());
        assert!(std::panic::catch_unwind(|| {
            let _guard = match lock.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::panic::resume_unwind(Box::new(()));
        })
        .is_err());
        assert!(lock.is_poisoned());

        drop(read_operation_lock(&lock));
        drop(write_operation_lock(&lock));
    }
}
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

#[cfg_attr(
    any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        all(target_os = "linux", target_env = "ohos")
    ),
    expect(
        dead_code,
        reason = "generic mobile and OHOS backends do not expose Ethernet address helpers"
    )
)]
pub(crate) const ETHER_ADDR_LEN: u8 = 6;

#[cfg(any(not(target_os = "linux"), feature = "address-management"))]
#[cfg_attr(
    any(
        target_os = "windows",
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        all(target_os = "linux", target_env = "ohos")
    ),
    expect(
        dead_code,
        reason = "these backends do not expose address enumeration through the shared getifaddrs helper"
    )
)]
pub(crate) fn get_if_addrs_by_name(if_name: String) -> std::io::Result<Vec<Interface>> {
    let addrs = getifaddrs::getifaddrs()?;
    let ifs = addrs.filter(|v| v.name == if_name).collect();
    Ok(ifs)
}

/// A transparent wrapper around DeviceImpl, providing synchronous I/O operations.
///
/// # Examples
///
/// Basic read/write operation:
///
/// ```no_run
/// use std::net::Ipv4Addr;
/// use tun_rs::DeviceBuilder;
///
/// fn main() -> std::io::Result<()> {
///     // Create a TUN device using the builder
///     let mut tun = DeviceBuilder::new()
///         .name("my-tun")
///         .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24, None)
///         .build_sync()?;
///
///     // Send a packet
///     // Example IP packet (Replace with real IP message)
///     let packet = b"[IP Packet: 10.0.0.1 -> 10.0.0.2] Hello, TUN!";
///     tun.send(packet)?;
///     println!("Sent {} bytes IP packet", packet.len());
///
///     // Receive a packet
///     let mut buf = [0u8; 1500];
///     let n = tun.recv(&mut buf)?;
///     println!("Received {} bytes: {:?}", n, &buf[..n]);
///
///     Ok(())
/// }
/// ```
#[repr(transparent)]
pub struct SyncDevice(pub(crate) DeviceImpl);

impl SyncDevice {
    /// Creates a synchronous device by taking ownership of an existing Unix file descriptor.
    ///
    /// Platform-specific TUN/TAP validation and setup can fail, so adoption returns
    /// an `io::Result`. Ownership is represented by [`OwnedFd`], avoiding a raw-fd
    /// double-close contract at this API boundary.
    ///
    /// On Linux, the descriptor must use `IFF_NO_PI` framing and must not use
    /// `IFF_VNET_HDR`; those properties cannot be reconstructed reliably from an
    /// adopted descriptor. The `OwnedFd` is consumed on both success and error.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor is not usable as a TUN/TAP device or
    /// platform-specific adoption/setup fails.
    #[cfg(unix)]
    pub fn from_fd(fd: OwnedFd) -> std::io::Result<Self> {
        Ok(SyncDevice(DeviceImpl::from_fd(fd)?))
    }

    /// Returns ownership of this device's Unix file descriptor.
    #[cfg(unix)]
    #[expect(
        unsafe_code,
        reason = "re-wraps the descriptor returned by an ownership-transferring IntoRawFd implementation"
    )]
    pub fn into_fd(self) -> OwnedFd {
        // SAFETY: DeviceImpl::into_raw_fd transfers ownership of one live descriptor.
        unsafe { OwnedFd::from_raw_fd(self.0.into_raw_fd()) }
    }

    /// Builds the internal device around a borrowed descriptor.
    ///
    /// # Safety
    /// The returned `SyncDevice` erases `fd`'s lifetime. Callers must retain the
    /// `BorrowedFd` for the complete lifetime of the returned device.
    #[cfg(unix)]
    #[expect(
        unsafe_code,
        reason = "internal lifetime-erasure boundary; public borrowed wrapper retains BorrowedFd"
    )]
    pub(crate) unsafe fn borrow_fd(fd: BorrowedFd<'_>) -> std::io::Result<Self> {
        // SAFETY: caller preserves the BorrowedFd lifetime around the returned device.
        unsafe { Ok(SyncDevice(DeviceImpl::borrow_fd(fd)?)) }
    }
    /// Receives data from the device into the provided buffer.
    ///
    /// Returns the number of bytes read, or an I/O error.
    ///
    /// # Example
    /// ```no_run
    /// use std::net::Ipv4Addr;
    /// use tun_rs::DeviceBuilder;
    /// let mut tun = DeviceBuilder::new()
    ///     .name("my-tun")
    ///     .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24, None)
    ///     .build_sync()
    ///     .unwrap();
    /// let mut buf = [0u8; 1500];
    /// tun.recv(&mut buf).unwrap();
    /// ```
    /// # Note
    /// Blocking the current thread if no packet is available
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.recv(buf)
    }
    /// Sends data from the provided buffer to the device.
    ///
    /// Returns the number of bytes written, or an I/O error.
    ///
    /// # Example
    /// ```no_run
    /// use std::net::Ipv4Addr;
    /// use tun_rs::DeviceBuilder;
    /// let mut tun = DeviceBuilder::new()
    ///     .name("my-tun")
    ///     .ipv4(Ipv4Addr::new(10, 0, 0, 1), 24, None)
    ///     .build_sync()
    ///     .unwrap();
    /// tun.send(b"hello").unwrap();
    /// ```
    #[inline]
    pub fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.send(buf)
    }
    /// Attempts to receive data from the device in a non-blocking fashion.
    ///
    /// Returns the number of bytes read or an error if the operation would block.
    #[cfg(target_os = "windows")]
    #[inline]
    pub fn try_recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.try_recv(buf)
    }
    /// Attempts to send data to the device in a non-blocking fashion.
    ///
    /// Returns the number of bytes written or an error if the operation would block.
    #[cfg(target_os = "windows")]
    #[inline]
    pub fn try_send(&self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.try_send(buf)
    }
    /// Shuts down the device on Windows.
    ///
    /// This may close the device or signal that no further operations will occur.
    #[cfg(target_os = "windows")]
    pub fn shutdown(&self) -> std::io::Result<()> {
        self.0.shutdown()
    }
    #[cfg(all(unix, feature = "experimental"))]
    pub fn shutdown(&self) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
    /// Reads data into the provided buffer, with support for interruption.
    ///
    /// This function attempts to read from the underlying file descriptor into `buf`,
    /// and can be interrupted using the given [`InterruptEvent`]. If the `event` is triggered
    /// while the read operation is blocked, the function will return early with
    /// an error of kind [`std::io::ErrorKind::Interrupted`].
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to store the read data.
    /// * `event` - An [`InterruptEvent`] used to interrupt the blocking read.
    ///
    /// # Returns
    ///
    /// On success, returns the number of bytes read. On failure, returns an [`std::io::Error`].
    ///
    /// # Platform-specific Behavior
    ///
    /// On **Unix platforms**, it is recommended to use this together with `set_nonblocking(true)`.
    /// Without setting non-blocking mode, concurrent reads may not respond properly to interrupt signals.
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(feature = "interruptible")]
    pub fn recv_intr(&self, buf: &mut [u8], event: &InterruptEvent) -> std::io::Result<usize> {
        self.0.read_interruptible(buf, event, None)
    }

    /// Like [`recv_intr`](Self::recv_intr), but with an optional timeout.
    ///
    /// This function reads data from the device into the provided buffer, but can be
    /// interrupted by the given event or by the timeout expiring.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to store the read data
    /// * `event` - The interrupt event that can cancel the operation
    /// * `timeout` - Optional duration to wait before returning with a timeout error
    ///
    /// # Returns
    ///
    /// - `Ok(n)` - Successfully read `n` bytes
    /// - `Err(e)` with `ErrorKind::Interrupted` - Operation was interrupted by the event
    /// - `Err(e)` with `ErrorKind::TimedOut` - Timeout expired before data was available
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(all(unix, feature = "interruptible"))]
    /// # {
    /// use std::time::Duration;
    /// use tun_rs::{DeviceBuilder, InterruptEvent};
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// let event = InterruptEvent::new()?;
    /// let mut buf = vec![0u8; 1500];
    ///
    /// // Read with a 5-second timeout
    /// match dev.recv_intr_timeout(&mut buf, &event, Some(Duration::from_secs(5))) {
    ///     Ok(n) => println!("Received {} bytes", n),
    ///     Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
    ///         println!("Timed out waiting for data");
    ///     }
    ///     Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
    ///         println!("Interrupted by event");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(feature = "interruptible")]
    pub fn recv_intr_timeout(
        &self,
        buf: &mut [u8],
        event: &InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> std::io::Result<usize> {
        self.0.read_interruptible(buf, event, timeout)
    }
    /// Like [`recv_intr`](Self::recv_intr), but reads into multiple buffers.
    ///
    /// This function behaves the same as [`recv_intr`](Self::recv_intr),
    /// but uses `readv` to fill the provided set of non-contiguous buffers.
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(all(unix, feature = "interruptible"))]
    pub fn recv_vectored_intr(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        event: &InterruptEvent,
    ) -> std::io::Result<usize> {
        self.0.readv_interruptible(bufs, event, None)
    }

    /// Like [`recv_vectored_intr`](Self::recv_vectored_intr), but with an optional timeout.
    ///
    /// This function reads data from the device into multiple buffers using vectored I/O,
    /// but can be interrupted by the given event or by the timeout expiring.
    ///
    /// # Arguments
    ///
    /// * `bufs` - Multiple buffers to store the read data
    /// * `event` - The interrupt event that can cancel the operation
    /// * `timeout` - Optional duration to wait before returning with a timeout error
    ///
    /// # Returns
    ///
    /// - `Ok(n)` - Successfully read `n` bytes total across all buffers
    /// - `Err(e)` with `ErrorKind::Interrupted` - Operation was interrupted by the event
    /// - `Err(e)` with `ErrorKind::TimedOut` - Timeout expired before data was available
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(all(unix, feature = "interruptible"))]
    /// # {
    /// use std::io::IoSliceMut;
    /// use std::time::Duration;
    /// use tun_rs::{DeviceBuilder, InterruptEvent};
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// let event = InterruptEvent::new()?;
    /// let mut header = [0u8; 20];
    /// let mut payload = [0u8; 1480];
    /// let mut bufs = [IoSliceMut::new(&mut header), IoSliceMut::new(&mut payload)];
    ///
    /// // Read with timeout into multiple buffers
    /// match dev.recv_vectored_intr_timeout(&mut bufs, &event, Some(Duration::from_secs(5))) {
    ///     Ok(n) => println!("Received {} bytes", n),
    ///     Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
    ///         println!("Timed out");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(all(unix, feature = "interruptible"))]
    pub fn recv_vectored_intr_timeout(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        event: &InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> std::io::Result<usize> {
        self.0.readv_interruptible(bufs, event, timeout)
    }
    #[cfg(feature = "interruptible")]
    pub fn wait_readable_intr(&self, event: &InterruptEvent) -> std::io::Result<()> {
        self.0.wait_readable_interruptible(event, None)
    }

    /// Like [`wait_readable_intr`](Self::wait_readable_intr), but with an optional timeout.
    ///
    /// This function waits until the device becomes readable, but can be interrupted
    /// by the given event or by the timeout expiring.
    ///
    /// # Arguments
    ///
    /// * `event` - The interrupt event that can cancel the wait
    /// * `timeout` - Optional duration to wait before returning with a timeout error
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Device is now readable
    /// - `Err(e)` with `ErrorKind::Interrupted` - Wait was interrupted by the event
    /// - `Err(e)` with `ErrorKind::TimedOut` - Timeout expired
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(all(unix, feature = "interruptible"))]
    /// # {
    /// use std::time::Duration;
    /// use tun_rs::{DeviceBuilder, InterruptEvent};
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// let event = InterruptEvent::new()?;
    ///
    /// // Wait for readability with timeout
    /// match dev.wait_readable_intr_timeout(&event, Some(Duration::from_secs(10))) {
    ///     Ok(()) => {
    ///         println!("Device is readable");
    ///         // Now try to read...
    ///     }
    ///     Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
    ///         println!("Timed out waiting for data");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(feature = "interruptible")]
    pub fn wait_readable_intr_timeout(
        &self,
        event: &InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> std::io::Result<()> {
        self.0.wait_readable_interruptible(event, timeout)
    }
    #[cfg(feature = "interruptible")]
    pub fn send_intr(&self, buf: &[u8], event: &InterruptEvent) -> std::io::Result<usize> {
        self.0.write_interruptible(buf, event)
    }

    /// Sends data to the device from multiple buffers using vectored I/O, with interruption support.
    ///
    /// Like [`send_intr`](Self::send_intr), but uses `writev` to send from multiple
    /// non-contiguous buffers in a single operation.
    ///
    /// # Arguments
    ///
    /// * `bufs` - Multiple buffers containing the data to send
    /// * `event` - The interrupt event that can cancel the operation
    ///
    /// # Returns
    ///
    /// - `Ok(n)` - Successfully sent `n` bytes total from all buffers
    /// - `Err(e)` with `ErrorKind::Interrupted` - Operation was interrupted by the event
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(all(unix, feature = "interruptible"))]
    /// # {
    /// use std::io::IoSlice;
    /// use tun_rs::{DeviceBuilder, InterruptEvent};
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// let event = InterruptEvent::new()?;
    /// let header = [0x45, 0x00, 0x00, 0x14]; // IPv4 header
    /// let payload = b"Hello, TUN!";
    /// let bufs = [IoSlice::new(&header), IoSlice::new(payload)];
    ///
    /// match dev.send_vectored_intr(&bufs, &event) {
    ///     Ok(n) => println!("Sent {} bytes", n),
    ///     Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
    ///         println!("Send was interrupted");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(all(unix, feature = "interruptible"))]
    pub fn send_vectored_intr(
        &self,
        bufs: &[IoSlice<'_>],
        event: &InterruptEvent,
    ) -> std::io::Result<usize> {
        self.0.writev_interruptible(bufs, event)
    }

    /// Waits for the device to become writable, with interruption support.
    ///
    /// This function waits until the device is ready to accept data for sending,
    /// but can be interrupted by the given event.
    ///
    /// # Arguments
    ///
    /// * `event` - The interrupt event that can cancel the wait
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Device is now writable
    /// - `Err(e)` with `ErrorKind::Interrupted` - Wait was interrupted by the event
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(all(unix, feature = "interruptible"))]
    /// # {
    /// use tun_rs::{DeviceBuilder, InterruptEvent};
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// let event = InterruptEvent::new()?;
    ///
    /// // Wait for device to be writable
    /// match dev.wait_writable_intr(&event) {
    ///     Ok(()) => {
    ///         println!("Device is writable");
    ///         // Now send data...
    ///     }
    ///     Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
    ///         println!("Wait was interrupted");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Feature
    ///
    /// This method is only available when the `interruptible` feature is enabled.
    #[cfg(all(unix, feature = "interruptible"))]
    #[inline]
    pub fn wait_writable_intr(&self, event: &InterruptEvent) -> std::io::Result<()> {
        self.0.wait_writable_interruptible(event)
    }
    /// Receives data from the device into multiple buffers using vectored I/O.
    ///
    /// **Note:** This method operates on a single packet only. It will only read data from one packet,
    /// even if multiple buffers are provided.
    ///
    /// Returns the total number of bytes read from the packet, or an error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(unix)]
    /// # {
    /// use std::io::IoSliceMut;
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// // Prepare multiple buffers for receiving data
    /// let mut header = [0u8; 20];
    /// let mut payload = [0u8; 1480];
    /// let mut bufs = [IoSliceMut::new(&mut header), IoSliceMut::new(&mut payload)];
    ///
    /// // Read one packet into the buffers
    /// let n = dev.recv_vectored(&mut bufs)?;
    /// println!("Received {} bytes total", n);
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[cfg(unix)]
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        self.0.recv_vectored(bufs)
    }
    /// Sends data to the device from multiple buffers using vectored I/O.
    ///
    /// **Note:** This method operates on a single packet only. It will only send the data contained in
    /// the provided buffers as one packet.
    ///
    /// Returns the total number of bytes written for the packet, or an error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(unix)]
    /// # {
    /// use std::io::IoSlice;
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// // Send a packet with header and payload in separate buffers
    /// let header = [0x45, 0x00, 0x00, 0x14]; // IPv4 header
    /// let payload = b"Hello, TUN!";
    /// let bufs = [IoSlice::new(&header), IoSlice::new(payload)];
    ///
    /// let n = dev.send_vectored(&bufs)?;
    /// println!("Sent {} bytes", n);
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[cfg(unix)]
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.0.send_vectored(bufs)
    }
    /// Checks whether the device is currently operating in nonblocking mode.
    ///
    /// Returns `true` if nonblocking mode is enabled, `false` otherwise, or an error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(unix)]
    /// # {
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// // Check current nonblocking mode
    /// if dev.is_nonblocking()? {
    ///     println!("Device is in nonblocking mode");
    /// } else {
    ///     println!("Device is in blocking mode");
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[cfg(unix)]
    pub fn is_nonblocking(&self) -> std::io::Result<bool> {
        self.0.is_nonblocking()
    }

    /// Sets the nonblocking mode for the device.
    ///
    /// - `nonblocking`: Pass `true` to enable nonblocking mode, `false` to disable.
    ///
    /// Returns an empty result on success or an I/O error.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(unix)]
    /// # {
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// // Enable nonblocking mode for non-blocking I/O
    /// dev.set_nonblocking(true)?;
    ///
    /// // Now recv() will return WouldBlock if no data is available
    /// let mut buf = [0u8; 1500];
    /// match dev.recv(&mut buf) {
    ///     Ok(n) => println!("Received {} bytes", n),
    ///     Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
    ///         println!("No data available");
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[cfg(unix)]
    pub fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        self.0.set_nonblocking(nonblocking)
    }

    /// Creates a new queue for multi-queue TUN/TAP devices on Linux.
    ///
    /// # Prerequisites
    /// - The `IFF_MULTI_QUEUE` flag must be enabled (via `.multi_queue(true)` in DeviceBuilder).
    /// - The system must support network interface multi-queue functionality.
    ///
    /// # Description
    /// When multi-queue is enabled, create a new queue by duplicating an existing one.
    /// This allows parallel packet processing across multiple threads/CPU cores.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    /// # {
    /// use std::thread;
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .with(|builder| {
    ///         builder.multi_queue(true); // Enable multi-queue support
    ///     })
    ///     .build_sync()?;
    ///
    /// // Clone the device to create a new queue
    /// let dev_clone = dev.try_clone()?;
    ///
    /// // Use the cloned device in another thread for parallel processing
    /// thread::spawn(move || {
    ///     let mut buf = [0u8; 1500];
    ///     loop {
    ///         if let Ok(n) = dev_clone.recv(&mut buf) {
    ///             println!("Thread 2 received {} bytes", n);
    ///         }
    ///     }
    /// });
    ///
    /// // Process packets in the main thread
    /// let mut buf = [0u8; 1500];
    /// loop {
    ///     let n = dev.recv(&mut buf)?;
    ///     println!("Thread 1 received {} bytes", n);
    /// }
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    pub fn try_clone(&self) -> std::io::Result<SyncDevice> {
        let device_impl = self.0.try_clone()?;
        Ok(SyncDevice(device_impl))
    }
}
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
impl SyncDevice {
    #[cfg(feature = "interruptible")]
    pub fn send_multiple_intr<B: ExpandBuffer>(
        &self,
        gro_table: &mut GROTable,
        bufs: &mut [B],
        offset: usize,
        event: &InterruptEvent,
    ) -> std::io::Result<usize> {
        self.send_multiple0(gro_table, bufs, offset, |tun, buf| {
            tun.write_interruptible(buf, event)
        })
    }
    #[cfg(feature = "interruptible")]
    pub fn recv_multiple_intr<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [B],
        sizes: &mut [usize],
        offset: usize,
        event: &InterruptEvent,
    ) -> std::io::Result<usize> {
        self.recv_multiple0(original_buffer, bufs, sizes, offset, |tun, buf| {
            tun.read_interruptible(buf, event, None)
        })
    }
}

impl Deref for SyncDevice {
    type Target = DeviceImpl;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(unix)]
impl AsRawFd for SyncDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
#[cfg(unix)]
impl AsFd for SyncDevice {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
#[cfg(unix)]
pub struct BorrowedSyncDevice<'dev> {
    dev: SyncDevice,
    _fd: BorrowedFd<'dev>,
}
#[cfg(unix)]
impl Deref for BorrowedSyncDevice<'_> {
    type Target = SyncDevice;
    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}
#[cfg(unix)]
impl<'dev> BorrowedSyncDevice<'dev> {
    /// Creates a borrowed synchronous device without taking ownership of the descriptor.
    ///
    /// The `BorrowedFd` lifetime statically prevents this wrapper from outliving the
    /// externally owned descriptor. Dropping the wrapper does not close or destroy the
    /// externally managed device.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor is not usable as a TUN/TAP device or
    /// platform-specific adoption/setup fails. The external descriptor remains owned
    /// by the caller on error.
    #[expect(
        unsafe_code,
        reason = "re-attaches the BorrowedFd lifetime around the internal lifetime-erasing device"
    )]
    pub fn from_fd(fd: BorrowedFd<'dev>) -> std::io::Result<Self> {
        // SAFETY: storing fd in the wrapper preserves the lifetime erased by SyncDevice.
        let dev = unsafe { SyncDevice::borrow_fd(fd)? };
        Ok(Self { dev, _fd: fd })
    }
}
