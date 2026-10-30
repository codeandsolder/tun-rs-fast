/*!
# Asynchronous Device Module

This module provides asynchronous I/O support for TUN/TAP interfaces through the [`AsyncDevice`] type.

## Overview

The async module enables non-blocking I/O operations on TUN/TAP devices, allowing you to efficiently
handle network traffic in async/await contexts. Two async runtime backends are supported:

- **Tokio**: Enable with the `async` or `async_tokio` feature
- **async-io**: Enable with the `async_io` feature (for async-std, smol, etc.)

**Important**: You must choose exactly one async runtime. Enabling both simultaneously will result
in a compile error.

## Feature Flags

- `async` (alias for `async_tokio`) - Use Tokio runtime
- `async_tokio` - Use Tokio runtime explicitly
- `async_io` - Use async-io runtime (for async-std, smol, and similar runtimes)
- `async_framed` - Enable framed I/O support with futures (requires one of the above)

## Usage with Tokio

Add to your `Cargo.toml`:

```toml
[dependencies]
tun-rs = { version = "2", features = ["async"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Example:

```no_run
# #[cfg(feature = "async_tokio")]
# {
use tun_rs::DeviceBuilder;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let dev = DeviceBuilder::new()
        .ipv4("10.0.0.1", 24, None)
        .build_async()?;

    let mut buf = vec![0u8; 65536];
    loop {
        let len = dev.recv(&mut buf).await?;
        println!("Received {} bytes", len);

        // Echo the packet back
        dev.send(&buf[..len]).await?;
    }
}
# }
```

## Usage with async-std

Add to your `Cargo.toml`:

```toml
[dependencies]
tun-rs = { version = "2", features = ["async_io"] }
async-std = { version = "1", features = ["attributes"] }
```

Example:

```no_run
# #[cfg(all(feature = "async_io", not(feature = "async_tokio")))]
# {
use tun_rs::DeviceBuilder;

#[async_std::main]
async fn main() -> std::io::Result<()> {
    let dev = DeviceBuilder::new()
        .ipv4("10.0.0.1", 24, None)
        .build_async()?;

    let mut buf = vec![0u8; 65536];
    loop {
        let len = dev.recv(&mut buf).await?;
        println!("Received {} bytes", len);
    }
}
# }
```

## Device Types

### `AsyncDevice`

The main async device type. Created via `DeviceBuilder::build_async()`.
Takes ownership of the underlying file descriptor and closes it when dropped.

### `BorrowedAsyncDevice`

A borrowed variant that does not take ownership of the file descriptor.
Useful when the file descriptor is managed externally (e.g., on mobile platforms).

```no_run
# #[cfg(unix)]
# {
use tun_rs::BorrowedAsyncDevice;

async fn use_borrowed_fd(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
    let dev = BorrowedAsyncDevice::from_fd(fd)?;

    let mut buf = vec![0u8; 1500];
    let len = dev.recv(&mut buf).await?;

    // fd is still valid after dev is dropped
    Ok(())
}
# }
```

## API Methods

### I/O Operations

- `recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>>`
  - Asynchronously read a packet from the device

- `send(&self, buf: &[u8]) -> impl Future<Output = io::Result<usize>>`
  - Asynchronously send a packet to the device

### Readiness Operations

- `readable(&self) -> impl Future<Output = io::Result<()>>`
  - Wait until the device is readable

- `writable(&self) -> impl Future<Output = io::Result<()>>`
  - Wait until the device is writable

These are useful for implementing custom I/O logic or integrating with other async primitives.

## Platform Support

Async I/O is supported on:
- Linux
- macOS
- Windows
- FreeBSD, OpenBSD, NetBSD
- Android, iOS (via borrowed file descriptors)

## Performance Considerations

- Async I/O is efficient for handling multiple connections or high concurrency
- For single-threaded blocking I/O, consider using [`crate::SyncDevice`] instead
- On Linux with offload enabled, use `recv_multiple`/`send_multiple` for best throughput
- Buffer sizes should be at least MTU + header overhead (typically 1500-65536 bytes)

## Error Handling

All async operations return `io::Result` types. Common errors include:
- `WouldBlock` (internally handled by async runtime)
- `Interrupted` (operation was interrupted, can be retried)
- `BrokenPipe` (device was closed)
- Platform-specific errors

## Descriptor Ownership

Unix descriptor adoption uses Rust's typed fd API:
- `AsyncDevice::from_fd(OwnedFd)` transfers ownership and returns setup failures as `io::Error`.
- `BorrowedAsyncDevice::from_fd(BorrowedFd<'_>)` keeps ownership external and cannot outlive the borrowed descriptor.
- `AsyncDevice::into_fd()` returns `OwnedFd` when the backend supports extraction.

Foreign APIs that expose only a raw integer still require one small unsafe conversion to `OwnedFd` or `BorrowedFd` at the FFI boundary; tun-rs itself does not require a raw-fd safety contract.
*/

#[cfg(unix)]
pub(crate) mod unix;
#[cfg(all(unix, not(target_os = "macos")))]
pub use unix::AsyncDevice;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::AsyncDevice;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::AsyncDevice;

#[cfg(all(
    any(feature = "async_io", feature = "async_tokio"),
    feature = "async_framed"
))]
#[cfg_attr(
    docsrs,
    doc(cfg(all(
        any(feature = "async_io", feature = "async_tokio"),
        feature = "async_framed"
    )))
)]
pub mod async_framed;

#[cfg(all(feature = "async_tokio", feature = "async_io", not(doc)))]
compile_error! {"More than one asynchronous runtime is simultaneously specified in features"}

/// A borrowed asynchronous TUN/TAP device.
///
/// This type wraps an [`AsyncDevice`] but does not take ownership of the underlying file descriptor.
/// It's designed for scenarios where the file descriptor is managed externally, such as:
///
/// - iOS PacketTunnelProvider (NetworkExtension framework)
/// - Android VpnService
/// - Other FFI scenarios where file descriptor ownership is managed by foreign code
///
/// # Ownership and Lifetime
///
/// Unlike [`AsyncDevice`], `BorrowedAsyncDevice`:
/// - Does NOT close the file descriptor when dropped
/// - Requires the caller to manage the file descriptor's lifetime
/// - Must not outlive the actual file descriptor
///
/// # Example
///
/// ```no_run
/// # #[cfg(unix)]
/// # async fn example(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<()> {
/// use tun_rs::BorrowedAsyncDevice;
///
/// let device = BorrowedAsyncDevice::from_fd(fd)?;
/// let mut buffer = vec![0u8; 1500];
/// let n = device.recv(&mut buffer).await?;
/// println!("Received {} bytes", n);
/// # Ok(())
/// # }
/// ```
#[cfg(unix)]
pub struct BorrowedAsyncDevice<'dev> {
    dev: AsyncDevice,
    _fd: std::os::fd::BorrowedFd<'dev>,
}
#[cfg(unix)]
impl std::ops::Deref for BorrowedAsyncDevice<'_> {
    type Target = AsyncDevice;
    fn deref(&self) -> &Self::Target {
        &self.dev
    }
}
#[cfg(unix)]
impl<'dev> BorrowedAsyncDevice<'dev> {
    /// Creates a borrowed async device without taking ownership of the descriptor.
    ///
    /// The `BorrowedFd` lifetime statically prevents this wrapper from outliving the
    /// externally owned descriptor. Creating an async wrapper may enable nonblocking
    /// mode or apply other platform setup to the shared underlying device.
    ///
    /// # Errors
    ///
    /// Returns an error if TUN/TAP adoption or async-runtime registration fails. The
    /// descriptor remains externally owned, though setup attempted before the error may
    /// have changed descriptor/device state.
    #[expect(
        unsafe_code,
        reason = "re-attaches the BorrowedFd lifetime around the internal lifetime-erasing async device"
    )]
    pub fn from_fd(fd: std::os::fd::BorrowedFd<'dev>) -> std::io::Result<Self> {
        // SAFETY: storing fd in the wrapper preserves the lifetime erased by AsyncDevice.
        let dev = unsafe { AsyncDevice::borrow_fd(fd)? };
        Ok(Self { dev, _fd: fd })
    }
}
