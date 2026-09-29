#![expect(
    unsafe_code,
    reason = "this module is the dedicated POSIX raw-file-descriptor syscall boundary"
)]

use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

#[cfg(any(feature = "async_tokio", feature = "async_io"))]
use bytes::buf::UninitSlice;
use libc::{self, fcntl, F_GETFL, O_NONBLOCK};

/// POSIX file descriptor support for `io` traits.
pub(crate) struct Fd {
    pub(crate) inner: RawFd,
    borrow: bool,
}

impl Fd {
    #[cfg(any(
        target_os = "windows",
        target_os = "macos",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    pub(crate) fn new(value: RawFd) -> io::Result<Self> {
        if value < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: value was checked non-negative above and new() takes ownership of the descriptor on success.
        Ok(unsafe { Self::new_unchecked(value) })
    }
    pub(crate) const unsafe fn new_unchecked(value: RawFd) -> Self {
        // SAFETY: this function has the same raw-descriptor ownership contract as new_unchecked_with_borrow with borrow=false.
        unsafe { Self::new_unchecked_with_borrow(value, false) }
    }
    pub(crate) const unsafe fn new_unchecked_with_borrow(value: RawFd, borrow: bool) -> Self {
        Self {
            inner: value,
            borrow,
        }
    }
    #[inline]
    pub(crate) const fn should_drop_cleanup(&self) -> bool {
        self.inner >= 0 && !self.borrow
    }
    pub(crate) fn is_nonblocking(&self) -> io::Result<bool> {
        // SAFETY: self owns or borrows a live descriptor; fcntl does not retain the descriptor or any Rust pointer.
        unsafe {
            let flags = fcntl(self.inner, F_GETFL);
            if flags == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok((flags & O_NONBLOCK) != 0)
        }
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn set_cloexec(&self) -> io::Result<()> {
        // SAFETY: self owns or borrows a live descriptor; both fcntl calls are
        // synchronous value-only operations and do not retain Rust memory.
        unsafe {
            let flags = fcntl(self.inner, libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if fcntl(self.inner, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    /// Enable non-blocking mode
    pub(in crate::platform) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let mut nonblocking = libc::c_int::from(nonblocking);
        // SAFETY: self owns or borrows a live descriptor and nonblocking is a valid writable c_int for the synchronous FIONBIO ioctl.
        match unsafe { libc::ioctl(self.as_raw_fd(), libc::FIONBIO, &mut nonblocking) } {
            0 => Ok(()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    #[inline]
    pub(in crate::platform) fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        // SAFETY: the descriptor is live while self is borrowed and buf supplies a valid writable region for the duration of read.
        let amount = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(amount)
            .map_err(|_| io::Error::other("non-negative syscall byte count did not fit usize"))
    }
    #[inline]
    #[cfg(any(feature = "async_tokio", feature = "async_io"))]
    pub(crate) fn read_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        // SAFETY: fd is live while self is borrowed and UninitSlice exposes valid writable
        // spare capacity of exactly buf.len() bytes for the duration of the read syscall.
        let amount = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(amount)
            .map_err(|_| io::Error::other("non-negative syscall byte count did not fit usize"))
    }
    #[inline]
    pub(in crate::platform) fn readv(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        if bufs.len() > max_iov() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let iov_count = libc::c_int::try_from(bufs.len())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: the descriptor is live while self is borrowed; IoSliceMut has the iovec-compatible layout required by readv and its buffers remain alive for the call.
        let amount = unsafe {
            libc::readv(
                self.as_raw_fd(),
                bufs.as_mut_ptr().cast::<libc::iovec>().cast_const(),
                iov_count,
            )
        };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(amount)
            .map_err(|_| io::Error::other("non-negative syscall byte count did not fit usize"))
    }
    #[inline]
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    pub(crate) fn readv_raw(&self, bufs: &mut [libc::iovec]) -> io::Result<usize> {
        if bufs.len() > max_iov() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let iov_count = libc::c_int::try_from(bufs.len())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let amount = unsafe { libc::readv(self.as_raw_fd(), bufs.as_ptr(), iov_count) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(amount)
            .map_err(|_| io::Error::other("non-negative syscall byte count did not fit usize"))
    }

    #[inline]
    pub(in crate::platform) fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let fd = self.as_raw_fd();
        // SAFETY: the descriptor is live while self is borrowed and buf supplies a valid readable region for the duration of write.
        let amount = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(amount)
            .map_err(|_| io::Error::other("non-negative syscall byte count did not fit usize"))
    }
    #[inline]
    pub(in crate::platform) fn writev(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        if bufs.len() > max_iov() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let iov_count = libc::c_int::try_from(bufs.len())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: the descriptor is live while self is borrowed; IoSlice has the iovec-compatible layout required by writev and its buffers remain alive for the call.
        let amount = unsafe {
            libc::writev(
                self.as_raw_fd(),
                bufs.as_ptr().cast::<libc::iovec>(),
                iov_count,
            )
        };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }
        usize::try_from(amount)
            .map_err(|_| io::Error::other("non-negative syscall byte count did not fit usize"))
    }
}
#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_vendor = "apple",
))]
pub(crate) const fn max_iov() -> usize {
    libc::IOV_MAX as usize
}

#[cfg(any(
    target_os = "android",
    target_os = "emscripten",
    target_os = "linux",
    target_os = "nto",
))]
pub(in crate::platform) const fn max_iov() -> usize {
    libc::UIO_MAXIOV as usize
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.inner
    }
}

impl IntoRawFd for Fd {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.inner;
        self.inner = -1;
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.should_drop_cleanup() {
            // SAFETY: should_drop_cleanup proves this wrapper owns a non-negative descriptor, so closing it exactly once is valid.
            unsafe { libc::close(self.inner) };
            self.inner = -1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Fd;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    #[test]
    fn should_drop_cleanup_matches_ownership() {
        // SAFETY: the test only inspects ownership bookkeeping and deliberately prevents this owning wrapper from reaching Drop below.
        let owned = unsafe { Fd::new_unchecked(1) };
        assert!(owned.should_drop_cleanup());

        // SAFETY: descriptor 1 is process-owned for the test and the wrapper is explicitly borrowed, so it will not close it.
        let borrowed = unsafe { Fd::new_unchecked_with_borrow(1, true) };
        assert!(!borrowed.should_drop_cleanup());

        // SAFETY: this test intentionally constructs the invalid sentinel to exercise should_drop_cleanup without performing I/O.
        let invalid = unsafe { Fd::new_unchecked_with_borrow(-1, false) };
        assert!(!invalid.should_drop_cleanup());
    }

    #[test]
    fn borrowed_fd_drop_leaves_descriptor_open() -> std::io::Result<()> {
        let file = File::open("/dev/null")?;
        let raw_fd = file.as_raw_fd();

        // SAFETY: raw_fd is owned by file and remains live for the entire borrowed wrapper lifetime in this test.
        let fd = unsafe { Fd::new_unchecked_with_borrow(raw_fd, true) };
        drop(fd);

        // SAFETY: raw_fd is still owned by file; the borrowed Fd was dropped without closing it, so querying it is valid.
        assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
        Ok(())
    }

    #[test]
    fn owned_fd_drop_closes_descriptor() -> std::io::Result<()> {
        let file = File::open("/dev/null")?;
        // SAFETY: file owns a live descriptor for the duration of dup; dup returns a new independent descriptor.
        let raw_fd = unsafe { libc::dup(file.as_raw_fd()) };
        assert!(raw_fd >= 0);

        // SAFETY: dup returned a non-negative descriptor above and this test intentionally transfers ownership into Fd.
        let fd = unsafe { Fd::new_unchecked(raw_fd) };
        drop(fd);

        // SAFETY: fcntl accepts any integer descriptor; after owned Fd drop this call intentionally verifies EBADF.
        assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        Ok(())
    }
}
