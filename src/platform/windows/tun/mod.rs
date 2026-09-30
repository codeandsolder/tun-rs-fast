#![expect(
    unsafe_code,
    reason = "the Wintun backend operates on opaque Wintun handles and Win32 wait APIs"
)]

#[cfg(feature = "async_framed")]
use bytes::buf::UninitSlice;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::{io, ptr};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS,
    WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::System::Threading::{WaitForMultipleObjects, INFINITE};

use crate::platform::windows::ffi;
use crate::platform::windows::ffi::encode_utf16;

mod adapter;
mod adapter_win7;
mod wintun_log;
mod wintun_raw;

pub use adapter::check_adapter_if_orphaned_devices;

/// The maximum size of wintun's internal ring buffer (in bytes)
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;

/// The minimum size of wintun's internal ring buffer (in bytes)
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;

/// Maximum pool name length including zero terminator
pub const MAX_POOL: usize = 256;

#[cfg(any(
    feature = "interruptible",
    feature = "async_tokio",
    feature = "async_io"
))]
fn finite_wait_timeout_ms(timeout: Option<std::time::Duration>) -> u32 {
    const MAX_FINITE_WAIT_MS: u32 = INFINITE - 1;
    timeout.map_or(INFINITE, |duration| {
        let millis = duration.as_millis().min(u128::from(MAX_FINITE_WAIT_MS));
        match u32::try_from(millis) {
            Ok(value) => value,
            Err(_) => MAX_FINITE_WAIT_MS,
        }
    })
}

pub struct TunDevice {
    index: u32,
    luid: NET_LUID_LH,
    win_tun_adapter: WinTunAdapter,
}
struct WinTunAdapter {
    win_tun: Arc<wintun_raw::wintun>,
    handle: wintun_raw::WINTUN_ADAPTER_HANDLE,
    event: OwnedHandle,
    ring_capacity: u32,
    state: State,
    session: RwLock<Option<WinTunSession>>,
    delete_driver: bool,
}
// SAFETY: Wintun documents packet receive/release and allocate/send operations
// as thread-safe. Adapter/session lifecycle mutation is serialized by the State
// mutex and session RwLock, and the opaque handles remain owned by this adapter.
unsafe impl Send for WinTunAdapter {}
// SAFETY: concurrent safe methods either use Wintun's documented thread-safe
// packet APIs or synchronize lifecycle changes through State/session locks; no
// safe method exposes the raw adapter/session pointers for unsynchronized use.
unsafe impl Sync for WinTunAdapter {}
struct WinTunSession {
    win_tun: Arc<wintun_raw::wintun>,
    handle: wintun_raw::WINTUN_SESSION_HANDLE,
    read_event: wintun_raw::HANDLE,
}
impl Drop for WinTunAdapter {
    fn drop(&mut self) {
        let session = self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        drop(session);
        // SAFETY: self exclusively owns the live adapter handle, and the session
        // was dropped above so no session can retain a dependency on the adapter.
        unsafe { self.win_tun.WintunCloseAdapter(self.handle) };
        if self.delete_driver {
            // SAFETY: this is a parameterless Wintun DLL operation. The loaded
            // function pointer was resolved when win_tun was constructed.
            unsafe { self.win_tun.WintunDeleteDriver() };
        }
    }
}
#[derive(Default)]
struct State {
    state: AtomicBool,
    lock: Mutex<()>,
}
impl State {
    fn check(&self) -> io::Result<()> {
        if self.is_enabled() {
            Ok(())
        } else {
            Err(io::Error::other("The interface has been disabled"))
        }
    }
    fn is_disabled(&self) -> bool {
        !self.state.load(Ordering::Relaxed)
    }
    fn is_enabled(&self) -> bool {
        self.state.load(Ordering::Relaxed)
    }
    fn disable(&self) {
        self.state.store(false, Ordering::Relaxed);
    }
    fn enable(&self) {
        self.state.store(true, Ordering::Relaxed);
    }
    fn lock(&self) -> MutexGuard<'_, ()> {
        self.lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
impl WinTunAdapter {
    fn disable(&self) -> io::Result<()> {
        let _guard = self.state.lock();
        if self.state.is_disabled() {
            return Ok(());
        }
        self.state.disable();
        if let Err(e) = ffi::set_event(self.event.as_raw_handle()) {
            self.state.enable();
            return Err(e);
        }
        _ = self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        ffi::reset_event(self.event.as_raw_handle())
    }

    fn enable(&self) -> io::Result<()> {
        let _guard = self.state.lock();
        if self.state.is_disabled() {
            let mut session = self
                .session
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // SAFETY: self owns a live adapter handle and ring_capacity was
            // range-validated by TunDevice construction.
            let session_handle = unsafe {
                self.win_tun
                    .WintunStartSession(self.handle, self.ring_capacity)
            };
            if session_handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: session_handle was returned non-null by WintunStartSession
            // and remains live until the WinTunSession below is dropped.
            let read_event_handle = unsafe { self.win_tun.WintunGetReadWaitEvent(session_handle) };
            if read_event_handle.is_null() {
                // SAFETY: session_handle is the live session created above and has
                // not yet been transferred into WinTunSession.
                unsafe { self.win_tun.WintunEndSession(session_handle) };
                return Err(io::Error::last_os_error());
            }

            let wintun_session = WinTunSession {
                win_tun: self.win_tun.clone(),
                handle: session_handle,
                read_event: read_event_handle,
            };
            session.replace(wintun_session);
            self.state.enable();
        }
        Ok(())
    }
    fn version(&self) -> String {
        // SAFETY: this parameterless call uses a function pointer resolved from
        // the loaded Wintun DLL and retains no Rust memory.
        let version = unsafe { self.win_tun.WintunGetRunningDriverVersion() };
        let v = version.to_be_bytes();
        format!(
            "{}.{}",
            u16::from_be_bytes([v[0], v[1]]),
            u16::from_be_bytes([v[2], v[3]])
        )
    }
    fn send(&self, buf: &[u8], event: Option<&OwnedHandle>) -> io::Result<usize> {
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            return session.send(buf, &self.state, event);
        }
        Err(io::Error::other("The interface has been disabled"))
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            return session.recv(&self.event, buf);
        }
        Err(io::Error::other("The interface has been disabled"))
    }
    fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            return session.try_send(buf);
        }
        Err(io::Error::other("The interface has been disabled"))
    }
    fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            return session.try_recv(buf);
        }
        Err(io::Error::other("The interface has been disabled"))
    }
    #[cfg(feature = "async_framed")]
    fn try_recv_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            return session.try_recv_uninit(buf);
        }
        Err(io::Error::other("The interface has been disabled"))
    }
    #[cfg(any(
        feature = "interruptible",
        feature = "async_tokio",
        feature = "async_io"
    ))]
    fn wait_readable_interruptible(
        &self,
        interrupt_event: &OwnedHandle,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        let guard = self
            .session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(session) = guard.as_ref() {
            return session.wait_readable_interruptible(&self.event, interrupt_event, timeout);
        }
        Err(io::Error::other("The interface has been disabled"))
    }
}

impl Drop for WinTunSession {
    fn drop(&mut self) {
        // SAFETY: WinTunSession exclusively owns this live Wintun session handle,
        // and Drop executes exactly once before the parent adapter is closed.
        unsafe { self.win_tun.WintunEndSession(self.handle) };
    }
}

impl WinTunSession {
    fn send(&self, buf: &[u8], state: &State, event: Option<&OwnedHandle>) -> io::Result<usize> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        let mut backoff = std::time::Duration::from_millis(0);
        loop {
            return match self.try_send(buf) {
                Ok(len) => Ok(len),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    state.check()?;
                    if start.elapsed() > timeout {
                        return Err(io::Error::from(io::ErrorKind::TimedOut));
                    }
                    if let Some(event) = event {
                        if ffi::wait_for_single_object(event.as_raw_handle(), 0).is_ok() {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "trigger interrupt",
                            ));
                        }
                    }
                    // Exponential backoff: 0, 1, 2, 4, 8, capped at 10ms
                    if backoff.is_zero() {
                        std::hint::spin_loop();
                        backoff = std::time::Duration::from_millis(1);
                    } else {
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(std::time::Duration::from_millis(10));
                    }
                    continue;
                }
                Err(e) => Err(e),
            };
        }
    }
    fn recv(&self, inner_event: &OwnedHandle, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Limit spin iterations to reduce CPU waste; use yield_now after a few spins
            for i in 0..16 {
                return match self.try_recv(buf) {
                    Ok(n) => Ok(n),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if i >= 4 {
                            std::thread::yield_now();
                        } else {
                            std::hint::spin_loop();
                        }
                        continue;
                    }
                    Err(e) => Err(e),
                };
            }
            // After spin attempts, block on the read event (also signaled on disable)
            self.wait_readable(inner_event)?;
        }
    }
    fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        let packet_len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Buffer too large: {} bytes exceeds maximum size of {} bytes",
                    buf.len(),
                    u32::MAX
                ),
            )
        })?;
        let win_tun = &self.win_tun;
        let handle = self.handle;
        // SAFETY: handle is the live session owned by self and packet_len is the
        // checked u32 representation of the source slice length.
        let bytes_ptr = unsafe { win_tun.WintunAllocateSendPacket(handle, packet_len) };
        if bytes_ptr.is_null() {
            // SAFETY: GetLastError has no pointer or lifetime preconditions and
            // must be read immediately after the failed Wintun call.
            match unsafe { GetLastError() } {
                ERROR_HANDLE_EOF => Err(std::io::Error::from(io::ErrorKind::WriteZero)),
                ERROR_BUFFER_OVERFLOW => Err(std::io::Error::from(io::ErrorKind::WouldBlock)),
                ERROR_INVALID_DATA => Err(std::io::Error::from(io::ErrorKind::InvalidData)),
                e => Err(io::Error::from_raw_os_error(e.cast_signed())),
            }
        } else {
            // SAFETY: Wintun allocated bytes_ptr for exactly buf.len() writable
            // bytes above; the source slice is initialized and non-overlapping.
            unsafe { ptr::copy_nonoverlapping(buf.as_ptr(), bytes_ptr, buf.len()) };
            // SAFETY: bytes_ptr is the outstanding send allocation returned for
            // this live session and is handed back exactly once.
            unsafe { win_tun.WintunSendPacket(handle, bytes_ptr) };
            Ok(buf.len())
        }
    }
    fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.try_recv_raw(buf.as_mut_ptr(), buf.len())
    }
    #[cfg(feature = "async_framed")]
    fn try_recv_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        self.try_recv_raw(buf.as_mut_ptr(), buf.len())
    }
    fn try_recv_raw(&self, dst: *mut u8, dst_len: usize) -> io::Result<usize> {
        let mut size = 0u32;

        let win_tun = &self.win_tun;
        let handle = self.handle;
        // SAFETY: handle is the live session owned by self and &mut size is
        // writable storage for Wintun's synchronous size out-parameter.
        let ptr = unsafe { win_tun.WintunReceivePacket(handle, &raw mut size) };

        if ptr.is_null() {
            // Wintun returns ERROR_NO_MORE_ITEMS instead of blocking if packets are not available.
            // SAFETY: GetLastError has no pointer or lifetime preconditions and
            // must be read immediately after the failed receive call.
            return match unsafe { GetLastError() } {
                ERROR_HANDLE_EOF => Err(std::io::Error::from(io::ErrorKind::UnexpectedEof)),
                ERROR_NO_MORE_ITEMS => Err(std::io::Error::from(io::ErrorKind::WouldBlock)),
                e => Err(io::Error::from_raw_os_error(e.cast_signed())),
            };
        }
        let size = size as usize;
        if size > dst_len {
            // SAFETY: ptr is the outstanding receive packet returned for this
            // live session and is released exactly once on this error path.
            unsafe { win_tun.WintunReleaseReceivePacket(handle, ptr) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination buffer too small",
            ));
        }
        // SAFETY: size <= dst_len above, callers provide dst valid for dst_len
        // writable bytes, and Wintun guarantees ptr references size packet bytes.
        unsafe { ptr::copy_nonoverlapping(ptr, dst, size) };
        // SAFETY: ptr is the outstanding receive packet returned for this live
        // session and has not been released on the success path yet.
        unsafe { win_tun.WintunReleaseReceivePacket(handle, ptr) };
        Ok(size)
    }
    #[cfg(any(
        feature = "interruptible",
        feature = "async_tokio",
        feature = "async_io"
    ))]
    fn wait_readable_interruptible(
        &self,
        inner_event: &OwnedHandle,
        interrupt_event: &OwnedHandle,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        //Wait on both the read handle and the shutdown handle so that we stop when requested
        let handles = [
            self.read_event,
            inner_event.as_raw_handle(),
            interrupt_event.as_raw_handle(),
        ];
        // SAFETY: handles is a live stack array of three valid wait handles;
        // WaitForMultipleObjects borrows the array synchronously and count matches.
        let timeout_ms = finite_wait_timeout_ms(timeout);
        let result = unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, timeout_ms) };
        match result {
            WAIT_FAILED => Err(io::Error::last_os_error()),
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => {
                Err(io::Error::from(io::ErrorKind::TimedOut))
            }
            _ => {
                if result == WAIT_OBJECT_0 {
                    //We have data!
                    Ok(())
                } else if result == WAIT_OBJECT_0 + 1 {
                    Err(io::Error::other("The interface has been disabled"))
                } else if result == WAIT_OBJECT_0 + 2 {
                    Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "trigger interrupt",
                    ))
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
    fn wait_readable(&self, inner_event: &OwnedHandle) -> io::Result<()> {
        //Wait on both the read handle and the shutdown handle so that we stop when requested
        let handles = [self.read_event, inner_event.as_raw_handle()];
        // SAFETY: handles is a live stack array of two valid wait handles;
        // WaitForMultipleObjects borrows the array synchronously and count matches.
        let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
        match result {
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => {
                if result == WAIT_OBJECT_0 {
                    //We have data!
                    Ok(())
                } else if result == WAIT_OBJECT_0 + 1 {
                    Err(io::Error::other("The interface has been disabled"))
                } else {
                    Err(io::Error::last_os_error())
                }
            }
        }
    }
}

impl TunDevice {
    pub fn open(
        wintun_path: &str,
        name: &str,
        ring_capacity: u32,
        delete_driver: bool,
        wintun_log: bool,
    ) -> std::io::Result<Self> {
        let range = MIN_RING_CAPACITY..=MAX_RING_CAPACITY;
        if !range.contains(&ring_capacity) {
            Err(io::Error::other(format!(
                "ring capacity {ring_capacity} not in [{MIN_RING_CAPACITY},{MAX_RING_CAPACITY}]"
            )))?;
        }
        let name_utf16 = encode_utf16(name);
        if name_utf16.len() > MAX_POOL {
            Err(io::Error::other("name too long"))?;
        }

        let event = ffi::create_event()?;

        // SAFETY: loading a native DLL is an explicit trust boundary. The configured
        // path is expected to name a Wintun DLL whose exported symbols have the ABI
        // described by the generated bindings; the loader verifies required symbols.
        let win_tun = unsafe { wintun_raw::wintun::new(wintun_path) }.map_err(io::Error::other)?;
        if wintun_log {
            wintun_log::set_default_logger_if_unset(&win_tun);
        }
        // SAFETY: name_utf16 is NUL-terminated storage produced by encode_utf16 and
        // remains live for the duration of the synchronous Wintun call.
        let adapter = unsafe { win_tun.WintunOpenAdapter(name_utf16.as_ptr()) };
        if adapter.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mut raw_luid = std::mem::MaybeUninit::<wintun_raw::NET_LUID>::uninit();
        // SAFETY: adapter was returned non-null above and raw_luid is writable
        // storage for the NET_LUID out-parameter.
        unsafe { win_tun.WintunGetAdapterLUID(adapter, raw_luid.as_mut_ptr()) };
        // SAFETY: WintunGetAdapterLUID initializes the complete NET_LUID output.
        let raw_luid = unsafe { raw_luid.assume_init() };
        // SAFETY: NET_LUID's Value member is the canonical 64-bit representation
        // initialized by WintunGetAdapterLUID above.
        let luid_value = unsafe { raw_luid.Value };
        let luid = NET_LUID_LH { Value: luid_value };

        let win_tun_adapter = WinTunAdapter {
            win_tun: Arc::new(win_tun),
            handle: adapter,
            state: State::default(),
            event,
            ring_capacity,
            session: RwLock::default(),
            delete_driver,
        };
        let index = ffi::luid_to_index(&luid)?;

        Ok(Self {
            index,
            luid,
            win_tun_adapter,
        })
    }
    pub fn create(
        wintun_path: &str,
        name: &str,
        description: &str,
        guid: Option<u128>,
        ring_capacity: u32,
        delete_driver: bool,
        wintun_log: bool,
    ) -> std::io::Result<Self> {
        let range = MIN_RING_CAPACITY..=MAX_RING_CAPACITY;
        if !range.contains(&ring_capacity) {
            Err(io::Error::other(format!(
                "ring capacity {ring_capacity} not in [{MIN_RING_CAPACITY},{MAX_RING_CAPACITY}]"
            )))?;
        }
        let name_utf16 = encode_utf16(name);
        let description_utf16 = encode_utf16(description);
        if name_utf16.len() > MAX_POOL {
            Err(io::Error::other("name too long"))?;
        }
        if description_utf16.len() > MAX_POOL {
            Err(io::Error::other("tunnel type too long"))?;
        }
        let event = ffi::create_event()?;

        // SAFETY: loading a native DLL is an explicit trust boundary. The configured
        // path is expected to name a Wintun DLL whose exported symbols have the ABI
        // described by the generated bindings; the loader verifies required symbols.
        let win_tun = unsafe { wintun_raw::wintun::new(wintun_path) }.map_err(io::Error::other)?;
        if wintun_log {
            wintun_log::set_default_logger_if_unset(&win_tun);
        }

        let guid = guid.map(|guid| {
            let guid = GUID::from_u128(guid);
            wintun_raw::GUID {
                Data1: guid.data1,
                Data2: guid.data2,
                Data3: guid.data3,
                Data4: guid.data4,
            }
        });

        // SAFETY: both UTF-16 strings are NUL-terminated and remain live for the
        // synchronous call; guid is either null or points to a live GUID value.
        let adapter = unsafe {
            win_tun.WintunCreateAdapter(
                name_utf16.as_ptr(),
                description_utf16.as_ptr(),
                guid.as_ref().map_or(ptr::null(), |guid| guid),
            )
        };
        if adapter.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mut raw_luid = std::mem::MaybeUninit::<wintun_raw::NET_LUID>::uninit();
        // SAFETY: adapter was returned non-null above and raw_luid is writable
        // storage for the NET_LUID out-parameter.
        unsafe { win_tun.WintunGetAdapterLUID(adapter, raw_luid.as_mut_ptr()) };
        // SAFETY: WintunGetAdapterLUID initializes the complete NET_LUID output.
        let raw_luid = unsafe { raw_luid.assume_init() };
        // SAFETY: NET_LUID's Value member is the canonical 64-bit representation
        // initialized by WintunGetAdapterLUID above.
        let luid_value = unsafe { raw_luid.Value };
        let luid = NET_LUID_LH { Value: luid_value };

        let win_tun_adapter = WinTunAdapter {
            win_tun: Arc::new(win_tun),
            handle: adapter,
            state: State::default(),
            event,
            ring_capacity,
            session: RwLock::default(),
            delete_driver,
        };
        let index = ffi::luid_to_index(&luid)?;

        Ok(Self {
            index,
            luid,
            win_tun_adapter,
        })
    }
    pub fn luid(&self) -> NET_LUID_LH {
        self.luid
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn get_name(&self) -> io::Result<String> {
        ffi::luid_to_alias(&self.luid)
    }
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.win_tun_adapter.send(buf, None)
    }

    #[cfg(any(
        feature = "interruptible",
        feature = "async_tokio",
        feature = "async_io"
    ))]
    #[inline]
    pub(crate) fn send_interruptible(&self, buf: &[u8], event: &OwnedHandle) -> io::Result<usize> {
        self.win_tun_adapter.send(buf, Some(event))
    }
    #[cfg(any(
        feature = "interruptible",
        feature = "async_tokio",
        feature = "async_io"
    ))]
    #[inline]
    pub(crate) fn wait_readable_interruptible(
        &self,
        interrupt_event: &OwnedHandle,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        self.win_tun_adapter
            .wait_readable_interruptible(interrupt_event, timeout)
    }
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.win_tun_adapter.recv(buf)
    }
    #[inline]
    pub fn try_send(&self, buf: &[u8]) -> io::Result<usize> {
        self.win_tun_adapter.try_send(buf)
    }
    #[inline]
    pub fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.win_tun_adapter.try_recv(buf)
    }
    #[inline]
    #[cfg(feature = "async_framed")]
    pub(crate) fn try_recv_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        self.win_tun_adapter.try_recv_uninit(buf)
    }
    pub fn shutdown(&self) -> io::Result<()> {
        self.win_tun_adapter.disable()
    }
    pub fn version(&self) -> String {
        self.win_tun_adapter.version()
    }
    pub fn enabled(&self, value: bool) -> io::Result<()> {
        if value {
            self.win_tun_adapter.enable()
        } else {
            self.win_tun_adapter.disable()
        }
    }
}
