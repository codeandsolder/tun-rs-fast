use crate::platform::windows::ffi;
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::Mutex;

pub struct InterruptEvent {
    pub(crate) handle: OwnedHandle,
    state: Mutex<i32>,
}
impl InterruptEvent {
    /// Creates a new interrupt event.
    ///
    /// # Errors
    /// Returns an I/O error if the underlying Windows event cannot be created.
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            handle: ffi::create_event()?,
            state: Mutex::new(0),
        })
    }
    /// Triggers the interrupt event.
    ///
    /// # Errors
    /// Returns an I/O error if signalling the Windows event fails.
    pub fn trigger(&self) -> io::Result<()> {
        self.trigger_value(1)
    }
    /// Stores a trigger value and signals the interrupt event.
    ///
    /// # Errors
    /// Returns an I/O error if signalling the Windows event fails.
    pub fn trigger_value(&self, val: i32) -> io::Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = val;
        ffi::set_event(self.handle.as_raw_handle())
    }
    #[cfg(feature = "interruptible")]
    pub fn is_trigger(&self) -> bool {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            != 0
    }
    #[cfg(feature = "interruptible")]
    pub fn value(&self) -> i32 {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Clears the trigger value and resets the interrupt event.
    ///
    /// # Errors
    /// Returns an I/O error if resetting the Windows event fails.
    #[cfg(feature = "interruptible")]
    ///
    /// # Errors
    /// Returns an error if the underlying Windows operation fails.
    pub fn reset(&self) -> io::Result<()> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = 0;
        ffi::reset_event(self.handle.as_raw_handle())
    }
}
