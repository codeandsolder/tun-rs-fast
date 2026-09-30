#![expect(
    unsafe_code,
    reason = "Windows 7 Wintun adapter cleanup crosses Win32 process and SetupAPI FFI boundaries"
)]

use std::{mem, ptr};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiGetClassDevsExW, SetupDiGetDevicePropertyW,
};
use windows_sys::Win32::Devices::Properties::DEVPROP_TYPE_BINARY;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INVALID_DATA, FILETIME, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::windows::{
    device::GUID_NETWORK_ADAPTER,
    ffi::{destroy_device_info_list, encode_utf16, enum_device_info},
    tun::adapter::{get_device_name, DEVPKEY_Wintun_OwningProcess},
};

#[repr(C)]
pub struct OwningProcess {
    process_id: u32,
    creation_time: FILETIME,
}

pub fn check_adapter_if_orphaned_devices_win7(adapter_name: &str) -> bool {
    let device_name = encode_utf16("ROOT\\Wintun");
    // SAFETY: device_name is NUL-terminated and optional pointer arguments are
    // null; SetupAPI returns a device-info-set handle on success.
    let dev_info = unsafe {
        SetupDiGetClassDevsExW(
            &GUID_NETWORK_ADAPTER,
            device_name.as_ptr(),
            ptr::null_mut(),
            0,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if dev_info == INVALID_HANDLE_VALUE as isize {
        // SAFETY: GetLastError has no pointer/lifetime preconditions and is read
        // immediately after the failed SetupAPI call.
        if unsafe { GetLastError() } != ERROR_INVALID_DATA {
            log::error!("Failed to get adapters");
        }
        return false;
    }

    let mut index = 0;
    let is_orphaned_adapter = loop {
        let Some(result) = enum_device_info(dev_info, index) else {
            break false;
        };
        let Ok(devinfo_data) = result else {
            index += 1;
            continue;
        };

        // SAFETY: ptype/buf are plain writable output storage; devinfo_data belongs
        // to dev_info, and SetupDiGetDevicePropertyW borrows all buffers synchronously.
        unsafe {
            let mut ptype = mem::zeroed();
            let mut buf: [u8; mem::size_of::<OwningProcess>()] = mem::zeroed();
            let Ok(buffer_len) = u32::try_from(buf.len()) else {
                return false;
            };

            let ok = SetupDiGetDevicePropertyW(
                dev_info,
                &raw const devinfo_data,
                &DEVPKEY_Wintun_OwningProcess,
                &raw mut ptype,
                buf.as_mut_ptr(),
                buffer_len,
                ptr::null_mut(),
                0,
            );

            if ok != 0 && ptype == DEVPROP_TYPE_BINARY && {
                // SAFETY: buf is [u8] (alignment 1) but OwningProcess requires alignment 4.
                // Use read_unaligned to avoid UB from misaligned access.
                let owning_process = std::ptr::read_unaligned(buf.as_ptr().cast::<OwningProcess>());
                !process_is_stale(&owning_process)
            } {
                index += 1;
                continue;
            }
        }

        let Ok(name) = get_device_name(dev_info, &devinfo_data) else {
            index += 1;
            continue;
        };
        if adapter_name == name {
            break true;
        }

        index += 1;
    };
    _ = destroy_device_info_list(dev_info);
    is_orphaned_adapter
}

fn process_is_stale(owning_process: &OwningProcess) -> bool {
    // SAFETY: process_id is an integer identifier obtained from Wintun metadata;
    // OpenProcess returns either a new owned handle or null.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            owning_process.process_id,
        )
    };
    if process.is_null() {
        return true;
    }
    // SAFETY: FILETIME is a plain Win32 POD value and zero is a valid temporary
    // initialization before GetProcessTimes overwrites the outputs.
    let mut creation_time: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: same invariant as creation_time; this storage is only an ignored output.
    let mut unused: FILETIME = unsafe { std::mem::zeroed() };
    // SAFETY: process is a live handle and all FILETIME pointers are writable for
    // the duration of this synchronous query.
    let ret = unsafe {
        GetProcessTimes(
            process,
            &raw mut creation_time,
            &raw mut unused,
            &raw mut unused,
            &raw mut unused,
        )
    };
    // SAFETY: process was returned non-null by OpenProcess and is closed exactly once.
    _ = unsafe { CloseHandle(process) };
    if ret == 0 {
        return false;
    }
    creation_time.dwHighDateTime == owning_process.creation_time.dwHighDateTime
        && creation_time.dwLowDateTime == owning_process.creation_time.dwLowDateTime
}
