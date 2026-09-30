#![expect(
    unsafe_code,
    reason = "Windows network/device configuration wrappers call Win32 APIs and own the raw handle/buffer invariants"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::{io, mem, ptr};

use windows_sys::Win32::Foundation::{
    ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry,
    GetIpInterfaceTable, GetUnicastIpAddressTable, InitializeIpForwardEntry,
    InitializeUnicastIpAddressEntry, SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::Networking::WinSock::{
    NlroManual, AF_INET, AF_INET6, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};
use windows_sys::Win32::System::Threading::{ResetEvent, SetEvent};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::{
    core::{BOOL, GUID},
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            SetupDiBuildDriverInfoList, SetupDiCallClassInstaller, SetupDiClassNameFromGuidW,
            SetupDiCreateDeviceInfoList, SetupDiCreateDeviceInfoW, SetupDiDestroyDeviceInfoList,
            SetupDiDestroyDriverInfoList, SetupDiEnumDeviceInfo, SetupDiEnumDriverInfoW,
            SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW, SetupDiGetDriverInfoDetailW,
            SetupDiOpenDevRegKey, SetupDiSetClassInstallParamsW, SetupDiSetDeviceRegistryPropertyW,
            SetupDiSetSelectedDevice, SetupDiSetSelectedDriverW, DICS_DISABLE, DICS_ENABLE,
            DICS_FLAG_GLOBAL, DIF_PROPERTYCHANGE, HDEVINFO, MAX_CLASS_NAME_LEN,
            SP_CLASSINSTALL_HEADER, SP_DEVINFO_DATA, SP_DRVINFO_DATA_V2_W,
            SP_DRVINFO_DETAIL_DATA_W, SP_PROPCHANGE_PARAMS,
        },
        Foundation::{
            CloseHandle, GetLastError, ERROR_NO_MORE_ITEMS, FALSE, FILETIME, HANDLE, TRUE,
            WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToAlias,
                ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
            },
            Ndis::NET_LUID_LH,
        },
        Storage::FileSystem::{
            CreateFileW, ReadFile, WriteFile, FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_SHARE_MODE,
        },
        System::{
            Com::StringFromGUID2,
            Registry::{RegNotifyChangeKeyValue, HKEY},
            Threading::{CreateEventW, WaitForSingleObject, INFINITE},
            IO::DeviceIoControl,
        },
    },
};

#[expect(non_snake_case, reason = "name mirrors the Windows API ABI")]
#[repr(C)]
#[derive(Clone, Copy)]
/// Custom type to handle variable size `SP_DRVINFO_DETAIL_DATA_W`
pub struct SP_DRVINFO_DETAIL_DATA_W2 {
    pub cbSize: u32,
    pub InfDate: FILETIME,
    pub CompatIDsOffset: u32,
    pub CompatIDsLength: u32,
    pub Reserved: usize,
    pub SectionName: [u16; 256],
    pub InfFileName: [u16; 260],
    pub DrvDescription: [u16; 256],
    pub HardwareID: [u16; 512],
}

/// Encode a string as a utf16 buffer
pub fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

pub fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

fn usize_to_u32(value: usize, what: &'static str) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} exceeds the Win32 u32 ABI limit"),
        )
    })
}

fn usize_to_i32(value: usize, what: &'static str) -> io::Result<i32> {
    i32::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{what} exceeds the Win32 i32 ABI limit"),
        )
    })
}

pub(crate) fn finite_wait_timeout_millis(duration: std::time::Duration) -> u32 {
    let whole_millis = duration.as_millis();
    let has_fraction = !duration.subsec_nanos().is_multiple_of(1_000_000);
    let rounded_up = whole_millis.saturating_add(u128::from(has_fraction));
    let max_finite = u128::from(INFINITE - 1);
    u32::try_from(rounded_up.min(max_finite)).unwrap_or(INFINITE - 1)
}

pub fn string_from_guid(guid: &GUID) -> io::Result<String> {
    let mut string = [0u16; 39];
    let capacity = usize_to_i32(string.len(), "GUID string buffer length")?;

    // SAFETY: guid is a live GUID and string owns capacity writable UTF-16
    // code units for the duration of this synchronous conversion.
    match unsafe { StringFromGUID2(guid, string.as_mut_ptr(), capacity) } {
        0 => Err(io::Error::other(
            "StringFromGUID2 reported an insufficient GUID string buffer",
        )),
        _ => Ok(decode_utf16(&string)),
    }
}

pub fn alias_to_luid(alias: &str) -> io::Result<NET_LUID_LH> {
    let alias = encode_utf16(alias);
    // SAFETY: NET_LUID_LH is a plain Win32 value type for which all-zero is a
    // valid initialization state before the API fills the output.
    let mut luid = unsafe { mem::zeroed() };
    // SAFETY: alias is NUL-terminated and live; luid is writable output storage.
    let status = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &raw mut luid) };
    win_result(status)?;
    Ok(luid)
}

pub fn luid_to_index(luid: &NET_LUID_LH) -> io::Result<u32> {
    let mut index = 0;
    // SAFETY: luid is a live input value and index is writable output storage.
    let status = unsafe { ConvertInterfaceLuidToIndex(luid, &raw mut index) };
    win_result(status)?;
    Ok(index)
}

pub fn luid_to_guid(luid: &NET_LUID_LH) -> io::Result<GUID> {
    // SAFETY: GUID is a plain Win32 value type and zero-initialization is valid
    // before the conversion API overwrites the output.
    let mut guid = unsafe { mem::zeroed() };
    // SAFETY: luid is live and guid is writable for the synchronous call.
    let status = unsafe { ConvertInterfaceLuidToGuid(luid, &raw mut guid) };
    win_result(status)?;
    Ok(guid)
}

pub fn luid_to_alias(luid: &NET_LUID_LH) -> io::Result<String> {
    // IF_MAX_STRING_SIZE + 1
    let mut alias = [0u16; 257];
    // SAFETY: luid is live and alias provides the documented
    // IF_MAX_STRING_SIZE + 1 writable UTF-16 code units.
    let status = unsafe { ConvertInterfaceLuidToAlias(luid, alias.as_mut_ptr(), alias.len()) };
    win_result(status)?;
    Ok(decode_utf16(&alias))
}
pub fn reset_event(handle: RawHandle) -> io::Result<()> {
    // SAFETY: callers supply a live event handle owned elsewhere; ResetEvent does
    // not take ownership and uses it only for the duration of the call.
    unsafe {
        if FALSE == ResetEvent(handle) {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
pub fn wait_for_single_object(handle: RawHandle, timeout: u32) -> io::Result<()> {
    // SAFETY: callers supply a live waitable handle; WaitForSingleObject borrows
    // the handle synchronously and does not alter its ownership.
    match unsafe { WaitForSingleObject(handle, timeout) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::from(io::ErrorKind::TimedOut)),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        value => Err(io::Error::other(format!(
            "WaitForSingleObject returned unexpected status {value:#x}"
        ))),
    }
}
pub fn set_event(handle: RawHandle) -> io::Result<()> {
    // SAFETY: callers supply a live event handle; SetEvent only borrows it.
    unsafe {
        if FALSE == SetEvent(handle) {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
pub fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: CreateEventW is called with null optional security/name pointers.
    // On success it returns a newly owned handle which is transferred exactly once
    // into OwnedHandle.
    unsafe {
        let read_event_handle = CreateEventW(ptr::null_mut(), 1, 0, ptr::null_mut());
        if read_event_handle.is_null() {
            Err(io::Error::last_os_error())?;
        }
        Ok(OwnedHandle::from_raw_handle(read_event_handle))
    }
}

pub fn create_file(
    file_name: &str,
    desired_access: u32,
    share_mode: FILE_SHARE_MODE,
    creation_disposition: FILE_CREATION_DISPOSITION,
    flags_and_attributes: FILE_FLAGS_AND_ATTRIBUTES,
) -> io::Result<HANDLE> {
    let file_name = encode_utf16(file_name);
    // SAFETY: file_name is NUL-terminated and all optional pointer parameters
    // are null; the returned HANDLE is checked before being exposed.
    let handle = unsafe {
        CreateFileW(
            file_name.as_ptr(),
            desired_access,
            share_mode,
            ptr::null_mut(),
            creation_disposition,
            flags_and_attributes,
            ptr::null_mut(),
        )
    };
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(handle)
    }
}

pub fn io_overlapped() -> OVERLAPPED {
    OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: windows_sys::Win32::System::IO::OVERLAPPED_0 {
            Anonymous: windows_sys::Win32::System::IO::OVERLAPPED_0_0 {
                Offset: 0,
                OffsetHigh: 0,
            },
        },
        hEvent: ptr::null_mut(),
    }
}

pub fn try_read_file(
    handle: HANDLE,
    io_overlapped: &mut OVERLAPPED,
    buffer: &mut [u8],
) -> io::Result<u32> {
    let mut ret = 0;
    let buffer_len = usize_to_u32(buffer.len(), "ReadFile buffer length")?;
    // SAFETY: handle and io_overlapped must remain valid until the overlapped
    // operation completes; the owning TAP layer guarantees that lifetime. buffer
    // supplies buffer_len writable bytes for this submission.
    unsafe {
        if 0 == ReadFile(
            handle,
            buffer.as_mut_ptr().cast(),
            buffer_len,
            &raw mut ret,
            io_overlapped,
        ) {
            Err(error_map())
        } else {
            Ok(ret)
        }
    }
}

pub fn try_write_file(
    handle: HANDLE,
    io_overlapped: &mut OVERLAPPED,
    buffer: &[u8],
) -> io::Result<u32> {
    let mut ret = 0;
    let buffer_len = usize_to_u32(buffer.len(), "WriteFile buffer length")?;
    // SAFETY: handle and io_overlapped remain valid until completion, and
    // buffer supplies buffer_len readable bytes for the submission.
    unsafe {
        if 0 == WriteFile(
            handle,
            buffer.as_ptr().cast(),
            buffer_len,
            &raw mut ret,
            io_overlapped,
        ) {
            Err(error_map())
        } else {
            Ok(ret)
        }
    }
}
fn error_map() -> io::Error {
    let e = io::Error::last_os_error();
    if e.raw_os_error().unwrap_or(0) == ERROR_IO_PENDING.cast_signed() {
        io::Error::from(io::ErrorKind::WouldBlock)
    } else {
        e
    }
}

pub fn try_io_overlapped(handle: HANDLE, io_overlapped: &OVERLAPPED) -> io::Result<u32> {
    let mut ret = 0;
    // SAFETY: handle owns the pending I/O represented by the live OVERLAPPED;
    // ret is writable storage for the transferred-byte count.
    unsafe {
        if 0 == GetOverlappedResult(handle, io_overlapped, &raw mut ret, 0) {
            let err = io::Error::last_os_error();
            if err.raw_os_error().unwrap_or(0) == ERROR_IO_INCOMPLETE.cast_signed() {
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            } else {
                Err(err)
            }
        } else {
            Ok(ret)
        }
    }
}
pub fn cancel_io_overlapped(handle: HANDLE, io_overlapped: &OVERLAPPED) -> io::Result<u32> {
    // SAFETY: the OVERLAPPED belongs to handle and remains live while cancellation
    // is requested and completion is subsequently awaited.
    unsafe {
        CancelIoEx(handle, io_overlapped);
        wait_io_overlapped(handle, io_overlapped)
    }
}

pub fn wait_io_overlapped(handle: HANDLE, io_overlapped: &OVERLAPPED) -> io::Result<u32> {
    let mut ret = 0;
    // SAFETY: io_overlapped belongs to handle and remains live until the wait
    // completes; ret is valid writable result storage.
    unsafe {
        if 0 == GetOverlappedResult(handle, io_overlapped, &raw mut ret, 1) {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }
}

pub fn create_device_info_list(guid: &GUID) -> io::Result<HDEVINFO> {
    // SAFETY: guid is live and the optional parent window handle is null.
    // SetupAPI returns a new device-info-set handle without borrowing Rust memory.
    match unsafe { SetupDiCreateDeviceInfoList(guid, ptr::null_mut()) } {
        -1 => Err(io::Error::last_os_error()),
        devinfo => Ok(devinfo),
    }
}

pub fn get_class_devs(guid: &GUID, flags: u32) -> io::Result<HDEVINFO> {
    // SAFETY: guid is live; optional enumerator/window pointers are null, and
    // SetupAPI returns an owned device-info-set handle on success.
    match unsafe { SetupDiGetClassDevsW(guid, ptr::null(), ptr::null_mut(), flags) } {
        -1 => Err(io::Error::last_os_error()),
        devinfo => Ok(devinfo),
    }
}

pub fn destroy_device_info_list(devinfo: HDEVINFO) -> io::Result<()> {
    // SAFETY: devinfo is an owned SetupAPI device-info-set handle released once.
    match unsafe { SetupDiDestroyDeviceInfoList(devinfo) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn class_name_from_guid(guid: &GUID) -> io::Result<String> {
    let class_name_capacity = usize::try_from(MAX_CLASS_NAME_LEN).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "MAX_CLASS_NAME_LEN exceeds usize",
        )
    })?;
    let mut class_name = vec![0; class_name_capacity];
    let class_name_len = usize_to_u32(class_name.len(), "class-name buffer length")?;
    // SAFETY: guid is live and class_name provides class_name_len writable
    // UTF-16 code units; the optional required-size pointer is null.
    match unsafe {
        SetupDiClassNameFromGuidW(
            guid,
            class_name.as_mut_ptr(),
            class_name_len,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(decode_utf16(&class_name)),
    }
}

pub fn create_device_info(
    devinfo: HDEVINFO,
    device_name: &str,
    guid: &GUID,
    device_description: &str,
    creation_flags: u32,
) -> io::Result<SP_DEVINFO_DATA> {
    // SAFETY: SP_DEVINFO_DATA is a C POD output structure; zeroed state is valid
    // before cbSize is initialized for SetupAPI.
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize = usize_to_u32(mem::size_of_val(&devinfo_data), "SP_DEVINFO_DATA size")?;
    let device_name = encode_utf16(device_name);
    let device_description = encode_utf16(device_description);
    // SAFETY: devinfo is live; both UTF-16 strings are NUL-terminated, guid is
    // live, and devinfo_data is correctly sized writable output storage.
    match unsafe {
        SetupDiCreateDeviceInfoW(
            devinfo,
            device_name.as_ptr(),
            guid,
            device_description.as_ptr(),
            ptr::null_mut(),
            creation_flags,
            &raw mut devinfo_data,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(devinfo_data),
    }
}

pub fn set_selected_device(devinfo: HDEVINFO, devinfo_data: &SP_DEVINFO_DATA) -> io::Result<()> {
    // SAFETY: devinfo and devinfo_data belong to the same live SetupAPI set and
    // are borrowed only for this synchronous selection call.
    match unsafe { SetupDiSetSelectedDevice(devinfo, std::ptr::from_ref(devinfo_data).cast()) } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn set_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: u32,
    value: &str,
) -> io::Result<()> {
    let value = encode_utf16(value);
    let value_bytes = value
        .len()
        .checked_mul(mem::size_of::<u16>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "registry value too large"))?;
    let value_bytes = usize_to_u32(value_bytes, "registry value byte length")?;
    // SAFETY: devinfo/devinfo_data identify a live device; value is a live
    // value_bytes-long UTF-16 buffer borrowed synchronously by SetupAPI.
    match unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast_mut(),
            property,
            value.as_ptr().cast(),
            value_bytes,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_device_registry_property(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    property: u32,
) -> io::Result<String> {
    let mut required_size: u32 = 0;
    // First call to get the required buffer size.
    // SAFETY: devinfo/devinfo_data are live and required_size is writable output;
    // the data buffer is intentionally null for this size query.
    unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
            property,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            &raw mut required_size,
        );
    }

    if required_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "property not found or empty",
        ));
    }

    let mut value = vec![
        0u16;
        usize::try_from(required_size / 2).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "registry value size exceeds usize",
            )
        })?
    ];
    // SAFETY: value is allocated from the size returned by the first call and
    // remains writable/live for the synchronous property read.
    match unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
            property,
            ptr::null_mut(),
            value.as_mut_ptr().cast(),
            required_size,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(decode_utf16(&value)),
    }
}

pub fn build_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &mut SP_DEVINFO_DATA,
    driver_type: u32,
) -> io::Result<()> {
    // SAFETY: devinfo_data belongs to live devinfo; SetupAPI borrows both for
    // this synchronous list-construction call.
    match unsafe {
        SetupDiBuildDriverInfoList(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast_mut(),
            driver_type,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn destroy_driver_info_list(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: u32,
) -> io::Result<()> {
    // SAFETY: this releases the driver-info list associated with the live
    // devinfo/devinfo_data pair; neither pointer escapes the call.
    match unsafe {
        SetupDiDestroyDriverInfoList(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
            driver_type,
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_driver_info_detail(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_data: &SP_DRVINFO_DATA_V2_W,
) -> io::Result<SP_DRVINFO_DETAIL_DATA_W2> {
    // SAFETY: this is a C-layout output buffer; zeroed trailing storage is valid
    // before cbSize is populated and SetupAPI fills the detail record.
    let mut drvinfo_detail: SP_DRVINFO_DETAIL_DATA_W2 = unsafe { mem::zeroed() };
    drvinfo_detail.cbSize = usize_to_u32(
        mem::size_of::<SP_DRVINFO_DETAIL_DATA_W>(),
        "SP_DRVINFO_DETAIL_DATA_W size",
    )?;
    let detail_size = usize_to_u32(
        mem::size_of_val(&drvinfo_detail),
        "driver detail buffer size",
    )?;

    // SAFETY: all SetupAPI records belong to the same live device-info set and
    // drvinfo_detail is a correctly sized writable output buffer.
    match unsafe {
        SetupDiGetDriverInfoDetailW(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
            std::ptr::from_ref(driver_data).cast(),
            (&raw mut drvinfo_detail).cast(),
            detail_size,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(drvinfo_detail),
    }
}

pub fn set_selected_driver(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_data: &SP_DRVINFO_DATA_V2_W,
) -> io::Result<()> {
    // SAFETY: devinfo_data and driver_data both originate from live devinfo and
    // are borrowed synchronously to select that driver.
    match unsafe {
        SetupDiSetSelectedDriverW(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast_mut(),
            std::ptr::from_ref(driver_data).cast_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn call_class_installer(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    install_function: u32,
) -> io::Result<()> {
    // SAFETY: devinfo_data belongs to live devinfo; the installer code is passed
    // through exactly as required by SetupAPI and no pointer escapes.
    match unsafe {
        SetupDiCallClassInstaller(
            install_function,
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn open_dev_reg_key(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    scope: u32,
    hw_profile: u32,
    key_type: u32,
    sam_desired: u32,
) -> io::Result<HKEY> {
    const INVALID_KEY_VALUE: HKEY = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE.cast();

    // SAFETY: devinfo_data belongs to live devinfo; SetupAPI borrows it and
    // returns a registry handle whose ownership is transferred to the caller.
    match unsafe {
        SetupDiOpenDevRegKey(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
            scope,
            hw_profile,
            key_type,
            sam_desired,
        )
    } {
        INVALID_KEY_VALUE => Err(io::Error::last_os_error()),
        key => Ok(key),
    }
}

pub fn notify_change_key_value(
    key: HKEY,
    watch_subtree: BOOL,
    notify_filter: u32,
    milliseconds: u32,
) -> io::Result<()> {
    const INVALID_HANDLE_VALUE: HKEY = windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE.cast();

    // SAFETY: optional security/name pointers are null; on success this creates
    // a new event handle owned by this function until CloseHandle below.
    let event = match unsafe { CreateEventW(ptr::null_mut(), FALSE, FALSE, ptr::null()) } {
        INVALID_HANDLE_VALUE => Err(io::Error::last_os_error()),
        event => Ok(event),
    }?;

    let result =
        // SAFETY: key and event are live handles and the asynchronous notification
        // writes only to event, which remains live through the wait.
        match unsafe { RegNotifyChangeKeyValue(key, watch_subtree, notify_filter, event, TRUE) } {
            // SAFETY: event remains live until this synchronous wait completes.
            0 => match unsafe { WaitForSingleObject(event, milliseconds) } {
                0 => Ok(()),
                0x102 => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Registry timed out",
                )),
                _ => Err(io::Error::last_os_error()),
            },
            _err => Err(io::Error::last_os_error()),
        };

    // SAFETY: event was created successfully above and is closed exactly once.
    unsafe { CloseHandle(event) };

    result
}

pub fn enum_driver_info(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    driver_type: u32,
    member_index: u32,
) -> Option<io::Result<SP_DRVINFO_DATA_V2_W>> {
    // SAFETY: SP_DRVINFO_DATA_V2_W is a C POD output structure; zeroed state is
    // valid before cbSize is initialized for SetupAPI.
    let mut driver_data: SP_DRVINFO_DATA_V2_W = unsafe { mem::zeroed() };
    driver_data.cbSize =
        match usize_to_u32(mem::size_of_val(&driver_data), "SP_DRVINFO_DATA_V2_W size") {
            Ok(size) => size,
            Err(error) => return Some(Err(error)),
        };
    // SAFETY: devinfo_data belongs to live devinfo and driver_data is correctly
    // sized writable storage for one enumerated record.
    match unsafe {
        SetupDiEnumDriverInfoW(
            devinfo,
            std::ptr::from_ref(devinfo_data).cast(),
            driver_type,
            member_index,
            &raw mut driver_data,
        )
    } {
        // SAFETY: GetLastError has no pointer preconditions and is read immediately
        // after the failed SetupAPI enumeration call.
        0 if unsafe { GetLastError() == ERROR_NO_MORE_ITEMS } => None,
        0 => Some(Err(io::Error::last_os_error())),
        _ => Some(Ok(driver_data)),
    }
}

pub fn enum_device_info(
    devinfo: HDEVINFO,
    member_index: u32,
) -> Option<io::Result<SP_DEVINFO_DATA>> {
    // SAFETY: SP_DEVINFO_DATA is a C POD output structure; zeroed state is valid
    // before cbSize is initialized for SetupAPI.
    let mut devinfo_data: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    devinfo_data.cbSize =
        match usize_to_u32(mem::size_of_val(&devinfo_data), "SP_DEVINFO_DATA size") {
            Ok(size) => size,
            Err(error) => return Some(Err(error)),
        };

    // SAFETY: devinfo is live and devinfo_data is correctly sized writable
    // storage for this synchronous enumeration call.
    match unsafe { SetupDiEnumDeviceInfo(devinfo, member_index, &raw mut devinfo_data) } {
        // SAFETY: GetLastError has no pointer preconditions and is read immediately
        // after the failed SetupAPI enumeration call.
        0 if unsafe { GetLastError() == ERROR_NO_MORE_ITEMS } => None,
        0 => Some(Err(io::Error::last_os_error())),
        _ => Some(Ok(devinfo_data)),
    }
}

pub fn device_io_control(
    handle: HANDLE,
    io_control_code: u32,
    in_buffer: &impl Copy,
    out_buffer: &mut impl Copy,
) -> io::Result<()> {
    let mut junk = 0;
    let in_size = usize_to_u32(mem::size_of_val(in_buffer), "DeviceIoControl input size")?;
    let out_size = usize_to_u32(mem::size_of_val(out_buffer), "DeviceIoControl output size")?;
    // SAFETY: handle is live; input/output pointers point to in_size/out_size
    // bytes of live Copy values, and the call is synchronous because OVERLAPPED is null.
    match unsafe {
        DeviceIoControl(
            handle,
            io_control_code,
            std::ptr::from_ref(in_buffer).cast(),
            in_size,
            std::ptr::from_mut(out_buffer).cast(),
            out_size,
            &raw mut junk,
            ptr::null_mut(),
        )
    } {
        0 => Err(io::Error::last_os_error()),
        _ => Ok(()),
    }
}

pub fn get_mtu_by_index(index: u32, is_v4: bool) -> io::Result<u32> {
    // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipinterfacetable#examples
    let mut if_table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
    let mut mtu = None;
    // SAFETY: if_table is writable pointer storage; on success Windows returns a
    // table allocation valid until FreeMibTable, and row reads stay within NumEntries.
    unsafe {
        if GetIpInterfaceTable(if is_v4 { AF_INET } else { AF_INET6 }, &raw mut if_table)
            != NO_ERROR
        {
            return Err(io::Error::last_os_error());
        }
        let ifaces = std::slice::from_raw_parts::<MIB_IPINTERFACE_ROW>(
            &raw const (*if_table).Table[0],
            (*if_table).NumEntries as usize,
        );
        for x in ifaces {
            if x.InterfaceIndex == index {
                mtu = Some(x.NlMtu);
                break;
            }
        }
        windows_sys::Win32::NetworkManagement::IpHelper::FreeMibTable(if_table as _);
    }
    if let Some(mtu) = mtu {
        Ok(mtu)
    } else {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }
}

/// Converts a Rust `IpAddr` into a Windows `SOCKADDR_INET` (port/scope left zero).
fn sockaddr_inet_from_ip(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}

/// Maps a Win32 status code (`NETIOAPI_API` / `WIN32_ERROR`) to an `io::Result`.
pub(crate) fn win_result(code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code.cast_signed()))
    }
}

/// Sets the interface metric (routing cost) for both IPv4 and IPv6 by interface index.
pub fn set_interface_metric(index: u32, metric: u32) -> io::Result<()> {
    for family in [AF_INET, AF_INET6] {
        let mut row = MIB_IPINTERFACE_ROW {
            Family: family,
            InterfaceIndex: index,
            ..Default::default()
        };
        // SAFETY: row contains a valid family/index key and writable storage for
        // this synchronous IP Helper query.
        win_result(unsafe { GetIpInterfaceEntry(&raw mut row) })?;

        row.Metric = metric;
        row.UseAutomaticMetric = false;
        // `GetIpInterfaceEntry` may return a `SitePrefixLength` that
        // `SetIpInterfaceEntry` rejects when writing the row back.
        row.SitePrefixLength = 0;
        // SAFETY: row was populated by GetIpInterfaceEntry and remains live for
        // this synchronous IP Helper update.
        win_result(unsafe { SetIpInterfaceEntry(&raw mut row) })?;
    }
    Ok(())
}

/// Sets the MTU (`NlMtu`) of the interface for the given family by interface index.
pub fn set_interface_mtu(index: u32, mtu: u32, is_v4: bool) -> io::Result<()> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: if is_v4 { AF_INET } else { AF_INET6 },
        InterfaceIndex: index,
        ..Default::default()
    };
    // SAFETY: row contains a valid family/index key and writable storage for
    // this synchronous IP Helper query.
    win_result(unsafe { GetIpInterfaceEntry(&raw mut row) })?;

    row.NlMtu = mtu;
    // `GetIpInterfaceEntry` returns a `SitePrefixLength` that `SetIpInterfaceEntry`
    // rejects (notably for IPv4); reset it to 0 before writing back. This is the
    // conventional workaround and is harmless for IPv6, where site prefixes are unused.
    row.SitePrefixLength = 0;
    // SAFETY: row was populated by GetIpInterfaceEntry and remains live for
    // this synchronous IP Helper update.
    win_result(unsafe { SetIpInterfaceEntry(&raw mut row) })
}

/// Adds a single unicast address to the interface, optionally installing a
/// default route via `gateway`. An already-existing identical entry is ignored.
pub fn add_address(
    index: u32,
    address: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: row is live writable storage for the documented initializer.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.InterfaceIndex = index;
    row.Address = sockaddr_inet_from_ip(address);
    row.OnLinkPrefixLength = prefix;

    // SAFETY: row is fully initialized and borrowed read-only for this synchronous create call.
    let code = unsafe { CreateUnicastIpAddressEntry(&raw const row) };
    if code != ERROR_OBJECT_ALREADY_EXISTS {
        win_result(code)?;
    }

    if let Some(gateway) = gateway {
        let mut route = MIB_IPFORWARD_ROW2::default();
        // SAFETY: route is live writable storage for the documented initializer.
        unsafe { InitializeIpForwardEntry(&raw mut route) };
        route.InterfaceIndex = index;
        // Install a default route (0.0.0.0/0 or ::/0) via `gateway`. `DestinationPrefix`
        // must carry a valid address family matching `NextHop`; `InitializeIpForwardEntry`
        // leaves it zeroed (AF_UNSPEC), which `CreateIpForwardEntry2` rejects as "not
        // specified". Use the unspecified address of the gateway's family.
        let unspecified = if gateway.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        route.DestinationPrefix.Prefix = sockaddr_inet_from_ip(unspecified);
        route.DestinationPrefix.PrefixLength = 0;
        // `InitializeIpForwardEntry` sets SitePrefixLength to an illegal value (255); for a
        // default route it must not exceed the destination prefix length (0), or
        // `CreateIpForwardEntry2` also fails with ERROR_INVALID_PARAMETER.
        route.SitePrefixLength = 0;
        route.NextHop = sockaddr_inet_from_ip(gateway);
        route.Metric = 0;
        route.Protocol = MIB_IPPROTO_NETMGMT;
        route.Origin = NlroManual;

        // SAFETY: route fields are initialized and borrowed read-only for this synchronous create call.
        let code = unsafe { CreateIpForwardEntry2(&raw const route) };
        if code != ERROR_OBJECT_ALREADY_EXISTS {
            win_result(code)?;
        }
    }
    Ok(())
}

/// Removes a single unicast address from the interface.
pub fn remove_address(index: u32, address: IpAddr) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: row is live writable storage for the documented initializer.
    unsafe { InitializeUnicastIpAddressEntry(&raw mut row) };
    row.InterfaceIndex = index;
    row.Address = sockaddr_inet_from_ip(address);
    // SAFETY: row identifies the address to delete and is borrowed read-only.
    win_result(unsafe { DeleteUnicastIpAddressEntry(&raw const row) })
}

/// Removes every unicast address of the given family from the interface.
fn clear_addresses(index: u32, is_v4: bool) -> io::Result<()> {
    let family = if is_v4 { AF_INET } else { AF_INET6 };
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    // SAFETY: table is writable pointer storage; success returns a Windows-owned allocation valid until FreeMibTable.
    win_result(unsafe { GetUnicastIpAddressTable(family, &raw mut table) })?;

    // Copy out the rows we want to delete before freeing the table.
    // SAFETY: successful GetUnicastIpAddressTable returned NumEntries contiguous rows
    // in storage that remains live until FreeMibTable below.
    let rows: Vec<MIB_UNICASTIPADDRESS_ROW> = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    }
    .iter()
    .filter(|row| row.InterfaceIndex == index)
    .copied()
    .collect();
    // SAFETY: table is the Windows allocation returned above and is freed exactly once after rows are copied.
    unsafe { FreeMibTable(table as _) };

    for row in &rows {
        // SAFETY: row is an owned copy from the valid Windows table and is borrowed read-only for deletion.
        win_result(unsafe { DeleteUnicastIpAddressEntry(row) })?;
    }
    // Also drop the gateway/default route(s) installed by `add_address` for this family,
    // keeping the route lifecycle symmetric with `set_address` (replace).
    clear_default_routes(index, is_v4)
}

/// Removes the interface's default routes (`0.0.0.0/0` / `::/0`) for the given family.
///
/// These are the gateway routes installed by [`add_address`]. On-link/subnet routes are
/// removed automatically by Windows when the owning address is deleted, so only the
/// explicit default route needs to be cleaned up here. This runs from [`clear_addresses`]
/// so that [`set_address`] replaces the old gateway route instead of leaking it; routes are
/// only ever created through `add_address` (i.e. via `set_address`), so this is the matching
/// teardown.
fn clear_default_routes(index: u32, is_v4: bool) -> io::Result<()> {
    let family = if is_v4 { AF_INET } else { AF_INET6 };
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    // SAFETY: table is writable pointer storage; success returns a Windows-owned route table valid until FreeMibTable.
    win_result(unsafe { GetIpForwardTable2(family, &raw mut table) })?;

    // Copy out this interface's default routes before freeing the table.
    // SAFETY: successful GetIpForwardTable2 returned NumEntries contiguous rows
    // in storage that remains live until FreeMibTable below.
    let rows: Vec<MIB_IPFORWARD_ROW2> = unsafe {
        std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
    }
    .iter()
    .filter(|row| row.InterfaceIndex == index && row.DestinationPrefix.PrefixLength == 0)
    .copied()
    .collect();
    // SAFETY: table is the Windows allocation returned above and is freed exactly once after rows are copied.
    unsafe { FreeMibTable(table as _) };

    for row in &rows {
        // SAFETY: row is an owned copy from the valid route table and is borrowed read-only for deletion.
        win_result(unsafe { DeleteIpForwardEntry2(row) })?;
    }
    Ok(())
}

/// Replaces all addresses of the same family on the interface with `address`,
/// optionally installing a default route via `gateway`.
pub fn set_address(
    index: u32,
    address: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
) -> io::Result<()> {
    clear_addresses(index, address.is_ipv4())?;
    add_address(index, address, prefix, gateway)
}

/// Enables or disables a device via `SetupAPI` (`DIF_PROPERTYCHANGE`), equivalent
/// to enabling/disabling it in Device Manager.
pub fn set_device_state(
    devinfo: HDEVINFO,
    devinfo_data: &SP_DEVINFO_DATA,
    enable: bool,
) -> io::Result<()> {
    let class_install_header_size = usize_to_u32(
        mem::size_of::<SP_CLASSINSTALL_HEADER>(),
        "SP_CLASSINSTALL_HEADER size",
    )?;
    let params_size = usize_to_u32(
        mem::size_of::<SP_PROPCHANGE_PARAMS>(),
        "SP_PROPCHANGE_PARAMS size",
    )?;
    let params = SP_PROPCHANGE_PARAMS {
        ClassInstallHeader: SP_CLASSINSTALL_HEADER {
            cbSize: class_install_header_size,
            InstallFunction: DIF_PROPERTYCHANGE,
        },
        StateChange: if enable { DICS_ENABLE } else { DICS_DISABLE },
        Scope: DICS_FLAG_GLOBAL,
        HwProfile: 0,
    };

    // `ClassInstallHeader` is the first field, so the struct pointer doubles as
    // the header pointer. Cast from the whole struct to avoid taking a reference
    // to a field of a `packed` struct (illegal on x86).
    // SAFETY: devinfo_data belongs to live devinfo; params begins with the required
    // class-install header and params_size matches the full structure.
    let ok = unsafe {
        SetupDiSetClassInstallParamsW(
            devinfo,
            std::ptr::from_ref(devinfo_data),
            (&raw const params).cast::<SP_CLASSINSTALL_HEADER>(),
            params_size,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    call_class_installer(devinfo, devinfo_data, DIF_PROPERTYCHANGE)
}

#[cfg(test)]
mod wait_tests {
    use super::{
        create_event, finite_wait_timeout_millis, set_event, wait_for_single_object, win_result,
    };
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::time::Duration;
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::ConvertInterfaceIndexToLuid, Ndis::NET_LUID_LH,
    };
    use windows_sys::Win32::System::Threading::INFINITE;

    #[test]
    fn netio_status_error_uses_returned_status() -> io::Result<()> {
        const STALE_LAST_ERROR: u32 = 0x1234;

        // Interface index zero is NET_IFINDEX_UNSPECIFIED and is reserved by
        // NDIS, so ConvertInterfaceIndexToLuid must reject it.
        let mut luid = NET_LUID_LH { Value: 0 };

        // SAFETY: SetLastError only updates this thread's error slot and has no
        // pointer or ownership preconditions.
        unsafe { windows_sys::Win32::Foundation::SetLastError(STALE_LAST_ERROR) };
        // SAFETY: luid is valid writable output storage; index zero is the
        // documented reserved/unspecified value used to force an API error.
        let status = unsafe { ConvertInterfaceIndexToLuid(0, &raw mut luid) };
        let error = win_result(status)
            .err()
            .ok_or_else(|| io::Error::other("reserved interface index unexpectedly resolved"))?;

        assert_ne!(
            error.raw_os_error(),
            Some(STALE_LAST_ERROR.cast_signed()),
            "wrapper returned stale GetLastError instead of the API status"
        );
        Ok(())
    }

    #[test]
    fn finite_wait_timeout_rounds_up_without_aliasing_infinite() {
        assert_eq!(finite_wait_timeout_millis(Duration::ZERO), 0);
        assert_eq!(finite_wait_timeout_millis(Duration::from_nanos(1)), 1);
        assert_eq!(finite_wait_timeout_millis(Duration::from_micros(1001)), 2);
        assert_eq!(
            finite_wait_timeout_millis(Duration::from_millis(u64::from(INFINITE))),
            INFINITE - 1
        );
    }

    #[test]
    fn unsignalled_event_reports_timeout() -> io::Result<()> {
        let event = create_event()?;
        let error = wait_for_single_object(event.as_raw_handle(), 0)
            .err()
            .ok_or_else(|| io::Error::other("unsignalled event unexpectedly became ready"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        Ok(())
    }

    #[test]
    fn signalled_event_is_ready() -> io::Result<()> {
        let event = create_event()?;
        set_event(event.as_raw_handle())?;
        wait_for_single_object(event.as_raw_handle(), 0)
    }
}
