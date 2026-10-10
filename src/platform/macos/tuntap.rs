#![expect(
    unsafe_code,
    reason = "macOS TUN/TAP creation and configuration uses system-control and ioctl FFI"
)]

use crate::builder::DeviceConfig;
use crate::platform::macos::sys::{
    ctl_info, ctliocginfo, in6_ifreq, siocgiflladdr, siocsiflladdr, siocsifmtu, IN6_IFF_NODAD,
    UTUN_CONTROL_NAME,
};
use crate::platform::macos::tap::Tap;
use crate::platform::unix::device::ctl;
use crate::platform::unix::Tun;
use crate::platform::ETHER_ADDR_LEN;
use crate::Layer;
#[cfg(any(feature = "async_tokio", feature = "async_io"))]
use bytes::buf::UninitSlice;
use libc::{
    c_char, sockaddr, socklen_t, AF_SYSTEM, AF_SYS_CONTROL, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM,
    SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
};
use std::ffi::{c_void, CStr};
use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::{io, mem};

fn copy_interface_name(name: &str, dst: &mut [c_char]) -> io::Result<()> {
    if name.len() >= dst.len() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "interface name exceeds Darwin IFNAMSIZ",
        ));
    }
    for (out, byte) in dst.iter_mut().zip(name.bytes()) {
        *out = byte.cast_signed();
    }
    Ok(())
}

pub enum TunTap {
    Tun(Tun),
    Tap(Tap),
}

impl TunTap {
    pub fn new(config: &DeviceConfig) -> io::Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let packet_information = config.packet_information.unwrap_or(false);
        match layer {
            Layer::L2 => Ok(TunTap::Tap(Tap::new(config)?)),
            Layer::L3 => {
                let id = config
                    .dev_name
                    .as_ref()
                    .map(|tun_name| {
                        if tun_name.len() >= IFNAMSIZ {
                            return Err(io::Error::new(
                                ErrorKind::InvalidInput,
                                "device name too long",
                            ));
                        }
                        if !tun_name.starts_with("utun") {
                            return Err(io::Error::new(
                                ErrorKind::InvalidInput,
                                "device name must start with utun",
                            ));
                        }
                        let unit = tun_name[4..]
                            .parse::<u32>()
                            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
                        unit.checked_add(1).ok_or_else(|| {
                            io::Error::new(
                                ErrorKind::InvalidInput,
                                "utun unit number overflows u32",
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or(0);

                let sockaddr_ctl_size = mem::size_of::<libc::sockaddr_ctl>();
                let sc_len = u8::try_from(sockaddr_ctl_size).map_err(|_| {
                    io::Error::new(ErrorKind::InvalidData, "sockaddr_ctl size exceeds u8")
                })?;
                let sc_family = u8::try_from(AF_SYSTEM).map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "AF_SYSTEM does not fit sockaddr family",
                    )
                })?;
                let sysaddr = u16::try_from(AF_SYS_CONTROL).map_err(|_| {
                    io::Error::new(ErrorKind::InvalidData, "AF_SYS_CONTROL does not fit u16")
                })?;
                let address_len = socklen_t::try_from(sockaddr_ctl_size).map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "sockaddr_ctl size exceeds socklen_t",
                    )
                })?;

                // SAFETY: socket and ioctl arguments are live C-layout values;
                // validated lengths match their backing objects and no pointer escapes.
                unsafe {
                    let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
                    let tun = crate::platform::unix::Fd::new(fd)?;
                    tun.set_cloexec()?;
                    let mut info = ctl_info {
                        ctl_id: 0,
                        ctl_name: {
                            let mut buffer = [0; 96];
                            for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut())
                            {
                                *o = i.cast_signed();
                            }
                            buffer
                        },
                    };

                    if let Err(err) = ctliocginfo(tun.inner, (&raw mut info).cast()) {
                        return Err(io::Error::from(err));
                    }

                    let addr = libc::sockaddr_ctl {
                        sc_id: info.ctl_id,
                        sc_len,
                        sc_family,
                        ss_sysaddr: sysaddr,
                        sc_unit: id,
                        sc_reserved: [0; 5],
                    };

                    let address = (&raw const addr).cast::<sockaddr>();
                    if libc::connect(tun.inner, address, address_len) < 0 {
                        return Err(io::Error::last_os_error());
                    }

                    let tun = Tun::new(tun);
                    tun.set_ignore_packet_info(!packet_information);
                    Ok(TunTap::Tun(tun))
                }
            }
        }
    }
    pub fn name(&self) -> io::Result<String> {
        match &self {
            TunTap::Tun(tun) => {
                let mut tun_name = [0u8; 64];
                let mut name_len: socklen_t = 64;

                let optval = (&raw mut tun_name).cast::<c_void>();
                let optlen = &raw mut name_len;
                // SAFETY: tun_name and name_len are writable live buffers for the
                // synchronous getsockopt call; their pointers do not escape.
                if unsafe {
                    libc::getsockopt(
                        tun.as_raw_fd(),
                        SYSPROTO_CONTROL,
                        UTUN_OPT_IFNAME,
                        optval,
                        optlen,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                let name = CStr::from_bytes_until_nul(&tun_name)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
                Ok(name.to_string_lossy().into_owned())
            }
            TunTap::Tap(tap) => Ok(tap.name().clone()),
        }
    }
    pub(crate) fn is_tun(&self) -> bool {
        match &self {
            TunTap::Tun(_) => true,
            TunTap::Tap(_) => false,
        }
    }
    pub fn is_nonblocking(&self) -> io::Result<bool> {
        match &self {
            TunTap::Tun(tun) => tun.is_nonblocking(),
            TunTap::Tap(tap) => tap.is_nonblocking(),
        }
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match &self {
            TunTap::Tun(tun) => tun.set_nonblocking(nonblocking),
            TunTap::Tap(tap) => tap.set_nonblocking(nonblocking),
        }
    }
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.send(buf),
            TunTap::Tap(tap) => tap.send(buf),
        }
    }
    #[inline]
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.send_vectored(bufs),
            TunTap::Tap(tap) => tap.send_vectored(bufs),
        }
    }
    #[inline]
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.recv(buf),
            TunTap::Tap(tap) => tap.recv(buf),
        }
    }
    #[cfg(any(feature = "async_tokio", feature = "async_io"))]
    #[inline]
    pub fn recv_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.recv_uninit(buf),
            TunTap::Tap(tap) => tap.recv_uninit(buf),
        }
    }
    #[inline]
    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.recv_vectored(bufs),
            TunTap::Tap(tap) => tap.recv_vectored(bufs),
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn read_interruptible(
        &self,
        buf: &mut [u8],
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.read_interruptible(buf, event, timeout),
            TunTap::Tap(tap) => tap.read_interruptible(buf, event, timeout),
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn readv_interruptible(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.readv_interruptible(bufs, event, timeout),
            TunTap::Tap(tap) => tap.readv_interruptible(bufs, event, timeout),
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn wait_readable_interruptible(
        &self,
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        match &self {
            TunTap::Tun(tun) => tun.wait_readable_interruptible(event, timeout),
            TunTap::Tap(tap) => tap.wait_readable_interruptible(event, timeout),
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn write_interruptible(
        &self,
        buf: &[u8],
        event: &crate::InterruptEvent,
    ) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.write_interruptible(buf, event),
            TunTap::Tap(tap) => tap.write_interruptible(buf, event),
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn writev_interruptible(
        &self,
        bufs: &[IoSlice<'_>],
        event: &crate::InterruptEvent,
    ) -> io::Result<usize> {
        match &self {
            TunTap::Tun(tun) => tun.writev_interruptible(bufs, event),
            TunTap::Tap(tap) => tap.writev_interruptible(bufs, event),
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn wait_writable_interruptible(
        &self,
        event: &crate::InterruptEvent,
    ) -> io::Result<()> {
        match &self {
            TunTap::Tun(tun) => tun.wait_writable_interruptible(event),
            TunTap::Tap(tap) => tap.wait_writable_interruptible(event),
        }
    }
    pub fn request(&self) -> io::Result<libc::ifreq> {
        let tun_name = self.name()?;
        // SAFETY: ifreq is a C POD request structure and zero is its initial state.
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        copy_interface_name(&tun_name, &mut req.ifr_name)?;
        Ok(req)
    }
    pub fn request_peer(&self) -> io::Result<Option<libc::ifreq>> {
        let name = match &self {
            TunTap::Tun(_) => return Ok(None),
            TunTap::Tap(tap) => tap.peer_name(),
        };
        // SAFETY: ifreq is a C POD request structure and zero is its initial state.
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        copy_interface_name(name, &mut req.ifr_name)?;
        Ok(Some(req))
    }
    pub fn request_v6(&self) -> io::Result<in6_ifreq> {
        let tun_name = self.name()?;
        let nodad = i16::try_from(IN6_IFF_NODAD)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "IN6_IFF_NODAD exceeds c_short"))?;
        // SAFETY: in6_ifreq is a C POD request structure and zero is its initial state.
        let mut req: in6_ifreq = unsafe { mem::zeroed() };
        copy_interface_name(&tun_name, &mut req.ifra_name)?;
        req.ifr_ifru.ifru_flags = nodad;
        Ok(req)
    }
    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> io::Result<()> {
        match &self {
            TunTap::Tun(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            TunTap::Tap(_) => {
                let mut ifr = self.request()?;
                let af_link = u8::try_from(libc::AF_LINK).map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "AF_LINK does not fit sockaddr family",
                    )
                })?;
                // SAFETY: ifr is live; we initialize the sockaddr union member
                // completely before passing it to the synchronous ioctl.
                unsafe {
                    ifr.ifr_ifru.ifru_addr.sa_family = af_link;
                    ifr.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;
                    for (i, v) in eth_addr.iter().enumerate() {
                        ifr.ifr_ifru.ifru_addr.sa_data[i] = v.cast_signed();
                    }
                    siocsiflladdr(ctl()?.inner, &raw const ifr)?;
                }
                Ok(())
            }
        }
    }
    pub fn mac_address(&self) -> io::Result<[u8; ETHER_ADDR_LEN as usize]> {
        match &self {
            TunTap::Tun(_) => Err(io::Error::from(io::ErrorKind::Unsupported)),
            TunTap::Tap(_) => {
                let mut ifr = self.request()?;
                let af_link = u8::try_from(libc::AF_LINK).map_err(|_| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        "AF_LINK does not fit sockaddr family",
                    )
                })?;
                // SAFETY: ifr is live; the ioctl fills the sockaddr union member
                // before the MAC bytes are read from it.
                unsafe {
                    ifr.ifr_ifru.ifru_addr.sa_family = af_link;
                    ifr.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;
                    siocgiflladdr(ctl()?.inner, &raw mut ifr)?;
                    let mut eth_addr = [0; ETHER_ADDR_LEN as usize];
                    for (i, v) in eth_addr.iter_mut().enumerate() {
                        *v = ifr.ifr_ifru.ifru_addr.sa_data[i].cast_unsigned();
                    }
                    Ok(eth_addr)
                }
            }
        }
    }
    #[inline]
    pub(crate) fn ignore_packet_info(&self) -> bool {
        match &self {
            TunTap::Tun(tun) => tun.ignore_packet_info(),
            TunTap::Tap(_) => false,
        }
    }
    pub(crate) fn set_ignore_packet_info(&self, ign: bool) {
        match &self {
            TunTap::Tun(tun) => tun.set_ignore_packet_info(ign),
            TunTap::Tap(_) => {}
        }
    }
    pub fn set_mtu(&self, value: u16) -> io::Result<()> {
        let ctl = ctl()?;
        let mut req = self.request()?;
        // SAFETY: req is live; writing the MTU member selects the correct union
        // variant before the synchronous ioctl reads it.
        unsafe {
            req.ifr_ifru.ifru_mtu = i32::from(value);
            siocsifmtu(ctl.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        if let Some(mut req) = self.request_peer()? {
            // SAFETY: same invariant as the primary interface request above.
            unsafe {
                req.ifr_ifru.ifru_mtu = i32::from(value);
                siocsifmtu(ctl.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
            }
        }
        Ok(())
    }
}
impl AsRawFd for TunTap {
    fn as_raw_fd(&self) -> RawFd {
        match &self {
            TunTap::Tun(tun) => tun.as_raw_fd(),
            TunTap::Tap(tap) => tap.as_raw_fd(),
        }
    }
}
impl IntoRawFd for TunTap {
    fn into_raw_fd(self) -> RawFd {
        match self {
            TunTap::Tun(tun) => tun.into_raw_fd(),
            TunTap::Tap(tap) => tap.into_raw_fd(),
        }
    }
}
