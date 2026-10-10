#![expect(
    unsafe_code,
    reason = "FreeBSD TUN/TAP configuration uses libc open/ioctl structures and borrowed raw descriptors"
)]

use crate::{
    builder::{DeviceConfig, Layer},
    platform::freebsd::sys::{
        ifaliasreq, in6_ifaliasreq, in6_ifreq, in6_ndireq, siocaifaddr, siocaifaddr_in6,
        siocdifaddr, siocdifaddr_in6, siocgifflags, siocgifmtu, siocifdestroy, siocsifflags,
        siocsifinfoin6, siocsiflladdr, siocsifmtu, siocsifname, sioctunsifhead, tungifname,
        IN6_IFF_NODAD, ND6_IFF_AUTO_LINKLOCAL,
    },
    platform::{
        unix::{sockaddr_union, Fd, Tun},
        ETHER_ADDR_LEN,
    },
    ToIpv4Address, ToIpv4Netmask, ToIpv6Address, ToIpv6Netmask,
};

use crate::platform::unix::device::{copy_device_name, ctl, ctl_v6};
use libc::{
    self, c_char, c_short, fcntl, ifreq, kinfo_file, AF_LINK, F_KINFO, IFF_UP, IFNAMSIZ, O_RDWR,
};
use std::io::ErrorKind;
use std::os::fd::{IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{ffi::CStr, io, mem, net::IpAddr, os::unix::io::AsRawFd, sync::RwLock};

/// A TUN device using the FreeBSD TUN/TAP driver.
pub struct DeviceImpl {
    name: RwLock<String>,
    pub(crate) tun: Tun,
    pub op_lock: RwLock<()>,
    pub associate_route: AtomicBool,
}
impl IntoRawFd for DeviceImpl {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.tun.fd.inner;
        self.tun.fd.inner = -1;
        fd
    }
}
impl Drop for DeviceImpl {
    fn drop(&mut self) {
        if !self.tun.fd.should_drop_cleanup() {
            return;
        }
        // Construct the request before we do anything
        let request = self.request();
        let fd = self.tun.fd.inner;
        self.tun.fd.inner = -1;
        // SAFETY: fd is the owned live device descriptor detached above; close
        // consumes it, and the destroy ioctl only borrows the live request object.
        unsafe {
            // Close the fd; without this `siocifdestroy` blocks forever
            libc::close(fd);

            // Attempt to destroy the device.
            if let (Ok(ctl), Ok(req)) = (ctl(), request) {
                _ = siocifdestroy(ctl.as_raw_fd(), &raw const req);
            }
        }
    }
}
impl DeviceImpl {
    /// Create a new `Device` for the given `Configuration`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "constructor signature matches the other platform DeviceImpl implementations"
    )]
    pub(crate) fn new(config: DeviceConfig) -> io::Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let associate_route = if layer == Layer::L3 {
            config.associate_route.unwrap_or(true)
        } else {
            false
        };
        let device_prefix = if layer == Layer::L3 { "tun" } else { "tap" };
        let dev_index = match config.dev_name.as_ref() {
            Some(tun_name) => {
                if tun_name.len() >= IFNAMSIZ {
                    return Err(io::Error::new(
                        ErrorKind::InvalidInput,
                        "device name too long",
                    ));
                }
                match layer {
                    Layer::L2 => {
                        if !tun_name.starts_with("tap") {
                            return Err(io::Error::new(
                                ErrorKind::InvalidInput,
                                "device name must start with tap",
                            ));
                        }
                    }
                    Layer::L3 => {
                        if !tun_name.starts_with("tun") {
                            return Err(io::Error::new(
                                ErrorKind::InvalidInput,
                                "device name must start with tun",
                            ));
                        }
                    }
                }
                Some(
                    tun_name[3..]
                        .parse::<u32>()
                        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?,
                )
            }
            None => None,
        };
        // SAFETY: each generated path is NUL-terminated and remains live for
        // the open call; Fd validates the returned descriptor before ownership.
        let tun = unsafe {
            if let Some(name_index) = dev_index.as_ref() {
                let device_path = format!("/dev/{device_prefix}{name_index}\0");
                let fd = libc::open(device_path.as_ptr().cast(), O_RDWR | libc::O_CLOEXEC);
                Fd::new(fd)?
            } else {
                'End: {
                    for i in 0..256 {
                        let device_path = format!("/dev/{device_prefix}{i}\0");
                        let fd = libc::open(device_path.as_ptr().cast(), O_RDWR | libc::O_CLOEXEC);
                        match Fd::new(fd) {
                            Ok(tun) => {
                                break 'End tun;
                            }
                            Err(e) => {
                                if e.raw_os_error() != Some(libc::EBUSY) {
                                    return Err(e);
                                }
                            }
                        }
                    }
                    return Err(io::Error::new(
                        ErrorKind::AlreadyExists,
                        "no available file descriptor",
                    ));
                }
            }
        };
        let tun = Tun::new(tun);
        if matches!(layer, Layer::L3) {
            Self::enable_tunsifhead_impl(&tun.fd)?;
            tun.set_ignore_packet_info(!config.packet_information.unwrap_or(false));
        } else {
            tun.set_ignore_packet_info(false);
        }
        let device = DeviceImpl {
            name: RwLock::new(match dev_index {
                Some(index) => format!("{device_prefix}{index}"),
                None => Self::name_from_path_of_fd(&tun)?,
            }),
            tun,
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(associate_route),
        };
        device.disable_default_sys_local_ipv6()?;
        Ok(device)
    }
    pub(crate) fn from_tun(tun: Tun) -> io::Result<Self> {
        let name = Self::name_of_fd_fallback(&tun)?;
        if name.starts_with("tap") {
            // Tap does not have PI
            tun.set_ignore_packet_info(false);
        } else {
            Self::enable_tunsifhead_impl(&tun.fd)?;
            tun.set_ignore_packet_info(true);
        }
        let dev = Self {
            name: RwLock::new(name),
            tun,
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(true),
        };
        Ok(dev)
    }

    fn disable_default_sys_local_ipv6(&self) -> std::io::Result<()> {
        let tun_name = self.name_impl()?;
        // SAFETY: in6_ndireq is a C POD request object and zero is its initial state.
        let mut req: in6_ndireq = unsafe { mem::zeroed() };
        copy_device_name(&tun_name, &mut req.ifra_name)?;
        req.ndi.flags &= !(ND6_IFF_AUTO_LINKLOCAL as u32);
        // SAFETY: req is a live writable request and the ioctl borrows it synchronously.
        unsafe {
            siocsifinfoin6(ctl_v6()?.as_raw_fd(), &raw mut req).map_err(io::Error::from)?;
        }
        Ok(())
    }

    // https://forums.freebsd.org/threads/ping6-address-family-not-supported-by-protocol-family.51467/
    // https://man.freebsd.org/cgi/man.cgi?query=tun&sektion=4&manpath=FreeBSD+5.3-RELEASE
    // https://web.mit.edu/freebsd/head/sys/net/if_tun.h
    // If the TUNSIFHEAD ioctl has been set, the address family must
    // be prepended, otherwise the packet is assumed to	be  of	type  AF_INET.
    // IPv6 needs AF_INET6.
    // The argument	should be a pointer to an int; a  non-zero value turns off "link-layer" mode, and enables "multi-af"
    // mode, where every packet is preceded	with a four byte ad-dress family.
    fn enable_tunsifhead_impl(device_fd: &Fd) -> std::io::Result<()> {
        // SAFETY: the ioctl borrows a live descriptor and integer argument only
        // for the duration of the call.
        unsafe {
            if let Err(err) = sioctunsifhead(device_fd.as_raw_fd(), std::ptr::from_ref(&1)) {
                return Err(io::Error::from(err));
            }
        }
        Ok(())
    }

    fn calc_dest_addr(addr: IpAddr, netmask: IpAddr) -> std::io::Result<IpAddr> {
        let prefix_len = ipnet::ip_mask_to_prefix(netmask)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        Ok(ipnet::IpNet::new(addr, prefix_len)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?
            .broadcast())
    }

    /// Set the IPv4 alias of the device.
    fn add_address(
        &self,
        addr: IpAddr,
        mask: IpAddr,
        dest: Option<IpAddr>,
        associate_route: bool,
    ) -> std::io::Result<()> {
        // SAFETY: request structs are live C-layout objects; each sockaddr union
        // member is initialized from the matching IP family before its ioctl.
        unsafe {
            match addr {
                IpAddr::V4(_) => {
                    let ctl = ctl()?;
                    let mut req: ifaliasreq = mem::zeroed();
                    let tun_name = self.name_impl()?;
                    copy_device_name(&tun_name, &mut req.ifran)?;

                    req.addr = crate::platform::unix::sockaddr_union::from((addr, 0)).addr;
                    if let Some(dest) = dest {
                        req.dstaddr = crate::platform::unix::sockaddr_union::from((dest, 0)).addr;
                    }
                    req.mask = crate::platform::unix::sockaddr_union::from((mask, 0)).addr;

                    if let Err(err) = siocaifaddr(ctl.as_raw_fd(), &raw const req) {
                        return Err(io::Error::from(err));
                    }
                    if let Err(e) = self.add_route(addr, mask, associate_route) {
                        log::warn!("{e:?}");
                    }
                }
                IpAddr::V6(_) => {
                    let IpAddr::V6(_) = mask else {
                        return Err(std::io::Error::from(ErrorKind::InvalidInput));
                    };
                    let tun_name = self.name_impl()?;
                    let mut req: in6_ifaliasreq = mem::zeroed();
                    copy_device_name(&tun_name, &mut req.ifra_name)?;
                    req.ifra_addr = sockaddr_union::from((addr, 0)).addr6;
                    req.ifra_prefixmask = sockaddr_union::from((mask, 0)).addr6;
                    req.in6_addrlifetime.ia6t_vltime = 0xffff_ffff_u32;
                    req.in6_addrlifetime.ia6t_pltime = 0xffff_ffff_u32;
                    req.ifra_flags = IN6_IFF_NODAD;
                    if let Err(err) = siocaifaddr_in6(ctl_v6()?.as_raw_fd(), &raw const req) {
                        return Err(io::Error::from(err));
                    }
                }
            }

            Ok(())
        }
    }

    /// Prepare a new request.
    fn request(&self) -> std::io::Result<ifreq> {
        // SAFETY: ifreq is a C POD request object and zero is its initial state.
        let mut req: ifreq = unsafe { mem::zeroed() };
        let tun_name = self.name_impl()?;
        copy_device_name(&tun_name, &mut req.ifr_name)?;
        Ok(req)
    }

    fn request_v6(&self) -> std::io::Result<in6_ifreq> {
        let tun_name = self.name_impl()?;
        // SAFETY: in6_ifreq is a C POD request object and zero is its initial state.
        let mut req: in6_ifreq = unsafe { mem::zeroed() };
        copy_device_name(&tun_name, &mut req.ifra_name)?;
        req.ifr_ifru.ifru_flags = IN6_IFF_NODAD;
        Ok(req)
    }
    fn add_route(&self, addr: IpAddr, netmask: IpAddr, associate_route: bool) -> io::Result<()> {
        if !associate_route {
            return Ok(());
        }
        let if_index = self.if_index_impl()?;
        let prefix_len = ipnet::ip_mask_to_prefix(netmask)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let mut manager = route_manager::RouteManager::new()?;
        let route = route_manager::Route::new(addr, prefix_len)
            .with_pref_source(addr)
            .with_if_index(if_index);
        manager.add(&route)?;
        Ok(())
    }
    fn name_of_fd(tun: &Tun) -> io::Result<String> {
        // SAFETY: req is writable C request storage; the ioctl initializes its
        // interface-name field before CStr reads the NUL-terminated result.
        unsafe {
            let mut req: ifreq = mem::zeroed();
            tungifname(tun.as_raw_fd(), &raw mut req).map_err(io::Error::from)?;
            let name = CStr::from_ptr(req.ifr_name.as_ptr())
                .to_string_lossy()
                .into_owned();
            Ok(name)
        }
    }

    fn name_of_fd_fallback(tun: &Tun) -> io::Result<String> {
        match Self::name_of_fd(tun) {
            Ok(name) => Ok(name),
            Err(err) if err.raw_os_error() == Some(libc::ENOTTY) => Self::name_from_path_of_fd(tun),
            Err(err) => Err(err),
        }
    }

    fn name_from_path_of_fd(tun: &Tun) -> io::Result<String> {
        use std::path::PathBuf;
        // SAFETY: path_info is writable C storage, fcntl initializes it, and
        // kf_path is read as the NUL-terminated path returned by the kernel.
        unsafe {
            let mut path_info: kinfo_file = std::mem::zeroed();
            path_info.kf_structsize = std::mem::size_of::<kinfo_file>() as libc::c_int;
            if fcntl(tun.as_raw_fd(), F_KINFO, &raw mut path_info) < 0 {
                return Err(io::Error::last_os_error());
            }
            let dev_path = CStr::from_ptr(path_info.kf_path.as_ptr().cast::<c_char>())
                .to_string_lossy()
                .into_owned();
            let path = PathBuf::from(dev_path);
            let device_name = path
                .file_name()
                .ok_or(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid device name",
                ))?
                .to_string_lossy()
                .to_string();
            Ok(device_name)
        }
    }
    /// Retrieves the name of the network interface.
    pub(crate) fn name_impl(&self) -> std::io::Result<String> {
        match Self::name_of_fd(&self.tun) {
            Ok(name) => {
                self.name
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone_from(&name);
                Ok(name)
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOTTY) => Ok(self
                .name
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()),
            Err(err) => Err(err),
        }
    }

    fn remove_all_address_v4(&self) -> io::Result<()> {
        // SAFETY: req_v4 is a live request and the delete ioctl only borrows it
        // synchronously while repeatedly removing configured IPv4 aliases.
        unsafe {
            let req_v4 = self.request()?;
            loop {
                if let Err(err) = siocdifaddr(ctl()?.as_raw_fd(), &raw const req_v4) {
                    if err == nix::errno::Errno::EADDRNOTAVAIL {
                        break;
                    }
                    return Err(io::Error::from(err));
                }
            }
        }
        Ok(())
    }
    fn set_network_address_impl<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        &self,
        address: &IPv4,
        netmask: &Netmask,
        destination: Option<&IPv4>,
        associate_route: bool,
    ) -> io::Result<()> {
        let addr = address.ipv4()?.into();
        let netmask = netmask.netmask()?.into();
        let default_dest = Self::calc_dest_addr(addr, netmask)?;
        let dest = destination
            .map(ToIpv4Address::ipv4)
            .transpose()?
            .map_or(default_dest, std::convert::Into::into);
        self.remove_all_address_v4()?;
        self.add_address(addr, netmask, Some(dest), associate_route)?;
        Ok(())
    }
}

// Public User Interface
impl DeviceImpl {
    /// Retrieves the name of the network interface.
    ///
    /// # Errors
    /// Returns an I/O error if the interface name cannot be queried.
    pub fn name(&self) -> std::io::Result<String> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.name_impl()
    }
    /// Sets a new name for the network interface.
    ///
    /// # Errors
    /// Returns an error for an invalid name or if the rename ioctl fails.
    pub fn set_name(&self, value: &str) -> std::io::Result<()> {
        use std::ffi::CString;
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if value.len() >= IFNAMSIZ {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "device name too long",
            ));
        }
        let mut req = self.request()?;
        let tun_name = CString::new(value)?;
        let mut tun_name: Vec<c_char> = tun_name
            .into_bytes_with_nul()
            .into_iter()
            .map(u8::cast_signed)
            .collect();
        // SAFETY: req and tun_name remain live for the synchronous rename ioctl;
        // ifru_data points at the NUL-terminated mutable buffer above.
        unsafe {
            req.ifr_ifru.ifru_data = tun_name.as_mut_ptr();
            siocsifname(ctl()?.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        let mut name = self
            .name
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        name.clear();
        name.push_str(value);
        Ok(())
    }
    /// If false, the program will not modify or manage routes in any way, allowing the system to handle all routing natively.
    /// If true (default), the program will automatically add or remove routes to provide consistent routing behavior across all platforms.
    /// Set this to be false to obtain the platform's default routing behavior.
    pub fn set_associate_route(&self, associate_route: bool) {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.associate_route
            .store(associate_route, Ordering::Relaxed);
    }
    /// Retrieve whether route is associated with the IP setting interface, see [`DeviceImpl::set_associate_route`]
    pub fn associate_route(&self) -> bool {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.associate_route.load(Ordering::Relaxed)
    }

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
    /// * `ign`
    ///     - If `true`, the TUN device will ignore packet information.
    ///     - If `false`, it will include packet information.
    /// # Note
    /// This only works for a TUN device; The invocation will be ignored if the device is a TAP.
    pub fn set_ignore_packet_info(&self, ign: bool) {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Ok(name) = self.name_impl() {
            if name.starts_with("tun") {
                self.tun.set_ignore_packet_info(ign);
            }
        }
    }
    /// Enables or disables the network interface.
    ///
    /// # Errors
    /// Returns an I/O error if interface flags cannot be queried or updated.
    pub fn enabled(&self, value: bool) -> std::io::Result<()> {
        let up = c_short::try_from(IFF_UP).map_err(|_| {
            io::Error::new(ErrorKind::InvalidData, "FreeBSD IFF_UP exceeds c_short")
        })?;
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: the first ioctl initializes the flags union member and the
        // second consumes the same live request synchronously.
        unsafe {
            let mut req = self.request()?;
            let ctl = ctl()?;
            if let Err(err) = siocgifflags(ctl.as_raw_fd(), &raw mut req) {
                return Err(io::Error::from(err));
            }

            if value {
                req.ifr_ifru.ifru_flags[0] |= up;
            } else {
                req.ifr_ifru.ifru_flags[0] &= !up;
            }

            if let Err(err) = siocsifflags(ctl.as_raw_fd(), &raw const req) {
                return Err(io::Error::from(err));
            }

            Ok(())
        }
    }
    /// Retrieves the current MTU (Maximum Transmission Unit) for the interface.
    ///
    /// # Errors
    /// Returns an I/O error if the MTU cannot be queried or represented by the public type.
    pub fn mtu(&self) -> std::io::Result<u16> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: req is live and the ioctl initializes the MTU union member
        // before it is read below.
        unsafe {
            let mut req = self.request()?;

            if let Err(err) = siocgifmtu(ctl()?.as_raw_fd(), &raw mut req) {
                return Err(io::Error::from(err));
            }

            let r: u16 = req.ifr_ifru.ifru_mtu.try_into().map_err(io::Error::other)?;
            Ok(r)
        }
    }
    /// Sets the MTU (Maximum Transmission Unit) for the interface.
    ///
    /// # Errors
    /// Returns an I/O error if the MTU cannot be applied.
    pub fn set_mtu(&self, value: u16) -> std::io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: writing the MTU member selects the intended union variant
        // before the synchronous ioctl reads it.
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_mtu = i32::from(value);

            if let Err(err) = siocsifmtu(ctl()?.as_raw_fd(), &raw const req) {
                return Err(io::Error::from(err));
            }
            Ok(())
        }
    }
    /// Sets the IPv4 network address, netmask, and an optional destination address.
    /// Remove all previous set IPv4 addresses and set the specified address.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public signature matches the cross-platform API and accepts owned conversion inputs"
    )]
    ///
    /// # Errors
    /// Returns an error for invalid address input or failed interface or route updates.
    pub fn set_network_address<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        &self,
        address: IPv4,
        netmask: Netmask,
        destination: Option<IPv4>,
    ) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let associate_route = self.associate_route.load(Ordering::Relaxed);
        self.set_network_address_impl(&address, &netmask, destination.as_ref(), associate_route)
    }
    /// Add IPv4 network address and netmask to the interface.
    ///
    /// On FreeBSD, this automatically calculates and configures the destination address
    /// based on the network address and netmask. If `associate_route` was enabled during
    /// device creation, the route will be automatically configured.
    ///
    /// # Arguments
    ///
    /// * `address` - The IPv4 address to add
    /// * `netmask` - The network mask (can be specified as a prefix length or full netmask)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(target_os = "freebsd")]
    /// # {
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// // Add additional IPv4 addresses
    /// dev.add_address_v4("10.0.1.1", 24)?;
    /// dev.add_address_v4("10.0.2.1", 24)?;
    /// println!("Added multiple IPv4 addresses");
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Platform
    ///
    /// FreeBSD only. Requires root privileges.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public signature matches the cross-platform API and accepts owned conversion inputs"
    )]
    ///
    /// # Errors
    /// Returns an error for invalid IPv4 input or failed address or route configuration.
    pub fn add_address_v4<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        &self,
        address: IPv4,
        netmask: Netmask,
    ) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let associate_route = self.associate_route.load(Ordering::Relaxed);
        let addr = address.ipv4()?.into();
        let netmask = netmask.netmask()?.into();
        let default_dest = Self::calc_dest_addr(addr, netmask)?;
        self.add_address(addr, netmask, Some(default_dest), associate_route)
    }
    /// Removes an IP address from the interface.
    ///
    /// # Errors
    /// Returns an I/O error if the requested address cannot be removed.
    pub fn remove_address(&self, addr: IpAddr) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // SAFETY: each request union member is initialized from the matching
        // address family before its synchronous delete ioctl.
        unsafe {
            match addr {
                IpAddr::V4(addr) => {
                    let mut req_v4 = self.request()?;
                    req_v4.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr;
                    if let Err(err) = siocdifaddr(ctl()?.as_raw_fd(), &raw const req_v4) {
                        return Err(io::Error::from(err));
                    }
                }
                IpAddr::V6(addr) => {
                    let mut req_v6 = self.request_v6()?;
                    req_v6.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr6;
                    if let Err(err) = siocdifaddr_in6(ctl_v6()?.as_raw_fd(), &raw const req_v6) {
                        return Err(io::Error::from(err));
                    }
                }
            }
            Ok(())
        }
    }
    /// Adds an IPv6 address and netmask to the interface.
    ///
    /// Configures the IPv6 address and prefix length on the TUN/TAP device.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IPv6 address to add
    /// * `netmask` - The network mask (can be specified as a prefix length or full netmask)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(target_os = "freebsd")]
    /// # {
    /// use tun_rs::DeviceBuilder;
    ///
    /// let dev = DeviceBuilder::new()
    ///     .ipv4("10.0.0.1", 24, None)
    ///     .build_sync()?;
    ///
    /// // Add IPv6 addresses
    /// dev.add_address_v6("fd00::1", 64)?;
    /// dev.add_address_v6("fd00::2", 64)?;
    /// println!("Added IPv6 addresses");
    /// # }
    /// # Ok::<(), std::io::Error>(())
    /// ```
    ///
    /// # Platform
    ///
    /// FreeBSD only. Requires root privileges.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public signature matches the cross-platform API and accepts owned conversion inputs"
    )]
    ///
    /// # Errors
    /// Returns an error for invalid IPv6 input or failed interface configuration.
    pub fn add_address_v6<IPv6: ToIpv6Address, Netmask: ToIpv6Netmask>(
        &self,
        addr: IPv6,
        netmask: Netmask,
    ) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let associate_route = self.associate_route.load(Ordering::Relaxed);
        self.add_address(
            addr.ipv6()?.into(),
            netmask.netmask()?.into(),
            None,
            associate_route,
        )
    }
    /// Sets the MAC (hardware) address for the interface.
    ///
    /// This function constructs an interface request and copies the provided MAC address
    /// into the hardware address field. It then applies the change via a system call.
    /// This operation is typically supported only for TAP devices.
    ///
    /// # Errors
    /// Returns an I/O error if the MAC address cannot be applied.
    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> std::io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let af_link = u8::try_from(AF_LINK).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "AF_LINK does not fit sockaddr family",
            )
        })?;
        // SAFETY: req is live and the sockaddr union member is fully initialized
        // before the synchronous link-layer ioctl reads it.
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;
            req.ifr_ifru.ifru_addr.sa_family = af_link;
            req.ifr_ifru.ifru_addr.sa_data[0..ETHER_ADDR_LEN as usize]
                .copy_from_slice(eth_addr.map(u8::cast_signed).as_slice());
            if let Err(err) = siocsiflladdr(ctl()?.as_raw_fd(), &raw const req) {
                return Err(io::Error::from(err));
            }
            Ok(())
        }
    }
    /// Retrieves the MAC (hardware) address of the interface.
    ///
    /// This function queries the MAC address by the interface name using getifaddrs.
    /// An error is returned if the MAC address cannot be found.
    ///
    /// # Errors
    /// Returns an I/O error if interface enumeration fails or no MAC address is found.
    pub fn mac_address(&self) -> std::io::Result<[u8; ETHER_ADDR_LEN as usize]> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let name = self.name_impl()?;
        let interfaces = getifaddrs::getifaddrs()?;
        for interface in interfaces {
            if interface.name == name {
                if let Some(mac) = interface.address.mac_addr() {
                    return Ok(mac);
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "MAC address not found for interface",
        ))
    }
    /// In Layer3(i.e. TUN mode), we need to put the tun interface into "`multi_af`" mode, which will prepend the address
    /// family to all packets (same as NetBSD).
    /// If this is not enabled, the kernel silently drops all IPv6 packets on output and gets confused on input.
    ///
    /// # Errors
    /// Returns an I/O error if multi-address-family mode cannot be enabled.
    pub fn enable_tunsifhead(&self) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::enable_tunsifhead_impl(&self.tun.fd)
    }
}

impl From<Layer> for c_short {
    fn from(layer: Layer) -> Self {
        match layer {
            Layer::L2 => 2,
            Layer::L3 => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsRawFd;

    #[test]
    fn borrowed_device_drop_leaves_descriptor_open() -> io::Result<()> {
        let file = File::open("/dev/null")?;
        let raw_fd = file.as_raw_fd();
        let device = DeviceImpl {
            name: RwLock::new("tun-test".into()),
            tun: Tun::new(unsafe { Fd::new_unchecked_with_borrow(raw_fd, true) }),
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(true),
        };

        drop(device);

        assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
        Ok(())
    }
}
