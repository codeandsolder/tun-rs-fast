#![expect(
    unsafe_code,
    reason = "OpenBSD TUN/TAP configuration uses libc open/ioctl structures and borrowed raw descriptors"
)]

use crate::{
    builder::{DeviceConfig, Layer},
    platform::openbsd::sys::{
        ifaliasreq, in6_aliasreq, in6_ifreq, siocaifaddr, siocaifaddr_in6, siocdifaddr,
        siocdifaddr_in6, siocgifflags, siocgifmtu, siocifcreate, siocifdestroy, siocsifflags,
        siocsiflladdr, siocsifmtu, IN6_IFF_NODAD,
    },
    platform::{
        unix::{sockaddr_union, Fd, Tun},
        ETHER_ADDR_LEN,
    },
    ToIpv4Address, ToIpv4Netmask, ToIpv6Address, ToIpv6Netmask,
};

use crate::platform::unix::device::{copy_device_name, ctl, ctl_v6};
use libc::{self, c_short, ifreq, AF_LINK, IFF_UP, IFNAMSIZ, O_RDWR};
use std::io::ErrorKind;
use std::os::fd::{IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::{io, mem, net::IpAddr, os::unix::io::AsRawFd};

/// A TUN device using the OpenBSD TUN/TAP driver.
pub struct DeviceImpl {
    name: String,
    pub(crate) tun: Tun,
    pub(crate) op_lock: RwLock<()>,
    pub(crate) associate_route: AtomicBool,
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
        // SAFETY: req and the control descriptor remain live for the
        // synchronous destroy ioctl.
        unsafe {
            if let (Ok(ctl), Ok(req)) = (ctl(), self.request()) {
                _ = siocifdestroy(ctl.as_raw_fd(), &raw const req);
            }
        }
    }
}
impl DeviceImpl {
    /// Create a new `Device` for the given `Configuration`.
    pub(crate) fn new(config: DeviceConfig) -> io::Result<Self> {
        let layer = config.layer.unwrap_or(Layer::L3);
        let associate_route = if layer == Layer::L3 {
            config.associate_route.unwrap_or(true)
        } else {
            false
        };
        if let Some(dev_name) = config.dev_name.as_ref() {
            Self::check_name(layer, dev_name)?;
        }
        let (dev_fd, name) = Self::create_tuntap(layer, config.dev_name)?;

        let tun = Tun::new(dev_fd);
        if layer == Layer::L2 {
            tun.set_ignore_packet_info(false);
        } else {
            tun.set_ignore_packet_info(!config.packet_information.unwrap_or(false));
        }
        Ok(DeviceImpl {
            name,
            tun,
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(associate_route),
        })
    }
    fn create_tuntap(layer: Layer, dev_name: Option<String>) -> io::Result<(Fd, String)> {
        let device_prefix = match layer {
            Layer::L2 => "tap",
            Layer::L3 => "tun",
        };
        if let Some(dev_name) = dev_name {
            if !dev_name.starts_with(device_prefix) {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("device name must start with {device_prefix}"),
                ));
            }
            let if_index = dev_name[3..]
                .parse::<u32>()
                .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
            let device_path = format!("/dev/{device_prefix}{if_index}\0");
            let fd = Self::open_create_dev(&dev_name, &device_path)?;
            Ok((fd, dev_name))
        } else {
            for index in 0..256 {
                let dev_name = format!("{device_prefix}{index}");
                let device_path = format!("/dev/{device_prefix}{index}\0");
                match Self::open_create_dev(&dev_name, &device_path) {
                    Ok(dev) => {
                        return Ok((dev, dev_name));
                    }
                    Err(e) => {
                        if e.raw_os_error() != Some(libc::EBUSY) {
                            return Err(e);
                        }
                    }
                }
            }
            Err(io::Error::last_os_error())
        }
    }
    fn check_name(layer: Layer, dev_name: &str) -> io::Result<()> {
        if dev_name.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "device name too long",
            ));
        }
        let device_prefix = match layer {
            Layer::L2 => "tap",
            Layer::L3 => "tun",
        };
        if dev_name.starts_with(device_prefix) {
            Ok(())
        } else {
            Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("device name must start with {device_prefix}"),
            ))
        }
    }

    fn open_device_path(device_path: &str) -> io::Result<Fd> {
        // SAFETY: all callers construct device_path with a trailing NUL byte and
        // the string remains live for the duration of open.
        let raw_fd = unsafe { libc::open(device_path.as_ptr().cast(), O_RDWR | libc::O_CLOEXEC) };
        Fd::new(raw_fd)
    }

    fn open_create_dev(dev_name: &str, device_path: &str) -> io::Result<Fd> {
        match Self::open_device_path(device_path) {
            Ok(dev) => Ok(dev),
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                if let Err(e) = DeviceImpl::create_dev(dev_name) {
                    if e.kind() != ErrorKind::AlreadyExists {
                        return Err(e);
                    }
                }
                Self::open_and_makedev_dev(dev_name, device_path)
            }
            Err(e) => Err(e),
        }
    }
    fn open_and_makedev_dev(dev_name: &str, device_path: &str) -> io::Result<Fd> {
        match Self::open_device_path(device_path) {
            Ok(fd) => Ok(fd),
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                DeviceImpl::makedev_dev(dev_name)?;
                Self::open_device_path(device_path)
            }
            Err(e) => Err(e),
        }
    }
    fn makedev_dev(name: &str) -> io::Result<()> {
        let status = std::process::Command::new("sh")
            .arg("MAKEDEV")
            .arg(name)
            .current_dir("/dev")
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "MAKEDEV {} failed with status {:?}",
                name,
                status.code()
            )))
        }
    }
    fn create_dev(name: &str) -> io::Result<()> {
        // SAFETY: ifreq is a C request object whose all-zero state is valid
        // before its name field is populated.
        let mut req: ifreq = unsafe { mem::zeroed() };
        copy_device_name(name, &mut req.ifr_name)?;
        // SAFETY: req is live and fully initialized for this synchronous ioctl.
        unsafe {
            siocifcreate(ctl()?.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        Ok(())
    }
    pub(crate) fn from_tun(tun: Tun) -> io::Result<Self> {
        let name = Self::name_of_fd(&tun)?;
        if name.starts_with("tap") {
            // Tap does not have PI
            tun.set_ignore_packet_info(false);
        } else {
            tun.set_ignore_packet_info(true);
        }
        Ok(Self {
            name,
            tun,
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(true),
        })
    }

    fn calc_dest_addr(addr: IpAddr, netmask: IpAddr) -> io::Result<IpAddr> {
        let prefix_len = ipnet::ip_mask_to_prefix(netmask)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        Ok(ipnet::IpNet::new(addr, prefix_len)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?
            .broadcast())
    }

    /// Set an IP alias of the device.
    fn add_address(
        &self,
        addr: IpAddr,
        mask: IpAddr,
        dest: Option<IpAddr>,
        associate_route: bool,
    ) -> io::Result<()> {
        // SAFETY: request structures are live C-layout objects; each sockaddr
        // member is initialized for the matching address family before ioctl.
        unsafe {
            match (addr, mask) {
                (IpAddr::V4(addr), IpAddr::V4(mask)) => {
                    let ctl = ctl()?;
                    let mut req: ifaliasreq = mem::zeroed();
                    let tun_name = self.name_impl()?;
                    copy_device_name(&tun_name, &mut req.ifra_name)?;

                    req.ifra_ifrau.ifrau_addr =
                        crate::platform::unix::sockaddr_union::from((addr, 0)).addr;
                    match dest {
                        Some(IpAddr::V4(dest)) => {
                            req.ifra_dstaddr =
                                crate::platform::unix::sockaddr_union::from((dest, 0)).addr;
                        }
                        Some(IpAddr::V6(_)) => {
                            return Err(io::Error::from(ErrorKind::InvalidInput));
                        }
                        None => {}
                    }
                    req.ifra_mask = crate::platform::unix::sockaddr_union::from((mask, 0)).addr;

                    siocaifaddr(ctl.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
                    if let Err(e) = self.add_route(addr.into(), mask.into(), associate_route) {
                        log::warn!("add_route {addr}/{mask} {e:?}");
                    }
                }
                (IpAddr::V6(addr), IpAddr::V6(mask)) => {
                    if dest.is_some() {
                        return Err(io::Error::from(ErrorKind::InvalidInput));
                    }
                    let tun_name = self.name_impl()?;
                    let mut req: in6_aliasreq = mem::zeroed();
                    copy_device_name(&tun_name, &mut req.ifra_name)?;
                    req.ifra_ifrau.ifrau_addr = sockaddr_union::from((addr, 0)).addr6;
                    req.ifra_prefixmask = sockaddr_union::from((mask, 0)).addr6;
                    req.ifra_lifetime.ia6t_vltime = 0xffff_ffff_u32;
                    req.ifra_lifetime.ia6t_pltime = 0xffff_ffff_u32;
                    req.ifra_flags = IN6_IFF_NODAD;
                    siocaifaddr_in6(ctl_v6()?.as_raw_fd(), &raw const req)
                        .map_err(io::Error::from)?;
                }
                _ => return Err(io::Error::from(ErrorKind::InvalidInput)),
            }
        }
        Ok(())
    }

    /// Prepare a new request.
    fn request(&self) -> io::Result<ifreq> {
        // SAFETY: ifreq is a C request object whose all-zero state is valid
        // before its interface name is populated.
        let mut req: ifreq = unsafe { mem::zeroed() };
        let tun_name = self.name_impl()?;
        copy_device_name(&tun_name, &mut req.ifr_name)?;
        Ok(req)
    }

    fn request_v6(&self) -> io::Result<in6_ifreq> {
        let tun_name = self.name_impl()?;
        // SAFETY: in6_ifreq is a C request object whose all-zero state is valid
        // before its name and flags fields are populated.
        let mut req: in6_ifreq = unsafe { mem::zeroed() };
        copy_device_name(&tun_name, &mut req.ifra_name)?;
        req.ifr_ifru.ifru_flags = IN6_IFF_NODAD;
        Ok(req)
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
    fn add_route(&self, addr: IpAddr, netmask: IpAddr, associate_route: bool) -> io::Result<()> {
        if !associate_route {
            return Ok(());
        }
        let if_index = self.if_index_impl()?;
        let prefix_len = ipnet::ip_mask_to_prefix(netmask)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let mut manager = route_manager::RouteManager::new()?;
        let route = route_manager::Route::new(addr, prefix_len).with_if_index(if_index);
        manager.add(&route)?;
        Ok(())
    }

    /// Retrieves the name of the network interface.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "shared platform interface exposes interface-name lookup as fallible"
    )]
    pub(crate) fn name_impl(&self) -> io::Result<String> {
        Ok(self.name.clone())
    }
    fn name_of_fd(tun: &Tun) -> io::Result<String> {
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: st points to writable stat storage and tun owns a live fd.
        if unsafe { libc::fstat(tun.as_raw_fd(), st.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstat initialized the complete stat object.
        let st = unsafe { st.assume_init() };
        let typ = st.st_mode & libc::S_IFMT;
        if typ != libc::S_IFCHR && typ != libc::S_IFBLK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fd is not a device file",
            ));
        }
        // SAFETY: st_rdev and typ came from successful fstat. devname returns
        // either a borrowed NUL-terminated static string or null.
        let ptr = unsafe { libc::devname(st.st_rdev, typ) };
        if ptr.is_null() {
            return Err(io::Error::other("devname returned NULL"));
        }
        // SAFETY: a non-null devname result is a NUL-terminated C string.
        let name = unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        if name == "??" {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unknown device name (\"??\")",
            ));
        }
        Ok(name)
    }

    fn remove_all_address_v4(&self) -> io::Result<()> {
        let req_v4 = self.request()?;
        // OpenBSD treats an unspecified IPv4 address in SIOCDIFADDR as
        // "delete the first IPv4 address"; repeat until none remain.
        loop {
            // SAFETY: req_v4 is live request storage borrowed synchronously.
            let result = unsafe { siocdifaddr(ctl()?.as_raw_fd(), &raw const req_v4) };
            match result {
                Ok(_) => {}
                Err(nix::errno::Errno::EADDRNOTAVAIL) => break,
                Err(err) => return Err(io::Error::from(err)),
            }
        }
        Ok(())
    }
}

//Public User Interface
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
    /// Enables or disables the network interface administratively.
    ///
    /// This toggles only `IFF_UP`; kernel-owned operational flags such as
    /// `IFF_RUNNING` are preserved.
    ///
    /// # Errors
    /// Returns an I/O error if interface flags cannot be queried or updated.
    pub fn enabled(&self, value: bool) -> io::Result<()> {
        let up = c_short::try_from(IFF_UP).map_err(|_| {
            io::Error::new(ErrorKind::InvalidData, "OpenBSD IFF_UP exceeds c_short")
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
                req.ifr_ifru.ifru_flags |= up;
            } else {
                req.ifr_ifru.ifru_flags &= !up;
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
    pub fn mtu(&self) -> io::Result<u16> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut req = self.request()?;
        // SAFETY: SIOCGIFMTU initializes the ifr_mtu / ifru_metric union member
        // before it is read below.
        unsafe {
            siocgifmtu(ctl()?.as_raw_fd(), &raw mut req).map_err(io::Error::from)?;
            u16::try_from(req.ifr_ifru.ifru_metric)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "OpenBSD MTU is outside u16"))
        }
    }

    /// Sets the MTU (Maximum Transmission Unit) for the interface.
    ///
    /// # Errors
    /// Returns an I/O error if the MTU cannot be applied.
    pub fn set_mtu(&self, value: u16) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut req = self.request()?;
        // SAFETY: ifru_metric is the OpenBSD ifr_mtu union alias. Writing it
        // selects the intended member before the synchronous ioctl reads it.
        unsafe {
            req.ifr_ifru.ifru_metric = i32::from(value);
            siocsifmtu(ctl()?.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        Ok(())
    }

    /// Sets the IPv4 network address, netmask, and an optional destination address.
    /// Remove all previous set IPv4 addresses and set the specified address.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public signature matches the cross-platform API and accepts owned conversion inputs"
    )]
    ///
    /// # Errors
    /// Returns an error for invalid IPv4 input or failed address or route configuration.
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
        let addr = address.ipv4()?.into();
        let netmask = netmask.netmask()?.into();
        let default_dest = Self::calc_dest_addr(addr, netmask)?;
        let dest = destination
            .as_ref()
            .map(ToIpv4Address::ipv4)
            .transpose()?
            .map_or(default_dest, std::convert::Into::into);
        self.remove_all_address_v4()?;
        self.add_address(addr, netmask, Some(dest), associate_route)
    }
    /// Add IPv4 network address and netmask to the interface.
    ///
    /// On OpenBSD, this automatically calculates and configures the destination address
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
    /// # #[cfg(target_os = "openbsd")]
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
    /// OpenBSD only. Requires root privileges.
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
    /// # #[cfg(target_os = "openbsd")]
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
    /// OpenBSD only. Requires root privileges.
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
    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> io::Result<()> {
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
        // SAFETY: writing the sockaddr member selects the union variant used by
        // SIOCSIFLLADDR; the request remains live for the synchronous ioctl.
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_addr.sa_len = ETHER_ADDR_LEN;
            req.ifr_ifru.ifru_addr.sa_family = af_link;
            req.ifr_ifru.ifru_addr.sa_data[0..ETHER_ADDR_LEN as usize]
                .copy_from_slice(eth_addr.map(u8::cast_signed).as_slice());
            siocsiflladdr(ctl()?.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        Ok(())
    }
    /// Retrieves the name of the network interface.
    ///
    /// # Errors
    /// Returns an I/O error if the interface name cannot be retrieved.
    pub fn name(&self) -> io::Result<String> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.name_impl()
    }
    /// Retrieves the MAC (hardware) address of the interface.
    ///
    /// This function queries the MAC address by the interface name using getifaddrs.
    /// An error is returned if the MAC address cannot be found.
    ///
    /// # Errors
    /// Returns an I/O error if interface enumeration fails or no MAC address is found.
    pub fn mac_address(&self) -> io::Result<[u8; ETHER_ADDR_LEN as usize]> {
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
        Err(io::Error::new(
            ErrorKind::NotFound,
            "MAC address not found for interface",
        ))
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
        // SAFETY: raw_fd is borrowed from `file`, which remains live through the
        // device drop below; the borrowed Fd is configured not to close it.
        let borrowed_fd = unsafe { Fd::new_unchecked_with_borrow(raw_fd, true) };
        let device = DeviceImpl {
            name: "tun-test".into(),
            tun: Tun::new(borrowed_fd),
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(true),
        };

        drop(device);

        // SAFETY: `file` still owns raw_fd, so it remains valid for this query.
        assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
        Ok(())
    }
}
