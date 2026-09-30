#![expect(
    unsafe_code,
    reason = "macOS interface configuration uses libc ioctl structures and raw socket FFI"
)]

use crate::{
    builder::DeviceConfig,
    platform::{
        macos::sys::{
            ifaliasreq, in6_ifaliasreq, in6_ifreq, siocaifaddr, siocaifaddr_in6, siocdifaddr,
            siocdifaddr_in6, siocgifflags, siocgifmtu, siocsifflags, IN6_IFF_NODAD,
        },
        unix::sockaddr_union,
    },
    ToIpv4Address, ToIpv4Netmask, ToIpv6Address, ToIpv6Netmask,
};

//const OVERWRITE_SIZE: usize = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();

use crate::platform::macos::tuntap::TunTap;
use crate::platform::unix::device::{ctl, ctl_v6};
use crate::platform::unix::Tun;
use crate::platform::ETHER_ADDR_LEN;
use libc::{self, c_char, c_short, IFF_RUNNING, IFF_UP};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, mem, net::IpAddr, os::unix::io::AsRawFd, sync::RwLock};

/// A TUN device using the TUN macOS driver.
pub struct DeviceImpl {
    pub(crate) tun: TunTap,
    pub(crate) op_lock: RwLock<()>,
    pub(crate) associate_route: AtomicBool,
}

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

impl DeviceImpl {
    /// Create a new `Device` for the given `Configuration`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "constructor signature matches the other platform DeviceImpl implementations"
    )]
    pub(crate) fn new(config: DeviceConfig) -> io::Result<Self> {
        let associate_route = config.associate_route;
        let tun_tap = TunTap::new(&config)?;
        let associate_route = if tun_tap.is_tun() {
            associate_route.unwrap_or(true)
        } else {
            false
        };
        let device_impl = DeviceImpl {
            tun: tun_tap,
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(associate_route),
        };
        Ok(device_impl)
    }
    #[expect(
        clippy::unnecessary_wraps,
        reason = "shared Unix raw-fd construction expects a fallible platform constructor"
    )]
    pub(crate) fn from_tun(tun: Tun) -> io::Result<Self> {
        Ok(Self {
            tun: TunTap::Tun(tun),
            op_lock: RwLock::new(()),
            associate_route: AtomicBool::new(true),
        })
    }
    /// Prepare a new request.
    fn request(&self) -> io::Result<libc::ifreq> {
        self.tun.request()
    }
    fn request_v6(&self) -> io::Result<in6_ifreq> {
        self.tun.request_v6()
    }

    pub(crate) fn calc_dest_addr(addr: IpAddr, netmask: IpAddr) -> io::Result<IpAddr> {
        let prefix_len = ipnet::ip_mask_to_prefix(netmask)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        Ok(ipnet::IpNet::new(addr, prefix_len)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?
            .broadcast())
    }

    /// Set the IPv4 alias of the device.
    fn add_address(
        &self,
        addr: Ipv4Addr,
        dest: Ipv4Addr,
        mask: Ipv4Addr,
        associate_route: bool,
    ) -> io::Result<()> {
        let tun_name = self.name_impl()?;
        // SAFETY: ifaliasreq is a C POD request structure for which zero is the
        // required initial state before fields are populated.
        let mut req: ifaliasreq = unsafe { mem::zeroed() };
        copy_interface_name(&tun_name, &mut req.ifra_name)?;
        // SAFETY: each sockaddr_union is initialized from the matching IP family;
        // req is fully live for the synchronous ioctl call.
        unsafe {
            req.ifra_addr = sockaddr_union::from((addr, 0)).addr;
            req.ifra_broadaddr = sockaddr_union::from((dest, 0)).addr;
            req.ifra_mask = sockaddr_union::from((mask, 0)).addr;
            siocaifaddr(ctl()?.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        if let Err(e) = self.add_route(addr.into(), mask.into(), associate_route) {
            log::warn!("{e:?}");
        }
        Ok(())
    }
    fn remove_route(&self, addr: IpAddr, netmask: IpAddr, associate_route: bool) -> io::Result<()> {
        if !associate_route {
            return Ok(());
        }
        let if_index = self.if_index_impl()?;
        let mut manager = route_manager::RouteManager::new()?;
        let net = ipnet::IpNet::with_netmask(addr, netmask)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let prefix_len = net.prefix_len();
        let route = route_manager::Route::new(net.network(), prefix_len)
            .with_gateway(addr)
            .with_if_index(if_index);
        manager.delete(&route)?;
        Ok(())
    }
    fn add_route(&self, addr: IpAddr, netmask: IpAddr, associate_route: bool) -> io::Result<()> {
        if !associate_route {
            return Ok(());
        }
        let if_index = self.if_index_impl()?;
        let mut manager = route_manager::RouteManager::new()?;
        let net = ipnet::IpNet::with_netmask(addr, netmask)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let prefix_len = net.prefix_len();
        let route = route_manager::Route::new(net.network(), prefix_len)
            .with_gateway(addr)
            .with_if_index(if_index);
        manager.add(&route)?;
        Ok(())
    }
    fn remove_all_address_v4(&self, associate_route: bool) -> io::Result<()> {
        let mut req_v4 = self.request()?;

        if let Ok(addrs) = crate::platform::get_if_addrs_by_name(&self.name_impl()?) {
            for v in addrs {
                let Some(addr) = v.address.ip_addr() else {
                    continue;
                };
                let Some(netmask) = v.address.netmask() else {
                    continue;
                };
                if addr.is_ipv6() || netmask.is_ipv6() {
                    continue;
                }
                // SAFETY: req_v4 is a live ifreq and the sockaddr union is
                // initialized from the matching address family before the ioctl.
                unsafe {
                    req_v4.ifr_ifru.ifru_addr = sockaddr_union::from((addr, 0)).addr;
                    if let Err(err) = siocdifaddr(ctl()?.as_raw_fd(), &raw const req_v4) {
                        return Err(io::Error::from(err));
                    }
                }
                if let Err(e) = self.remove_route(addr, netmask, associate_route) {
                    log::warn!("remove_route {addr}-{netmask},{e}");
                }
            }
        }
        Ok(())
    }
    /// Sets the IPv4 network address, netmask, and an optional destination address.
    /// Remove all previous set IPv4 addresses and set the specified address.
    fn set_network_address_impl<IPv4: ToIpv4Address, Netmask: ToIpv4Netmask>(
        &self,
        address: &IPv4,
        netmask: &Netmask,
        destination: Option<&IPv4>,
        associate_route: bool,
    ) -> io::Result<()> {
        let netmask = netmask.netmask()?;
        let address = address.ipv4()?;
        let default_dest = Self::calc_dest_addr(address.into(), netmask.into())?;
        let IpAddr::V4(default_dest) = default_dest else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid destination for address/netmask",
            ));
        };
        let dest = destination
            .map(ToIpv4Address::ipv4)
            .transpose()?
            .unwrap_or(default_dest);
        self.remove_all_address_v4(associate_route)?;
        self.add_address(address, dest, netmask, associate_route)?;
        Ok(())
    }
    pub(crate) fn name_impl(&self) -> io::Result<String> {
        self.tun.name()
    }
}

// Public User Interface
impl DeviceImpl {
    /// Retrieves the name of the network interface.
    ///
    /// # Errors
    /// Returns an I/O error if the interface name cannot be queried.
    pub fn name(&self) -> io::Result<String> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.name_impl()
    }
    /// System behavior:
    /// On macOS, adding an IP to a feth interface will automatically add a route,
    /// while adding an IP to an utun interface will not.
    ///
    /// If false, the program will not modify or manage routes in any way, allowing the system to handle all routing natively.
    /// If true (default), the program will automatically add or remove routes to provide consistent routing behavior across all platforms.
    /// Set this to be false to obtain the platform's default routing behavior.
    pub fn set_associate_route(&self, associate_route: bool) {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.tun.is_tun() {
            self.associate_route
                .store(associate_route, Ordering::Relaxed);
        }
    }
    /// Retrieve whether route is associated with the IP setting interface, see [`DeviceImpl::set_associate_route`]
    pub fn associate_route(&self) -> bool {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.associate_route.load(Ordering::Relaxed)
    }
    /// Enables or disables the network interface.
    ///
    /// If `value` is true, the interface is enabled by setting the `IFF_UP` and `IFF_RUNNING` flags.
    /// If false, the `IFF_UP` flag is cleared. The change is applied using a system call.
    ///
    /// # Errors
    /// Returns an I/O error if interface flags cannot be queried or updated.
    pub fn enabled(&self, value: bool) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let up_running = c_short::try_from(IFF_UP | IFF_RUNNING).map_err(|_| {
            io::Error::new(
                ErrorKind::InvalidData,
                "Darwin interface flags exceed c_short",
            )
        })?;
        let up = c_short::try_from(IFF_UP)
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "Darwin IFF_UP exceeds c_short"))?;
        // SAFETY: req is a live ifreq owned by this function. The first ioctl
        // initializes the flags union member and the second consumes that member.
        // SAFETY: req is a live ifreq and siocgifmtu initializes the MTU union
        // member before it is read below.
        unsafe {
            let ctl = ctl()?;
            let mut req = self.request()?;
            siocgifflags(ctl.as_raw_fd(), &raw mut req).map_err(io::Error::from)?;
            if value {
                req.ifr_ifru.ifru_flags |= up_running;
            } else {
                req.ifr_ifru.ifru_flags &= !up;
            }
            siocsifflags(ctl.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        Ok(())
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
        // SAFETY: req is a live ifreq and the ioctl initializes the MTU
        // union member before it is read below.
        unsafe {
            let ctl = ctl()?;
            let mut req = self.request()?;

            if let Err(err) = siocgifmtu(ctl.as_raw_fd(), &raw mut req) {
                return Err(io::Error::from(err));
            }

            let r: u16 = req.ifr_ifru.ifru_mtu.try_into().map_err(io::Error::other)?;
            Ok(r)
        }
    }
    /// Sets the MTU (Maximum Transmission Unit) for the interface.
    ///
    /// # Errors
    /// Returns an I/O error if the MTU cannot be applied to the interface.
    pub fn set_mtu(&self, value: u16) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.tun.set_mtu(value)
    }
    /// Sets the IPv4 network address, netmask, and an optional destination address.
    /// Remove all previous set IPv4 addresses and set the specified address.
    ///
    /// # Errors
    /// Returns an error for invalid address input or failed interface or route updates.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "public signature matches the cross-platform API and accepts owned conversion inputs"
    )]
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
    /// On macOS, this automatically calculates and configures the destination address
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
    /// # #[cfg(target_os = "macos")]
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
    /// macOS only. Requires administrator privileges.
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
        let netmask = netmask.netmask()?;
        let address = address.ipv4()?;
        let default_dest = Self::calc_dest_addr(address.into(), netmask.into())?;
        let IpAddr::V4(default_dest) = default_dest else {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid destination for address/netmask",
            ));
        };
        self.add_address(address, default_dest, netmask, associate_route)?;
        Ok(())
    }
    /// Remove an IP address from the interface.
    ///
    /// # Errors
    /// Returns an I/O error if the address or associated route cannot be removed.
    pub fn remove_address(&self, addr: IpAddr) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let is_associate_route = self.associate_route.load(Ordering::Relaxed);
        // SAFETY: request structs are live and each address union member is set
        // from the matching IP family before its synchronous delete ioctl.
        unsafe {
            match addr {
                IpAddr::V4(addr_v4) => {
                    let mut req_v4 = self.request()?;
                    req_v4.ifr_ifru.ifru_addr = sockaddr_union::from((addr_v4, 0)).addr;
                    if let Err(err) = siocdifaddr(ctl()?.as_raw_fd(), &raw const req_v4) {
                        return Err(io::Error::from(err));
                    }
                    if let Ok(addrs) = crate::platform::get_if_addrs_by_name(&self.name_impl()?) {
                        for v in addrs.iter().filter(|v| v.address.ip_addr() == Some(addr)) {
                            let Some(netmask) = v.address.netmask() else {
                                continue;
                            };
                            if let Err(e) = self.remove_route(addr, netmask, is_associate_route) {
                                log::warn!("remove_route {addr}-{netmask},{e}");
                            }
                        }
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
    /// Add an IPv6 address and netmask to the interface.
    ///
    /// Configures the IPv6 address and prefix length on the TUN device.
    ///
    /// # Arguments
    ///
    /// * `addr` - The IPv6 address to add
    /// * `netmask` - The network mask (can be specified as a prefix length or full netmask)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(target_os = "macos")]
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
    /// macOS only. Requires administrator privileges.
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
        let addr = addr.ipv6()?;
        let tun_name = self.name_impl()?;
        // SAFETY: in6_ifaliasreq is a C POD request structure for which zero is
        // a valid initialization before fields are populated.
        let mut req: in6_ifaliasreq = unsafe { mem::zeroed() };
        copy_interface_name(&tun_name, &mut req.ifra_name)?;
        let network_addr = ipnet::IpNet::new(addr.into(), netmask.prefix()?)
            .map_err(|e| io::Error::new(ErrorKind::InvalidInput, e))?;
        let mask = network_addr.netmask();
        // SAFETY: both sockaddr unions are initialized from IPv6 values and req
        // remains live for the synchronous ioctl call.
        unsafe {
            req.ifra_addr = sockaddr_union::from((addr, 0)).addr6;
            req.ifra_prefixmask = sockaddr_union::from((mask, 0)).addr6;
            req.in6_addrlifetime.ia6t_vltime = 0xffff_ffff_u32;
            req.in6_addrlifetime.ia6t_pltime = 0xffff_ffff_u32;
            req.ifra_flags = IN6_IFF_NODAD;
            siocaifaddr_in6(ctl_v6()?.as_raw_fd(), &raw const req).map_err(io::Error::from)?;
        }
        Ok(())
    }
    /// Set MAC address on L2 layer
    ///
    /// # Errors
    /// Returns an I/O error if the device is not layer 2 or the MAC address cannot be applied.
    pub fn set_mac_address(&self, eth_addr: [u8; ETHER_ADDR_LEN as usize]) -> io::Result<()> {
        let _guard = self
            .op_lock
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.tun.set_mac_address(eth_addr)
    }
    /// Retrieve MAC address for the device
    ///
    /// # Errors
    /// Returns an I/O error if the device is not layer 2 or the MAC address cannot be queried.
    pub fn mac_address(&self) -> io::Result<[u8; ETHER_ADDR_LEN as usize]> {
        let _guard = self
            .op_lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.tun.mac_address()
    }
}
