#![expect(
    unsafe_code,
    reason = "socket address conversion is the dedicated libc union/FFI boundary"
)]

/// # Safety
unsafe fn sockaddr_to_rs_addr(sa: &sockaddr_union) -> Option<std::net::SocketAddr> {
    // SAFETY: ss_family selects the active sockaddr layout before its corresponding union member is read.
    unsafe {
        match libc::c_int::from(sa.addr_stor.ss_family) {
            libc::AF_INET => {
                let sa_in = sa.addr4;
                let ip = std::net::Ipv4Addr::from(sa_in.sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be(sa_in.sin_port);
                Some(std::net::SocketAddr::new(ip.into(), port))
            }
            libc::AF_INET6 => {
                let sa_in6 = sa.addr6;
                let ip = std::net::Ipv6Addr::from(sa_in6.sin6_addr.s6_addr);
                let port = u16::from_be(sa_in6.sin6_port);
                Some(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    ip,
                    port,
                    sa_in6.sin6_flowinfo,
                    sa_in6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "sockaddr family constants and sockaddr structure sizes are ABI-defined to fit their destination fields"
)]
const fn rs_addr_to_sockaddr(addr: std::net::SocketAddr) -> sockaddr_union {
    match addr {
        std::net::SocketAddr::V4(ipv4) => {
            // SAFETY: zero is a valid byte initialization for this C sockaddr union; the IPv4 member is fully populated before the value escapes.
            let mut addr: sockaddr_union = unsafe { std::mem::zeroed() };
            #[cfg(any(
                target_os = "freebsd",
                target_os = "macos",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            {
                addr.addr4.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
            }
            addr.addr4.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.addr4.sin_addr.s_addr = u32::from_ne_bytes(ipv4.ip().octets());
            addr.addr4.sin_port = ipv4.port().to_be();
            addr
        }
        std::net::SocketAddr::V6(ipv6) => {
            // SAFETY: zero is a valid byte initialization for this C sockaddr union; the IPv6 member is fully populated before the value escapes.
            let mut addr: sockaddr_union = unsafe { std::mem::zeroed() };
            #[cfg(any(
                target_os = "freebsd",
                target_os = "macos",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            {
                addr.addr6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
            }
            addr.addr6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.addr6.sin6_addr.s6_addr = ipv6.ip().octets();
            addr.addr6.sin6_port = ipv6.port().to_be();
            addr.addr6.sin6_flowinfo = ipv6.flowinfo();
            addr.addr6.sin6_scope_id = ipv6.scope_id();
            addr
        }
    }
}

/// # Safety
/// `dst` must point to writable storage for at least
/// `min(size, size_of::<sockaddr_union>())` bytes. The pointer must be derived from
/// the complete backing C object being overwritten, not from a narrower Rust reference
/// to one of its fields. The destination must not overlap the local source value.
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
pub(crate) unsafe fn ipaddr_to_sockaddr<T>(
    src_addr: T,
    src_port: u16,
    dst: *mut libc::c_void,
    size: usize,
) where
    T: Into<std::net::IpAddr>,
{
    let sa = rs_addr_to_sockaddr((src_addr.into(), src_port).into());
    let copy_len = size.min(std::mem::size_of::<sockaddr_union>());
    // SAFETY: the caller guarantees dst is valid for copy_len writable bytes and
    // does not overlap the live local source union. u8 alignment is 1.
    unsafe {
        std::ptr::copy_nonoverlapping((&raw const sa).cast::<u8>(), dst.cast::<u8>(), copy_len);
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union sockaddr_union {
    pub addr_stor: libc::sockaddr_storage,
    pub addr6: libc::sockaddr_in6,
    pub addr4: libc::sockaddr_in,
    pub addr: libc::sockaddr,
}

impl From<libc::sockaddr_storage> for sockaddr_union {
    fn from(addr: libc::sockaddr_storage) -> Self {
        sockaddr_union { addr_stor: addr }
    }
}

impl From<libc::sockaddr_in6> for sockaddr_union {
    fn from(addr: libc::sockaddr_in6) -> Self {
        sockaddr_union { addr6: addr }
    }
}

impl From<libc::sockaddr_in> for sockaddr_union {
    fn from(addr: libc::sockaddr_in) -> Self {
        sockaddr_union { addr4: addr }
    }
}

impl From<libc::sockaddr> for sockaddr_union {
    fn from(addr: libc::sockaddr) -> Self {
        sockaddr_union { addr }
    }
}

impl From<std::net::SocketAddr> for sockaddr_union {
    fn from(addr: std::net::SocketAddr) -> Self {
        rs_addr_to_sockaddr(addr)
    }
}

impl TryFrom<sockaddr_union> for std::net::SocketAddr {
    type Error = std::io::Error;

    fn try_from(addr: sockaddr_union) -> Result<Self, Self::Error> {
        // SAFETY: the family tag is read from the storage member first; sockaddr_to_rs_addr only reads the union member selected by that tag.
        unsafe { sockaddr_to_rs_addr(&addr).ok_or_else(|| std::io::ErrorKind::InvalidInput.into()) }
    }
}

impl<T: Into<std::net::IpAddr>> From<(T, u16)> for sockaddr_union {
    fn from((ip, port): (T, u16)) -> Self {
        let ip: std::net::IpAddr = ip.into();
        rs_addr_to_sockaddr(std::net::SocketAddr::new(ip, port))
    }
}

#[test]
fn test_conversion() -> std::io::Result<()> {
    let old = std::net::SocketAddr::new([127, 0, 0, 1].into(), 0x0208);
    let addr = rs_addr_to_sockaddr(old);
    #[cfg(target_endian = "big")]
    // SAFETY: rs_addr_to_sockaddr initialized the IPv4 union member selected by
    // the test before these field reads.
    unsafe {
        assert_eq!(0x7f00_0001, addr.addr4.sin_addr.s_addr);
        assert_eq!(0x0208, addr.addr4.sin_port);
    }
    #[cfg(target_endian = "little")]
    // SAFETY: rs_addr_to_sockaddr initialized the IPv4 union member selected by the test before these field reads.
    unsafe {
        assert_eq!(0x0100_007f, addr.addr4.sin_addr.s_addr);
        assert_eq!(0x0802, addr.addr4.sin_port);
    }
    // SAFETY: addr was created by rs_addr_to_sockaddr, so its family tag and selected union member agree.
    let ip = unsafe { sockaddr_to_rs_addr(&addr) }
        .ok_or_else(|| std::io::Error::other("IPv4 sockaddr round-trip failed"))?;
    assert_eq!(ip, old);

    let old = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::LOCALHOST,
        0x0208,
        0x0123_4567,
        17,
    ));
    let addr = rs_addr_to_sockaddr(old);
    // SAFETY: rs_addr_to_sockaddr initialized the IPv6 union member selected by the test.
    unsafe {
        assert_eq!(addr.addr6.sin6_flowinfo, 0x0123_4567);
        assert_eq!(addr.addr6.sin6_scope_id, 17);
    }
    // SAFETY: addr was created by rs_addr_to_sockaddr, so its family tag and selected union member agree.
    let ip = unsafe { sockaddr_to_rs_addr(&addr) }
        .ok_or_else(|| std::io::Error::other("IPv6 sockaddr round-trip failed"))?;
    assert_eq!(ip, old);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let old = std::net::IpAddr::V4([10, 0, 0, 33].into());
        // SAFETY: zero is valid initialization for the C sockaddr union before the helper writes the selected member.
        let mut addr: sockaddr_union = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::sockaddr_in>();

        // SAFETY: the destination pointer comes from the complete sockaddr_union allocation,
        // which is writable for at least size bytes and cannot overlap the local source union.
        unsafe { ipaddr_to_sockaddr(old, 0x0208, (&raw mut addr).cast(), size) };
        // SAFETY: addr was initialized immediately above and ipaddr_to_sockaddr populated its tagged sockaddr bytes before conversion.
        let ip = unsafe { sockaddr_to_rs_addr(&addr) }
            .ok_or_else(|| std::io::Error::other("IP sockaddr conversion failed"))?;
        assert_eq!(ip, std::net::SocketAddr::new(old, 0x0208));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[test]
fn miri_ipaddr_to_sockaddr_writes_enclosing_storage() -> std::io::Result<()> {
    let old = std::net::IpAddr::V4([10, 26, 1, 100].into());
    // SAFETY: all-zero is a valid initial byte state for the libc ifreq union storage.
    let mut ifru: libc::__c_anonymous_ifr_ifru = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();

    // SAFETY: the pointer is derived from the complete ifreq union allocation, not
    // from ifru_addr, and the declared size is exactly that writable allocation.
    unsafe { ipaddr_to_sockaddr(old, 0x0208, (&raw mut ifru).cast(), size) };

    // SAFETY: ipaddr_to_sockaddr initialized the sockaddr prefix of the union above.
    let addr = sockaddr_union::from(unsafe { ifru.ifru_addr });
    let actual = std::net::SocketAddr::try_from(addr)?;
    assert_eq!(actual, std::net::SocketAddr::new(old, 0x0208));
    Ok(())
}
