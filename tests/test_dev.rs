#![expect(
    unsafe_code,
    reason = "integration tests explicitly exercise Unix typed-fd ownership and adoption contracts"
)]
#[cfg(not(feature = "async_io"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(feature = "async_io"))]
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(feature = "async_io"))]
use pnet_packet::ip::IpNextHeaderProtocols;
#[cfg(not(feature = "async_io"))]
use pnet_packet::Packet;
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
use tun_rs::DeviceBuilder;
#[cfg(unix)]
use tun_rs::SyncDevice;

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[cfg(not(any(feature = "async_tokio", feature = "async_io")))]
#[test]
fn test_udp_v4() -> std::io::Result<()> {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv4("10.26.1.100", 24, None)
        .build_sync()?;
    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v4 = Arc::new(AtomicBool::new(false));
    let test_udp_v4_c = test_udp_v4.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut buf = vec![0; 65_535];
        loop {
            let len = device.recv(&mut buf)?;
            if let Some(ipv4_packet) = pnet_packet::ipv4::Ipv4Packet::new(&buf[..len]) {
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    if let Some(udp_packet) =
                        pnet_packet::udp::UdpPacket::new(ipv4_packet.payload())
                    {
                        if udp_packet.payload() == test_msg.as_bytes() {
                            test_udp_v4.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            if test_udp_v4.load(Ordering::Relaxed) {
                recv_flag.store(true, Ordering::Release);
                return Ok(());
            }
        }
    });
    std::thread::sleep(Duration::from_secs(6));
    let udp_socket = std::net::UdpSocket::bind("10.26.1.100:0")?;
    udp_socket.send_to(test_msg.as_bytes(), "10.26.1.101:8080")?;
    let time_now = std::time::Instant::now();
    // check whether the thread completes
    while !recv_flag_c.load(Ordering::Acquire) {
        if time_now.elapsed().as_secs() > 2 {
            // no promise due to the timeout
            let v4 = test_udp_v4_c.load(Ordering::Relaxed);
            if !v4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout waiting for IPv4 UDP packet",
                ));
            }
        }
    }
    // recv_flag_c == true
    // all modifications to test_udp_v4_c must be visible
    let v4 = test_udp_v4_c.load(Ordering::Relaxed);
    assert!(v4);
    worker
        .join()
        .map_err(|_| std::io::Error::other("IPv4 receive worker panicked"))??;
    Ok(())
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[cfg(not(any(feature = "async_tokio", feature = "async_io")))]
#[test]
fn test_udp_v6() -> std::io::Result<()> {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv6("fd12:3456:789a:1111:2222:3333:4444:5555", 64)
        .build_sync()?;
    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v6 = Arc::new(AtomicBool::new(false));
    let test_udp_v6_c = test_udp_v6.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        let mut buf = vec![0; 65_535];
        loop {
            let len = device.recv(&mut buf)?;
            if let Some(ipv6_packet) = pnet_packet::ipv6::Ipv6Packet::new(&buf[..len]) {
                if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Udp {
                    if let Some(udp_packet) =
                        pnet_packet::udp::UdpPacket::new(ipv6_packet.payload())
                    {
                        if udp_packet.payload() == test_msg.as_bytes() {
                            test_udp_v6.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            if test_udp_v6.load(Ordering::Relaxed) {
                recv_flag.store(true, Ordering::Release);
                return Ok(());
            }
        }
    });
    std::thread::sleep(Duration::from_secs(6));
    let udp_socket = std::net::UdpSocket::bind("[fd12:3456:789a:1111:2222:3333:4444:5555]:0")?;
    udp_socket.send_to(
        test_msg.as_bytes(),
        "[fd12:3456:789a:1111:2222:3333:4444:5556]:8080",
    )?;
    let time_now = std::time::Instant::now();
    // check whether the thread completes
    while !recv_flag_c.load(Ordering::Acquire) {
        if time_now.elapsed().as_secs() > 2 {
            // no promise due to the timeout
            let v6 = test_udp_v6_c.load(Ordering::Relaxed);
            if !v6 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timeout waiting for IPv6 UDP packet",
                ));
            }
        }
    }
    // recv_flag_c == true
    // all modifications to test_udp_v6_c must be visible
    let v6 = test_udp_v6_c.load(Ordering::Relaxed);
    assert!(v6);
    worker
        .join()
        .map_err(|_| std::io::Error::other("IPv6 receive worker panicked"))??;
    Ok(())
}
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[cfg(feature = "async_tokio")]
#[tokio::test]
async fn test_udp_v4() {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv4("10.26.1.100", 24, None)
        .build_async()
        .unwrap();

    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v4 = Arc::new(AtomicBool::new(false));
    let test_udp_v4_c = test_udp_v4.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    let handler = tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            let len = device.recv(&mut buf).await.unwrap();
            if let Some(ipv4_packet) = pnet_packet::ipv4::Ipv4Packet::new(&buf[..len]) {
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    if let Some(udp_packet) =
                        pnet_packet::udp::UdpPacket::new(ipv4_packet.payload())
                    {
                        if udp_packet.payload() == test_msg.as_bytes() {
                            test_udp_v4.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
            if test_udp_v4.load(Ordering::Relaxed) {
                recv_flag.store(true, Ordering::Release);
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_secs(6)).await;

    let udp_socket = tokio::net::UdpSocket::bind("10.26.1.100:0").await.unwrap();
    udp_socket
        .send_to(test_msg.as_bytes(), "10.26.1.101:8080")
        .await
        .unwrap();
    tokio::select! {
        _=tokio::time::sleep(Duration::from_secs(2))=>{
            // no promise due to the timeout
            let v4 = test_udp_v4_c.load(Ordering::Relaxed);
            assert!(v4, "timeout: test_udp_v4 = {v4}");
        }
        _=handler=>{
            // all modifications to test_udp_v4_c and test_udp_v6_c must be visible
            let flag = recv_flag_c.load(Ordering::Acquire); //synchronize
            assert!(flag, "recv_flag = {flag}");
            let v4 = test_udp_v4_c.load(Ordering::Relaxed);
            assert!(v4);
        }
    }
}
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[cfg(feature = "async_tokio")]
#[tokio::test]
async fn test_udp_v6() {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv6("fd12:3456:789a:1111:2222:3333:4444:5555", 64)
        .build_async()
        .unwrap();

    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v6 = Arc::new(AtomicBool::new(false));
    let test_udp_v6_c = test_udp_v6.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    let handler = tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            let len = device.recv(&mut buf).await.unwrap();
            if let Some(ipv6_packet) = pnet_packet::ipv6::Ipv6Packet::new(&buf[..len]) {
                if ipv6_packet.get_next_header() == IpNextHeaderProtocols::Udp {
                    if let Some(udp_packet) =
                        pnet_packet::udp::UdpPacket::new(ipv6_packet.payload())
                    {
                        if udp_packet.payload() == test_msg.as_bytes() {
                            test_udp_v6.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }

            if test_udp_v6.load(Ordering::Relaxed) {
                recv_flag.store(true, Ordering::Release);
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_secs(6)).await;
    let udp_socket = tokio::net::UdpSocket::bind("[fd12:3456:789a:1111:2222:3333:4444:5555]:0")
        .await
        .unwrap();
    udp_socket
        .send_to(
            test_msg.as_bytes(),
            "[fd12:3456:789a:1111:2222:3333:4444:5556]:8080",
        )
        .await
        .unwrap();

    tokio::select! {
        _=tokio::time::sleep(Duration::from_secs(2))=>{
            // no promise due to the timeout
            let v6 = test_udp_v6_c.load(Ordering::Relaxed);
            assert!(v6, "timeout: test_udp_v6 = {v6}");
        }
        _=handler=>{
            // all modifications to test_udp_v4_c and test_udp_v6_c must be visible
            let flag = recv_flag_c.load(Ordering::Acquire); //synchronize
            assert!(flag, "recv_flag = {flag}");
            let v6 = test_udp_v6_c.load(Ordering::Relaxed);
            assert!(v6 );
        }
    }
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[test]
fn test_op() -> std::io::Result<()> {
    let device = DeviceBuilder::new()
        .ipv4("10.26.2.100", 24, None)
        .ipv6("fd12:3456:789a:5555:2222:3333:4444:5555", 120)
        .build_sync()?;

    #[cfg(any(target_os = "macos", target_os = "openbsd"))]
    device.set_ignore_packet_info(true);
    #[cfg(any(target_os = "macos", target_os = "openbsd"))]
    assert!(device.ignore_packet_info());

    device.set_mtu(1500)?;
    assert_eq!(device.mtu()?, 1500);

    #[cfg(target_os = "macos")]
    device.set_associate_route(true);
    #[cfg(target_os = "macos")]
    assert!(device.associate_route());

    #[cfg(feature = "address-management")]
    {
        let vec = device.addresses()?;
        assert!(vec
            .iter()
            .any(|ip| *ip == std::net::Ipv4Addr::new(10, 26, 2, 100)));
        assert!(vec.iter().any(|ip| *ip
            == std::net::Ipv6Addr::new(
                0xfd12, 0x3456, 0x789a, 0x5555, 0x2222, 0x3333, 0x4444, 0x5555
            )));

        device.set_network_address("10.26.3.200", 24, None)?;
        let vec = device.addresses()?;
        assert!(vec
            .iter()
            .any(|ip| *ip == std::net::Ipv4Addr::new(10, 26, 3, 200)));
        assert!(vec.iter().any(|ip| *ip
            == std::net::Ipv6Addr::new(
                0xfd12, 0x3456, 0x789a, 0x5555, 0x2222, 0x3333, 0x4444, 0x5555
            )));
        assert!(!vec.contains(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10, 26, 2, 100
        ))));

        device.add_address_v4("10.6.0.1", 24)?;
        let vec = device.addresses()?;
        assert!(vec.contains(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 6, 0, 1))));
        assert!(vec.contains(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10, 26, 3, 200
        ))));

        device.remove_address(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 6, 0, 1)))?;
        let vec = device.addresses()?;
        assert!(!vec.contains(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 6, 0, 1))));
        assert!(vec.contains(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            10, 26, 3, 200
        ))));

        device.add_address_v6("fdab:cdef:1234:5678:9abc:def0:1234:5678", 64)?;
        let vec = device.addresses()?;
        assert!(vec.contains(&std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0xfdab, 0xcdef, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x1234, 0x5678,
        ))));
    }

    device.enabled(true)?;

    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos"))
    ))]
    device.set_name("tun66")?;
    std::thread::sleep(Duration::from_secs(3));

    #[cfg(any(
        target_os = "windows",
        all(target_os = "linux", not(target_env = "ohos"))
    ))]
    assert_eq!(device.name()?, "tun66");

    assert!(device.if_index().is_ok());

    // Windows-only configuration that was migrated from netsh/wmic commands to
    // windows-sys APIs. None of these expose a public read-back getter, so we assert
    // that the configure path succeeds: a malformed FFI call (wrong struct layout,
    // flags, GUID conversion, or a failed dynamic load) returns an error and fails here.
    #[cfg(target_os = "windows")]
    {
        // `if_luid()` is exposed for downstream crates; it must resolve to a LUID.
        assert!(device.if_luid().is_ok());

        // `set_metric` -> Get/SetIpInterfaceEntry.
        device
            .set_metric(100)
            .expect("set_metric(100) should succeed");

        // `set_dns_servers` -> SetInterfaceDnsSettings (resolved at run time) with a
        // netsh fallback. Exercise IPv4 (primary + secondary) and IPv6, then clear both.
        let v4_dns: [std::net::IpAddr; 2] =
            ["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
        device.set_dns_servers(&v4_dns).unwrap();
        let v6_dns: [std::net::IpAddr; 1] = ["2001:4860:4860::8888".parse().unwrap()];
        device.set_dns_servers(&v6_dns).unwrap();
        device.clear_dns_servers(true).unwrap();
        device.clear_dns_servers(false).unwrap();
    }

    #[cfg(all(target_os = "linux", not(target_env = "ohos")))]
    assert!(device.is_running()?);
    Ok(())
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[test]
fn create_tun() -> std::io::Result<()> {
    #[cfg(not(target_os = "macos"))]
    let name = "tun12";
    #[cfg(target_os = "macos")]
    let name = "utun12";

    let device = DeviceBuilder::new().name(name).build_sync()?;
    let dev_name = device.name()?;
    assert_eq!(dev_name.as_str(), name);
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        use tun_rs::BorrowedSyncDevice;

        {
            let borrowed = BorrowedSyncDevice::from_fd(device.as_fd())?;
            assert_eq!(borrowed.name()?, name);
        }
        assert_eq!(device.name()?, name);

        let fd = device.into_fd();
        let sync_device = SyncDevice::from_fd(fd)?;
        let dev_name = sync_device.name()?;
        assert_eq!(dev_name, name);
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[test]
fn adopted_fd_rejects_virtio_header_framing_and_consumes_ownership() -> std::io::Result<()> {
    use std::io;
    use std::os::fd::AsRawFd;

    let device = DeviceBuilder::new().offload(true).build_sync()?;
    let fd = device.into_fd();
    let raw_fd = fd.as_raw_fd();

    let Err(error) = SyncDevice::from_fd(fd) else {
        return Err(io::Error::other(
            "adopting an `IFF_VNET_HDR` descriptor unexpectedly succeeded",
        ));
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    // Ownership moved into from_fd even though platform validation rejected it.
    // SAFETY: `fcntl(F_GETFD)` accepts any integer descriptor and reports `EBADF` for a closed one.
    assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    Ok(())
}

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
#[test]
fn create_tap() -> std::io::Result<()> {
    #[cfg(not(target_os = "macos"))]
    let name = "tap12";
    #[cfg(target_os = "macos")]
    let name = "feth12";

    let device = DeviceBuilder::new()
        .name(name)
        .layer(tun_rs::Layer::L2)
        .build_sync()?;
    let dev_name = device.name()?;
    assert_eq!(dev_name.as_str(), name);
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let fd = device.into_fd();
        let sync_device = SyncDevice::from_fd(fd)?;
        let dev_name = sync_device.name()?;
        assert_eq!(dev_name, name);
    }
    Ok(())
}

/// Dedicated Windows test covering every public API migrated from netsh/wmic to
/// windows-sys in PR `#140`.  Each section is labelled with the underlying Windows
/// API that was newly wired up.
#[cfg(target_os = "windows")]
#[test]
fn test_windows_new_apis() {
    use std::net::IpAddr;
    use tun_rs::DeviceBuilder;

    let device = DeviceBuilder::new()
        .ipv4("10.26.9.100", 24, None)
        .ipv6("fd12:3456:789a:9999:2222:3333:4444:5555", 64)
        .build_sync()
        .unwrap();

    // ── 1. if_luid() ─────────────────────────────────────────────────────────
    // New public API; a valid adapter LUID is never zero.
    let luid = device.if_luid().expect("if_luid() should succeed");
    let luid_value = unsafe { luid.Value };
    assert_ne!(luid_value, 0, "LUID must be non-zero for a live adapter");

    // ── 2. set_metric() ──────────────────────────────────────────────────────
    // Now uses GetIpInterfaceEntry / SetIpInterfaceEntry for both AF_INET and
    // AF_INET6.  No public read-back getter exists, so we assert the call
    // succeeds for two different values (exercises the full round-trip twice).
    device
        .set_metric(50)
        .expect("set_metric(50) should succeed");
    device
        .set_metric(100)
        .expect("set_metric(100) should succeed");

    // ── 3. set_mtu / mtu (IPv4) ──────────────────────────────────────────────
    // Now uses SetIpInterfaceEntry with NlMtu; read back via GetIpInterfaceTable.
    device.set_mtu(1400).expect("set_mtu(1400) should succeed");
    assert_eq!(
        device.mtu().expect("mtu() should succeed"),
        1400,
        "mtu() read-back should match the value written by set_mtu()"
    );

    // ── 4. set_mtu_v6 / mtu_v6 (IPv6) ───────────────────────────────────────
    // Same path but with is_v4=false; mtu_v6() reads back via GetIpInterfaceTable
    // with AF_INET6.
    device
        .set_mtu_v6(1380)
        .expect("set_mtu_v6(1380) should succeed");
    assert_eq!(
        device.mtu_v6().expect("mtu_v6() should succeed"),
        1380,
        "mtu_v6() read-back should match the value written by set_mtu_v6()"
    );

    // ── 5. set_network_address without gateway ───────────────────────────────
    // ffi::set_address clears all existing IPv4 unicast addresses and installs
    // the new one.  The old address must disappear.
    device
        .set_network_address("10.26.9.200", 24, None)
        .expect("set_network_address (no gateway) should succeed");
    let addrs = device.addresses().unwrap();
    assert!(
        addrs.contains(&"10.26.9.200".parse::<IpAddr>().unwrap()),
        "new address 10.26.9.200 should be present after set_network_address"
    );
    assert!(
        !addrs.contains(&"10.26.9.100".parse::<IpAddr>().unwrap()),
        "old address 10.26.9.100 should have been removed by set_network_address"
    );

    // ── 6. set_network_address WITH gateway ──────────────────────────────────
    // Exercises the default-route creation path in ffi::add_address that was
    // specifically fixed in this PR (DestinationPrefix address family +
    // SitePrefixLength=0 for CreateIpForwardEntry2).
    device
        .set_network_address("10.26.9.150", 24, Some("10.26.9.1"))
        .expect("set_network_address with gateway should succeed");
    let addrs = device.addresses().unwrap();
    assert!(
        addrs.contains(&"10.26.9.150".parse::<IpAddr>().unwrap()),
        "address 10.26.9.150 should be present after set_network_address with gateway"
    );
    assert!(
        !addrs.contains(&"10.26.9.200".parse::<IpAddr>().unwrap()),
        "previous address 10.26.9.200 should have been cleared"
    );

    // ── 7. add_address_v6 ────────────────────────────────────────────────────
    // ffi::add_address with None gateway; verifies the address appears in the
    // interface's address list.
    device
        .add_address_v6("fdab:cdef:1234:5678:9abc:def0:1234:0001", 64)
        .expect("add_address_v6 should succeed");
    let addrs = device.addresses().unwrap();
    assert!(
        addrs.contains(
            &"fdab:cdef:1234:5678:9abc:def0:1234:0001"
                .parse::<IpAddr>()
                .unwrap()
        ),
        "IPv6 address should be present after add_address_v6"
    );

    // ── 8. remove_address (IPv6) ─────────────────────────────────────────────
    // ffi::remove_address; confirms the address is gone after deletion.
    device
        .remove_address(
            "fdab:cdef:1234:5678:9abc:def0:1234:0001"
                .parse::<IpAddr>()
                .unwrap(),
        )
        .expect("remove_address (IPv6) should succeed");
    let addrs = device.addresses().unwrap();
    assert!(
        !addrs.contains(
            &"fdab:cdef:1234:5678:9abc:def0:1234:0001"
                .parse::<IpAddr>()
                .unwrap()
        ),
        "IPv6 address should be absent after remove_address"
    );

    // ── 9. set_dns_servers (IPv4) ────────────────────────────────────────────
    // dns::set_dns_servers → SetInterfaceDnsSettings (or netsh fallback).
    let ipv4_dns: &[IpAddr] = &["8.8.8.8".parse().unwrap(), "8.8.4.4".parse().unwrap()];
    device
        .set_dns_servers(ipv4_dns)
        .expect("set_dns_servers (IPv4 primary+secondary) should succeed");

    // ── 10. set_dns_servers (IPv6) ───────────────────────────────────────────
    let ipv6_dns: &[IpAddr] = &["2001:4860:4860::8888".parse().unwrap()];
    device
        .set_dns_servers(ipv6_dns)
        .expect("set_dns_servers (IPv6) should succeed");

    // ── 11. set_dns_servers — validation: empty list must be rejected ────────
    assert!(
        device.set_dns_servers(&[]).is_err(),
        "set_dns_servers with an empty slice must return Err (InvalidInput)"
    );

    // ── 12. set_dns_servers — validation: mixed families must be rejected ────
    let mixed: &[IpAddr] = &[
        "8.8.8.8".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
    ];
    assert!(
        device.set_dns_servers(mixed).is_err(),
        "set_dns_servers with mixed IPv4/IPv6 addresses must return Err (InvalidInput)"
    );

    // ── 13. clear_dns_servers ────────────────────────────────────────────────
    // dns::clear_dns_servers → SetInterfaceDnsSettings with empty NameServer
    // (or netsh fallback).
    device
        .clear_dns_servers(true)
        .expect("clear_dns_servers (IPv4) should succeed");
    device
        .clear_dns_servers(false)
        .expect("clear_dns_servers (IPv6) should succeed");
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[test]
fn linux_rejects_packet_information_with_vnet_offload() -> std::io::Result<()> {
    let Err(error) = DeviceBuilder::new()
        .packet_information(true)
        .offload(true)
        .build_sync()
    else {
        return Err(std::io::Error::other(
            "unsupported PI + vnet-header combination was accepted",
        ));
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    Ok(())
}

/// Regression test for the device-wide `TUN_F_*` offload mask not being
/// cleared on attach with `offload=false`.
///
/// The kernel keeps `tun->set_features` (`TSO/HW_CSUM/etc.`) state per
/// device, not per fd. When a persistent TUN is first attached with
/// `offload=true`, the kernel raises these features. A later attach with
/// `offload=false` correctly omits `IFF_VNET_HDR` on the new tfile, but if
/// the device-wide mask is not reset, the kernel still treats the device
/// as offload-capable and delivers GSO aggregates that the new (offload-
/// unaware) caller misinterprets as oversized single packets. The fix is
/// to issue `TUNSETOFFLOAD(0)` in the offload=false branch of
/// `DeviceImpl::new`.
///
/// Marked `#[ignore]`: requires `CAP_NET_ADMIN` (root) and `ethtool` in
/// PATH; creates and deletes a persistent TUN device named `tunoffldclr`.
/// Run with:
///   `cargo test --test test_dev -- --ignored offload_mask_cleared`
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[cfg(not(feature = "async_io"))]
#[test]
#[ignore = "requires CAP_NET_ADMIN, ethtool, and a persistent TUN device"]
fn test_offload_mask_cleared_on_reattach_without_offload() -> std::io::Result<()> {
    use std::process::Command;

    const NAME: &str = "tunoffldclr";

    // Parse `ethtool -k <name>` output for a single feature flag's state.
    // Lines look like:
    //   tx-tcp-segmentation: on
    //   tx-checksum-ip-generic: off
    fn ethtool_feature(name: &str, feature: &str) -> std::io::Result<bool> {
        let output = Command::new("ethtool").args(["-k", name]).output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "ethtool -k {name} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(feature) {
                if let Some(value) = rest.strip_prefix(':') {
                    let value = value.trim();
                    if value.starts_with("on") {
                        return Ok(true);
                    }
                    if value.starts_with("off") {
                        return Ok(false);
                    }
                }
            }
        }
        Err(std::io::Error::other(format!(
            "feature `{feature}` not found in `ethtool -k {name}` output:\n{stdout}"
        )))
    }

    // Clean any leftover device from a previous failed run. Ignore errors.
    let _ = Command::new("ip").args(["link", "delete", NAME]).status();

    // ── Attach #1: offload=true, persisted ──────────────────────────────
    // Raises the device-wide `TUN_F_*` mask via TUNSETOFFLOAD.
    let dev1 = DeviceBuilder::new().name(NAME).offload(true).build_sync()?;
    dev1.persist()?;

    // Sanity check: the features set by TUN_F_CSUM | TUN_F_TSO4 |
    // TUN_F_TSO6 should be visible to ethtool.
    let tso_after_offload = ethtool_feature(NAME, "tx-tcp-segmentation")?;
    let csum_after_offload = ethtool_feature(NAME, "tx-checksum-ip-generic")?;

    // Drop attach #1. The device persists; tun->set_features is unchanged.
    drop(dev1);

    // ── Attach #2: offload=false ────────────────────────────────────────
    // With the fix in DeviceImpl::new, TUNSETOFFLOAD(0) clears the mask.
    // Without the fix, ethtool still reports TSO/HW_CSUM on.
    let dev2 = DeviceBuilder::new()
        .name(NAME)
        .offload(false)
        .build_sync()?;

    let tso_after_clear = ethtool_feature(NAME, "tx-tcp-segmentation")?;
    let csum_after_clear = ethtool_feature(NAME, "tx-checksum-ip-generic")?;

    drop(dev2);

    // Cleanup before asserting so a failed assert doesn't leak the device.
    let _ = Command::new("ip").args(["link", "delete", NAME]).status();

    assert!(
        tso_after_offload,
        "ethtool sanity: tx-tcp-segmentation should be ON after offload=true attach"
    );
    assert!(
        csum_after_offload,
        "ethtool sanity: tx-checksum-ip-generic should be ON after offload=true attach"
    );
    assert!(
        !tso_after_clear,
        "regression: tx-tcp-segmentation still ON after offload=false attach \
         (device-wide TUN_F_TSO* not cleared)"
    );
    assert!(
        !csum_after_clear,
        "regression: tx-checksum-ip-generic still ON after offload=false attach \
         (device-wide TUN_F_CSUM not cleared)"
    );
    Ok(())
}
