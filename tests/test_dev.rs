#![expect(
    unused_imports,
    reason = "privileged integration-test imports vary by target and async runtime"
)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;

use pnet_packet::ip::IpNextHeaderProtocols;
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
use tun_rs::SyncDevice;

#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
const TEST_IPV4_LOCAL: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 26, 1, 100);
#[cfg(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
const TEST_IPV4_REMOTE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 26, 1, 101);

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
fn test_udp_v4() -> TestResult {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv4(TEST_IPV4_LOCAL, 24, None)
        .build_sync()?;
    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v4 = Arc::new(AtomicBool::new(false));
    let test_udp_v4_c = test_udp_v4.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok(len) = device.recv(&mut buf) else {
                return;
            };
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
    std::thread::sleep(Duration::from_secs(6));
    let udp_socket = std::net::UdpSocket::bind((TEST_IPV4_LOCAL, 0))?;
    udp_socket.send_to(test_msg.as_bytes(), (TEST_IPV4_REMOTE, 8080))?;
    let time_now = std::time::Instant::now();
    // check whether the thread completes
    while !recv_flag_c.load(Ordering::Acquire) {
        if time_now.elapsed().as_secs() > 2 {
            // no promise due to the timeout
            let v4 = test_udp_v4_c.load(Ordering::Relaxed);
            assert!(v4, "timeout: test_udp_v4 = {v4}");
            return Ok(());
        }
    }
    // recv_flag_c == true
    // all modifications to test_udp_v4_c must be visible
    let v4 = test_udp_v4_c.load(Ordering::Relaxed);
    assert!(v4);
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
fn test_udp_v6() -> TestResult {
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
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok(len) = device.recv(&mut buf) else {
                return;
            };
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
            assert!(v6, "timeout: test_udp_v6 = {v6}");
            return Ok(());
        }
    }
    // recv_flag_c == true
    // all modifications to test_udp_v6_c must be visible
    let v6 = test_udp_v6_c.load(Ordering::Relaxed);
    assert!(v6);
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
async fn test_udp_v4() -> TestResult {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv4(TEST_IPV4_LOCAL, 24, None)
        .build_async()?;

    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v4 = Arc::new(AtomicBool::new(false));
    let test_udp_v4_c = test_udp_v4.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    let mut handler = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok(len) = device.recv(&mut buf).await else {
                return;
            };
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

    let udp_socket = tokio::net::UdpSocket::bind((TEST_IPV4_LOCAL, 0)).await?;
    udp_socket
        .send_to(test_msg.as_bytes(), (TEST_IPV4_REMOTE, 8080))
        .await?;
    tokio::select! {
        ()=tokio::time::sleep(Duration::from_secs(2))=>{
            handler.abort();
            let _ = handler.await;
            let v4 = test_udp_v4_c.load(Ordering::Relaxed);
            assert!(v4, "timeout: test_udp_v4 = {v4}");
        }
        _=&mut handler=>{
            // all modifications to test_udp_v4_c must be visible
            let flag = recv_flag_c.load(Ordering::Acquire); //synchronize
            assert!(flag, "recv_flag = {flag}");
            let v4 = test_udp_v4_c.load(Ordering::Relaxed);
            assert!(v4);
        }
    }
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
async fn test_udp_v6() -> TestResult {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv6("fd12:3456:789a:1111:2222:3333:4444:5555", 64)
        .build_async()?;

    let device = Arc::new(device);
    let _device = device.clone();
    let test_udp_v6 = Arc::new(AtomicBool::new(false));
    let test_udp_v6_c = test_udp_v6.clone();
    let recv_flag = Arc::new(AtomicBool::new(false));
    let recv_flag_c = recv_flag.clone();
    let mut handler = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok(len) = device.recv(&mut buf).await else {
                return;
            };
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
    let udp_socket =
        tokio::net::UdpSocket::bind("[fd12:3456:789a:1111:2222:3333:4444:5555]:0").await?;
    udp_socket
        .send_to(
            test_msg.as_bytes(),
            "[fd12:3456:789a:1111:2222:3333:4444:5556]:8080",
        )
        .await?;

    tokio::select! {
        ()=tokio::time::sleep(Duration::from_secs(2))=>{
            handler.abort();
            let _ = handler.await;
            let v6 = test_udp_v6_c.load(Ordering::Relaxed);
            assert!(v6, "timeout: test_udp_v6 = {v6}");
        }
        _=&mut handler=>{
            // all modifications to test_udp_v6_c must be visible
            let flag = recv_flag_c.load(Ordering::Acquire); //synchronize
            assert!(flag, "recv_flag = {flag}");
            let v6 = test_udp_v6_c.load(Ordering::Relaxed);
            assert!(v6 );
        }
    }
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
#[cfg(feature = "async_io")]
#[async_std::test]
async fn test_async_io_udp_v4() -> TestResult {
    let test_msg = "test udp";
    let device = DeviceBuilder::new()
        .ipv4(TEST_IPV4_LOCAL, 24, None)
        .build_async()?;

    let sender = async_std::task::spawn(async move {
        async_std::task::sleep(Duration::from_secs(6)).await;
        let udp_socket = async_std::net::UdpSocket::bind((TEST_IPV4_LOCAL, 0)).await?;
        udp_socket
            .send_to(test_msg.as_bytes(), (TEST_IPV4_REMOTE, 8080))
            .await?;
        Ok::<(), std::io::Error>(())
    });

    let received = async_std::future::timeout(Duration::from_secs(8), async {
        let mut buf = vec![0u8; 65_535];
        loop {
            let len = device.recv(&mut buf).await?;
            let Some(ipv4_packet) = pnet_packet::ipv4::Ipv4Packet::new(&buf[..len]) else {
                continue;
            };
            if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
                continue;
            }
            let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(ipv4_packet.payload()) else {
                continue;
            };
            if udp_packet.payload() == test_msg.as_bytes() {
                return Ok::<(), std::io::Error>(());
            }
        }
    })
    .await;
    sender.await?;
    received.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "async-io IPv4 receive timed out",
        )
    })??;
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
#[cfg(feature = "async_io")]
#[async_std::test]
async fn test_async_io_udp_v6() -> TestResult {
    let test_msg = "test udp";
    let local = "fd12:3456:789a:1111:2222:3333:4444:5555";
    let remote = "fd12:3456:789a:1111:2222:3333:4444:5556";
    let device = DeviceBuilder::new().ipv6(local, 64).build_async()?;
    let local_socket = format!("[{local}]:0");
    let remote_socket = format!("[{remote}]:8080");

    let sender = async_std::task::spawn(async move {
        async_std::task::sleep(Duration::from_secs(6)).await;
        let udp_socket = async_std::net::UdpSocket::bind(local_socket).await?;
        udp_socket
            .send_to(test_msg.as_bytes(), remote_socket)
            .await?;
        Ok::<(), std::io::Error>(())
    });

    let received = async_std::future::timeout(Duration::from_secs(8), async {
        let mut buf = vec![0u8; 65_535];
        loop {
            let len = device.recv(&mut buf).await?;
            let Some(ipv6_packet) = pnet_packet::ipv6::Ipv6Packet::new(&buf[..len]) else {
                continue;
            };
            if ipv6_packet.get_next_header() != IpNextHeaderProtocols::Udp {
                continue;
            }
            let Some(udp_packet) = pnet_packet::udp::UdpPacket::new(ipv6_packet.payload()) else {
                continue;
            };
            if udp_packet.payload() == test_msg.as_bytes() {
                return Ok::<(), std::io::Error>(());
            }
        }
    })
    .await;
    sender.await?;
    received.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "async-io IPv6 receive timed out",
        )
    })??;
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
fn test_op() -> TestResult {
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

    let vec = device.addresses()?;
    assert!(vec.contains(&"10.26.2.100".parse::<std::net::IpAddr>()?));
    assert!(vec.contains(&"fd12:3456:789a:5555:2222:3333:4444:5555".parse::<std::net::IpAddr>()?));

    device.set_network_address("10.26.3.200", 24, None)?;
    let vec = device.addresses()?;
    assert!(vec.contains(&"10.26.3.200".parse::<std::net::IpAddr>()?));
    assert!(vec.contains(&"fd12:3456:789a:5555:2222:3333:4444:5555".parse::<std::net::IpAddr>()?));
    assert!(!vec.contains(&"10.26.2.100".parse::<std::net::IpAddr>()?));

    device.add_address_v4("10.6.0.1", 24)?;
    let vec = device.addresses()?;
    assert!(vec.contains(&"10.6.0.1".parse::<std::net::IpAddr>()?));
    assert!(vec.contains(&"10.26.3.200".parse::<std::net::IpAddr>()?));

    device.remove_address("10.6.0.1".parse::<std::net::IpAddr>()?)?;
    let vec = device.addresses()?;
    assert!(!vec.contains(&"10.6.0.1".parse::<std::net::IpAddr>()?));
    assert!(vec.contains(&"10.26.3.200".parse::<std::net::IpAddr>()?));

    device.add_address_v6("fdab:cdef:1234:5678:9abc:def0:1234:5678", 64)?;
    let vec = device.addresses()?;
    assert!(vec.contains(&"fdab:cdef:1234:5678:9abc:def0:1234:5678".parse::<std::net::IpAddr>()?));

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
        device.set_metric(100)?;

        // `set_dns_servers` -> SetInterfaceDnsSettings (resolved at run time) with a
        // netsh fallback. Exercise IPv4 (primary + secondary) and IPv6, then clear both.
        let v4_dns: [std::net::IpAddr; 2] = ["8.8.8.8".parse()?, "8.8.4.4".parse()?];
        device.set_dns_servers(&v4_dns)?;
        let v6_dns: [std::net::IpAddr; 1] = ["2001:4860:4860::8888".parse()?];
        device.set_dns_servers(&v6_dns)?;
        device.clear_dns_servers(true)?;
        device.clear_dns_servers(false)?;
    }

    #[cfg(unix)]
    {
        device.set_nonblocking(true)?;
        assert!(device.is_nonblocking()?);
        device.set_nonblocking(false)?;
        assert!(!device.is_nonblocking()?);
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
#[cfg_attr(
    unix,
    expect(
        unsafe_code,
        reason = "this test verifies the explicit raw-fd ownership-transfer constructor"
    )
)]
fn create_tun() -> TestResult {
    #[cfg(not(target_os = "macos"))]
    let name = "tun12";
    #[cfg(target_os = "macos")]
    let name = "utun12";

    let device = DeviceBuilder::new().name(name).build_sync()?;
    let dev_name = device.name()?;
    assert_eq!(dev_name.as_str(), name);
    #[cfg(unix)]
    {
        use std::os::fd::IntoRawFd;
        let fd = device.into_raw_fd();
        // SAFETY: IntoRawFd transfers ownership of the still-open TUN/TAP descriptor;
        // SyncDevice::from_fd immediately takes over that ownership.
        unsafe {
            let sync_device = SyncDevice::from_fd(fd)?;
            let dev_name = sync_device.name()?;
            assert_eq!(dev_name, name);
        }
    }
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
#[cfg_attr(
    all(unix, not(target_os = "macos")),
    expect(
        unsafe_code,
        reason = "this test verifies the explicit raw-fd ownership-transfer constructor"
    )
)]
fn create_tap() -> TestResult {
    #[cfg(not(target_os = "macos"))]
    let name = "tap12";
    #[cfg(target_os = "macos")]
    let name = "feth12";

    let device_result = DeviceBuilder::new()
        .name(name)
        .layer(tun_rs::Layer::L2)
        .build_sync();
    #[cfg(target_os = "windows")]
    let device = match device_result {
        Ok(device) => device,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && error.to_string() == "No driver found" =>
        {
            // TAP-Windows is an external prerequisite. Its absence is a valid
            // environment state; the backend must report that state explicitly.
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    #[cfg(not(target_os = "windows"))]
    let device = device_result?;
    let dev_name = device.name()?;
    assert_eq!(dev_name.as_str(), name);
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::fd::IntoRawFd;
        let fd = device.into_raw_fd();
        // SAFETY: IntoRawFd transfers ownership of the still-open TUN/TAP descriptor;
        // SyncDevice::from_fd immediately takes over that ownership.
        unsafe {
            let sync_device = SyncDevice::from_fd(fd)?;
            let dev_name = sync_device.name()?;
            assert_eq!(dev_name, name);
        }
    }
    Ok(())
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    )
))]
#[test]
#[expect(
    unsafe_code,
    reason = "the test exercises the public borrowed raw-fd constructor while an owning SyncDevice keeps the descriptor alive"
)]
fn borrowed_sync_device_does_not_take_fd_ownership() -> TestResult {
    use std::os::fd::AsRawFd;
    use tun_rs::BorrowedSyncDevice;

    let device = DeviceBuilder::new().build_sync()?;
    let name = device.name()?;
    let raw_fd = device.as_raw_fd();

    // SAFETY: device owns raw_fd and remains alive until after the borrowed wrapper is dropped.
    let borrowed = unsafe { BorrowedSyncDevice::borrow_raw(raw_fd)? };
    assert_eq!(borrowed.name()?, name);
    drop(borrowed);

    // Dropping the borrowed wrapper must leave the original owner usable.
    assert_eq!(device.name()?, name);
    Ok(())
}

#[cfg(target_os = "netbsd")]
#[test]
fn netbsd_tun_mtu_matches_kernel_limits() -> TestResult {
    let device = DeviceBuilder::new().build_sync()?;

    device.set_mtu(576)?;
    assert_eq!(device.mtu()?, 576);
    assert!(device.set_mtu(575).is_err());

    device.set_mtu(1500)?;
    assert_eq!(device.mtu()?, 1500);
    assert!(device.set_mtu(1501).is_err());
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[test]
fn linux_multiqueue_clone_preserves_device_identity() -> TestResult {
    let device = DeviceBuilder::new().multi_queue(true).build_sync()?;
    let clone = device.try_clone()?;
    assert_eq!(clone.name()?, device.name()?);
    assert_eq!(clone.if_index()?, device.if_index()?);
    Ok(())
}

#[cfg(all(
    feature = "interruptible",
    unix,
    any(
        target_os = "macos",
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
    )
))]
#[test]
fn sync_interruptible_receive_forwards_interrupt() -> TestResult {
    use tun_rs::InterruptEvent;

    let device = DeviceBuilder::new().build_sync()?;
    let event = InterruptEvent::new()?;
    let mut buf = [0u8; 64];

    event.trigger_value(42)?;
    let interrupted = device
        .recv_intr_timeout(&mut buf, &event, Some(Duration::from_secs(1)))
        .err()
        .ok_or_else(|| std::io::Error::other("triggered receive was not interrupted"))?;
    assert_eq!(interrupted.kind(), std::io::ErrorKind::Interrupted);
    assert_eq!(event.value(), 42);

    Ok(())
}

/// Dedicated Windows test covering every public API migrated from netsh/wmic to
/// windows-sys in PR `#140`.  Each section is labelled with the underlying Windows
/// API that was newly wired up.
#[cfg(target_os = "windows")]
#[test]
#[expect(
    unsafe_code,
    reason = "reading NET_LUID_LH.Value exercises the Windows union returned by the public API"
)]
fn test_windows_new_apis() -> TestResult {
    use std::net::IpAddr;
    use tun_rs::DeviceBuilder;

    let device = DeviceBuilder::new()
        .ipv4("10.26.9.100", 24, None)
        .ipv6("fd12:3456:789a:9999:2222:3333:4444:5555", 64)
        .build_sync()?;

    // ── 1. if_luid() ─────────────────────────────────────────────────────────
    // New public API; a valid adapter LUID is never zero.
    let luid = device.if_luid()?;
    let luid_value = unsafe { luid.Value };
    assert_ne!(luid_value, 0, "LUID must be non-zero for a live adapter");

    // ── 2. set_metric() ──────────────────────────────────────────────────────
    // Now uses GetIpInterfaceEntry / SetIpInterfaceEntry for both AF_INET and
    // AF_INET6.  No public read-back getter exists, so we assert the call
    // succeeds for two different values (exercises the full round-trip twice).
    device.set_metric(50)?;
    device.set_metric(100)?;

    // ── 3. set_mtu / mtu (IPv4) ──────────────────────────────────────────────
    // Now uses SetIpInterfaceEntry with NlMtu; read back via GetIpInterfaceTable.
    device.set_mtu(1400)?;
    assert_eq!(
        device.mtu()?,
        1400,
        "mtu() read-back should match the value written by set_mtu()"
    );

    // ── 4. set_mtu_v6 / mtu_v6 (IPv6) ───────────────────────────────────────
    // Same path but with is_v4=false; mtu_v6() reads back via GetIpInterfaceTable
    // with AF_INET6.
    device.set_mtu_v6(1380)?;
    assert_eq!(
        device.mtu_v6()?,
        1380,
        "mtu_v6() read-back should match the value written by set_mtu_v6()"
    );

    // ── 5. set_network_address without gateway ───────────────────────────────
    // ffi::set_address clears all existing IPv4 unicast addresses and installs
    // the new one.  The old address must disappear.
    device.set_network_address("10.26.9.200", 24, None)?;
    let addrs = device.addresses()?;
    assert!(
        addrs.contains(&"10.26.9.200".parse::<IpAddr>()?),
        "new address 10.26.9.200 should be present after set_network_address"
    );
    assert!(
        !addrs.contains(&"10.26.9.100".parse::<IpAddr>()?),
        "old address 10.26.9.100 should have been removed by set_network_address"
    );

    // ── 6. set_network_address WITH gateway ──────────────────────────────────
    // Exercises the default-route creation path in ffi::add_address that was
    // specifically fixed in this PR (DestinationPrefix address family +
    // SitePrefixLength=0 for CreateIpForwardEntry2).
    device.set_network_address("10.26.9.150", 24, Some("10.26.9.1"))?;
    let addrs = device.addresses()?;
    assert!(
        addrs.contains(&"10.26.9.150".parse::<IpAddr>()?),
        "address 10.26.9.150 should be present after set_network_address with gateway"
    );
    assert!(
        !addrs.contains(&"10.26.9.200".parse::<IpAddr>()?),
        "previous address 10.26.9.200 should have been cleared"
    );

    // ── 7. add_address_v6 ────────────────────────────────────────────────────
    // ffi::add_address with None gateway; verifies the address appears in the
    // interface's address list.
    device.add_address_v6("fdab:cdef:1234:5678:9abc:def0:1234:0001", 64)?;
    let addrs = device.addresses()?;
    assert!(
        addrs.contains(&"fdab:cdef:1234:5678:9abc:def0:1234:0001".parse::<IpAddr>()?),
        "IPv6 address should be present after add_address_v6"
    );

    // ── 8. remove_address (IPv6) ─────────────────────────────────────────────
    // ffi::remove_address; confirms the address is gone after deletion.
    device.remove_address("fdab:cdef:1234:5678:9abc:def0:1234:0001".parse::<IpAddr>()?)?;
    let addrs = device.addresses()?;
    assert!(
        !addrs.contains(&"fdab:cdef:1234:5678:9abc:def0:1234:0001".parse::<IpAddr>()?),
        "IPv6 address should be absent after remove_address"
    );

    // ── 9. set_dns_servers (IPv4) ────────────────────────────────────────────
    // dns::set_dns_servers → SetInterfaceDnsSettings (or netsh fallback).
    let ipv4_dns: &[IpAddr] = &["8.8.8.8".parse()?, "8.8.4.4".parse()?];
    device.set_dns_servers(ipv4_dns)?;

    // ── 10. set_dns_servers (IPv6) ───────────────────────────────────────────
    let ipv6_dns: &[IpAddr] = &["2001:4860:4860::8888".parse()?];
    device.set_dns_servers(ipv6_dns)?;

    // ── 11. set_dns_servers — validation: empty list must be rejected ────────
    assert!(
        device.set_dns_servers(&[]).is_err(),
        "set_dns_servers with an empty slice must return Err (InvalidInput)"
    );

    // ── 12. set_dns_servers — validation: mixed families must be rejected ────
    let mixed: &[IpAddr] = &["8.8.8.8".parse()?, "2001:4860:4860::8888".parse()?];
    assert!(
        device.set_dns_servers(mixed).is_err(),
        "set_dns_servers with mixed IPv4/IPv6 addresses must return Err (InvalidInput)"
    );

    // ── 13. clear_dns_servers ────────────────────────────────────────────────
    // dns::clear_dns_servers → SetInterfaceDnsSettings with empty NameServer
    // (or netsh fallback).
    device.clear_dns_servers(true)?;
    device.clear_dns_servers(false)?;
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
/// `cargo test --test test_dev -- --ignored offload_mask_cleared`
#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[cfg(not(any(feature = "async_tokio", feature = "async_io")))]
#[test]
#[ignore = "requires CAP_NET_ADMIN, ethtool, and persistent TUN support"]
fn test_offload_mask_cleared_on_reattach_without_offload() -> TestResult {
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
        stdout
            .lines()
            .find_map(|line| {
                let trimmed = line.trim();
                let value = trimmed.strip_prefix(feature)?.strip_prefix(':')?.trim();
                if value.starts_with("on") {
                    Some(true)
                } else if value.starts_with("off") {
                    Some(false)
                } else {
                    None
                }
            })
            .ok_or_else(|| std::io::Error::other("requested ethtool feature was not found"))
    }

    struct TunCleanup(&'static str);
    impl Drop for TunCleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "delete", self.0]).status();
        }
    }

    // Clean any leftover device from a previous failed run. Ignore errors.
    let _ = Command::new("ip").args(["link", "delete", NAME]).status();
    let _cleanup = TunCleanup(NAME);

    // ── Attach #1: offload=true, persisted ──────────────────────────────
    // Raises the device-wide TUN_F_* mask via TUNSETOFFLOAD.
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
