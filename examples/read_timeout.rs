#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
use std::sync::Arc;
use std::time::Duration;
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
use tun_rs::DeviceBuilder;
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd",
    target_os = "netbsd",
))]
use tun_rs::InterruptEvent;
fn main() -> Result<(), std::io::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();
    let (tx, rx) = std::sync::mpsc::channel();

    let handle = ctrlc2::set_handler(move || {
        let _ = tx.send(());
        true
    })
    .map_err(|error| std::io::Error::other(error.to_string()))?;

    main_entry(&rx)?;
    handle
        .join()
        .map_err(|_| std::io::Error::other("Ctrl-C handler thread panicked"))?;
    Ok(())
}
#[cfg(any(
    target_os = "ios",
    target_os = "tvos",
    target_os = "android",
    all(target_os = "linux", target_env = "ohos")
))]
fn main_entry(_quit: &Receiver<()>) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this example requires native TUN/TAP device creation",
    ))
}
#[cfg(any(
    target_os = "windows",
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
))]
fn main_entry(quit: &Receiver<()>) -> Result<(), std::io::Error> {
    let dev = DeviceBuilder::new()
        .ipv4(Ipv4Addr::new(10, 0, 0, 12), 24, None)
        .mtu(1400)
        .build_sync()?;

    println!("if_index = {:?}", dev.if_index());
    #[cfg(unix)]
    dev.set_nonblocking(true)?;

    let event = Arc::new(InterruptEvent::new()?);
    let event_clone = event.clone();
    let join = std::thread::spawn(move || -> std::io::Result<()> {
        let mut buf = [0; 4096];
        loop {
            match dev.recv_intr_timeout(&mut buf, &event_clone, Some(Duration::from_millis(1000))) {
                Ok(len) => {
                    println!("recv_intr_timeout Ok({len})");
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    println!("read_interruptible Err({e:?})");
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    // If the interrupt event is to be reused, it must be reset before the next wait.
                    if event_clone.is_trigger() {
                        event_clone.reset()?;
                        println!("read_interruptible Err({e:?})");
                    }
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
    });
    _ = quit.recv();
    std::thread::sleep(Duration::from_millis(100));
    event.trigger()?;
    let thread_result = join
        .join()
        .map_err(|_| std::io::Error::other("reader thread panicked"))?;
    thread_result?;
    Ok(())
}
