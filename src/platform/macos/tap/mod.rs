#![expect(
    unsafe_code,
    reason = "macOS TAP support uses BPF/NDRV libc calls and raw interface structures"
)]

/*
link https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/sockio.h
link https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_fake.c
link https://www.zerotier.com/blog/how-zerotier-eliminated-kernel-extensions-on-macos/
 */
/*
* link https://github.com/zerotier/ZeroTierOne/blob/dev/osdep/MacEthernetTapAgent.c
*
* This creates a pair of feth devices with the lower numbered device
* being the virtual interface and the other being the device
* used to actually read and write packets. The latter gets no IP config
* and is only used for I/O. The behavior of feth is similar to the
* veth pairs that exist on Linux.
*
* The feth device has only existed since MacOS Sierra, but that's fairly
* long ago in Mac terms.
*
* I/O with feth must be done using two different sockets. The BPF socket
* is used to receive packets, while an AF_NDRV (low-level network driver
* access) socket must be used to inject. AF_NDRV can't read IP frames
* since BSD doesn't forward packets out the NDRV tap if they've already
* been handled, and while BPF can inject its MTU for injected packets
* is limited to 2048.
*
* All this stuff is basically undocumented. A lot of tracing through
* the Darwin/XNU kernel source was required to figure out how to make
* this actually work.
﻿
*
* See also:
*
* https://apple.stackexchange.com/questions/337715/fake-ethernet-interfaces-feth-if-fake-anyone-ever-seen-this
*
*/
use crate::builder::DeviceConfig;
use crate::platform::macos::sys::siocifcreate;
use crate::platform::unix::Fd;
#[cfg(any(feature = "async_tokio", feature = "async_io"))]
use bytes::buf::UninitSlice;
use bytes::BytesMut;
use libc::{ifreq, IFNAMSIZ};
use nix::errno::Errno;
use std::collections::VecDeque;
use std::ffi::CString;
use std::io;
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::sync::Mutex;

const FETH: &str = "feth";
const BUFFER_LEN: usize = 131_072;
const BPF_HDR_SIZE: usize = std::mem::size_of::<libc::bpf_hdr>();

#[inline]
fn next_bpf_step(bh_hdrlen: usize, bh_caplen: usize) -> Option<usize> {
    let step = (bh_hdrlen + bh_caplen + 3) & !3;
    (step >= BPF_HDR_SIZE).then_some(step)
}

pub(crate) fn run_command(command: &str, args: &[&str]) -> io::Result<()> {
    let out = std::process::Command::new(command).args(args).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("{command} failed with: \"{err}\"");
        return Err(io::Error::other(info));
    }
    Ok(())
}

pub struct Tap {
    s_bpf_fd: Fd,
    s_ndrv_fd: Fd,
    peer_feth: Feth,
    dev_feth: Feth,
    receive: Mutex<ReceiveState>,
}

struct ReceiveState {
    packets: VecDeque<BytesMut>,
    scratch: Vec<u8>,
}

impl Default for ReceiveState {
    fn default() -> Self {
        Self {
            packets: VecDeque::new(),
            scratch: vec![0; BUFFER_LEN],
        }
    }
}

struct Feth {
    is_drop: bool,
    name: String,
}
impl Drop for Feth {
    fn drop(&mut self) {
        if self.is_drop {
            _ = run_command("ifconfig", &[&self.name, "destroy"]);
            self.is_drop = false;
        }
    }
}
impl IntoRawFd for Tap {
    fn into_raw_fd(mut self) -> RawFd {
        self.peer_feth.is_drop = false;
        self.dev_feth.is_drop = false;
        self.s_bpf_fd.into_raw_fd()
    }
}
fn open_ndrv() -> io::Result<Fd> {
    // SAFETY: socket has no pointer arguments and returns a new descriptor or -1.
    let raw_fd = unsafe { libc::socket(libc::AF_NDRV, libc::SOCK_RAW, 0) };
    let fd = Fd::new(raw_fd)?;
    _ = fd.set_cloexec();
    Ok(fd)
}

fn ifreq_name(ifr: &ifreq) -> String {
    let bytes: Vec<u8> = ifr
        .ifr_name
        .iter()
        .copied()
        .take_while(|value| *value != 0)
        .map(i8::cast_unsigned)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn create_feth(
    ndrv: &Fd,
    requested_name: Option<&String>,
    reuse: bool,
    persist: bool,
) -> io::Result<(Feth, ifreq)> {
    let mut ifr = new_ifreq(requested_name)?;
    // SAFETY: ifr is a live writable C request object for the synchronous ioctl.
    if let Err(error) = unsafe { siocifcreate(ndrv.inner, &raw mut ifr) } {
        if error != Errno::EEXIST || !reuse {
            return Err(error.into());
        }
    }
    let feth = Feth {
        is_drop: !persist,
        name: ifreq_name(&ifr),
    };
    Ok((feth, ifr))
}

fn bind_ndrv(ndrv: &Fd, peer_name: &str) -> io::Result<()> {
    let sockaddr_size = size_of::<libc::sockaddr_ndrv>();
    let snd_len = u8::try_from(sockaddr_size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sockaddr_ndrv size exceeds u8"))?;
    let socklen = u32::try_from(sockaddr_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sockaddr_ndrv size exceeds socklen_t",
        )
    })?;
    let snd_family = u8::try_from(libc::AF_NDRV).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "AF_NDRV does not fit sockaddr family",
        )
    })?;

    // SAFETY: sockaddr_ndrv is a C POD address structure and zero is a valid
    // initial state before its fields are populated.
    let mut address: libc::sockaddr_ndrv = unsafe { std::mem::zeroed() };
    address.snd_len = snd_len;
    address.snd_family = snd_family;
    let name_bytes = peer_name.as_bytes();
    if name_bytes.len() >= address.snd_name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "peer interface name is too long for sockaddr_ndrv",
        ));
    }
    address.snd_name[..name_bytes.len()].copy_from_slice(name_bytes);

    // SAFETY: address is fully initialized, socklen matches its backing object,
    // and both syscalls borrow it only for the duration of the call.
    unsafe {
        let raw = (&raw const address).cast::<libc::sockaddr>();
        if libc::bind(ndrv.inner, raw, socklen) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::connect(ndrv.inner, raw, socklen) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn configure_bpf(peer_ifr: &mut ifreq) -> io::Result<Fd> {
    let bpf = open_bpf()?;
    let mut buffer_len = BUFFER_LEN;
    let mut enable = 1i32;
    let mut disable = 0i32;

    // SAFETY: each ioctl receives the live object type expected by the
    // corresponding Darwin BPF request and borrows it synchronously.
    unsafe {
        if libc::ioctl(bpf.inner, libc::BIOCSBLEN, &mut buffer_len) != 0
            || libc::ioctl(bpf.inner, libc::BIOCIMMEDIATE, &mut enable) != 0
            || libc::ioctl(bpf.inner, libc::BIOCSSEESENT, &mut disable) != 0
            || libc::ioctl(bpf.inner, libc::BIOCSETIF, peer_ifr) != 0
            || libc::ioctl(bpf.inner, libc::BIOCSHDRCMPLT, &mut enable) != 0
            || libc::ioctl(bpf.inner, u64::from(libc::BIOCPROMISC), &mut enable) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(bpf)
}

impl Tap {
    pub fn new(config: &DeviceConfig) -> io::Result<Tap> {
        let s_ndrv_fd = open_ndrv()?;
        let reuse = config.reuse_dev.unwrap_or(true);
        let persist = config.persist.unwrap_or(false);

        let (dev_feth, _) = create_feth(&s_ndrv_fd, config.dev_name.as_ref(), reuse, persist)?;
        std::thread::sleep(std::time::Duration::from_millis(1));

        let (peer_feth, mut peer_ifr) =
            create_feth(&s_ndrv_fd, config.peer_feth.as_ref(), reuse, persist)?;
        std::thread::sleep(std::time::Duration::from_millis(1));

        run_command("ifconfig", &[&peer_feth.name, "peer", &dev_feth.name])?;
        bind_ndrv(&s_ndrv_fd, &peer_feth.name)?;
        let s_bpf_fd = configure_bpf(&mut peer_ifr)?;

        Ok(Self {
            s_bpf_fd,
            s_ndrv_fd,
            dev_feth,
            peer_feth,
            receive: Mutex::new(ReceiveState::default()),
        })
    }
    // pub fn as_s_ndrv_fd(&self) -> RawFd {
    //     self.s_ndrv_fd.as_raw_fd()
    // }
    // pub fn as_s_bpf_fd(&self) -> RawFd {
    //     self.s_bpf_fd.as_raw_fd()
    // }
    pub fn name(&self) -> &String {
        &self.dev_feth.name
    }
    pub fn peer_name(&self) -> &String {
        &self.peer_feth.name
    }
    pub fn is_nonblocking(&self) -> io::Result<bool> {
        self.s_bpf_fd.is_nonblocking()
    }
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.s_bpf_fd.set_nonblocking(nonblocking)?;
        self.s_ndrv_fd.set_nonblocking(nonblocking)?;
        Ok(())
    }
    #[inline]
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.s_ndrv_fd.write(buf)
    }
    #[inline]
    pub fn send_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.s_ndrv_fd.writev(bufs)
    }
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .receive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.packets.is_empty() {
            self.recv_to_buffer(&mut guard)?;
        }

        let Some(buffer) = guard.packets.pop_front() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "recv buffer is empty",
            ));
        };
        if buf.len() < buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small",
            ));
        }
        buf[..buffer.len()].copy_from_slice(&buffer);
        Ok(buffer.len())
    }
    #[cfg(any(feature = "async_tokio", feature = "async_io"))]
    pub fn recv_uninit(&self, buf: &mut UninitSlice) -> io::Result<usize> {
        let mut guard = self
            .receive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.packets.is_empty() {
            self.recv_to_buffer(&mut guard)?;
        }

        let Some(buffer) = guard.packets.pop_front() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "recv buffer is empty",
            ));
        };
        if buf.len() < buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small",
            ));
        }
        // SAFETY: the destination length was checked above, buffer contains
        // initialized bytes, and the independent allocations cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(buffer.as_ptr(), buf.as_mut_ptr(), buffer.len());
        }
        Ok(buffer.len())
    }
    fn recv_to_buffer(&self, state: &mut ReceiveState) -> io::Result<()> {
        let ReceiveState { packets, scratch } = state;
        let len = self.s_bpf_fd.read(scratch.as_mut_slice())?;
        if len > 0 {
            let buffer = &scratch[..len];
            let mut p = 0;
            while p < len {
                let remaining_bytes = len - p;
                if remaining_bytes < BPF_HDR_SIZE {
                    break;
                }
                // SAFETY: read_unaligned handles byte-buffer alignment, and p is
                // bounded so at least a complete bpf_hdr remains before this read.
                let hdr: libc::bpf_hdr = unsafe {
                    std::ptr::read_unaligned(buffer.as_ptr().add(p).cast::<libc::bpf_hdr>())
                };
                let bh_caplen = hdr.bh_caplen as usize;
                let bh_hdrlen = hdr.bh_hdrlen as usize;
                if bh_caplen > 0 && p + bh_hdrlen + bh_caplen <= len {
                    let packet = &buffer[p + bh_hdrlen..p + bh_hdrlen + bh_caplen];
                    packets.push_back(packet.into());
                }
                let Some(step) = next_bpf_step(bh_hdrlen, bh_caplen) else {
                    break;
                };
                p += step;
            }
        }
        Ok(())
    }

    pub fn recv_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let mut guard = self
            .receive
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.packets.is_empty() {
            self.recv_to_buffer(&mut guard)?;
        }

        let Some(buf) = guard.packets.pop_front() else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "recv buffer is empty",
            ));
        };
        let len: usize = bufs.iter().map(|v| v.len()).sum();
        if len < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small",
            ));
        }
        let mut pos = 0;
        for b in bufs {
            let n = b.len().min(buf.len() - pos);
            if n == 0 {
                break;
            }
            b[..n].copy_from_slice(&buf[pos..pos + n]);
            pos += n;
            if pos == buf.len() {
                break;
            }
        }
        Ok(pos)
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn read_interruptible(
        &self,
        buf: &mut [u8],
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<usize> {
        loop {
            self.wait_readable_interruptible(event, timeout)?;
            match self.recv(buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                rs => return rs,
            }
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
        loop {
            self.wait_readable_interruptible(event, timeout)?;
            match self.recv_vectored(bufs) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                rs => return rs,
            }
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn wait_readable_interruptible(
        &self,
        event: &crate::InterruptEvent,
        timeout: Option<std::time::Duration>,
    ) -> io::Result<()> {
        self.s_bpf_fd.wait_readable(Some(event), timeout)
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn write_interruptible(
        &self,
        buf: &[u8],
        event: &crate::InterruptEvent,
    ) -> io::Result<usize> {
        loop {
            self.wait_writable_interruptible(event)?;
            return match self.s_ndrv_fd.write(buf) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                rs => rs,
            };
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn writev_interruptible(
        &self,
        bufs: &[IoSlice<'_>],
        event: &crate::InterruptEvent,
    ) -> io::Result<usize> {
        loop {
            self.wait_writable_interruptible(event)?;
            return match self.s_ndrv_fd.writev(bufs) {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    continue;
                }
                rs => rs,
            };
        }
    }
    #[cfg(feature = "interruptible")]
    #[inline]
    pub(crate) fn wait_writable_interruptible(
        &self,
        event: &crate::InterruptEvent,
    ) -> io::Result<()> {
        self.s_ndrv_fd.wait_writable(Some(event), None)
    }
}
impl AsRawFd for Tap {
    fn as_raw_fd(&self) -> RawFd {
        self.s_bpf_fd.as_raw_fd()
    }
}

fn open_bpf() -> io::Result<Fd> {
    for i in 1..5000 {
        let path = CString::new(format!("/dev/bpf{i}").into_bytes())?;
        // SAFETY: path is a live NUL-terminated CString; open returns a new descriptor or -1.
        let bpf_fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        match Fd::new(bpf_fd) {
            Ok(fd) => {
                _ = fd.set_cloexec();
                return Ok(fd);
            }
            Err(e) => {
                if e.raw_os_error() == Some(libc::EBUSY) {
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No available /dev/bpf",
    ))
}
fn new_ifreq(name: Option<&String>) -> io::Result<ifreq> {
    if let Some(name) = name {
        new_ifreq_str(name.as_str())
    } else {
        new_ifreq_str(FETH)
    }
}
fn new_ifreq_str(name: &str) -> io::Result<ifreq> {
    let bytes = name.as_bytes();
    if bytes.len() >= IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
    }
    if bytes.len() < 4 || &bytes[..4] != FETH.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The prefix of the network card name must be 'feth'",
        ));
    }
    // SAFETY: ifreq is a C POD request structure; zero is a valid initial state.
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    for (i, &b) in bytes.iter().enumerate() {
        ifr.ifr_name[i] = b.cast_signed();
    }
    ifr.ifr_name[bytes.len()] = 0;
    Ok(ifr)
}
