# Test specification map

The test suite treats the crate's public API documentation, feature contracts, and platform behavior as the specification. Tests are layered so pure logic is fast and deterministic, while kernel/device behavior is exercised only where the required OS facilities exist.

| Specification area | Executable evidence | CI tier |
| --- | --- | --- |
| Address and netmask conversion, all valid prefix lengths, invalid/non-contiguous masks | `builder::tests` | Every Linux PR; native release platforms |
| Builder defaults, last-write/accumulation semantics, `with` guard | `builder::tests` | Every Linux PR; native release platforms |
| Documentation examples and public signatures | doctests in default, Tokio, async-io matrices | Every Linux PR |
| Mutually exclusive async runtimes | `Async runtime exclusivity contract` workflow step checks the expected compile error | Every Linux PR |
| Bytes framing, EOF behavior, buffer sizing and growth contracts | `async_device::async_framed::tests` | Tokio and async-io matrices |
| POSIX descriptor ownership and scatter/gather I/O | `platform::unix::fd::tests` | Every Unix native unit run |
| Interrupt event state, timeout, readiness, blocked-write cancellation | `platform::unix::interrupt::tests` | `interruptible` feature matrices |
| Sockaddr conversions and raw-storage provenance | ordinary unit tests plus `miri_...` tests | Every Linux PR |
| Virtio header ABI, GRO classification, GRO coalescing, GSO rejection and successful TCP/UDP segmentation | `platform::linux::offload::tests` | Every Linux PR |
| Sync TUN IPv4/IPv6 packet reception and device configuration/readback | `tests/test_dev.rs` under sudo | Every Linux PR |
| Tokio TUN IPv4/IPv6 packet reception | `tests/test_dev.rs` under sudo | Every Linux PR |
| async-io TUN IPv4/IPv6 packet reception | `tests/test_dev.rs` under sudo | Every Linux PR |
| Raw-FD ownership transfer and borrowed-FD lifetime | `create_tun`, `create_tap`, `borrowed_sync_device_does_not_take_fd_ownership` | Every Linux PR; applicable native platforms on release |
| Nonblocking mode and SyncDevice interrupt/timeout forwarding | `test_op`, `sync_interruptible_wait_distinguishes_interrupt_and_timeout` | Every Linux PR |
| Linux multi-queue clone identity | `linux_multiqueue_clone_preserves_device_identity` | Every Linux PR |
| Linux persistent-device offload reset | `test_offload_mask_cleared_on_reattach_without_offload` | Every Linux PR, dedicated privileged ignored-test invocation |
| Windows/macOS native library behavior | normal `build_n_test` matrix | Release tags |
| FreeBSD pure library behavior | `build_n_test_freebsd` native VM unit matrices | Release tags |
| NetBSD, Android, iOS, tvOS, OpenHarmony build compatibility | cross-target compile jobs | Release tags |

Performance claims are benchmark concerns, not correctness assertions; correctness tests check packet contents and invariants rather than timing. Hardware/driver availability and OS routing policy are not mocked as if they were kernel behavior: privileged/native integration tests cover those boundaries where CI provides the real platform.
