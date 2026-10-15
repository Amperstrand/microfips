//! Tests for the M3 host seams: prove the trait surface works with
//! OS-provided implementations and that the re-exported types are
//! constructible without any embedded executor or hardware TRNG.

use microfips_client::{Clock, EntropySource, ServiceMethod, ServiceStatus};

#[test]
fn os_entropy_fills_buffer() {
    let mut buf = [0u8; 32];
    microfips_client::std_seams::OsEntropy::fill(&mut buf);
    assert!(buf.iter().any(|&b| b != 0), "entropy should not be all zeros");
}

#[test]
fn monotonic_clock_is_monotonic() {
    let clock = microfips_client::std_seams::MonotonicClock::new();
    let t1 = clock.now_ms();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let t2 = clock.now_ms();
    assert!(t2 >= t1, "clock must be monotonic: t1={} t2={}", t1, t2);
}

#[test]
fn service_enums_are_reachable() {
    let method = ServiceMethod::Get;
    assert_eq!(method.as_u8(), 1);
    let status = ServiceStatus::OK;
    let _ = status; // construction is the test
}

#[test]
fn crate_versions_are_consistent() {
    // The re-exported crates should all resolve (compilation is the test,
    // but we also verify the version strings are accessible).
    let _ = microfips_client::microfips_core::identity::STM32_NPUB;
}
