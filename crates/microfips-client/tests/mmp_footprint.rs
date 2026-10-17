//! #234 footprint canary: the facade's `mmp` opt-in must be the only
//! path that compiles the MMP layer for facade consumers.
//!
//! Compile-time probes, not runtime asserts — the whole point is WHAT
//! RESOLVES. With `--features mmp` the protocol's mmp module must be
//! reachable through the facade (the feature genuinely activates it);
//! this file's second half proves the inverse by NOT compiling against
//! the gated path when the feature is off — the `#[cfg]` pair means a
//! feature-graph regression (mmp leaking back in via dependency
//! defaults) fails here as a missing-symbol/unused-probe error only if
//! the leak re-adds the module, and the canary script
//! (scripts/check-mmp-footprint.sh) asserts the resolution-level
//! difference with `cargo metadata`, which — unlike `cargo tree
//! --features` from a workspace root (observed silently ignoring the
//! flag, 2026-10-16) — is deterministic about the feature set it was
//! asked to resolve.

#[cfg(feature = "mmp")]
#[test]
fn mmp_opt_in_reaches_the_protocol_layer() {
    // protocol::mmp is #[cfg(feature = "mmp")]-gated; this path only
    // compiles when the facade's mmp feature genuinely activated the
    // protocol's. Reachability IS the assertion.
    use microfips_client::microfips_protocol::mmp::MmpMetrics;
    let _metrics = MmpMetrics::default();
}

#[cfg(not(feature = "mmp"))]
#[test]
fn mmp_off_still_builds_the_full_facade_surface() {
    // The no-mmp build must keep the whole advertised facade surface
    // (Node, Transport, service types, seams) — mmp-off reduces
    // footprint, not API. A leak in the other direction (mmp becoming
    // REQUIRED) fails here; the footprint side is asserted by
    // scripts/check-mmp-footprint.sh at the resolution level.
    use microfips_client::{EntropySource, Node, Transport};

    struct E;
    impl EntropySource for E {
        fn fill(dest: &mut [u8]) {
            dest.fill(1);
        }
    }

    struct NoTransport;
    impl Transport for NoTransport {
        type Error = core::fmt::Error;
        async fn wait_ready(&mut self) -> Result<(), Self::Error> {
            core::future::pending().await
        }
        async fn send(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
            Err(core::fmt::Error)
        }
        async fn recv(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
            core::future::pending().await
        }
    }

    // Minimal local RNG through the protocol's re-exported rand_core
    // traits — keeps this probe independent of facade adapter additions.
    use microfips_client::microfips_protocol::transport::{CryptoRng, RngCore};
    struct LocalRng;
    impl RngCore for LocalRng {
        fn next_u32(&mut self) -> u32 {
            7
        }
        fn next_u64(&mut self) -> u64 {
            7
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            E::fill(dst)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
            E::fill(dst);
            Ok(())
        }
    }
    impl CryptoRng for LocalRng {}

    let _node: Node<NoTransport, LocalRng> = Node::new(NoTransport, LocalRng, [1; 32], [2; 33]);
}
