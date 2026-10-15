//! Size probe, OURS config: the linked flash cost of driving our identity
//! path (fips-noise k256 pure-Rust backend + fips-identity) on a bare-metal
//! target.
//!
//! Methodology (must stay identical to size-probe-upstream): same allocator,
//! same entry shape, same black_box discipline, same release profile. The
//! measured delta between the two probes is attributable to the backend
//! crates.

#![no_std]
#![no_main]

use core::{
    alloc::{GlobalAlloc, Layout},
    cell::UnsafeCell,
    hint::black_box,
};

// Minimal bump allocator: enough to link and run the identity path. Identical
// in both probes so it cancels in the delta.
struct Heap(UnsafeCell<[u8; 32 * 1024]>);
unsafe impl Sync for Heap {}
static HEAP: Heap = Heap(UnsafeCell::new([0u8; 32 * 1024]));

struct BumpNext(UnsafeCell<usize>);
unsafe impl Sync for BumpNext {}
#[global_allocator]
static ALLOC: BumpNext = BumpNext(UnsafeCell::new(0));

unsafe impl GlobalAlloc for BumpNext {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = HEAP.0.get() as usize;
        let next = self.0.get();
        // SAFETY: single-threaded probe; next is only touched here.
        let mut offset = unsafe { *next };
        offset = offset.wrapping_add(layout.align() - 1) & !(layout.align() - 1);
        if offset + layout.size() > 32 * 1024 {
            return core::ptr::null_mut();
        }
        // SAFETY: single-threaded probe; next is only touched here.
        unsafe { *next = offset + layout.size() };
        (base + offset) as *mut u8
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

/// Bare-metal entry for the probe image (never runs on hardware; linking is
/// the measurement).
#[unsafe(no_mangle)]
pub extern "C" fn _probe_entry() -> ! {
    let secret = [0x07u8; 32];

    // Our path, comparable op-for-op with the upstream probe: secret ->
    // compressed pubkey (k256 via fips-noise) -> NodeAddr (fips-identity).
    if let Ok(compressed) = fips_noise::ecdh_pubkey(&secret) {
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&compressed[1..33]);
        let node_addr = fips_identity::NodeAddr::from_pubkey_x(&x_only);
        black_box(node_addr.as_bytes());
    }

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
