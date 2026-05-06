pub fn init() {
    const HEAP_SIZE: usize = 72 * 1024;
    #[link_section = ".dram2_uninit"]
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    // SAFETY: HEAP is a static mut accessed once during initialization before any allocation.
    // The pointer (&raw mut HEAP) has 'static lifetime. esp_alloc requires the region to
    // remain valid for the program duration — satisfied because HEAP is static.
    unsafe {
        esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
            &raw mut HEAP as *mut u8,
            HEAP_SIZE,
            esp_alloc::MemoryCapability::Internal.into(),
        ));
    }
}
