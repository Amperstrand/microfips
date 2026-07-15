/// Set GPIO2 (onboard LED) high.
///
/// # Safety
/// GPIO peripheral must be initialized via `esp_hal::init()`.
#[cfg(feature = "esp32")]
pub unsafe fn gpio2_set() {
    let gpio = &*esp_hal::peripherals::GPIO::PTR;
    gpio.out_w1ts().write(|w| w.out_data_w1ts().bits(1 << 2));
}

/// Set GPIO2 (onboard LED) high.
///
/// # Safety
/// GPIO peripheral must be initialized via `esp_hal::init()`.
#[cfg(any(feature = "esp32s3", feature = "esp32c3"))]
pub unsafe fn gpio2_set() {
    let gpio = &*esp_hal::peripherals::GPIO::PTR;
    gpio.out_w1ts().write(|w| w.out_w1ts().bits(1 << 2));
}

/// Clear GPIO2 (onboard LED) low.
///
/// # Safety
/// GPIO peripheral must be initialized via `esp_hal::init()`.
#[cfg(feature = "esp32")]
pub unsafe fn gpio2_clear() {
    let gpio = &*esp_hal::peripherals::GPIO::PTR;
    gpio.out_w1tc().write(|w| w.out_data_w1tc().bits(1 << 2));
}

/// Clear GPIO2 (onboard LED) low.
///
/// # Safety
/// GPIO peripheral must be initialized via `esp_hal::init()`.
#[cfg(any(feature = "esp32s3", feature = "esp32c3"))]
pub unsafe fn gpio2_clear() {
    let gpio = &*esp_hal::peripherals::GPIO::PTR;
    gpio.out_w1tc().write(|w| w.out_w1tc().bits(1 << 2));
}
