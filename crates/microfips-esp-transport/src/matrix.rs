//! Single-pixel driver for the M5 ATOM Matrix 5x5 LED (WS2812, GPIO27).
//!
//! HARDWARE SAFETY (owner directive 2026-10-15): at most ONE pixel is
//! ever lit, every channel is capped at `MAX_CHANNEL` (M5Stack's own
//! note says the matrix and enclosure overheat above FastLED brightness
//! 20), and every flash is rewritten to black after `FLASH_MS` by
//! [`MatrixPixel::poll`] — so even a lost follow-up command cannot leave
//! the pixel latched on.

use esp_hal::gpio::{Level, Output};
use esp_hal::rmt::{PulseCode, Rmt, TxChannelConfig, TxChannelCreator};

/// Channel-level cap for every R/G/B component (M5Stack overheating note).
pub const MAX_CHANNEL: u8 = 20;
/// Owner directive: never keep the pixel on longer than this.
pub const FLASH_MS: u64 = 2000;

/// Tick source 10 MHz -> 100 ns per RMT tick; WS2812 timings in ticks.
const T1H: u16 = 7;
const T1L: u16 = 6;
const T0H: u16 = 3;
const T0L: u16 = 9;
const RESET_LOW: u16 = 300;

pub struct MatrixPixel<'d> {
    tx: Option<esp_hal::rmt::Channel<'d, esp_hal::Blocking, esp_hal::rmt::Tx>>,
    off_at: Option<embassy_time::Instant>,
}

impl<'d> MatrixPixel<'d> {
    pub fn new(rmt: Rmt<'d, esp_hal::Blocking>, pin: Output<'d>) -> Self {
        let config = TxChannelConfig::default()
            .with_clk_divider(8u8)
            .with_idle_output_level(Level::Low)
            .with_idle_output(true)
            .with_carrier_modulation(false);
        let tx = rmt
            .channel0
            .configure_tx(&config)
            .map(|ch| ch.with_pin(pin))
            .expect("RMT channel0 for the matrix pixel");
        let mut p = Self {
            tx: Some(tx),
            off_at: None,
        };
        p.write((0, 0, 0));
        p
    }

    fn cap(v: u8) -> u8 {
        v.min(MAX_CHANNEL)
    }

    fn write(&mut self, rgb: (u8, u8, u8)) {
        let grb = [Self::cap(rgb.1), Self::cap(rgb.0), Self::cap(rgb.2)];
        let mut seq = [PulseCode::new(Level::High, T0H, Level::Low, T0L); 26];
        let mut i = 0;
        for byte in grb {
            for bit in (0..8).rev() {
                seq[i] = if (byte >> bit) & 1 == 1 {
                    PulseCode::new(Level::High, T1H, Level::Low, T1L)
                } else {
                    PulseCode::new(Level::High, T0H, Level::Low, T0L)
                };
                i += 1;
            }
        }
        seq[24] = PulseCode::new(Level::Low, RESET_LOW, Level::Low, 0);
        seq[25] = PulseCode::end_marker();
        if let Some(tx) = self.tx.take() {
            self.tx = Some(match tx.transmit(&seq) {
                Ok(transaction) => match transaction.wait() {
                    Ok(channel) | Err((_, channel)) => channel,
                },
                Err((_, channel)) => channel,
            });
        }
    }

    /// Light the single center pixel green and schedule the auto-off.
    pub fn flash(&mut self) {
        self.write((0, MAX_CHANNEL, 0));
        self.off_at =
            Some(embassy_time::Instant::now() + embassy_time::Duration::from_millis(FLASH_MS));
    }

    /// Extinguish immediately.
    pub fn off(&mut self) {
        self.off_at = None;
        self.write((0, 0, 0));
    }

    /// Called from the node handler tick: rewrites black once the
    /// deadline passes, so no flash outlives `FLASH_MS`.
    pub fn poll(&mut self) {
        if let Some(deadline) = self.off_at {
            if embassy_time::Instant::now() >= deadline {
                self.off();
            }
        }
    }

    pub fn is_on(&self) -> bool {
        self.off_at.is_some()
    }

    pub fn remaining_ms(&self) -> u64 {
        match self.off_at {
            None => 0,
            Some(d) => d
                .saturating_duration_since(embassy_time::Instant::now())
                .as_millis() as u64,
        }
    }
}
