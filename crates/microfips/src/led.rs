use core::sync::atomic::Ordering;

use embassy_stm32::gpio::Output;

use crate::config::{
    S_BOOT, S_DISCONNECTED, S_ERR, S_HANDSHAKE_OK, S_HB_RX, S_HB_TX, S_MSG1_SENT, S_USB_READY,
};
use crate::stats::STAT_STATE;

pub struct Leds {
    pub green: Output<'static>,
    pub orange: Output<'static>,
    pub red: Output<'static>,
    pub blue: Output<'static>,
}

impl Leds {
    pub fn set_state(&mut self, state: u32) {
        STAT_STATE.store(state, Ordering::Relaxed);
        match state {
            S_BOOT => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            S_USB_READY => {
                self.green.set_high();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            S_MSG1_SENT => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_low();
            }
            S_HANDSHAKE_OK => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_high();
            }
            S_HB_TX => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_low();
            }
            S_HB_RX => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_high();
                self.blue.set_high();
            }
            S_ERR => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_high();
                self.blue.set_low();
            }
            S_DISCONNECTED => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            _ => {}
        }
    }

    pub fn blink_green_once(&mut self) {
        self.green.set_high();
        cortex_m::asm::delay(8_000_000);
        self.green.set_low();
        cortex_m::asm::delay(8_000_000);
    }
}
