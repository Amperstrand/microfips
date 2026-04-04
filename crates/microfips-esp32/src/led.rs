use esp_hal::gpio::Output;

use crate::config::{LED_OFF, LED_ON};

pub struct Led(pub Output<'static>);

impl Led {
    pub fn set_state(&mut self, state: u32) {
        match state {
            LED_OFF => self.0.set_low(),
            LED_ON => self.0.set_high(),
            _ => {}
        }
    }
}
