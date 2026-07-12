//! Display module for STM32F469I-DISCO LCD debug output (#113).
//!
//! Initializes SDRAM + DSI/LTDC display via BSP, renders FIPS protocol state
//! and counters as text on the LCD. Feature-gated behind `display`.

use core::fmt::Write;
use core::sync::atomic::Ordering;

use embassy_stm32::peripherals;
use embassy_stm32::Peri;
use embassy_stm32f469i_disco::display::{BoardHint, DisplayCtrl, SdramCtrl};
use embassy_time::{Duration, Ticker};
use embedded_graphics::{
    mono_font::{ascii::FONT_6X10, MonoTextStyleBuilder},
    pixelcolor::Rgb888,
    prelude::*,
    text::Text,
};
use heapless::String;

use crate::config::*;
use crate::stats::{
    STAT_DATA_RX, STAT_DATA_TX, STAT_HB_RX, STAT_HB_TX, STAT_MSG1_TX, STAT_MSG2_RX, STAT_RECV_PKT,
    STAT_STATE, STAT_USB_ERR,
};

pub fn create_display(
    sdram: &SdramCtrl,
    ltdc: Peri<'static, peripherals::LTDC>,
    dsihost: Peri<'static, peripherals::DSIHOST>,
    te_pin: Peri<'static, peripherals::PJ2>,
    reset_pin: Peri<'static, peripherals::PH7>,
) -> DisplayCtrl<'static> {
    DisplayCtrl::new(
        sdram,
        ltdc,
        dsihost,
        te_pin,
        reset_pin,
        BoardHint::ForceNt35510,
    )
}

const STATE_NAMES: [&str; 8] = [
    "BOOT",
    "USB_READY",
    "MSG1_SENT",
    "HS_OK",
    "HB_TX",
    "HB_RX",
    "ERROR",
    "DISCONNECTED",
];

fn state_name(state: u32) -> &'static str {
    if (state as usize) < STATE_NAMES.len() {
        STATE_NAMES[state as usize]
    } else {
        "???"
    }
}

fn fmt_line(buf: &mut String<40>, args: core::fmt::Arguments) {
    buf.clear();
    let _ = buf.write_fmt(args);
}

pub fn render_status(display: &mut DisplayCtrl<'static>, uptime_secs: u32) {
    let state = STAT_STATE.load(Ordering::Relaxed);
    let msg1 = STAT_MSG1_TX.load(Ordering::Relaxed);
    let msg2 = STAT_MSG2_RX.load(Ordering::Relaxed);
    let hb_tx = STAT_HB_TX.load(Ordering::Relaxed);
    let hb_rx = STAT_HB_RX.load(Ordering::Relaxed);
    let data_tx = STAT_DATA_TX.load(Ordering::Relaxed);
    let data_rx = STAT_DATA_RX.load(Ordering::Relaxed);
    let usb_err = STAT_USB_ERR.load(Ordering::Relaxed);
    let recv_pkt = STAT_RECV_PKT.load(Ordering::Relaxed);

    let mut fb = display.fb();
    let _ = fb.clear(Rgb888::BLACK);

    let style = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(Rgb888::GREEN)
        .build();

    let style_err = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(Rgb888::RED)
        .build();

    let style_dim = MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(Rgb888::new(0x66, 0x66, 0x66))
        .build();

    let mut line = String::<40>::new();

    let _ = Text::new("microfips STM32F469I", Point::new(4, 12), style).draw(&mut fb);

    let state_color = if state == S_ERR { style_err } else { style };
    fmt_line(&mut line, format_args!("State: {}", state_name(state)));
    let _ = Text::new(&line, Point::new(4, 24), state_color).draw(&mut fb);

    fmt_line(&mut line, format_args!("MSG1:{} MSG2:{}", msg1, msg2));
    let _ = Text::new(&line, Point::new(4, 36), style).draw(&mut fb);

    fmt_line(&mut line, format_args!("HB tx:{} rx:{}", hb_tx, hb_rx));
    let _ = Text::new(&line, Point::new(4, 48), style).draw(&mut fb);

    fmt_line(
        &mut line,
        format_args!("Data tx:{} rx:{}", data_tx, data_rx),
    );
    let _ = Text::new(&line, Point::new(4, 60), style).draw(&mut fb);

    let err_color = if usb_err > 0 { style_err } else { style_dim };
    fmt_line(
        &mut line,
        format_args!("USB err:{} Pkt:{}", usb_err, recv_pkt),
    );
    let _ = Text::new(&line, Point::new(4, 72), err_color).draw(&mut fb);

    fmt_line(&mut line, format_args!("Uptime: {}s", uptime_secs));
    let _ = Text::new(&line, Point::new(4, 84), style_dim).draw(&mut fb);
}

/// Embassy task that refreshes the display every second with current FIPS state.
///
/// Call via `spawner.spawn(display_task(display))` after display init.
#[embassy_executor::task]
pub async fn display_task(mut display: DisplayCtrl<'static>) {
    let mut ticker = Ticker::every(Duration::from_secs(1));
    let mut uptime: u32 = 0;

    loop {
        render_status(&mut display, uptime);
        uptime = uptime.saturating_add(1);
        ticker.next().await;
    }
}
