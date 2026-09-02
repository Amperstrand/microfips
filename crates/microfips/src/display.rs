//! Display module for STM32F469I-DISCO LCD debug output (#113).
//!
//! Renders FIPS protocol state and counters as text on the LCD via the BSP
//! `DisplayCtrl`. SDRAM + DSI/LTDC panel init lives in `main.rs` (canonical
//! BSP sequence); this module only owns the render task. Feature-gated behind
//! `display`.

use core::fmt::Write;
use core::sync::atomic::Ordering;

use embassy_stm32f469i_disco::DisplayCtrl;
use embassy_time::{Duration, Ticker};
use embedded_graphics::{
    draw_target::DrawTarget,
    mono_font::{ascii::FONT_6X10, MonoTextStyle, MonoTextStyleBuilder},
    pixelcolor::Rgb888,
    prelude::*,
    primitives::{PrimitiveStyle, Rectangle},
    text::{Baseline, Text},
};
use heapless::String;

use microfips_core::identity::bech32::x_only_to_npub;
use microfips_core::identity::STM32_NPUB;

use crate::config::*;
use crate::stats::{
    PANIC_LINE, STAT_DATA_RX, STAT_DATA_TX, STAT_HB_RX, STAT_HB_TX, STAT_MSG1_TX, STAT_MSG2_RX,
    STAT_RECV_PKT, STAT_STATE, STAT_USB_ERR,
};

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

fn text_style(color: Rgb888) -> MonoTextStyle<'static, Rgb888> {
    MonoTextStyleBuilder::new()
        .font(&FONT_6X10)
        .text_color(color)
        .build()
}

/// Draw one text line: erase the line's band, then draw the text.
///
/// Per-line erase (instead of a full-frame `clear`) avoids a once-per-second
/// black flash: LTDC scans the framebuffer continuously, so a full clear is
/// visible as a one-frame flicker at the 1 Hz refresh rate.
fn draw_line<T: DrawTarget<Color = Rgb888>>(
    fb: &mut T,
    top: i32,
    text: &str,
    style: MonoTextStyle<'_, Rgb888>,
) {
    let width = fb.bounding_box().size.width as i32;
    // 12 px band: FONT_6X10 glyph (10 px, Baseline::Top anchoring) + 1 px slack
    // on each side. Line pitch is 14 px, so bands never overlap.
    let band = Rectangle::with_corners(Point::new(0, top - 1), Point::new(width - 1, top + 10));
    let _ = band
        .into_styled(PrimitiveStyle::with_fill(Rgb888::BLACK))
        .draw(fb);
    let _ = Text::with_baseline(text, Point::new(4, top), style, Baseline::Top).draw(fb);
}

fn fmt_line(buf: &mut String<48>, args: core::fmt::Arguments) {
    buf.clear();
    let _ = buf.write_fmt(args);
}

/// Full bech32 npub of the compiled-in STM32 identity: 63 chars, one line at
/// FONT_6X10 (63 * 6 + 4 = 382 px < 480 px portrait width). The *public*
/// identity only — never render the secret key.
fn npub_string() -> String<64> {
    // STM32_NPUB is a 33-byte compressed key; the x-only half is bytes [1..33].
    let mut x_only = [0u8; 32];
    x_only.copy_from_slice(&STM32_NPUB[1..33]);
    let mut s = String::<64>::new();
    for b in x_only_to_npub(&x_only) {
        let _ = s.push(b as char);
    }
    s
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

    let style = text_style(Rgb888::GREEN);
    let style_err = text_style(Rgb888::RED);
    let style_dim = text_style(Rgb888::new(0x66, 0x66, 0x66));

    let mut line = String::<48>::new();

    let state_color = if state == S_ERR { style_err } else { style };
    if state == S_ERR {
        // Last-error visibility (#113): the panic handler stores the location
        // line before setting S_ERR.
        let panic_at = PANIC_LINE.load(Ordering::Relaxed);
        fmt_line(
            &mut line,
            format_args!("State: ERROR (panic @ line {})", panic_at),
        );
    } else {
        fmt_line(&mut line, format_args!("State: {}", state_name(state)));
    }
    draw_line(&mut fb, 32, &line, state_color);

    fmt_line(&mut line, format_args!("MSG1:{} MSG2:{}", msg1, msg2));
    draw_line(&mut fb, 46, &line, style);

    fmt_line(&mut line, format_args!("HB tx:{} rx:{}", hb_tx, hb_rx));
    draw_line(&mut fb, 60, &line, style);

    fmt_line(
        &mut line,
        format_args!("Data tx:{} rx:{}", data_tx, data_rx),
    );
    draw_line(&mut fb, 74, &line, style);

    let err_color = if usb_err > 0 { style_err } else { style_dim };
    fmt_line(
        &mut line,
        format_args!("USB err:{} Pkt:{}", usb_err, recv_pkt),
    );
    draw_line(&mut fb, 88, &line, err_color);

    fmt_line(&mut line, format_args!("Uptime: {}s", uptime_secs));
    draw_line(&mut fb, 102, &line, style_dim);
}

/// Embassy task that refreshes the display every second with current FIPS state.
///
/// Spawn after the canonical BSP init in `main.rs`:
/// `spawner.spawn(display_task(display))`.
#[embassy_executor::task]
pub async fn display_task(mut display: DisplayCtrl<'static>) {
    // One-time full clear + static identity lines (title, npub). Everything
    // below y=32 is redrawn per tick by render_status.
    {
        let mut fb = display.fb();
        fb.clear(Rgb888::BLACK);

        draw_line(
            &mut fb,
            4,
            "microfips STM32F469I",
            text_style(Rgb888::GREEN),
        );
        draw_line(
            &mut fb,
            18,
            &npub_string(),
            text_style(Rgb888::new(0x66, 0x66, 0x66)),
        );
    }

    let mut ticker = Ticker::every(Duration::from_secs(1));
    let mut uptime: u32 = 0;

    loop {
        render_status(&mut display, uptime);
        uptime = uptime.saturating_add(1);
        ticker.next().await;
    }
}
