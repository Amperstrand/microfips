//! ESP-NOW ↔ USB-serial gateway (not a FIPS node).
//!
//! Relays FMP frames between an ESP-NOW leaf node and the host: ESP-NOW
//! payloads are reassembled (see `microfips_esp_common::espnow_frag`) and
//! written to USB Serial/JTAG with a 2-byte LE length prefix — the format
//! `tools/serial_udp_bridge.py` expects — and length-prefixed frames from
//! the host are fragmented and sent back over ESP-NOW.
//!
//! Single-peer: the gateway unicasts to whichever node's frame it saw
//! last, and broadcasts until it has seen one. The log output stays
//! uninitialized on purpose — USB Serial/JTAG carries frames, and log
//! text would corrupt the stream.

use embassy_time::{with_timeout, Duration};
use embedded_io_async::{Read, Write};
use esp_hal::peripherals::{USB_DEVICE, WIFI};
use esp_hal::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx};
use esp_hal::Async;
use esp_radio::esp_now::{
    EspNowManager, EspNowReceiver, EspNowSender, EspNowWifiInterface, PeerInfo, BROADCAST_ADDRESS,
};
use microfips_esp_common::espnow_frag::{
    Fragmenter, SrcReassembler, ESP_NOW_MAX_PAYLOAD, MAX_MESSAGE,
};
use portable_atomic::{AtomicU64, Ordering};

/// Last-seen node MAC, shared between the two relay directions.
/// Bit 63 = valid flag, low 48 bits = MAC (big-endian).
static PEER_MAC: AtomicU64 = AtomicU64::new(0);

/// If the host stops draining USB (bridge not running), writes stall on a
/// full FIFO. Frames must then be dropped, not queued — blocking here would
/// wedge the radio→host direction until reboot. A torn frame from a
/// timed-out partial write is cleaned up by the bridge's length-prefix
/// resynchronization.
const USB_WRITE_TIMEOUT_MS: u64 = 500;

fn pack_mac(mac: [u8; 6]) -> u64 {
    let mut v = 0u64;
    let mut i = 0;
    while i < 6 {
        v = (v << 8) | mac[i] as u64;
        i += 1;
    }
    v | (1u64 << 63)
}

fn unpack_mac(v: u64) -> Option<[u8; 6]> {
    if v & (1u64 << 63) == 0 {
        return None;
    }
    let mut mac = [0u8; 6];
    let mut i = 0;
    while i < 6 {
        mac[5 - i] = (v >> (8 * i)) as u8;
        i += 1;
    }
    Some(mac)
}

/// Host → radio: parse length-prefixed frames from USB, fragment, send.
#[embassy_executor::task]
async fn usb_to_espnow_task(
    mut usb_rx: UsbSerialJtagRx<'static, Async>,
    mut sender: EspNowSender<'static>,
) {
    let mut fragmenter = Fragmenter::new();
    let mut acc = [0u8; 2 + MAX_MESSAGE];
    let mut acc_len = 0usize;
    let mut tmp = [0u8; 256];
    loop {
        let n = match Read::read(&mut usb_rx, &mut tmp).await {
            Ok(n) => n,
            Err(_) => {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    crate::config::RECV_RETRY_DELAY_MS,
                ))
                .await;
                continue;
            }
        };
        if acc_len + n > acc.len() {
            // stream out of sync beyond any legal frame — resynchronize
            acc_len = 0;
            continue;
        }
        acc[acc_len..acc_len + n].copy_from_slice(&tmp[..n]);
        acc_len += n;

        loop {
            if acc_len < 2 {
                break;
            }
            let ml = u16::from_le_bytes([acc[0], acc[1]]) as usize;
            if ml == 0 || ml > MAX_MESSAGE {
                acc_len = 0;
                break;
            }
            if acc_len < 2 + ml {
                break;
            }
            let dst = unpack_mac(PEER_MAC.load(Ordering::Relaxed)).unwrap_or(BROADCAST_ADDRESS);
            if let Some(fragments) = fragmenter.fragments(&acc[2..2 + ml]) {
                for (header, chunk) in fragments {
                    let mut payload = [0u8; ESP_NOW_MAX_PAYLOAD];
                    payload[..header.len()].copy_from_slice(&header);
                    payload[header.len()..header.len() + chunk.len()].copy_from_slice(chunk);
                    // best-effort: on radio error the frame is lost, the
                    // protocol layers above retry
                    let _ = sender
                        .send_async(&dst, &payload[..header.len() + chunk.len()])
                        .await;
                }
            }
            acc.copy_within(2 + ml..acc_len, 0);
            acc_len -= 2 + ml;
        }
    }
}

/// Radio → host: reassemble ESP-NOW fragments, length-prefix, write to USB.
/// Also learns the node's MAC for the reverse direction.
async fn espnow_to_usb(
    mut receiver: EspNowReceiver<'static>,
    mut usb_tx: UsbSerialJtagTx<'static, Async>,
    manager: EspNowManager<'static>,
) -> ! {
    let mut reassembler = SrcReassembler::new();
    loop {
        let received = receiver.receive_async().await;
        let src = received.info.src_address;
        let Some(frame) = reassembler.push(src, received.data()) else {
            continue;
        };
        if unpack_mac(PEER_MAC.load(Ordering::Relaxed)) != Some(src) {
            if !manager.peer_exists(&src) {
                let _ = manager.add_peer(PeerInfo {
                    interface: EspNowWifiInterface::Station,
                    peer_address: src,
                    lmk: None,
                    channel: None,
                    encrypt: false,
                });
            }
            PEER_MAC.store(pack_mac(src), Ordering::Relaxed);
        }
        let prefix = (frame.len() as u16).to_le_bytes();
        let timeout = Duration::from_millis(USB_WRITE_TIMEOUT_MS);
        match with_timeout(timeout, usb_tx.write_all(&prefix)).await {
            Ok(Ok(())) => {}
            _ => continue,
        }
        match with_timeout(timeout, usb_tx.write_all(frame)).await {
            Ok(Ok(())) => {}
            _ => continue,
        }
        let _ = with_timeout(timeout, usb_tx.flush()).await;
    }
}

pub async fn run_espnow_gateway(
    spawner: embassy_executor::Spawner,
    gpio2: esp_hal::peripherals::GPIO2<'static>,
    wifi: WIFI<'static>,
    usb_device: USB_DEVICE<'static>,
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> ! {
    crate::heap::init();
    let mut led = crate::runner::make_led(gpio2);
    // TrngSource must outlive the WiFi driver; this function never returns.
    let (_trng_source, _trng) = crate::runner::init_trng(rng_periph, adc1);

    let (wifi_controller, interfaces) =
        esp_radio::wifi::new(wifi, Default::default()).expect("wifi::new failed");
    // Dropping the controller stops the radio; the gateway runs forever.
    core::mem::forget(wifi_controller);

    let esp_now = interfaces.esp_now;
    let _ = esp_now.set_channel(crate::config::ESP_NOW_CHANNEL);
    let (manager, sender, receiver) = esp_now.split();

    let usb = UsbSerialJtag::new(usb_device).into_async();
    let (usb_rx, usb_tx) = usb.split();

    spawner.spawn(usb_to_espnow_task(usb_rx, sender).expect("spawn usb task failed"));

    led.set_state(crate::config::LED_ON);
    espnow_to_usb(receiver, usb_tx, manager).await
}
