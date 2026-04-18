//! FIPS-compatible control interface for ESP32 BLE/L2CAP/WiFi firmware.
//! Reads line-delimited commands, responds with JSON.
//!
//! ESP32-D0WD: reads from UART0 RX via GPIO matrix (GPIO3).
//! ESP32-S3: reads from USB Serial JTAG RX FIFO (GPIO44 goes through
//! USB Serial JTAG, not UART0 — esp-println outputs via USB Serial JTAG ROM
//! functions on S3, so control input must match).

#![cfg(any(feature = "ble", feature = "l2cap", feature = "wifi"))]

use core::ptr::{null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use crate::config::RESET_REGISTER;
use crate::node_info::{NodeIdentity, PeerInfo};
use crate::stats::StatsSnapshot;

const LINE_BUF_SIZE: usize = 128;

// --- ESP32-D0WD: UART0 register access ---
#[cfg(feature = "esp32")]
const UART_FIFO_REG: *mut u32 = (0x3FF4_0000 + 0x00) as *mut u32;
#[cfg(feature = "esp32")]
const UART_STATUS_REG: *const u32 = (0x3FF4_0000 + 0x1C) as *const u32;
#[cfg(feature = "esp32")]
const GPIO_FUNC_IN_SEL_BASE: usize = 0x3FF4_4350;

#[cfg(feature = "esp32")]
fn init_rx() {
    unsafe {
        let gpio_in_sel = (GPIO_FUNC_IN_SEL_BASE + 4 * 44) as *mut u32;
        write_volatile(gpio_in_sel, 3u32 | (1 << 7));
    }
}

#[cfg(feature = "esp32")]
fn rx_available() -> bool {
    let status = unsafe { read_volatile(UART_STATUS_REG) };
    (status & 0xFF) != 0
}

#[cfg(feature = "esp32")]
fn read_byte() -> u8 {
    (unsafe { read_volatile(UART_FIFO_REG) } & 0xFF) as u8
}

// --- ESP32-S3: USB Serial JTAG EP1 CDC register access ---
#[cfg(feature = "esp32s3")]
const USB_SERIAL_JTAG_BASE: usize = 0x6003_8000;
#[cfg(feature = "esp32s3")]
const USB_SERIAL_JTAG_EP1_REG: *const u32 = (USB_SERIAL_JTAG_BASE + 0x08) as *const u32;
#[cfg(feature = "esp32s3")]
const USB_SERIAL_JTAG_EP1_CONF_REG: *mut u32 = (USB_SERIAL_JTAG_BASE + 0x0C) as *mut u32;
#[cfg(feature = "esp32s3")]
const USB_SERIAL_JTAG_IN_EP1_ST_REG: *const u32 = (USB_SERIAL_JTAG_BASE + 0x44) as *const u32;

#[cfg(feature = "esp32s3")]
fn init_rx() {}

#[cfg(feature = "esp32s3")]
fn rx_available() -> bool {
    unsafe {
        let st = read_volatile(USB_SERIAL_JTAG_IN_EP1_ST_REG);
        (st & 0x04) != 0
    }
}

#[cfg(feature = "esp32s3")]
fn read_byte() -> u8 {
    unsafe {
        let val = read_volatile(USB_SERIAL_JTAG_EP1_REG) & 0xFF;
        // Clear EP1 done by writing bit 0 of EP1_CONF (wr_done)
        write_volatile(USB_SERIAL_JTAG_EP1_CONF_REG, 0x01);
        val as u8
    }
}

static PEER_PUB_CELL: StaticCell<[u8; 33]> = StaticCell::new();
static PEER_PUB_READY: AtomicBool = AtomicBool::new(false);
static PEER_PUB_PTR: AtomicPtr<[u8; 33]> = AtomicPtr::new(null_mut());

static NODE_IDENTITY_CELL: StaticCell<NodeIdentity> = StaticCell::new();
static NODE_IDENTITY_READY: AtomicBool = AtomicBool::new(false);
static NODE_IDENTITY_PTR: AtomicPtr<NodeIdentity> = AtomicPtr::new(null_mut());

static TRANSPORT_TYPE_CELL: StaticCell<&'static str> = StaticCell::new();
static TRANSPORT_TYPE_READY: AtomicBool = AtomicBool::new(false);
static TRANSPORT_TYPE_PTR: AtomicPtr<&'static str> = AtomicPtr::new(null_mut());

pub fn set_peer_pub(pubkey: [u8; 33]) {
    if PEER_PUB_READY.load(Ordering::Acquire) {
        return;
    }
    let peer_pub = PEER_PUB_CELL.init(pubkey) as *mut [u8; 33];
    PEER_PUB_PTR.store(peer_pub, Ordering::Release);
    PEER_PUB_READY.store(true, Ordering::Release);
}

pub fn init_control(identity: &NodeIdentity, transport_type: &'static str) {
    if !NODE_IDENTITY_READY.load(Ordering::Acquire) {
        let node_identity = NODE_IDENTITY_CELL.init(NodeIdentity {
            node_addr_hex: identity.node_addr_hex,
            pubkey_hex: identity.pubkey_hex,
        }) as *mut NodeIdentity;
        NODE_IDENTITY_PTR.store(node_identity, Ordering::Release);
        NODE_IDENTITY_READY.store(true, Ordering::Release);
    }

    if !TRANSPORT_TYPE_READY.load(Ordering::Acquire) {
        let transport_ptr = TRANSPORT_TYPE_CELL.init(transport_type) as *mut &'static str;
        TRANSPORT_TYPE_PTR.store(transport_ptr, Ordering::Release);
        TRANSPORT_TYPE_READY.store(true, Ordering::Release);
    }
}

fn node_identity() -> Option<&'static NodeIdentity> {
    if !NODE_IDENTITY_READY.load(Ordering::Acquire) {
        return None;
    }
    let ptr = NODE_IDENTITY_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { &*ptr })
}

fn transport_type() -> &'static str {
    if !TRANSPORT_TYPE_READY.load(Ordering::Acquire) {
        return "unknown";
    }
    let ptr = TRANSPORT_TYPE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return "unknown";
    }
    unsafe { *ptr }
}

fn peer_pub() -> Option<&'static [u8; 33]> {
    if !PEER_PUB_READY.load(Ordering::Acquire) {
        return None;
    }
    let ptr = PEER_PUB_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { &*ptr })
}

fn respond_error(message: &str) {
    esp_println::println!(r#"{{"status":"error","message":"{}"}}"#, message);
}

fn handle_show_status() {
    let Some(identity) = node_identity() else {
        respond_error("control not initialized");
        return;
    };

    let transport_type = transport_type();
    let snapshot = StatsSnapshot::capture();

    esp_println::println!(
        r#"{{"status":"ok","data":{{"node_addr":"{}","npub":"{}","state":"{}","uptime_secs":{},"transport_type":"{}"}}}}"#,
        identity.node_addr_str(),
        identity.pubkey_str(),
        snapshot.state_str(),
        snapshot.uptime_secs,
        transport_type,
    );
}

fn handle_show_peers() {
    if !PEER_PUB_READY.load(Ordering::Acquire) {
        respond_error("no peer connected");
        return;
    }

    let Some(peer_pub) = peer_pub() else {
        respond_error("peer pubkey unavailable");
        return;
    };

    let peer = PeerInfo::from_pubkey(peer_pub);
    esp_println::println!(
        r#"{{"status":"ok","data":{{"node_addr":"{}","pubkey":"{}"}}}}"#,
        peer.node_addr_str(),
        peer.pubkey_str(),
    );
}

fn handle_show_stats() {
    let snapshot = StatsSnapshot::capture();
    let srtt = microfips_protocol::mmp::stats::srtt_ms();
    let loss = microfips_protocol::mmp::stats::loss_pct();
    let goodput = microfips_protocol::mmp::stats::goodput_kbps();
    let jitter = microfips_protocol::mmp::stats::jitter_us();

    #[cfg(feature = "l2cap")]
    let l2cap = crate::l2cap_host::l2cap_stats_snapshot();
    #[cfg(not(feature = "l2cap"))]
    let l2cap = ();

    #[cfg(feature = "l2cap")]
    esp_println::println!(
        r#"{{"status":"ok","data":{{"msg1_tx":{},"msg2_rx":{},"hb_tx":{},"hb_rx":{},"data_tx":{},"data_rx":{},"srtt_ms":{},"loss_permil":{},"goodput_kbps":{},"jitter_us":{},"l2cap_zero_frame_disconnects":{},"l2cap_recv_timeouts":{},"l2cap_send_timeouts":{},"l2cap_send_errors":{},"l2cap_rx_drops":{},"l2cap_pubkey_ok":{},"l2cap_central_connects":{},"l2cap_peripheral_connects":{},"l2cap_last_role":{},"l2cap_last_reason":{}}}}}"#,
        snapshot.msg1_tx,
        snapshot.msg2_rx,
        snapshot.hb_tx,
        snapshot.hb_rx,
        snapshot.data_tx,
        snapshot.data_rx,
        srtt,
        loss,
        goodput,
        jitter,
        l2cap.zero_frame_disconnects,
        l2cap.recv_timeouts,
        l2cap.send_timeouts,
        l2cap.send_errors,
        l2cap.rx_drops,
        l2cap.pubkey_ok,
        l2cap.central_connects,
        l2cap.peripheral_connects,
        l2cap.last_role,
        l2cap.last_reason,
    );

    #[cfg(not(feature = "l2cap"))]
    esp_println::println!(
        r#"{{"status":"ok","data":{{"msg1_tx":{},"msg2_rx":{},"hb_tx":{},"hb_rx":{},"data_tx":{},"data_rx":{},"srtt_ms":{},"loss_permil":{},"goodput_kbps":{},"jitter_us":{}}}}}"#,
        snapshot.msg1_tx,
        snapshot.msg2_rx,
        snapshot.hb_tx,
        snapshot.hb_rx,
        snapshot.data_tx,
        snapshot.data_rx,
        srtt,
        loss,
        goodput,
        jitter,
    );
}

fn handle_help() {
    esp_println::println!("show_status show_peers show_stats help version reset");
}

fn handle_version() {
    esp_println::println!(
        "{} {}",
        crate::config::DEVICE_NAME,
        env!("CARGO_PKG_VERSION")
    );
}

fn handle_reset() {
    esp_println::println!(r#"{{"status":"ok","data":{{"message":"resetting"}}}}"#);
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
    unsafe {
        core::ptr::write_volatile(RESET_REGISTER as *mut u32, 1 << 31);
    }
    loop {
        core::hint::spin_loop();
    }
}

fn handle_command(line: &[u8]) {
    let Ok(raw) = core::str::from_utf8(line) else {
        respond_error("invalid utf8 command");
        return;
    };

    let cmd = raw.trim();
    if cmd.is_empty() {
        return;
    }

    match cmd {
        "show_status" => handle_show_status(),
        "show_peers" => handle_show_peers(),
        "show_stats" => handle_show_stats(),
        "help" => handle_help(),
        "version" => handle_version(),
        "reset" => handle_reset(),
        _ => respond_error("unknown command"),
    }
}

#[embassy_executor::task]
pub async fn control_task() {
    init_rx();

    let mut line_buf = [0u8; LINE_BUF_SIZE];
    let mut line_len = 0usize;

    loop {
        if rx_available() {
            let byte = read_byte();

            if byte == b'\n' || byte == b'\r' {
                if line_len != 0 {
                    handle_command(&line_buf[..line_len]);
                    line_len = 0;
                }
                continue;
            }

            if line_len < line_buf.len() {
                line_buf[line_len] = byte;
                line_len += 1;
            } else {
                line_len = 0;
                respond_error("command too long");
            }
        }

        Timer::after(Duration::from_millis(10)).await;
    }
}
