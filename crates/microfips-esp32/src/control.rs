//! FIPS-compatible control interface over UART0 for ESP32 BLE/L2CAP firmware.
//! Reads line-delimited commands from UART0 RX, responds with JSON on UART0 TX.
//! UART0 TX is shared with esp_println (both write to the same FIFO, no conflict).

#![cfg(any(feature = "ble", feature = "l2cap"))]

use core::ptr::{null_mut, read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use crate::node_info::{NodeIdentity, PeerInfo};
use crate::stats::StatsSnapshot;

const UART0_BASE: usize = 0x3FF4_0000;
const UART_FIFO_REG: *const u32 = (UART0_BASE + 0x00) as *const u32;
const UART_STATUS_REG: *const u32 = (UART0_BASE + 0x1C) as *const u32;

const GPIO_FUNC_IN_SEL_BASE: usize = 0x3FF4_4350;
const U0RXD_SIG_IN_IDX: usize = 44;
const GPIO3_NUM: u32 = 3;
const RXFIFO_CNT_MASK: u32 = 0xFF;
const LINE_BUF_SIZE: usize = 128;

fn uart0_init_rx() {
    unsafe {
        let gpio3_in_sel = (GPIO_FUNC_IN_SEL_BASE + 4 * U0RXD_SIG_IN_IDX) as *mut u32;
        write_volatile(gpio3_in_sel, GPIO3_NUM | (1 << 7));
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

fn uart0_rx_available() -> bool {
    let status = unsafe { read_volatile(UART_STATUS_REG) };
    (status & RXFIFO_CNT_MASK) != 0
}

fn uart0_read_byte() -> u8 {
    let value = unsafe { read_volatile(UART_FIFO_REG) };
    (value & 0xFF) as u8
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
    esp_println::println!(
        r#"{{"status":"ok","data":{{"msg1_tx":{},"msg2_rx":{},"hb_tx":{},"hb_rx":{},"data_tx":{},"data_rx":{}}}}}"#,
        snapshot.msg1_tx,
        snapshot.msg2_rx,
        snapshot.hb_tx,
        snapshot.hb_rx,
        snapshot.data_tx,
        snapshot.data_rx,
    );
}

fn handle_help() {
    esp_println::println!("show_status show_peers show_stats help version");
}

fn handle_version() {
    esp_println::println!("microfips-esp32 {}", env!("CARGO_PKG_VERSION"));
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
        _ => respond_error("unknown command"),
    }
}

#[embassy_executor::task]
pub async fn control_task() {
    uart0_init_rx();

    let mut line_buf = [0u8; LINE_BUF_SIZE];
    let mut line_len = 0usize;

    loop {
        if uart0_rx_available() {
            let byte = uart0_read_byte();

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
