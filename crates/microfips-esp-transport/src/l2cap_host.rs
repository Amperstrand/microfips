#![cfg(feature = "l2cap")]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use bt_hci::{ControllerToHostPacket, FromHciBytes, FromHciBytesError, HostToControllerPacket, WriteHci};
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use esp_radio::ble::controller::BleConnector;
use static_cell::StaticCell;
use trouble_host::l2cap::{L2capChannelReader, L2capChannelWriter};
use trouble_host::prelude::{
    AddrKind, Address, AdStructure, Advertisement, BdAddr, DefaultPacketPool, ExternalController, Host,
    HostResources, L2capChannel, L2capChannelConfig, PacketPool, Stack, BR_EDR_NOT_SUPPORTED,
    ConnectConfig, PhySet, RequestedConnParams, ScanConfig as TroubleScanConfig,
    LE_GENERAL_DISCOVERABLE,
};

use crate::config::{
    DEVICE_SECRET, FIPS_BLE_ADDR, FIPS_EXPECTED_PUBKEY, L2CAP_FIPS_SERVICE_UUID_LE,
    L2CAP_FRAME_CAP, L2CAP_PSM, RECV_RETRY_DELAY_MS, USE_PUBLIC_BLE_ADDRESS,
};

const L2CAP_SDU_CAP: usize = L2CAP_FRAME_CAP + 2;

static L2CAP_HOST_RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 3>> =
    StaticCell::new();
static L2CAP_RX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
static L2CAP_TX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
static L2CAP_READY_SIG: Signal<CriticalSectionRawMutex, [u8; 33]> = Signal::new();
static L2CAP_TASK_STARTED: AtomicBool = AtomicBool::new(false);
static L2CAP_LINK_UP: AtomicBool = AtomicBool::new(false);

fn init_heap() {
    const HEAP_SIZE: usize = 72 * 1024;
    static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
    unsafe {
        esp_alloc::HEAP.add_region(esp_alloc::HeapRegion::new(
            &raw mut HEAP as *mut u8,
            HEAP_SIZE,
            esp_alloc::MemoryCapability::Internal.into(),
        ));
    }
}

#[derive(Debug, Clone, Copy)]
enum BleHciError {
    Io,
    Parse,
}

impl core::fmt::Display for BleHciError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io => f.write_str("BLE HCI I/O error"),
            Self::Parse => f.write_str("BLE HCI parse error"),
        }
    }
}

impl core::error::Error for BleHciError {}

impl embedded_io::Error for BleHciError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl From<FromHciBytesError> for BleHciError {
    fn from(_: FromHciBytesError) -> Self {
        Self::Parse
    }
}

struct BleHciTransport<'d> {
    connector: core::cell::UnsafeCell<BleConnector<'d>>,
}

unsafe impl Sync for BleHciTransport<'_> {}
unsafe impl Send for BleHciTransport<'_> {}

impl<'d> BleHciTransport<'d> {
    fn new(connector: BleConnector<'d>) -> Self {
        Self {
            connector: core::cell::UnsafeCell::new(connector),
        }
    }
}

impl embedded_io::ErrorType for BleHciTransport<'_> {
    type Error = BleHciError;
}

impl bt_hci::transport::Transport for BleHciTransport<'_> {
    async fn read<'a>(&self, rx: &'a mut [u8]) -> Result<ControllerToHostPacket<'a>, Self::Error> {
        let rx_ptr: *mut [u8] = rx;
        loop {
            let connector = unsafe { &mut *self.connector.get() };
            let len = unsafe { connector.next(&mut *rx_ptr) }.map_err(|_| BleHciError::Io)?;
            if len == 0 {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(1)).await;
                continue;
            }
            match ControllerToHostPacket::from_hci_bytes_complete(&rx[..len]) {
                Ok(pkt) => return Ok(pkt),
                Err(_) => {
                    log::warn!("parse error, dropping packet");
                    continue;
                }
            }
        }
    }

    async fn write<T: HostToControllerPacket>(&self, val: &T) -> Result<(), Self::Error> {
        let mut buf = [0u8; 259];
        let wi = bt_hci::transport::WithIndicator::new(val);
        let len = wi.size();
        wi.write_hci(&mut buf[..len]).map_err(|_| BleHciError::Io)?;
        let connector = unsafe { &mut *self.connector.get() };
        connector
            .write(&buf[..len])
            .map(|_| ())
            .map_err(|_| BleHciError::Io)
    }
}

fn drain_l2cap_channels() {
    while L2CAP_TX_CH.try_receive().is_ok() {}
    while L2CAP_RX_CH.try_receive().is_ok() {}
}

fn mark_link_down() {
    L2CAP_LINK_UP.store(false, Ordering::Release);
}

fn mark_link_ready(peer_pub: [u8; 33]) {
    L2CAP_LINK_UP.store(true, Ordering::Release);
    L2CAP_READY_SIG.signal(peer_pub);
}

async fn exchange_pubkeys<T, P>(
    secret: &[u8; 32],
    writer: &mut L2capChannelWriter<'_, P>,
    reader: &mut L2capChannelReader<'_, P>,
    stack: &Stack<'_, T, P>,
) -> Option<[u8; 33]>
where
    T: trouble_host::prelude::Controller,
    P: PacketPool,
{
    let local_pub = microfips_core::noise::ecdh_pubkey(secret).ok()?;

    // FIPS macos-ble commit 8c388cf: wire format [len:2BE][0x00][pubkey:32][flags:1]
    let payload_len: u16 = 34;
    let mut tx = [0u8; 36];
    tx[0..2].copy_from_slice(&payload_len.to_be_bytes());
    tx[2] = 0x00;
    tx[3..35].copy_from_slice(&local_pub[1..33]);
    tx[35] = 0x00;

    log::info!("sending pubkey exchange ({}B payload, {}B wire)", payload_len, tx.len());
    writer.send(stack, &tx).await.ok()?;

    let mut rx_buf = [0u8; L2CAP_SDU_CAP];
    let result = embassy_time::with_timeout(
        embassy_time::Duration::from_secs(5),
        reader.receive(stack, &mut rx_buf),
    )
    .await;

    match result {
        Ok(Ok(n)) => {
            // Old: [0x0021][0x00][pubkey:32] = 35B, New: [0x0022][0x00][pubkey:32][flags:1] = 36B
            if n < 35 {
                log::warn!("pubkey exchange recv too short: {}B", n);
                return None;
            }
            let payload_len = u16::from_be_bytes([rx_buf[0], rx_buf[1]]) as usize;
            if !(payload_len == 33 || payload_len == 34) {
                log::warn!("pubkey exchange bad payload len: {}", payload_len);
                return None;
            }
            if rx_buf[2] != 0x00 {
                log::warn!("pubkey exchange bad prefix: 0x{:02X}", rx_buf[2]);
                return None;
            }

            let mut peer_pub = [0u8; 33];
            peer_pub[0] = 0x02;
            peer_pub[1..33].copy_from_slice(&rx_buf[3..35]);

            {
                let mut hex = [0u8; 64];
                microfips_esp_common::node_info::hex_encode(&peer_pub[1..33], &mut hex);
                log::info!("peer x-only pubkey: {}", core::str::from_utf8(&hex).unwrap_or("?"));
            }

            if payload_len == 34 && n == 36 {
                let flags = rx_buf[35];
                log::info!("pubkey exchange OK (got {}B, flags: 0x{:02X})", n, flags);
            } else {
                log::info!("pubkey exchange OK (got {}B, old format)", n);
            }
            Some(peer_pub)
        }
        Ok(Err(e)) => {
            log::warn!("pubkey exchange recv error: {:?}", e);
            None
        }
        Err(_) => {
            log::warn!("pubkey exchange timeout");
            None
        }
    }
}

fn peer_is_fips(peer_pub: &[u8; 33]) -> bool {
    peer_pub[1..33] == FIPS_EXPECTED_PUBKEY
}

/// Relay frames between L2CAP channel and internal channels.
///
/// Wire format (matches FIPS `BluerStream` on `linux-ble-stability-v2`):
///   TX: `[2B BE len][FMP frame]` → L2CAP SDU
///   RX: L2CAP SDU → `[2B BE len][FMP frame]` → strip prefix → internal channel
///
/// Framing NOTE: The 2-byte BE length prefix is NOT upstream FIPS behavior.
/// It was added in commit `42d9adb` for macOS CoreBluetooth byte-stream
/// coalescing. On Linux SeqPacket it's redundant but harmless. Both sides
/// must match. See FIPS `src/transport/ble/mod.rs` framing comment.
async fn relay_l2cap_frames<T, P>(
    stack: &Stack<'_, T, P>,
    writer: &mut L2capChannelWriter<'_, P>,
    reader: &mut L2capChannelReader<'_, P>,
    recv_disconnect_log: &'static str,
    send_disconnect_log: &'static str,
)
where
    T: trouble_host::prelude::Controller,
    P: PacketPool,
{
    let mut rx_buf = [0u8; L2CAP_SDU_CAP];

    let mut tx_count: u32 = 0;
    let mut rx_count: u32 = 0;

    loop {
        match select(reader.receive(stack, &mut rx_buf), L2CAP_TX_CH.receive()).await {
            Either::First(Ok(n)) => {
                if n < 2 {
                    log::warn!("RX: SDU too short ({}B), disconnecting", n);
                    mark_link_down();
                    break;
                }
                let payload_len = u16::from_be_bytes([rx_buf[0], rx_buf[1]]) as usize;
                if n < 2 + payload_len || payload_len > L2CAP_FRAME_CAP {
                    log::warn!(
                        "RX: bad length prefix ({}B payload in {}B SDU), disconnecting",
                        payload_len, n
                    );
                    mark_link_down();
                    break;
                }
                let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
                if frame.extend_from_slice(&rx_buf[2..2 + payload_len]).is_err() {
                    mark_link_down();
                    break;
                }

                rx_count += 1;
                let phase = frame.first().copied().unwrap_or(0xFF);

                if rx_count <= 5 || rx_count % 20 == 0 {
                    let hex_len = payload_len.min(32);
                    let mut hex = [0u8; 64];
                    microfips_esp_common::node_info::hex_encode(
                        &frame[..hex_len],
                        &mut hex[..hex_len * 2],
                    );
                    log::info!(
                        "RX #{}: {}B phase={:#04x} first32={}",
                        rx_count,
                        payload_len,
                        phase,
                        core::str::from_utf8(&hex[..hex_len * 2]).unwrap_or("?")
                    );
                }

                if L2CAP_RX_CH.try_send(frame).is_err() {
                    log::warn!("RX: L2CAP_RX_CH full, dropping {}B frame #{}", payload_len, rx_count);
                }
            }
            Either::First(Err(_)) => {
                log::warn!("{} (after {} RX, {} TX frames)", recv_disconnect_log, rx_count, tx_count);
                mark_link_down();
                break;
            }
            Either::Second(frame) => {
                let len = frame.len() as u16;
                let mut sdu = heapless::Vec::<u8, L2CAP_SDU_CAP>::new();
                if sdu.extend_from_slice(&len.to_be_bytes()).is_err() || sdu.extend_from_slice(&frame).is_err() {
                    log::warn!("TX: frame too large for SDU ({}B)", len);
                    mark_link_down();
                    break;
                }

                tx_count += 1;
                let phase = frame.first().copied().unwrap_or(0xFF);

                if tx_count <= 5 || tx_count % 20 == 0 {
                    let hex_len = (len as usize).min(32);
                    let mut hex = [0u8; 64];
                    microfips_esp_common::node_info::hex_encode(
                        &frame[..hex_len],
                        &mut hex[..hex_len * 2],
                    );
                    log::info!(
                        "TX #{}: {}B phase={:#04x} first32={}",
                        tx_count,
                        len,
                        phase,
                        core::str::from_utf8(&hex[..hex_len * 2]).unwrap_or("?")
                    );
                }

                match writer.send(stack, &sdu).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::warn!(
                            "{}: {:?} (after {} RX, {} TX frames)",
                            send_disconnect_log,
                            e,
                            rx_count,
                            tx_count
                        );
                        mark_link_down();
                        break;
                    }
                }
            }
        }
    }
}

#[embassy_executor::task]
pub async fn l2cap_host_task() {
    log::info!("started");
    init_heap();
    log::info!("heap initialized");

    let Ok(radio) = esp_radio::init() else {
        log::error!("esp_radio::init failed");
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
        }
    };
    log::info!("esp_radio initialized");

    let bt = unsafe { esp_hal::peripherals::Peripherals::steal().BT };
    let Ok(connector) = BleConnector::new(&radio, bt, Default::default()) else {
        log::error!("BleConnector::new failed");
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
        }
    };
    log::info!("connector ready");

    let controller: ExternalController<_, 20> = ExternalController::new(BleHciTransport::new(connector));
    log::info!("controller created");
    let resources = L2CAP_HOST_RESOURCES.init(HostResources::new());
    log::info!("host resources initialized");
    let stack = trouble_host::new(controller, resources);
    let stack = if USE_PUBLIC_BLE_ADDRESS {
        stack
    } else {
        let ble_addr: [u8; 6] = [
            0xff,
            DEVICE_SECRET[27],
            DEVICE_SECRET[28],
            DEVICE_SECRET[29],
            DEVICE_SECRET[30],
            DEVICE_SECRET[31],
        ];
        stack.set_random_address(Address::random(ble_addr))
    };
    log::info!("stack initialized");

    let Host {
        mut central,
        mut peripheral,
        mut runner,
        ..
    } = stack.build();
    log::info!("host built (central + peripheral)");

    let _ = embassy_futures::join::join(
        async {
            match runner.run().await {
                Ok(()) => log::info!("runner exited ok"),
                Err(e) => log::error!("runner error: {:?}", e),
            }
        },
        async {
            loop {
                let fips_addr = BdAddr::new(FIPS_BLE_ADDR);

                let mut central_session = None;
                // Try both PUBLIC and RANDOM address types — BlueZ may use either
                // after adapter reset (hciconfig down/up, bluetooth service restart).
                let addr_kinds = [AddrKind::PUBLIC, AddrKind::RANDOM];
                'outer: for attempt in 0..3u8 {
                    for &addr_kind in &addr_kinds {
                        let connect_config = ConnectConfig {
                            scan_config: TroubleScanConfig {
                                active: true,
                                filter_accept_list: &[(addr_kind, &fips_addr)],
                                phys: PhySet::M1,
                                interval: embassy_time::Duration::from_millis(100),
                                window: embassy_time::Duration::from_millis(100),
                                timeout: embassy_time::Duration::from_secs(5),
                            },
                            connect_params: RequestedConnParams::default(),
                        };

                        log::info!(
                            "attempting central connect to FIPS (attempt {}/3, {:?})",
                            attempt + 1,
                            addr_kind
                        );
                        match central.connect(&connect_config).await {
                            Ok(conn) => {
                                log::info!("BLE central connected ({:?}), handle {:?}", addr_kind, conn.handle());

                                embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;

                                let l2cap_config = L2capChannelConfig {
                                    mtu: Some(2048),
                                    ..Default::default()
                                };

                                log::info!("creating L2CAP channel on PSM {}...", L2CAP_PSM);
                                match L2capChannel::create(&stack, &conn, L2CAP_PSM, &l2cap_config).await {
                                    Ok(channel) => {
                                        log::info!("L2CAP channel created on PSM {}", L2CAP_PSM);
                                        let (mut writer, mut reader) = channel.split();
                                        match exchange_pubkeys(
                                            &DEVICE_SECRET,
                                            &mut writer,
                                            &mut reader,
                                            &stack,
                                        )
                                        .await
                                        {
                                            Some(peer_pub) => {
                                                if !peer_is_fips(&peer_pub) {
                                                    let mut hex = [0u8; 64];
                                                    microfips_esp_common::node_info::hex_encode(&peer_pub[1..33], &mut hex);
                                                    log::warn!(
                                                        "rejecting central peer (not FIPS): {}",
                                                        core::str::from_utf8(&hex).unwrap_or("?")
                                                    );
                                                    drain_l2cap_channels();
                                                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                                                        RECV_RETRY_DELAY_MS,
                                                    ))
                                                    .await;
                                                    mark_link_down();
                                                } else {
                                                    central_session = Some((conn, writer, reader, peer_pub));
                                                    break 'outer;
                                                }
                                            }
                                            None => {
                                                log::warn!("central pubkey exchange failed");
                                                drain_l2cap_channels();
                                                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                                                    RECV_RETRY_DELAY_MS,
                                                ))
                                                .await;
                                                mark_link_down();
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::warn!("L2CAP create error on PSM {}: {:?}", L2CAP_PSM, e);
                                        drain_l2cap_channels();
                                        embassy_time::Timer::after(embassy_time::Duration::from_millis(
                                            RECV_RETRY_DELAY_MS,
                                        ))
                                        .await;
                                        mark_link_down();
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "central connect attempt {} ({:?}) failed: {:?}",
                                    attempt + 1,
                                    addr_kind,
                                    e
                                );
                            }
                        }
                    }
                }

                if let Some((conn, mut writer, mut reader, peer_pub)) = central_session {
                    log::info!("central connection ready");
                    drain_l2cap_channels();
                    mark_link_ready(peer_pub);
                    relay_l2cap_frames(
                        &stack,
                        &mut writer,
                        &mut reader,
                        "central receive loop disconnected",
                        "central send loop disconnected",
                    )
                    .await;
                    drop(conn);
                    mark_link_down();
                    drain_l2cap_channels();
                    log::info!("central disconnected, retrying");
                    continue;
                }

                mark_link_down();
                log::info!("advertising as peripheral");

                let mut adv_data = [0u8; 31];
                let Ok(adv_len) = AdStructure::encode_slice(
                    &[
                        AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                        AdStructure::ServiceUuids128(&L2CAP_FIPS_SERVICE_UUID_LE),
                    ],
                    &mut adv_data,
                ) else {
                    log::error!("adv_data encode failed");
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                        RECV_RETRY_DELAY_MS,
                    ))
                    .await;
                    continue;
                };

                let mut scan_data = [0u8; 31];
                let caps = crate::config::ble_caps::LEAF_ONLY;
                let Ok(scan_len) = AdStructure::encode_slice(
                    &[
                        AdStructure::CompleteLocalName(b"microfips-l2cap"),
                        AdStructure::ServiceData16 {
                            uuid: crate::config::FIPS_CAPS_SERVICE_UUID,
                            data: &[caps],
                        },
                    ],
                    &mut scan_data,
                ) else {
                    log::error!("scan_data encode failed");
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                        RECV_RETRY_DELAY_MS,
                    ))
                    .await;
                    continue;
                };

                let advertiser = match peripheral
                    .advertise(
                        &Default::default(),
                        Advertisement::ConnectableScannableUndirected {
                            adv_data: &adv_data[..adv_len],
                            scan_data: &scan_data[..scan_len],
                        },
                    )
                    .await
                {
                    Ok(a) => {
                        log::info!("BLE advertising started");
                        a
                    }
                    Err(e) => {
                        log::error!("advertise() error: {:?}", e);
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;
                        continue;
                    }
                };

                let conn = match advertiser.accept().await {
                    Ok(c) => {
                        log::info!("BLE connection accepted");
                        c
                    }
                    Err(e) => {
                        log::warn!("peripheral accept error: {:?}", e);
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(
                            RECV_RETRY_DELAY_MS,
                        ))
                        .await;
                        continue;
                    }
                };

                let l2cap_config = L2capChannelConfig {
                    mtu: Some(2048),
                    ..Default::default()
                };

                let channel =
                    match L2capChannel::accept(&stack, &conn, &[L2CAP_PSM], &l2cap_config).await {
                        Ok(ch) => {
                            log::info!("L2CAP channel accepted on PSM {}", L2CAP_PSM);
                            ch
                        }
                        Err(e) => {
                            log::error!("L2CAP accept error on PSM {}: {:?}", L2CAP_PSM, e);
                            drain_l2cap_channels();
                            embassy_time::Timer::after(embassy_time::Duration::from_millis(
                                RECV_RETRY_DELAY_MS,
                            ))
                            .await;
                            continue;
                        }
                    };

                let (mut writer, mut reader) = channel.split();

                let Some(peer_pub) = exchange_pubkeys(&DEVICE_SECRET, &mut writer, &mut reader, &stack)
                    .await
                    else {
                        log::error!("pubkey exchange failed");
                        drain_l2cap_channels();
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(
                            RECV_RETRY_DELAY_MS,
                        ))
                        .await;
                        continue;
                    };

                if !peer_is_fips(&peer_pub) {
                    let mut hex = [0u8; 64];
                    microfips_esp_common::node_info::hex_encode(&peer_pub[1..33], &mut hex);
                    log::warn!(
                        "rejecting peripheral peer (not FIPS): {}",
                        core::str::from_utf8(&hex).unwrap_or("?")
                    );
                    drain_l2cap_channels();
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                        RECV_RETRY_DELAY_MS,
                    ))
                    .await;
                    continue;
                }

                drain_l2cap_channels();
                mark_link_ready(peer_pub);
                relay_l2cap_frames(
                    &stack,
                    &mut writer,
                    &mut reader,
                    "peripheral receive loop disconnected",
                    "peripheral send loop disconnected",
                )
                .await;

                mark_link_down();
                drain_l2cap_channels();
                log::info!("disconnected, re-advertising");
            }
        },
    )
    .await;
}

pub fn l2cap_task_started() -> &'static AtomicBool {
    &L2CAP_TASK_STARTED
}

pub fn l2cap_link_up() -> bool {
    L2CAP_LINK_UP.load(Ordering::Relaxed)
}

pub async fn wait_for_l2cap_ready() -> [u8; 33] {
    L2CAP_READY_SIG.wait().await
}

pub async fn l2cap_send_frame(frame: heapless::Vec<u8, L2CAP_FRAME_CAP>) {
    L2CAP_TX_CH.send(frame).await;
}

pub async fn l2cap_recv_frame() -> heapless::Vec<u8, L2CAP_FRAME_CAP> {
    L2CAP_RX_CH.receive().await
}
