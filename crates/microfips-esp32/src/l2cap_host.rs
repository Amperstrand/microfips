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
    Address, AdStructure, Advertisement, BR_EDR_NOT_SUPPORTED, DefaultPacketPool,
    ExternalController, Host, HostResources, L2capChannel, L2capChannelConfig, LE_GENERAL_DISCOVERABLE,
    PacketPool, Stack,
};

use crate::config::{
    ESP32_SECRET, L2CAP_FIPS_SERVICE_UUID_LE, L2CAP_FRAME_CAP, L2CAP_PSM, RECV_RETRY_DELAY_MS,
};

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

    let mut tx = [0u8; 33];
    tx[0] = 0x00;
    tx[1..].copy_from_slice(&local_pub[1..33]);

    writer.send(stack, &tx).await.ok()?;

    let mut rx_buf = [0u8; 33];
    let result = embassy_time::with_timeout(
        embassy_time::Duration::from_secs(5),
        reader.receive(stack, &mut rx_buf),
    )
    .await;

    match result {
        Ok(Ok(33)) if rx_buf[0] == 0x00 => {
            let mut peer_pub = [0u8; 33];
            peer_pub[0] = 0x02;
            peer_pub[1..33].copy_from_slice(&rx_buf[1..33]);
            log::info!("pubkey exchange OK");
            Some(peer_pub)
        }
        _ => None,
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
    let ble_addr: [u8; 6] = [
        0xff,
        ESP32_SECRET[27],
        ESP32_SECRET[28],
        ESP32_SECRET[29],
        ESP32_SECRET[30],
        ESP32_SECRET[31],
    ];
    let stack = trouble_host::new(controller, resources)
        .set_random_address(Address::random(ble_addr));
    log::info!("stack initialized");

    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();
    log::info!("host built (peripheral only)");

    let _ = embassy_futures::join::join(
        async {
            match runner.run().await {
                Ok(()) => log::info!("runner exited ok"),
                Err(e) => log::error!("runner error: {:?}", e),
            }
        },
        async {
            let mut had_connection = false;
            loop {
                mark_link_down();
                if had_connection {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;
                }
                had_connection = true;
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
                            continue;
                        }
                    };

                let (mut writer, mut reader) = channel.split();

                let Some(peer_pub) = exchange_pubkeys(&ESP32_SECRET, &mut writer, &mut reader, &stack)
                    .await
                    else {
                        log::error!("pubkey exchange failed");
                        continue;
                    };

                drain_l2cap_channels();

                // FIPS probe does pubkey exchange then disconnects without sending
                // protocol frames.  Wait for the first real FMP frame (MSG1, 114B)
                // to confirm this is a promoted connection, not a discarded probe.
                // Only then signal readiness so Node::run() starts.
                let mut first_buf = [0u8; L2CAP_FRAME_CAP];
                let first_result = embassy_time::with_timeout(
                    embassy_time::Duration::from_secs(5),
                    reader.receive(&stack, &mut first_buf),
                )
                .await;

                let first_frame = match first_result {
                    Ok(Ok(n)) if n >= 4 => {
                        let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
                        if frame.extend_from_slice(&first_buf[..n]).is_err() {
                            log::warn!("first frame too large ({}B), re-advertising", n);
                            continue;
                        }
                        log::info!("first frame received ({}B), connection confirmed", n);
                        frame
                    }
                    Ok(Ok(n)) => {
                        log::warn!("first frame too small ({}B), re-advertising", n);
                        continue;
                    }
                    Ok(Err(_)) => {
                        log::warn!("connection closed before first frame, re-advertising");
                        continue;
                    }
                    Err(_) => {
                        log::warn!("timeout waiting for first frame, re-advertising");
                        continue;
                    }
                };

                mark_link_ready(peer_pub);
                L2CAP_RX_CH.send(first_frame).await;

                let mut rx_buf = [0u8; L2CAP_FRAME_CAP];

                loop {
                    match select(reader.receive(&stack, &mut rx_buf), L2CAP_TX_CH.receive()).await {
                        Either::First(Ok(n)) => {
                            let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
                            if frame.extend_from_slice(&rx_buf[..n]).is_err() {
                                mark_link_down();
                                break;
                            }
                            L2CAP_RX_CH.send(frame).await;
                        }
                        Either::First(Err(_)) => {
                            log::warn!("receive loop disconnected");
                            mark_link_down();
                            break;
                        }
                        Either::Second(frame) => {
                            if writer.send(&stack, &frame).await.is_err() {
                                log::warn!("send loop disconnected");
                                mark_link_down();
                                break;
                            }
                        }
                    }
                }

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
    L2CAP_TX_CH.send(frame).await
}

pub async fn l2cap_recv_frame() -> heapless::Vec<u8, L2CAP_FRAME_CAP> {
    L2CAP_RX_CH.receive().await
}
