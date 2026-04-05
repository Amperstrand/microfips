#![cfg(feature = "l2cap")]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use bt_hci::{
    param::{AddrKind, BdAddr},
    ControllerToHostPacket, FromHciBytes, FromHciBytesError, HostToControllerPacket, WriteHci,
};
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use esp_radio::ble::{controller::BleConnector, have_hci_read_data};
use microfips_protocol::transport::Transport;
use static_cell::StaticCell;
use trouble_host::{
    connection::{ConnectConfig, ScanConfig},
    prelude::{
        Address, AdStructure, Advertisement, DefaultPacketPool, EventHandler, ExternalController,
        Host, HostResources, L2capChannel, L2capChannelConfig, L2capChannelReader,
        L2capChannelWriter, PhySet, RequestedConnParams, Scanner, BR_EDR_NOT_SUPPORTED,
        LE_GENERAL_DISCOVERABLE,
    },
};

use crate::config::{
    BLE_DEVICE_NAME, L2CAP_AD_TYPE_COMPLETE_UUID128, L2CAP_FIPS_SERVICE_UUID_LE, L2CAP_FRAME_CAP,
    L2CAP_PSM, L2CAP_SCAN_DURATION_SECS, RECV_RETRY_DELAY_MS,
};
use crate::config::ESP32_SECRET;

static HOST_RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 3>> = StaticCell::new();
static L2CAP_RX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
static L2CAP_TX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
static L2CAP_TASK_STARTED: AtomicBool = AtomicBool::new(false);
static L2CAP_CONNECTED_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static L2CAP_LINK_UP: AtomicBool = AtomicBool::new(false);
/// Peer pubkey from the most recent pubkey exchange (set by l2cap_host_task,
/// read by main after wait_ready). `None` until exchange completes.
static PEER_PUB: [core::sync::atomic::AtomicU8; 33] = [
    const { core::sync::atomic::AtomicU8::new(0) }; 33
];

fn store_peer_pub(pubkey: &[u8; 33]) {
    for (slot, byte) in PEER_PUB.iter().zip(pubkey.iter()) {
        slot.store(*byte, core::sync::atomic::Ordering::Relaxed);
    }
}

pub fn take_peer_pub() -> Option<[u8; 33]> {
    if PEER_PUB[0].swap(0, core::sync::atomic::Ordering::Acquire) == 0 {
        return None;
    }
    let mut pk = [0u8; 33];
    for (byte, slot) in pk.iter_mut().zip(PEER_PUB.iter()) {
        *byte = slot.load(core::sync::atomic::Ordering::Relaxed);
    }
    Some(pk)
}

struct ScanResult {
    found: AtomicBool,
    addr_kind: AtomicU8,
    addr: [AtomicU8; 6],
}

impl ScanResult {
    const fn new() -> Self {
        Self {
            found: AtomicBool::new(false),
            addr_kind: AtomicU8::new(0),
            addr: [
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
                AtomicU8::new(0),
            ],
        }
    }

    fn store(&self, addr_kind: AddrKind, bd_addr: &BdAddr) {
        if self.found.load(Ordering::Relaxed) {
            return;
        }

        self.found.store(true, Ordering::Relaxed);
        let kind_raw: u8 = unsafe { core::mem::transmute(addr_kind) };
        self.addr_kind.store(kind_raw, Ordering::Relaxed);
        let raw = bd_addr.raw();
        for (slot, value) in self.addr.iter().zip(raw.iter().copied()) {
            slot.store(value, Ordering::Relaxed);
        }
    }

    fn take(&self) -> Option<(AddrKind, BdAddr)> {
        if !self.found.swap(false, Ordering::Relaxed) {
            return None;
        }

        let kind = if self.addr_kind.load(Ordering::Relaxed) == 1 {
            AddrKind::RANDOM
        } else {
            AddrKind::PUBLIC
        };

        let mut raw = [0u8; 6];
        for (idx, slot) in self.addr.iter().enumerate() {
            raw[idx] = slot.load(Ordering::Relaxed);
        }
        Some((kind, BdAddr::new(raw)))
    }
}

static L2CAP_SCAN_RESULT: ScanResult = ScanResult::new();

struct L2capEventHandler;

impl EventHandler for L2capEventHandler {
    fn on_adv_reports(&self, mut it: bt_hci::param::LeAdvReportsIter<'_>) {
        while let Some(Ok(report)) = it.next() {
            if adv_data_contains_fips_uuid(report.data) {
                esp_println::println!("[l2cap] scan: FIPS peer found {:?}", report.addr);
                L2CAP_SCAN_RESULT.store(report.addr_kind, &report.addr);
            }
        }
    }
}

fn adv_data_contains_fips_uuid(data: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 <= data.len() {
        let len = data[i] as usize;
        if len < 2 || i + len > data.len() {
            break;
        }

        if data[i + 1] == L2CAP_AD_TYPE_COMPLETE_UUID128 {
            let uuid_start = i + 2;
            let uuid_end = uuid_start + 16;
            if uuid_end <= data.len() && data[uuid_start..uuid_end] == L2CAP_FIPS_SERVICE_UUID_LE[0] {
                return true;
            }
        }
        i += len + 1;
    }
    false
}

fn drain_channels() {
    while L2CAP_TX_CH.try_receive().is_ok() {}
    while L2CAP_RX_CH.try_receive().is_ok() {}
}

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
        loop {
            if !have_hci_read_data() {
                embassy_futures::yield_now().await;
                continue;
            }
            let connector = unsafe { &mut *self.connector.get() };
            let len = connector.next(rx).map_err(|_| BleHciError::Io)?;
            if len > 0 {
                return ControllerToHostPacket::from_hci_bytes_complete(&rx[..len])
                    .map_err(BleHciError::from);
            }
            embassy_futures::yield_now().await;
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

#[embassy_executor::task]
pub async fn l2cap_host_task() {
    init_heap();

    let Ok(radio) = esp_radio::init() else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
        }
    };

    let bt = unsafe { esp_hal::peripherals::Peripherals::steal().BT };
    let Ok(connector) = BleConnector::new(&radio, bt, Default::default()) else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
        }
    };

    let controller: ExternalController<_, 20> =
        ExternalController::new(BleHciTransport::new(connector));
    let resources = HOST_RESOURCES.init(HostResources::new());
    let stack = trouble_host::new(controller, resources)
        .set_random_address(Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]));

    let Host {
        mut central,
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let _ = embassy_futures::join::join(
        async {
            let _ = runner.run_with_handler(&L2capEventHandler).await;
        },
        async {
            loop {
                let scan_result = {
                    let mut scanner = Scanner::new(central);
                    let scan_config = ScanConfig {
                        active: true,
                        filter_accept_list: &[],
                        phys: PhySet::M1,
                        interval: embassy_time::Duration::from_millis(100),
                        window: embassy_time::Duration::from_millis(100),
                        timeout: embassy_time::Duration::from_secs(0),
                    };

                    let scan_err = match scanner.scan(&scan_config).await {
                        Ok(_) => None,
                        Err(e) => {
                            esp_println::println!("[l2cap_task] scan start error: {:?}", e);
                            Some(e)
                        }
                    };

                    if scan_err.is_some() {
                        embassy_time::Timer::after(embassy_time::Duration::from_secs(1)).await;
                    } else {
                        embassy_time::Timer::after(embassy_time::Duration::from_secs(
                            L2CAP_SCAN_DURATION_SECS,
                        ))
                        .await;
                    }

                    central = scanner.into_inner();
                    scan_err
                };

                if scan_result.is_some() {
                    continue;
                }

                if let Some((addr_kind, bd_addr)) = L2CAP_SCAN_RESULT.take() {
                    let connect_config = ConnectConfig {
                        scan_config: ScanConfig {
                            filter_accept_list: &[(addr_kind, &bd_addr)],
                            ..Default::default()
                        },
                        connect_params: RequestedConnParams::default(),
                    };

                    match central.connect(&connect_config).await {
                        Ok(conn) => {
                            let l2cap_config = L2capChannelConfig {
                                mtu: Some(2048),
                                ..Default::default()
                            };
                            match L2capChannel::create(&stack, &conn, L2CAP_PSM, &l2cap_config).await {
                                Ok(channel) => {
                                    let (mut writer, mut reader) = channel.split();

                                    let mut peer_pub = [0u8; 33];
                                    let exchange_ok = match microfips_core::noise::ecdh_pubkey(&ESP32_SECRET) {
                                        Ok(local_pub) => {
                                            let mut tx = [0u8; 33];
                                            tx[0] = 0x00;
                                            tx[1..].copy_from_slice(&local_pub[1..33]);

                                            if writer.send(&stack, &tx).await.is_err() {
                                                false
                                            } else {
                                                let mut rx_buf = [0u8; 33];
                                                let result = embassy_time::with_timeout(
                                                    embassy_time::Duration::from_secs(5),
                                                    reader.receive(&stack, &mut rx_buf),
                                                )
                                                .await;

                                                match result {
                                                    Ok(Ok(33)) if rx_buf[0] == 0x00 => {
                                                        peer_pub[0] = 0x02;
                                                        peer_pub[1..]
                                                            .copy_from_slice(&rx_buf[1..33]);
                                                        esp_println::println!("[l2cap] pubkey exchange OK");
                                                        true
                                                    }
                                                    _ => false,
                                                }
                                            }
                                        }
                                        Err(_) => false,
                                    };

                                    if exchange_ok {
                                        store_peer_pub(&peer_pub);
                                        drain_channels();
                                        L2CAP_LINK_UP.store(true, Ordering::Relaxed);
                                        L2CAP_CONNECTED_SIG.signal(());
                                        let mut rx_buf = [0u8; L2CAP_FRAME_CAP];

                                        loop {
                                            match select(
                                                reader.receive(&stack, &mut rx_buf),
                                                L2CAP_TX_CH.receive(),
                                            )
                                            .await
                                            {
                                                Either::First(Ok(n)) => {
                                                    let mut frame =
                                                        heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
                                                    if frame.extend_from_slice(&rx_buf[..n]).is_err() {
                                                        L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                                        break;
                                                    }
                                                    L2CAP_RX_CH.send(frame).await;
                                                }
                                                Either::First(Err(_)) => {
                                                    L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                                    break;
                                                }
                                                Either::Second(frame) => {
                                                    if writer.send(&stack, &frame).await.is_err() {
                                                        L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                        drain_channels();
                                    } else {
                                        esp_println::println!("[l2cap] pubkey exchange failed (central)");
                                    }
                                }
                                Err(e) => {
                                    esp_println::println!("[l2cap] L2CAP create error: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            esp_println::println!("[l2cap] central connect error: {:?}", e);
                        }
                    }
                } else {
                    let mut adv_data = [0u8; 31];
                    let Ok(adv_len) = AdStructure::encode_slice(
                        &[
                            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                            AdStructure::CompleteLocalName(BLE_DEVICE_NAME.as_bytes()),
                        ],
                        &mut adv_data,
                    ) else {
                        embassy_time::Timer::after(embassy_time::Duration::from_millis(
                            RECV_RETRY_DELAY_MS,
                        ))
                        .await;
                        continue;
                    };

                    let mut scan_data = [0u8; 31];
                    let Ok(scan_len) = AdStructure::encode_slice(
                        &[AdStructure::ServiceUuids128(&L2CAP_FIPS_SERVICE_UUID_LE)],
                        &mut scan_data,
                    ) else {
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
                        Ok(a) => a,
                        Err(_) => {
                            embassy_time::Timer::after(embassy_time::Duration::from_millis(500))
                                .await;
                            continue;
                        }
                    };

                    let conn = match advertiser.accept().await {
                        Ok(c) => c,
                        Err(_) => {
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

                    let channel = match L2capChannel::accept(&stack, &conn, &[L2CAP_PSM], &l2cap_config).await {
                        Ok(ch) => ch,
                        Err(_) => {
                            drain_channels();
                            continue;
                        }
                    };

                    let (mut writer, mut reader) = channel.split();

                    let mut peer_pub = [0u8; 33];
                    let exchange_ok = match microfips_core::noise::ecdh_pubkey(&ESP32_SECRET) {
                        Ok(local_pub) => {
                            let mut tx = [0u8; 33];
                            tx[0] = 0x00;
                            tx[1..].copy_from_slice(&local_pub[1..33]);

                            if writer.send(&stack, &tx).await.is_err() {
                                false
                            } else {
                                let mut rx_buf = [0u8; 33];
                                let result = embassy_time::with_timeout(
                                    embassy_time::Duration::from_secs(5),
                                    reader.receive(&stack, &mut rx_buf),
                                )
                                .await;

                                match result {
                                    Ok(Ok(33)) if rx_buf[0] == 0x00 => {
                                        peer_pub[0] = 0x02;
                                        peer_pub[1..].copy_from_slice(&rx_buf[1..33]);
                                        esp_println::println!("[l2cap] pubkey exchange OK");
                                        true
                                    }
                                    _ => false,
                                }
                            }
                        }
                        Err(_) => false,
                    };

                    if exchange_ok {
                        store_peer_pub(&peer_pub);
                        drain_channels();
                        L2CAP_LINK_UP.store(true, Ordering::Relaxed);
                        L2CAP_CONNECTED_SIG.signal(());
                        let mut rx_buf = [0u8; L2CAP_FRAME_CAP];

                        loop {
                            match select(reader.receive(&stack, &mut rx_buf), L2CAP_TX_CH.receive()).await {
                                Either::First(Ok(n)) => {
                                    let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
                                    if frame.extend_from_slice(&rx_buf[..n]).is_err() {
                                        L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                        break;
                                    }
                                    L2CAP_RX_CH.send(frame).await;
                                }
                                Either::First(Err(_)) => {
                                    L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                    break;
                                }
                                Either::Second(frame) => {
                                    if writer.send(&stack, &frame).await.is_err() {
                                        L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                        }

                        L2CAP_LINK_UP.store(false, Ordering::Relaxed);
                        drain_channels();
                    } else {
                        esp_println::println!("[l2cap] pubkey exchange failed (peripheral)");
                    }
                }
            }
        },
    )
    .await;
}

#[derive(Debug, Clone, Copy)]
pub enum L2capError {
    Disconnected,
    FrameTooLarge,
    InitFailed,
}

pub struct L2capTransport;

impl Transport for L2capTransport {
    type Error = L2capError;

    async fn wait_ready(&mut self) -> Result<(), L2capError> {
        if !L2CAP_TASK_STARTED.swap(true, Ordering::Relaxed) {
            let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
            spawner
                .spawn(l2cap_host_task())
                .map_err(|_| L2capError::InitFailed)?;
        }

        if L2CAP_LINK_UP.load(Ordering::Relaxed) {
            return Ok(());
        }

        loop {
            L2CAP_CONNECTED_SIG.wait().await;
            if L2CAP_LINK_UP.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), L2capError> {
        if !L2CAP_LINK_UP.load(Ordering::Relaxed) {
            return Err(L2capError::Disconnected);
        }
        if data.len() > L2CAP_FRAME_CAP {
            return Err(L2capError::FrameTooLarge);
        }

        let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
        frame
            .extend_from_slice(data)
            .map_err(|_| L2capError::FrameTooLarge)?;
        L2CAP_TX_CH.send(frame).await;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, L2capError> {
        loop {
            if !L2CAP_LINK_UP.load(Ordering::Relaxed) {
                return Err(L2capError::Disconnected);
            }

            match select(
                L2CAP_RX_CH.receive(),
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RECV_RETRY_DELAY_MS,
                )),
            )
            .await
            {
                Either::First(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    return Ok(n);
                }
                Either::Second(()) => continue,
            }
        }
    }
}
