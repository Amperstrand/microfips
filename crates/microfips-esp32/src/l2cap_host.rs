#![cfg(feature = "l2cap")]

extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use bt_hci::{ControllerToHostPacket, FromHciBytes, FromHciBytesError, HostToControllerPacket, WriteHci};
use bt_hci::param::{AddrKind, BdAddr};
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use esp_radio::ble::controller::BleConnector;
use static_cell::StaticCell;
use trouble_host::connection::{ConnectConfig, ScanConfig};
use trouble_host::prelude::{
    Address, AdStructure, Advertisement, DefaultPacketPool, EventHandler, ExternalController,
    Host, HostResources, L2capChannel, L2capChannelConfig, PhySet, RequestedConnParams,
    Scanner, BR_EDR_NOT_SUPPORTED, LE_GENERAL_DISCOVERABLE,
};

use crate::config::{
    AD_TYPE_COMPLETE_UUID128, L2CAP_FIPS_SERVICE_UUID_LE, L2CAP_FRAME_CAP, L2CAP_PSM,
    L2CAP_SCAN_DURATION_SECS, RECV_RETRY_DELAY_MS,
};

static L2CAP_HOST_RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 3>> =
    StaticCell::new();
static L2CAP_RX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
static L2CAP_TX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
static L2CAP_CONNECTED_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static L2CAP_TASK_STARTED: AtomicBool = AtomicBool::new(false);
static L2CAP_LINK_UP: AtomicBool = AtomicBool::new(false);
static L2CAP_CONN_GEN: AtomicU32 = AtomicU32::new(0);

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
                    esp_println::println!("[hci] parse error, dropping packet");
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
        for i in 0..6 {
            self.addr[i].store(raw[i], Ordering::Relaxed);
        }
    }

    fn take(&self) -> Option<(AddrKind, BdAddr)> {
        if !self.found.swap(false, Ordering::Relaxed) {
            return None;
        }
        let kind_byte = self.addr_kind.load(Ordering::Relaxed);
        let kind = if kind_byte == 1 {
            AddrKind::RANDOM
        } else {
            AddrKind::PUBLIC
        };
        let mut raw = [0u8; 6];
        for i in 0..6 {
            raw[i] = self.addr[i].load(Ordering::Relaxed);
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
        let ty = data[i + 1];
        if ty == AD_TYPE_COMPLETE_UUID128 {
            let uuid_start = i + 2;
            let uuid_end = uuid_start + 16;
            if uuid_end <= data.len() {
                let uuid = &data[uuid_start..uuid_end];
                if uuid == L2CAP_FIPS_SERVICE_UUID_LE[0] {
                    return true;
                }
            }
        }
        i += len + 1;
    }
    false
}

fn drain_l2cap_channels() {
    while L2CAP_TX_CH.try_receive().is_ok() {}
    while L2CAP_RX_CH.try_receive().is_ok() {}
}

#[embassy_executor::task]
pub async fn l2cap_host_task() {
    esp_println::println!("[l2cap_task] started");
    init_heap();
    esp_println::println!("[l2cap_task] heap initialized");

    let Ok(radio) = esp_radio::init() else {
        esp_println::println!("[l2cap_task] esp_radio::init failed");
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
        }
    };
    esp_println::println!("[l2cap_task] esp_radio initialized");

    let bt = unsafe { esp_hal::peripherals::Peripherals::steal().BT };
    let Ok(connector) = BleConnector::new(&radio, bt, Default::default()) else {
        esp_println::println!("[l2cap_task] BleConnector::new failed");
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
        }
    };
    esp_println::println!("[l2cap_task] connector ready");

    let controller: ExternalController<_, 20> = ExternalController::new(BleHciTransport::new(connector));
    esp_println::println!("[l2cap_task] controller created");
    let resources = L2CAP_HOST_RESOURCES.init(HostResources::new());
    esp_println::println!("[l2cap_task] host resources initialized");
    let stack = trouble_host::new(controller, resources)
        .set_random_address(Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]));
    esp_println::println!("[l2cap_task] stack initialized");

    let Host {
        mut central,
        mut peripheral,
        mut runner,
        ..
    } = stack.build();
    esp_println::println!("[l2cap_task] host built (central+peripheral)");

    let _ = embassy_futures::join::join(
        async {
            match runner.run_with_handler(&L2capEventHandler).await {
                Ok(()) => esp_println::println!("[l2cap_task] runner exited ok"),
                Err(e) => esp_println::println!("[l2cap_task] runner error: {:?}", e),
            }
        },
        async {
            loop {
                esp_println::println!("[l2cap_task] scanning for FIPS peer...");

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
                    esp_println::println!("[l2cap_task] FIPS peer found, connecting as central...");
                    let connect_config = ConnectConfig {
                        scan_config: ScanConfig {
                            filter_accept_list: &[(addr_kind, &bd_addr)],
                            ..Default::default()
                        },
                        connect_params: RequestedConnParams::default(),
                    };

                    match central.connect(&connect_config).await {
                        Ok(conn) => {
                            esp_println::println!("[l2cap] central connected, creating L2CAP channel");
                            let l2cap_config = L2capChannelConfig {
                                mtu: Some(2048),
                                ..Default::default()
                            };
                            match L2capChannel::create(&stack, &conn, L2CAP_PSM, &l2cap_config).await {
                                Ok(channel) => {
                                    esp_println::println!("[l2cap] L2CAP channel created (central)");
                                    drain_l2cap_channels();
                                    L2CAP_CONN_GEN.fetch_add(1, Ordering::Release);
                                    L2CAP_LINK_UP.store(true, Ordering::Release);
                                    L2CAP_CONNECTED_SIG.signal(());
                                    let (mut writer, mut reader) = channel.split();
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
                                    drain_l2cap_channels();
                                    esp_println::println!("[l2cap] central channel disconnected");
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
                    esp_println::println!(
                        "[l2cap_task] no FIPS peer found, advertising as peripheral"
                    );
                    let mut adv_data = [0u8; 31];
                    let Ok(adv_len) = AdStructure::encode_slice(
                        &[
                            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                            AdStructure::CompleteLocalName(b"microfips-l2cap"),
                        ],
                        &mut adv_data,
                    ) else {
                        esp_println::println!("[l2cap_task] adv_data encode failed");
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
                        esp_println::println!("[l2cap_task] scan_data encode failed");
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
                            esp_println::println!("[l2cap] BLE advertising started");
                            a
                        }
                        Err(e) => {
                            esp_println::println!("[l2cap_task] advertise() error: {:?}", e);
                            embassy_time::Timer::after(embassy_time::Duration::from_millis(500))
                                .await;
                            continue;
                        }
                    };

                    let conn = match advertiser.accept().await {
                        Ok(c) => {
                            esp_println::println!("[l2cap] BLE connection accepted");
                            c
                        }
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

                    let channel =
                        match L2capChannel::accept(&stack, &conn, &[L2CAP_PSM], &l2cap_config)
                            .await
                        {
                            Ok(ch) => {
                                esp_println::println!(
                                    "[l2cap] L2CAP channel accepted on PSM 0x0085"
                                );
                                ch
                            }
                            Err(_) => {
                                drain_l2cap_channels();
                                continue;
                            }
                        };

                    drain_l2cap_channels();

                    L2CAP_CONN_GEN.fetch_add(1, Ordering::Release);
                    L2CAP_LINK_UP.store(true, Ordering::Release);
                    L2CAP_CONNECTED_SIG.signal(());
                    let (mut writer, mut reader) = channel.split();
                    let mut rx_buf = [0u8; L2CAP_FRAME_CAP];

                    loop {
                        match select(reader.receive(&stack, &mut rx_buf), L2CAP_TX_CH.receive()).await
                        {
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
                    drain_l2cap_channels();
                }
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

pub async fn wait_for_l2cap_link() {
    loop {
        L2CAP_CONNECTED_SIG.wait().await;
        if l2cap_link_up() {
            return;
        }
    }
}

pub fn l2cap_conn_gen() -> u32 {
    L2CAP_CONN_GEN.load(Ordering::Acquire)
}

pub fn l2cap_drain_channels() {
    drain_l2cap_channels();
}

pub async fn l2cap_send_frame(frame: heapless::Vec<u8, L2CAP_FRAME_CAP>) {
    L2CAP_TX_CH.send(frame).await;
}

pub async fn l2cap_recv_frame() -> heapless::Vec<u8, L2CAP_FRAME_CAP> {
    L2CAP_RX_CH.receive().await
}
