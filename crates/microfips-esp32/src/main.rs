#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(any(feature = "ble", feature = "l2cap"))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU32, Ordering};

use core::panic::PanicInfo;

#[cfg(any(feature = "ble", feature = "l2cap"))]
extern crate alloc;

#[cfg(feature = "ble")]
use embassy_futures::select::{Either, select};
#[cfg(any(feature = "ble", feature = "l2cap"))]
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
#[cfg(any(feature = "ble", feature = "l2cap"))]
use embassy_sync::channel::Channel;
#[cfg(feature = "l2cap")]
use embassy_sync::channel::{Receiver, Sender};
#[cfg(feature = "ble")]
use embassy_sync::signal::Signal;
#[cfg(any(feature = "ble", feature = "l2cap"))]
use esp_radio::ble::{controller::BleConnector, have_hci_read_data};
#[cfg(any(feature = "ble", feature = "l2cap"))]
use static_cell::StaticCell;
#[cfg(any(feature = "ble", feature = "l2cap"))]
use bt_hci::{ControllerToHostPacket, FromHciBytes, FromHciBytesError, HostToControllerPacket, WriteHci};
#[cfg(feature = "ble")]
use trouble_host::prelude::*;
#[cfg(feature = "l2cap")]
use trouble_host::prelude::{
    Address, AdStructure, Advertisement, DefaultPacketPool, ExternalController, Host,
    HostResources, L2capChannel, L2capChannelConfig,
};

use esp_hal::gpio::{Level, Output};
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::uart::{Config, RxConfig, Uart};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup, Async};
use rand_core::RngCore;

use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_protocol::fsp_handler::FspDualHandler;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;

/// ESP32 identity secret key: 31 zero bytes + 0x02 (secp256k1 generator * 2).
/// npub: npub1ccz8l9zpa47k6vz9gphftsrumpw80rjt3nhnefat4symjhrsnmjs38mnyd
/// node_addr: 0135da2f8acf7b9e3090939432e47684
const ESP32_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

/// STM32 peer pubkey (DEFAULT_SECRET -> ecdh_pubkey -> compressed point).
/// node_addr: 132f39a98c31baaddba6525f5d43f295
const STM32_PEER_PUB: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

const STM32_NODE_ADDR: [u8; 16] = [
    0x13, 0x2f, 0x39, 0xa9, 0x8c, 0x31, 0xba, 0xad, 0xdb, 0xa6, 0x52, 0x5f, 0x5d, 0x43, 0xf2, 0x95,
];

#[used]
static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_DATA_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_DATA_RX: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "ble")]
#[used]
static STAT_BLE_CONNECT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "ble")]
#[used]
static STAT_BLE_DISCONNECT: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "ble")]
#[used]
static STAT_BLE_TX: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "ble")]
#[used]
static STAT_BLE_RX: AtomicU32 = AtomicU32::new(0);

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let gpio = unsafe { &*esp_hal::peripherals::GPIO::PTR };
    loop {
        gpio.out_w1ts()
            .write(|w| unsafe { w.out_data_w1ts().bits(1 << 2) });
        for _ in 0..PANIC_BLINK_CYCLES {
            core::hint::spin_loop();
        }
        gpio.out_w1tc()
            .write(|w| unsafe { w.out_data_w1tc().bits(1 << 2) });
        for _ in 0..PANIC_BLINK_CYCLES {
            core::hint::spin_loop();
        }
    }
}

const LED_OFF: u32 = 0;
const LED_ON: u32 = 2;
const PANIC_BLINK_CYCLES: u32 = 5_000_000;
const UART_FIFO_THRESHOLD: u16 = 64;
const UART_BAUDRATE: u32 = 115200;
const WAIT_READY_DELAY_MS: u64 = 500;
const RECV_RETRY_DELAY_MS: u64 = 10;

#[cfg(any(feature = "ble", feature = "l2cap"))]
#[allow(dead_code)]
const BLE_DEVICE_NAME: &str = "microfips-esp32";
#[cfg(feature = "ble")]
#[allow(dead_code)]
const BLE_MAX_FRAME: usize = 252;
#[cfg(feature = "l2cap")]
const L2CAP_FRAME_CAP: usize = 512;
#[cfg(feature = "l2cap")]
const L2CAP_PSM: u16 = 0x0085;

#[cfg(feature = "ble")]
#[allow(dead_code)]
mod ble_uuids {
    pub const FIPS_SERVICE_UUID: u128 = 0x6f696670_7300_4265_8001_000000000001;
    pub const FIPS_RX_UUID: u128 = 0x6f696670_7300_4265_8002_000000000002;
    pub const FIPS_TX_UUID: u128 = 0x6f696670_7300_4265_8003_000000000003;
}

#[cfg(feature = "ble")]
const FIPS_SERVICE_UUID_LE: [[u8; 16]; 1] = [[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x65, 0x42, 0x00, 0x73, 0x70, 0x66, 0x69,
    0x6f,
]];

#[cfg(feature = "ble")]
static HOST_RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 2>> = StaticCell::new();
#[cfg(feature = "l2cap")]
type L2capPacketPool = DefaultPacketPool;
#[cfg(feature = "l2cap")]
static L2CAP_HOST_RESOURCES: StaticCell<HostResources<L2capPacketPool, 1, 3>> = StaticCell::new();
#[cfg(feature = "ble")]
static BLE_RX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, BLE_MAX_FRAME>, 4> = Channel::new();
#[cfg(feature = "ble")]
static BLE_TX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, BLE_MAX_FRAME>, 4> = Channel::new();
#[cfg(feature = "ble")]
static BLE_CONNECTED_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
#[cfg(feature = "ble")]
static BLE_TASK_STARTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "ble")]
static BLE_LINK_UP: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "l2cap")]
static L2CAP_RX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
#[cfg(feature = "l2cap")]
static L2CAP_TX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4> =
    Channel::new();
#[cfg(feature = "l2cap")]
static L2CAP_TASK_STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(any(feature = "ble", feature = "l2cap"))]
#[allow(dead_code)]
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

struct Led(Output<'static>);

impl Led {
    fn set_state(&mut self, state: u32) {
        match state {
            LED_OFF => self.0.set_low(),
            LED_ON => self.0.set_high(),
            _ => {}
        }
    }
}

struct UartTransport {
    tx: esp_hal::uart::UartTx<'static, Async>,
    rx: esp_hal::uart::UartRx<'static, Async>,
}

#[derive(Debug)]
struct UartError;

impl Transport for UartTransport {
    type Error = UartError;

    async fn wait_ready(&mut self) -> Result<(), UartError> {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(WAIT_READY_DELAY_MS)).await;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), UartError> {
        use embedded_io_async::Write;
        self.tx.write_all(data).await.map_err(|_| UartError)?;
        self.tx.flush().map_err(|_| UartError)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UartError> {
        use embedded_io_async::Read;
        loop {
            match Read::read(&mut self.rx, buf).await {
                Ok(n) => return Ok(n),
                Err(_) => {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                        RECV_RETRY_DELAY_MS,
                    ))
                    .await;
                    continue;
                }
            }
        }
    }
}

#[cfg(feature = "ble")]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BleError {
    Disconnected,
    FrameTooLarge,
    InitFailed,
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
#[derive(Debug, Clone, Copy)]
enum BleHciError {
    Io,
    Parse,
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
impl core::fmt::Display for BleHciError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io => f.write_str("BLE HCI I/O error"),
            Self::Parse => f.write_str("BLE HCI parse error"),
        }
    }
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
impl core::error::Error for BleHciError {}

#[cfg(any(feature = "ble", feature = "l2cap"))]
impl embedded_io::Error for BleHciError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
impl From<FromHciBytesError> for BleHciError {
    fn from(_: FromHciBytesError) -> Self {
        Self::Parse
    }
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
struct BleHciTransport<'d> {
    // Safety: single-threaded Embassy executor — read() and write() are never called
    // concurrently. Using UnsafeCell avoids holding a mutex lock across an .await point
    // (which would deadlock when runner and advertiser share the same join()).
    connector: core::cell::UnsafeCell<BleConnector<'d>>,
}

// Safety: BleConnector is used only from one executor task at a time (single-threaded).
#[cfg(any(feature = "ble", feature = "l2cap"))]
unsafe impl Sync for BleHciTransport<'_> {}
#[cfg(any(feature = "ble", feature = "l2cap"))]
unsafe impl Send for BleHciTransport<'_> {}

#[cfg(any(feature = "ble", feature = "l2cap"))]
impl<'d> BleHciTransport<'d> {
    fn new(connector: BleConnector<'d>) -> Self {
        Self {
            connector: core::cell::UnsafeCell::new(connector),
        }
    }
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
impl embedded_io::ErrorType for BleHciTransport<'_> {
    type Error = BleHciError;
}

#[cfg(any(feature = "ble", feature = "l2cap"))]
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
        connector.write(&buf[..len]).map(|_| ()).map_err(|_| BleHciError::Io)
    }
}

#[cfg(feature = "ble")]
#[gatt_server(mutex_type = CriticalSectionRawMutex)]
struct FipsBleServer {
    fips_service: FipsService,
}

#[cfg(feature = "ble")]
#[gatt_service(uuid = ble_uuids::FIPS_SERVICE_UUID)]
struct FipsService {
    #[characteristic(uuid = ble_uuids::FIPS_RX_UUID, write)]
    rx_data: heapless::Vec<u8, BLE_MAX_FRAME>,

    #[characteristic(uuid = ble_uuids::FIPS_TX_UUID, read, notify)]
    tx_data: heapless::Vec<u8, BLE_MAX_FRAME>,
}

#[cfg(feature = "ble")]
#[embassy_executor::task]
async fn ble_host_task() {
    init_heap();

    let Ok(radio) = esp_radio::init() else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
        }
    };

    let bt = unsafe { esp_hal::peripherals::Peripherals::steal().BT };
    let Ok(connector) = BleConnector::new(&radio, bt, Default::default()) else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
        }
    };

    let controller: ExternalController<_, 20> = ExternalController::new(BleHciTransport::new(connector));
    let resources = HOST_RESOURCES.init(HostResources::new());
    let stack = trouble_host::new(controller, resources)
        .set_random_address(Address::random([0xff, 0x8f, 0x1a, 0x05, 0xe4, 0xff]));

    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let Ok(server) = FipsBleServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: BLE_DEVICE_NAME,
        appearance: &appearance::UNKNOWN,
    })) else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
        }
    };

        let _ = embassy_futures::join::join(runner.run(), async {
        esp_println::println!("[ble_task] starting advertising loop");
        loop {
            let mut adv_data = [0u8; 31];
            let Ok(adv_len) = AdStructure::encode_slice(
                &[
                    AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
                    AdStructure::CompleteLocalName(BLE_DEVICE_NAME.as_bytes()),
                ],
                &mut adv_data,
            ) else {
                esp_println::println!("[ble_task] adv_data encode failed");
                continue;
            };

            let mut scan_data = [0u8; 31];
            let Ok(scan_len) = AdStructure::encode_slice(
                &[AdStructure::ServiceUuids128(&FIPS_SERVICE_UUID_LE)],
                &mut scan_data,
            ) else {
                esp_println::println!("[ble_task] scan_data encode failed");
                continue;
            };

            esp_println::println!("[ble_task] calling peripheral.advertise()...");
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
                    esp_println::println!("[ble_task] advertising started, waiting for connection");
                    a
                }
                Err(e) => {
                    esp_println::println!("[ble_task] advertise() error: {:?}", e);
                    continue;
                }
            };

            let conn = match advertiser.accept().await {
                Ok(c) => match c.with_attribute_server(&server) {
                    Ok(conn) => conn,
                    Err(e) => {
                        esp_println::println!("[ble_task] with_attribute_server error: {:?}", e);
                        continue;
                    }
                },
                Err(e) => {
                    esp_println::println!("[ble_task] accept() error: {:?}", e);
                    continue;
                }
            };

            BLE_LINK_UP.store(true, Ordering::Relaxed);
            STAT_BLE_CONNECT.fetch_add(1, Ordering::Relaxed);
            BLE_CONNECTED_SIG.signal(());
            esp_println::println!("[ble_task] central connected");

            loop {
                match select(conn.next(), BLE_TX_CH.receive()).await {
                    Either::First(GattConnectionEvent::Disconnected { .. }) => {
                        BLE_LINK_UP.store(false, Ordering::Relaxed);
                        STAT_BLE_DISCONNECT.fetch_add(1, Ordering::Relaxed);
                        esp_println::println!("[ble_task] central disconnected, re-advertising");
                        break;
                    }
                    Either::First(GattConnectionEvent::Gatt { event }) => {
                        match event {
                            GattEvent::Write(e) => {
                                if e.handle() == server.fips_service.rx_data.handle {
                                    let mut frame = heapless::Vec::<u8, BLE_MAX_FRAME>::new();
                                    if frame.extend_from_slice(e.data()).is_ok() {
                                        BLE_RX_CH.send(frame).await;
                                        STAT_BLE_RX.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                if let Ok(reply) = e.accept() {
                                    reply.send().await;
                                }
                            }
                            other => {
                                if let Ok(reply) = other.accept() {
                                    reply.send().await;
                                }
                            }
                        }
                    }
                    Either::First(_) => {}
                    Either::Second(frame) => {
                        if server.fips_service.tx_data.notify(&conn, &frame).await.is_err() {
                            BLE_LINK_UP.store(false, Ordering::Relaxed);
                            STAT_BLE_DISCONNECT.fetch_add(1, Ordering::Relaxed);
                            esp_println::println!("[ble_task] central disconnected, re-advertising");
                            break;
                        }
                        STAT_BLE_TX.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    })
    .await;
}

#[cfg(feature = "l2cap")]
#[embassy_executor::task]
async fn l2cap_host_task(
    _l2cap_rx: Sender<'static, CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4>,
    _l2cap_tx: Receiver<'static, CriticalSectionRawMutex, heapless::Vec<u8, L2CAP_FRAME_CAP>, 4>,
) {
    init_heap();

    let Ok(radio) = esp_radio::init() else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
        }
    };

    let bt = unsafe { esp_hal::peripherals::Peripherals::steal().BT };
    let Ok(connector) = BleConnector::new(&radio, bt, Default::default()) else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
        }
    };

    let controller: ExternalController<_, 20> = ExternalController::new(BleHciTransport::new(connector));
    let resources = L2CAP_HOST_RESOURCES.init(HostResources::new());
    let stack = trouble_host::new(controller, resources)
        .set_random_address(Address::random([0xfe, 0x8f, 0x1a, 0x05, 0xe4, 0xfe]));

    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let _ = embassy_futures::join::join(runner.run(), async {
        esp_println::println!("[l2cap_task] L2CAP listener ready");
        loop {
            let mut adv_data = [0u8; 31];
            let Ok(adv_len) = AdStructure::encode_slice(
                &[AdStructure::CompleteLocalName(BLE_DEVICE_NAME.as_bytes())],
                &mut adv_data,
            ) else {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
                continue;
            };

            let advertiser = match peripheral
                .advertise(
                    &Default::default(),
                    Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_len],
                        scan_data: &[],
                    },
                )
                .await
            {
                Ok(a) => a,
                Err(_) => {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
                    continue;
                }
            };

            let conn = match advertiser.accept().await {
                Ok(c) => c,
                Err(_) => {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
                    continue;
                }
            };

            let config = L2capChannelConfig {
                mtu: Some(2048),
                ..Default::default()
            };

            let _ = L2capChannel::accept(&stack, &conn, &[L2CAP_PSM], &config).await;

            loop {
                embassy_time::Timer::after_millis(1000).await;
            }
        }
    })
    .await;
}

#[cfg(feature = "ble")]
#[allow(dead_code)]
struct BleTransport {
    tx_buf: [u8; 256],
    tx_len: usize,
}

#[cfg(feature = "ble")]
impl BleTransport {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            tx_buf: [0u8; 256],
            tx_len: 0,
        }
    }
}

#[cfg(feature = "ble")]
impl Transport for BleTransport {
    type Error = BleError;

    async fn wait_ready(&mut self) -> Result<(), BleError> {
        if !BLE_TASK_STARTED.swap(true, Ordering::Relaxed) {
            let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
            spawner.spawn(ble_host_task()).map_err(|_| BleError::InitFailed)?;
        }

        if BLE_LINK_UP.load(Ordering::Relaxed) {
            return Ok(());
        }

        loop {
            BLE_CONNECTED_SIG.wait().await;
            if BLE_LINK_UP.load(Ordering::Relaxed) {
                return Ok(());
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), BleError> {
        if !BLE_LINK_UP.load(Ordering::Relaxed) {
            return Err(BleError::Disconnected);
        }
        if self.tx_len + data.len() > self.tx_buf.len() {
            self.tx_len = 0;
            return Err(BleError::FrameTooLarge);
        }

        self.tx_buf[self.tx_len..self.tx_len + data.len()].copy_from_slice(data);
        self.tx_len += data.len();

        if self.tx_len < 2 {
            return Ok(());
        }

        let payload_len = u16::from_le_bytes([self.tx_buf[0], self.tx_buf[1]]) as usize;
        let frame_len = 2 + payload_len;
        if frame_len > BLE_MAX_FRAME {
            self.tx_len = 0;
            return Err(BleError::FrameTooLarge);
        }
        if self.tx_len < frame_len {
            return Ok(());
        }

        let mut frame = heapless::Vec::<u8, BLE_MAX_FRAME>::new();
        frame
            .extend_from_slice(&self.tx_buf[..frame_len])
            .map_err(|_| BleError::FrameTooLarge)?;
        BLE_TX_CH.send(frame).await;

        let remaining = self.tx_len - frame_len;
        if remaining > 0 {
            self.tx_buf.copy_within(frame_len..self.tx_len, 0);
        }
        self.tx_len = remaining;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, BleError> {
        loop {
            if !BLE_LINK_UP.load(Ordering::Relaxed) {
                return Err(BleError::Disconnected);
            }
            match select(
                BLE_RX_CH.receive(),
                embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)),
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

struct EspRng(Trng);

impl rand_core::RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for EspRng {}

struct EspHandler<'a> {
    led: &'a mut Led,
    fsp: FspDualHandler,
}

impl NodeHandler for EspHandler<'_> {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => {
                self.led.set_state(LED_ON);
            }
            NodeEvent::Msg1Sent => {
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::HandshakeOk => {
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::HeartbeatSent => {
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::HeartbeatRecv => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Disconnected => {
                self.led.set_state(LED_OFF);
            }
            NodeEvent::Error => {
                self.led.set_state(LED_OFF);
            }
        }
        self.fsp.on_event_default(event);
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != 0x00 {
            return HandleResult::None;
        }
        STAT_DATA_RX.fetch_add(1, Ordering::Relaxed);
        let result = self.fsp.on_message(msg_type, payload, resp);
        if let HandleResult::SendDatagram(_) = result {
            STAT_DATA_TX.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn poll_at(&self) -> Option<embassy_time::Instant> {
        self.fsp.poll_at()
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        let result = self.fsp.on_tick(resp);
        if let HandleResult::SendDatagram(_) = result {
            STAT_DATA_TX.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let _sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let mut led = Led(Output::new(
        peripherals.GPIO2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut trng = Trng::try_new().unwrap();

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    #[cfg(not(any(feature = "ble", feature = "l2cap")))]
    {
    let uart_config = Config::default()
        .with_rx(RxConfig::default().with_fifo_full_threshold(UART_FIFO_THRESHOLD))
        .with_baudrate(UART_BAUDRATE);
    let uart = Uart::new(peripherals.UART0, uart_config)
        .unwrap()
        .with_tx(peripherals.GPIO1)
        .with_rx(peripherals.GPIO3)
        .into_async();
    let (rx, tx) = uart.split();
    let transport = UartTransport { tx, rx };

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_SECRET, DEFAULT_PEER_PUB);

    let fsp = FspDualHandler::new_dual(
        ESP32_SECRET,
        resp_eph,
        init_eph,
        &STM32_PEER_PUB,
        STM32_NODE_ADDR,
    );
    let mut handler = EspHandler { led: &mut led, fsp };

    node.run(&mut handler).await;
    }

    #[cfg(feature = "ble")]
    {
        esp_println::println!("[microfips] BLE mode starting");

        let transport = BleTransport::new();

        esp_println::println!("[microfips] BLE advertising as '{}'", BLE_DEVICE_NAME);

        let rng = EspRng(trng);
        let mut node = Node::new(transport, rng, ESP32_SECRET, DEFAULT_PEER_PUB);

        let fsp = FspDualHandler::new_dual(ESP32_SECRET, resp_eph, init_eph, &STM32_PEER_PUB, STM32_NODE_ADDR);
        let mut handler = EspHandler { led: &mut led, fsp };

        esp_println::println!("[microfips] Node running...");
        node.run(&mut handler).await;
    }

    #[cfg(feature = "l2cap")]
    {
        esp_println::println!("[microfips] L2CAP mode starting");

        if !L2CAP_TASK_STARTED.swap(true, Ordering::Relaxed) {
            let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
            if spawner
                .spawn(l2cap_host_task(L2CAP_RX_CH.sender(), L2CAP_TX_CH.receiver()))
                .is_err()
            {
                loop {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS)).await;
                }
            }
        }

        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(1000)).await;
        }
    }
}
