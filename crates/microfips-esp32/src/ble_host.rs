#![cfg(feature = "ble")]

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use bt_hci::{
    ControllerToHostPacket, FromHciBytes, FromHciBytesError, HostToControllerPacket, WriteHci,
};
use embassy_futures::select::{select, Either};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::signal::Signal;
use esp_radio::ble::{controller::BleConnector, have_hci_read_data};
use static_cell::StaticCell;
use trouble_host::prelude::*;

use crate::config::{
    ble_uuids, BLE_DEVICE_NAME, BLE_MAX_FRAME, FIPS_SERVICE_UUID_LE, RECV_RETRY_DELAY_MS,
};
use crate::stats::{STAT_BLE_CONNECT, STAT_BLE_DISCONNECT, STAT_BLE_RX, STAT_BLE_TX};

static HOST_RESOURCES: StaticCell<HostResources<DefaultPacketPool, 1, 2>> = StaticCell::new();
static BLE_RX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, BLE_MAX_FRAME>, 4> =
    Channel::new();
static BLE_TX_CH: Channel<CriticalSectionRawMutex, heapless::Vec<u8, BLE_MAX_FRAME>, 4> =
    Channel::new();
static BLE_CONNECTED_SIG: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static BLE_TASK_STARTED: AtomicBool = AtomicBool::new(false);
static BLE_LINK_UP: AtomicBool = AtomicBool::new(false);

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

#[gatt_server(mutex_type = CriticalSectionRawMutex)]
struct FipsBleServer {
    fips_service: FipsService,
}

#[gatt_service(uuid = ble_uuids::FIPS_SERVICE_UUID)]
struct FipsService {
    #[characteristic(uuid = ble_uuids::FIPS_RX_UUID, write)]
    rx_data: heapless::Vec<u8, BLE_MAX_FRAME>,

    #[characteristic(uuid = ble_uuids::FIPS_TX_UUID, read, notify)]
    tx_data: heapless::Vec<u8, BLE_MAX_FRAME>,
}

#[embassy_executor::task]
pub async fn ble_host_task() {
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
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let Ok(server) = FipsBleServer::new_with_config(GapConfig::Peripheral(PeripheralConfig {
        name: BLE_DEVICE_NAME,
        appearance: &appearance::UNKNOWN,
    })) else {
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(RECV_RETRY_DELAY_MS))
                .await;
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

            loop {
                match select(conn.next(), BLE_TX_CH.receive()).await {
                    Either::First(GattConnectionEvent::Disconnected { .. }) => {
                        BLE_LINK_UP.store(false, Ordering::Relaxed);
                        STAT_BLE_DISCONNECT.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                    Either::First(GattConnectionEvent::Gatt { event }) => match event {
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
                    },
                    Either::First(_) => {}
                    Either::Second(frame) => {
                        if server
                            .fips_service
                            .tx_data
                            .notify(&conn, &frame)
                            .await
                            .is_err()
                        {
                            BLE_LINK_UP.store(false, Ordering::Relaxed);
                            STAT_BLE_DISCONNECT.fetch_add(1, Ordering::Relaxed);
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

pub fn ble_task_started() -> &'static AtomicBool {
    &BLE_TASK_STARTED
}

pub fn ble_link_up() -> bool {
    BLE_LINK_UP.load(Ordering::Relaxed)
}

pub async fn wait_for_link() {
    loop {
        BLE_CONNECTED_SIG.wait().await;
        if ble_link_up() {
            return;
        }
    }
}

pub async fn send_frame(frame: heapless::Vec<u8, BLE_MAX_FRAME>) {
    BLE_TX_CH.send(frame).await;
}

pub async fn recv_frame() -> heapless::Vec<u8, BLE_MAX_FRAME> {
    BLE_RX_CH.receive().await
}
