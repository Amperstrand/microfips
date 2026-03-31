#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::sync::atomic::{AtomicU32, Ordering};

use core::panic::PanicInfo;

use esp_hal::gpio::{Level, Output};
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::uart::{Config, RxConfig, Uart};
use esp_hal::{Async, interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
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
    0x13, 0x2f, 0x39, 0xa9, 0x8c, 0x31, 0xba, 0xad,
    0xdb, 0xa6, 0x52, 0x5f, 0x5d, 0x43, 0xf2, 0x95,
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let gpio = unsafe { &*esp_hal::peripherals::GPIO::PTR };
    loop {
        gpio.out_w1ts().write(|w| unsafe { w.out_data_w1ts().bits(1 << 2) });
        for _ in 0..5_000_000 {
            core::hint::spin_loop();
        }
        gpio.out_w1tc().write(|w| unsafe { w.out_data_w1tc().bits(1 << 2) });
        for _ in 0..5_000_000 {
            core::hint::spin_loop();
        }
    }
}

struct Led(Output<'static>);

impl Led {
    fn set_state(&mut self, state: u32) {
        match state {
            0 => self.0.set_low(),
            2 => self.0.set_high(),
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
        embassy_time::Timer::after(embassy_time::Duration::from_millis(500)).await;
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
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(10)).await;
                    continue;
                }
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
            NodeEvent::Msg1Sent => {
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(2);
            }
            NodeEvent::HandshakeOk => {
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(2);
            }
            NodeEvent::HeartbeatSent => {
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::HeartbeatRecv => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
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

    let mut led = Led(Output::new(peripherals.GPIO2, Level::Low, esp_hal::gpio::OutputConfig::default()));

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut trng = Trng::try_new().unwrap();

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let uart_config = Config::default()
        .with_rx(RxConfig::default().with_fifo_full_threshold(64))
        .with_baudrate(115200);
    let uart = Uart::new(peripherals.UART0, uart_config)
        .unwrap()
        .with_tx(peripherals.GPIO1)
        .with_rx(peripherals.GPIO3)
        .into_async();
    let (rx, tx) = uart.split();
    let transport = UartTransport { tx, rx };

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_SECRET, DEFAULT_PEER_PUB);

    let fsp = FspDualHandler::new_dual(ESP32_SECRET, resp_eph, init_eph, &STM32_PEER_PUB, STM32_NODE_ADDR);
    let mut handler = EspHandler { led: &mut led, fsp };

    node.run(&mut handler).await;
}
