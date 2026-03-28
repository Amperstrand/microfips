#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use defmt_rtt as _;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::rng::Rng;
use embassy_stm32::usb::Driver;
use embassy_stm32::{Config, bind_interrupts, peripherals, rng, usb};
use embassy_usb::Builder;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use static_cell::StaticCell;

use microfips_protocol::node::{Node, NodeHandler, NodeState};
use microfips_protocol::transport::{CryptoRng, Transport};

static PANIC_LINE: AtomicU32 = AtomicU32::new(0);
#[used]
static _PANIC_LINE_KEEP: &AtomicU32 = &PANIC_LINE;

static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
static STAT_USB_ERR: AtomicU32 = AtomicU32::new(0);
static STAT_STATE: AtomicU32 = AtomicU32::new(0);
static STAT_DATA_RX: AtomicU32 = AtomicU32::new(0);
static STAT_DATA_TX: AtomicU32 = AtomicU32::new(0);

const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\n\r\nmicrofips OK\n";

const S_BOOT: u32 = 0;
const S_USB_READY: u32 = 1;
const S_MSG1_SENT: u32 = 2;
const S_HANDSHAKE_OK: u32 = 3;
const S_HB_TX: u32 = 4;
const S_HB_RX: u32 = 5;
const S_ERR: u32 = 6;
const S_DISCONNECTED: u32 = 7;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        PANIC_LINE.store(loc.line(), Ordering::Relaxed);
    }
    STAT_STATE.store(S_ERR, Ordering::Relaxed);
    loop {
        cortex_m::asm::delay(500_000);
        cortex_m::asm::delay(500_000);
    }
}

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

const CDC_PKT: usize = 64;

const MCU_SECRET: [u8; 32] = [
    0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4, 0xee, 0xb5,
    0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7, 0x84, 0x3f, 0x83, 0x2e,
];

const VPS_PUB: [u8; 33] = [
    0x03, 0x41, 0x5f, 0x38, 0xf9, 0xae, 0x39, 0xf2, 0x41, 0xdf, 0x21, 0xf1, 0x7b, 0xe4, 0x0a, 0x07,
    0xcf, 0x2a, 0xa6, 0xa8, 0x9e, 0xe7, 0x14, 0xf7, 0x48, 0x17, 0xc3, 0x0f, 0xf4, 0x84, 0xb2, 0x49,
    0x02,
];

static EP_OUT_BUF: StaticCell<[u8; 1024]> = StaticCell::new();

// ---------------------------------------------------------------------------
// Transport: USB CDC ACM
// ---------------------------------------------------------------------------

struct CdcTransport<'d> {
    class: CdcAcmClass<'d, Driver<'d, peripherals::USB_OTG_FS>>,
}

impl Transport for CdcTransport<'_> {
    type Error = EndpointError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        self.class.wait_connection().await;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut off = 0;
        while off < data.len() {
            let end = core::cmp::min(off + CDC_PKT, data.len());
            self.class.write_packet(&data[off..end]).await?;
            off = end;
        }
        if !data.is_empty() && data.len() % CDC_PKT == 0 {
            self.class.write_packet(&[]).await?;
        }
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.class.read_packet(buf).await
    }
}

// ---------------------------------------------------------------------------
// CryptoRng: hardware RNG
// ---------------------------------------------------------------------------

struct HwRng(Rng<'static, peripherals::RNG>);

impl CryptoRng for HwRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        self.0.fill_bytes(buf);
    }
}

// ---------------------------------------------------------------------------
// NodeHandler: LEDs + stats + HTTP datagram response
// ---------------------------------------------------------------------------

struct Leds {
    green: Output<'static>,
    orange: Output<'static>,
    red: Output<'static>,
    blue: Output<'static>,
}

impl Leds {
    fn set_state(&mut self, state: u32) {
        STAT_STATE.store(state, Ordering::Relaxed);
        match state {
            S_BOOT => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            S_USB_READY => {
                self.green.set_high();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            S_MSG1_SENT => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_low();
            }
            S_HANDSHAKE_OK => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_high();
            }
            S_HB_TX => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_low();
            }
            S_HB_RX => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_high();
                self.blue.set_high();
            }
            S_ERR => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_high();
                self.blue.set_low();
            }
            S_DISCONNECTED => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            _ => {}
        }
    }

    fn blink_green_once(&mut self) {
        self.green.set_high();
        cortex_m::asm::delay(8_000_000);
        self.green.set_low();
        cortex_m::asm::delay(8_000_000);
    }
}

struct FirmwareHandler {
    leds: Leds,
}

impl NodeHandler for FirmwareHandler {
    fn on_state(&mut self, state: NodeState) {
        match state {
            NodeState::Connected => {
                self.leds.set_state(S_USB_READY);
            }
            NodeState::HandshakeStarted => {
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_MSG1_SENT);
            }
            NodeState::HandshakeComplete => {
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HANDSHAKE_OK);
            }
            NodeState::HeartbeatSent => {
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HB_TX);
                self.leds.set_state(S_HANDSHAKE_OK);
            }
            NodeState::HeartbeatReceived => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HB_RX);
            }
            NodeState::Error => {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_ERR);
            }
            NodeState::Disconnected => {
                self.leds.set_state(S_DISCONNECTED);
            }
        }
    }

    fn on_datagram(&mut self, payload: &[u8], response: &mut [u8]) -> Option<usize> {
        STAT_DATA_RX.fetch_add(1, Ordering::Relaxed);
        if payload.len() >= 3 && &payload[..3] == b"GET" {
            STAT_DATA_TX.fetch_add(1, Ordering::Relaxed);
            let n = HTTP_RESPONSE.len().min(response.len());
            response[..n].copy_from_slice(&HTTP_RESPONSE[..n]);
            Some(n)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.pll_src = PllSource::HSI;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV8,
            mul: PllMul::MUL168,
            divp: Some(PllPDiv::DIV2),
            divq: Some(PllQDiv::DIV7),
            divr: None,
        });
        config.rcc.sys = Sysclk::PLL1_P;
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.mux.clk48sel = mux::Clk48sel::PLL1_Q;
    }
    let p = embassy_stm32::init(config);

    let mut leds = Leds {
        green: Output::new(p.PG6, Level::Low, Speed::Low),
        orange: Output::new(p.PD4, Level::Low, Speed::Low),
        red: Output::new(p.PD5, Level::Low, Speed::Low),
        blue: Output::new(p.PK3, Level::Low, Speed::Low),
    };

    leds.blink_green_once();
    leds.blink_green_once();

    let rng = HwRng(Rng::new(p.RNG, Irqs));

    leds.blink_green_once();
    leds.blink_green_once();

    let ep_out_buf = EP_OUT_BUF.init([0u8; 1024]);
    let mut usb_cfg = embassy_stm32::usb::Config::default();
    usb_cfg.vbus_detection = false;

    let driver = Driver::new_fs(p.USB_OTG_FS, Irqs, p.PA12, p.PA11, ep_out_buf, usb_cfg);

    let mut usb_cfg = embassy_usb::Config::new(0xc0de, 0xcafe);
    usb_cfg.manufacturer = Some("Amperstrand");
    usb_cfg.product = Some("microfips");
    usb_cfg.serial_number = Some("stm32f469i-disc");

    let mut cfg_desc = [0; 256];
    let mut bos_desc = [0; 256];
    let mut ctl_buf = [0; 64];
    let mut cdc_st = State::new();

    let mut builder = Builder::new(
        driver,
        usb_cfg,
        &mut cfg_desc,
        &mut bos_desc,
        &mut [],
        &mut ctl_buf,
    );

    let class = CdcAcmClass::new(&mut builder, &mut cdc_st, CDC_PKT as u16);
    let mut usb = builder.build();

    let transport = CdcTransport { class };
    let handler = FirmwareHandler { leds };
    let mut node = Node::with_handler(transport, rng, MCU_SECRET, VPS_PUB, handler);

    let usb_fut = usb.run();
    let fips_fut = node.run();

    join(usb_fut, fips_fut).await;
}
