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
use embassy_time::{Duration, Timer};
use embassy_usb::Builder;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use static_cell::StaticCell;

use microfips_core::fmp;
use microfips_core::fsp::{FspSession, handle_fsp_datagram};
use microfips_core::identity::{DEFAULT_PEER_PUB, DEFAULT_SECRET};
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;

static PANIC_LINE: AtomicU32 = AtomicU32::new(0);
#[used]
static _PANIC_LINE_KEEP: &AtomicU32 = &PANIC_LINE;

#[used]
static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_USB_ERR: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_STATE: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_RECV_PKT: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_DATA_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_DATA_TX: AtomicU32 = AtomicU32::new(0);

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

static GLOBAL_RNG: StaticCell<Rng<'static, peripherals::RNG>> = StaticCell::new();
static EP_OUT_BUF: StaticCell<[u8; 1024]> = StaticCell::new();

// ---------------------------------------------------------------------------
// Transport adapter: wraps CDC ACM class for the protocol crate's Transport trait
// ---------------------------------------------------------------------------

struct CdcTransport<'d> {
    class: &'d mut CdcAcmClass<'d, Driver<'d, peripherals::USB_OTG_FS>>,
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
            match self.class.write_packet(&data[off..end]).await {
                Ok(()) => {}
                Err(e) => {
                    STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }
            off = end;
        }
        if !data.is_empty() && data.len().is_multiple_of(CDC_PKT) {
            self.class.write_packet(&[]).await.inspect_err(|_| {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
            })?;
        }
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.class.read_packet(buf).await {
            Ok(n) => {
                STAT_RECV_PKT.fetch_add(1, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RNG adapter: wraps embassy hardware RNG for rand_core traits
// ---------------------------------------------------------------------------

struct HwRng(&'static mut Rng<'static, peripherals::RNG>);

impl rand_core::RngCore for HwRng {
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

impl rand_core::CryptoRng for HwRng {}

// ---------------------------------------------------------------------------
// LED state machine (hardware-specific, kept in firmware)
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

// ---------------------------------------------------------------------------
// NodeHandler: bridges protocol events to LEDs, stats, and app logic
// ---------------------------------------------------------------------------

struct FipsHandler<'a> {
    leds: &'a mut Leds,
    fsp_session: FspSession,
    fsp_ephemeral: [u8; 32],
    fsp_epoch: [u8; 8],
}

impl NodeHandler for FipsHandler<'_> {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => {
                self.leds.set_state(S_USB_READY);
            }
            NodeEvent::Msg1Sent => {
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_MSG1_SENT);
                embassy_futures::yield_now().await;
            }
            NodeEvent::HandshakeOk => {
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HANDSHAKE_OK);
                self.fsp_session.reset();
                self.fsp_epoch = [0x01, 0, 0, 0, 0, 0, 0, 0];
                Timer::after(Duration::from_millis(500)).await;
            }
            NodeEvent::HeartbeatSent => {
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HB_TX);
                self.leds.set_state(S_HANDSHAKE_OK);
            }
            NodeEvent::HeartbeatRecv => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HB_RX);
            }
            NodeEvent::Disconnected => {
                self.leds.set_state(S_DISCONNECTED);
            }
            NodeEvent::Error => {
                self.leds.set_state(S_ERR);
            }
        }
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        STAT_DATA_RX.fetch_add(1, Ordering::Relaxed);
        match handle_fsp_datagram(
            &mut self.fsp_session,
            &DEFAULT_SECRET,
            &self.fsp_ephemeral,
            &self.fsp_epoch,
            payload,
            resp,
        ) {
            Ok(microfips_core::fsp::FspHandlerResult::None) => HandleResult::None,
            Ok(microfips_core::fsp::FspHandlerResult::SendDatagram(len)) => {
                STAT_DATA_TX.fetch_add(1, Ordering::Relaxed);
                HandleResult::SendDatagram(len)
            }
            Err(_) => HandleResult::None,
        }
    }
}

// ---------------------------------------------------------------------------
// Main entry point
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

    let rng = GLOBAL_RNG.init(Rng::new(p.RNG, Irqs));

    let mut fsp_ephemeral = [0u8; 32];
    rng.fill_bytes(&mut fsp_ephemeral);

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

    let mut class = CdcAcmClass::new(&mut builder, &mut cdc_st, CDC_PKT as u16);
    let mut usb = builder.build();

    leds.blink_green_once();

    let transport = CdcTransport { class: &mut class };
    let hw_rng = HwRng(rng);
    let mut node = Node::new(transport, hw_rng, DEFAULT_SECRET, DEFAULT_PEER_PUB);
    let mut handler = FipsHandler {
        leds: &mut leds,
        fsp_session: FspSession::new(),
        fsp_ephemeral,
        fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
    };

    let usb_fut = usb.run();
    let fips_fut = node.run(&mut handler);

    join(usb_fut, fips_fut).await;
}
