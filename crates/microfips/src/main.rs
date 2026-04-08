#![no_std]
#![no_main]

mod cdc_transport;
mod config;
mod handler;
mod led;
mod rng;
mod stats;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::rng::Rng;
use embassy_stm32::usb::Driver;
use embassy_stm32::{bind_interrupts, peripherals, rng as stm32_rng, usb, Config};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::Builder;
use static_cell::StaticCell;

use microfips_core::identity::{STM32_SECRET, VPS_PEER_PUB};
use microfips_http_demo::DemoService;
use microfips_protocol::fsp_handler::FspDualHandler;
use microfips_protocol::node::Node;
use microfips_service::FspServiceAdapter;

use crate::cdc_transport::CdcTransport;
use crate::config::*;
use crate::handler::FipsHandler;
use crate::led::Leds;
use crate::rng::HwRng;
use crate::stats::{PANIC_LINE, STAT_STATE};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        PANIC_LINE.store(loc.line(), Ordering::Relaxed);
    }
    STAT_STATE.store(S_ERR, Ordering::Relaxed);
    loop {
        cortex_m::asm::delay(PANIC_BLINK_CYCLES);
        cortex_m::asm::delay(PANIC_BLINK_CYCLES);
    }
}

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    HASH_RNG => stm32_rng::InterruptHandler<peripherals::RNG>;
});

static GLOBAL_RNG: StaticCell<Rng<'static, peripherals::RNG>> = StaticCell::new();
static EP_OUT_BUF: StaticCell<[u8; 1024]> = StaticCell::new();

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

    let mut resp_eph = [0u8; 32];
    rng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    rng.fill_bytes(&mut init_eph);

    leds.blink_green_once();

    let ep_out_buf = EP_OUT_BUF.init([0u8; 1024]);
    let mut usb_cfg = embassy_stm32::usb::Config::default();
    usb_cfg.vbus_detection = false;

    let driver = Driver::new_fs(p.USB_OTG_FS, Irqs, p.PA12, p.PA11, ep_out_buf, usb_cfg);

    let mut usb_cfg = embassy_usb::Config::new(0xc0de, 0xcafe);
    usb_cfg.manufacturer = Some("Amperstrand");
    usb_cfg.product = Some("microfips");
    usb_cfg.serial_number = Some("stm32f469i-disc");

    let mut cfg_desc = [0; USB_DESC_BUF_SIZE];
    let mut bos_desc = [0; USB_DESC_BUF_SIZE];
    let mut ctl_buf = [0; USB_CTL_BUF_SIZE];
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
    let mut node = Node::new(transport, hw_rng, STM32_SECRET, VPS_PEER_PUB);
    let mut handler = FipsHandler {
        leds: &mut leds,
        fsp: FspDualHandler::new_dual(
            STM32_SECRET,
            resp_eph,
            init_eph,
            &ESP32_PEER_PUB,
            ESP32_NODE_ADDR,
            1u64.to_le_bytes(),
            FspServiceAdapter::new(DemoService::new()),
        ),
    };

    let usb_fut = usb.run();
    let fips_fut = node.run(&mut handler);

    join(usb_fut, fips_fut).await;
}
