#![no_std]
#![no_main]

#[cfg(all(feature = "board-f469", feature = "board-f746"))]
compile_error!("Only one board feature can be enabled at a time");

mod cdc_transport;
mod config;
mod handler;
mod led;
mod rng;
mod stats;

#[cfg(feature = "board-f469")]
mod board_f469;
#[cfg(feature = "board-f746")]
mod board_f746;

#[cfg(feature = "board-f469")]
use board_f469 as board;
#[cfg(feature = "board-f746")]
use board_f746 as board;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::rng::Rng;
use embassy_stm32::usb::Driver;
use embassy_stm32::{bind_interrupts, peripherals, rng as stm32_rng, usb};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::Builder;
use static_cell::StaticCell;

use microfips_core::identity::{STM32_NSEC, VPS_NPUB};
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

#[cfg(feature = "board-f469")]
bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    HASH_RNG => stm32_rng::InterruptHandler<peripherals::RNG>;
});

#[cfg(feature = "board-f746")]
bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    RNG => stm32_rng::InterruptHandler<peripherals::RNG>;
});

static GLOBAL_RNG: StaticCell<Rng<'static, peripherals::RNG>> = StaticCell::new();
static EP_OUT_BUF: StaticCell<[u8; 1024]> = StaticCell::new();

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let p = embassy_stm32::init(board::clock_config());

    // After a soft reset (SYSRESETREQ from st-flash), the USB OTG FS peripheral
    // can retain stale PHY state that prevents re-enumeration. The BSP provides
    // a complete reset sequence (clock disable, peripheral reset, core soft reset,
    // PHY power-cycle) via reset_usb_phy().
    #[cfg(feature = "display")]
    embassy_stm32f469i_disco::reset_usb_phy();

    #[cfg(not(feature = "display"))]
    {
        let rcc = embassy_stm32::pac::RCC;

        rcc.ahb2enr().modify(|w| w.set_usb_otg_fsen(false));
        cortex_m::asm::delay(100);
        rcc.ahb2enr().modify(|w| w.set_usb_otg_fsen(true));

        rcc.ahb2rstr().modify(|w| w.set_usb_otg_fsrst(true));
        cortex_m::asm::delay(100);
        rcc.ahb2rstr().modify(|w| w.set_usb_otg_fsrst(false));
        cortex_m::asm::delay(100);

        let otg_global = 0x5000_0000usize as *mut u32;
        unsafe {
            let mut timeout = 100_000u32;
            while otg_global.add(0x010 / 4).read_volatile() & (1 << 31) == 0 {
                timeout -= 1;
                if timeout == 0 {
                    break;
                }
            }

            otg_global.add(0x010 / 4).write_volatile(1);
            timeout = 100_000u32;
            while otg_global.add(0x010 / 4).read_volatile() & 1 != 0 {
                timeout -= 1;
                if timeout == 0 {
                    break;
                }
            }

            otg_global.add(0x038 / 4).write_volatile(0);
            cortex_m::asm::delay(100);
            otg_global.add(0x038 / 4).write_volatile(1 << 16);
        }
    }

    // F746G-DISCO: PK3 = LCD_BL_CTRL. Drive LOW to turn off the LCD backlight.
    #[cfg(feature = "board-f746")]
    let _backlight = Output::new(p.PK3, Level::Low, Speed::Low);

    #[cfg(feature = "board-f469")]
    let mut leds = Leds {
        green: Output::new(p.PG6, Level::Low, Speed::Low),
        orange: Output::new(p.PD4, Level::Low, Speed::Low),
        red: Output::new(p.PD5, Level::Low, Speed::Low),
        blue: Output::new(p.PK3, Level::Low, Speed::Low),
    };

    #[cfg(feature = "board-f746")]
    let mut leds = Leds {
        green: Output::new(p.PI1, Level::Low, Speed::Low),
        orange: Output::new(p.PI2, Level::Low, Speed::Low),
        red: Output::new(p.PI3, Level::Low, Speed::Low),
        blue: Output::new(p.PG6, Level::Low, Speed::Low),
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
    usb_cfg.serial_number = Some(board::USB_SERIAL);

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
    let mut node = Node::new(transport, hw_rng, STM32_NSEC, VPS_NPUB);
    let mut handler = FipsHandler {
        leds: &mut leds,
        fsp: FspDualHandler::new_dual(
            STM32_NSEC,
            resp_eph,
            init_eph,
            &ESP32_NPUB,
            ESP32_NODE_ADDR,
            1u64.to_le_bytes(),
            FspServiceAdapter::new(DemoService::new()),
        ),
    };

    let usb_fut = usb.run();
    let fips_fut = node.run(&mut handler);

    join(usb_fut, fips_fut).await;
}
