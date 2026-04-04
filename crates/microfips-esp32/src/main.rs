#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

mod config;
mod handler;
mod led;
mod rng;
mod stats;
mod uart_transport;
#[cfg(feature = "wifi")]
mod wifi_transport;

#[cfg(feature = "ble")]
mod ble_host;
#[cfg(feature = "ble")]
mod ble_transport;

use core::panic::PanicInfo;

use esp_hal::gpio::{Level, Output};
use esp_hal::rng::{Trng, TrngSource};
#[cfg(all(not(feature = "ble"), not(feature = "wifi")))]
use esp_hal::uart::{Config, RxConfig, Uart};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_protocol::node::Node;
use rand_core::RngCore;

#[cfg(feature = "ble")]
use crate::ble_transport::BleTransport;
use crate::config::{ESP32_SECRET, PANIC_BLINK_CYCLES};
#[cfg(all(not(feature = "ble"), not(feature = "wifi")))]
use crate::config::{UART_BAUDRATE, UART_FIFO_THRESHOLD};
use crate::handler::{build_demo_fsp, EspHandler};
use crate::led::Led;
use crate::rng::EspRng;
#[cfg(all(not(feature = "ble"), not(feature = "wifi")))]
use crate::uart_transport::UartTransport;
#[cfg(feature = "wifi")]
use crate::wifi_transport::build_wifi_transport;

#[cfg(all(feature = "ble", feature = "wifi"))]
compile_error!("features `ble` and `wifi` are mutually exclusive");

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

    let mut responder_ephemeral = [0u8; 32];
    trng.fill_bytes(&mut responder_ephemeral);
    let mut initiator_ephemeral = [0u8; 32];
    trng.fill_bytes(&mut initiator_ephemeral);

    #[cfg(all(not(feature = "ble"), not(feature = "wifi")))]
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
        let fsp = build_demo_fsp(responder_ephemeral, initiator_ephemeral);
        let mut handler = EspHandler { led: &mut led, fsp };
        node.run(&mut handler).await;
    }

    #[cfg(feature = "wifi")]
    {
        esp_println::println!("[microfips] WiFi mode starting");
        let transport = build_wifi_transport(_spawner, peripherals.WIFI, &mut trng).await;
        let rng = EspRng(trng);
        let mut node = Node::new(transport, rng, ESP32_SECRET, DEFAULT_PEER_PUB);
        node.set_raw_framing(true);
        let fsp = build_demo_fsp(responder_ephemeral, initiator_ephemeral);
        let mut handler = EspHandler { led: &mut led, fsp };
        esp_println::println!("[microfips] Node running over WiFi...");
        node.run(&mut handler).await;
    }

    #[cfg(feature = "ble")]
    {
        esp_println::println!("[microfips] BLE mode starting");
        let transport = BleTransport::new();
        let rng = EspRng(trng);
        let mut node = Node::new(transport, rng, ESP32_SECRET, DEFAULT_PEER_PUB);
        let fsp = build_demo_fsp(responder_ephemeral, initiator_ephemeral);
        let mut handler = EspHandler { led: &mut led, fsp };
        esp_println::println!("[microfips] Node running...");
        node.run(&mut handler).await;
    }
}
