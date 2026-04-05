#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::panic::PanicInfo;

use esp_hal::gpio::Level;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::uart::{Config, RxConfig, Uart};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_protocol::node::Node;
use microfips_protocol::transport::Transport;
use rand_core::RngCore;

mod config;
mod handler;
mod led;
mod rng;
mod stats;
mod uart_transport;

#[cfg(feature = "ble")]
mod ble_host;
#[cfg(feature = "ble")]
mod ble_transport;
#[cfg(feature = "l2cap")]
mod l2cap_host;
#[cfg(feature = "l2cap")]
mod l2cap_transport;

use config::{
    ESP32_SECRET, PANIC_BLINK_CYCLES, RECV_RETRY_DELAY_MS, UART_BAUDRATE, UART_FIFO_THRESHOLD,
};
use handler::{build_demo_fsp, EspHandler};
use led::Led;
use rng::EspRng;
use uart_transport::UartTransport;

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

    #[cfg(any(feature = "ble", feature = "l2cap"))]
    esp_println::println!("[microfips] main started");

    let mut led = Led(esp_hal::gpio::Output::new(
        peripherals.GPIO2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut trng = Trng::try_new().unwrap();
    #[cfg(any(feature = "ble", feature = "l2cap"))]
    esp_println::println!("[microfips] trng ready");

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

        let fsp = build_demo_fsp(resp_eph, init_eph);
        let mut handler = EspHandler { led: &mut led, fsp };

        node.run(&mut handler).await;
    }

    #[cfg(feature = "ble")]
    {
        esp_println::println!("[microfips] BLE mode starting");

        let transport = ble_transport::BleTransport::new();

        esp_println::println!(
            "[microfips] BLE advertising as '{}'",
            config::BLE_DEVICE_NAME
        );

        let rng = EspRng(trng);
        let mut node = Node::new(transport, rng, ESP32_SECRET, DEFAULT_PEER_PUB);

        let fsp = build_demo_fsp(resp_eph, init_eph);
        let mut handler = EspHandler { led: &mut led, fsp };

        esp_println::println!("[microfips] Node running...");
        node.run(&mut handler).await;
    }

    #[cfg(feature = "l2cap")]
    {
        esp_println::println!("[microfips] L2CAP mode starting");

        let mut transport = l2cap_transport::L2capTransport::new();
        if transport.wait_ready().await.is_err() {
            esp_println::println!("[microfips] ERROR: L2CAP transport init failed");
            loop {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RECV_RETRY_DELAY_MS,
                ))
                .await;
            }
        }

        let peer_pub = transport.peer_pub();
        esp_println::println!("[microfips] pubkey exchange complete");

        let rng = EspRng(trng);
        let mut node = Node::new(transport, rng, ESP32_SECRET, peer_pub);
        node.set_raw_framing(true);

        let fsp = build_demo_fsp(resp_eph, init_eph);
        let mut handler = EspHandler { led: &mut led, fsp };

        esp_println::println!("[microfips] Node running (L2CAP)...");
        node.run(&mut handler).await;
    }
}
