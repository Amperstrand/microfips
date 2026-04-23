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
use rand_core::RngCore;

use microfips_esp32s3::config::{ESP32S3_SECRET, PANIC_BLINK_CYCLES, UART_BAUDRATE, UART_FIFO_THRESHOLD};
use microfips_esp32s3::handler::{build_demo_fsp, EspHandler};
use microfips_esp32s3::led::Led;
use microfips_esp32s3::rng::EspRng;
use microfips_esp32s3::uart_transport::UartTransport;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let gpio = unsafe { &*esp_hal::peripherals::GPIO::PTR };
    loop {
        gpio.out_w1ts().write(|w| unsafe { w.out_w1ts().bits(1 << 2) });
        for _ in 0..PANIC_BLINK_CYCLES {
            core::hint::spin_loop();
        }
        gpio.out_w1tc().write(|w| unsafe { w.out_w1tc().bits(1 << 2) });
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

    let mut led = Led(esp_hal::gpio::Output::new(
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

    let uart_config = Config::default()
        .with_rx(RxConfig::default().with_fifo_full_threshold(UART_FIFO_THRESHOLD))
        .with_baudrate(UART_BAUDRATE);
    let uart = Uart::new(peripherals.UART0, uart_config)
        .unwrap()
        .with_tx(peripherals.GPIO43)
        .with_rx(peripherals.GPIO44)
        .into_async();
    let (rx, tx) = uart.split();
    let transport = UartTransport { tx, rx };

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32S3_SECRET, DEFAULT_PEER_PUB);

    let fsp = build_demo_fsp(resp_eph, init_eph);
    let mut handler = EspHandler { led: &mut led, fsp };

    node.run(&mut handler).await;
}
