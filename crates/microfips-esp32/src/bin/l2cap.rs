#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::panic::PanicInfo;

use esp_hal::gpio::Level;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use microfips_protocol::node::Node;
use microfips_protocol::transport::Transport;
use rand_core::RngCore;

use microfips_esp32::config::{ESP32_SECRET, PANIC_BLINK_CYCLES, RECV_RETRY_DELAY_MS};
use microfips_esp32::handler::{build_demo_fsp, EspHandler};
use microfips_esp32::l2cap_transport::L2capTransport;
use microfips_esp32::led::Led;
use microfips_esp32::rng::EspRng;

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

    esp_println::println!("[microfips] L2CAP mode starting");

    let mut led = Led(esp_hal::gpio::Output::new(
        peripherals.GPIO2,
        Level::Low,
        esp_hal::gpio::OutputConfig::default(),
    ));

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut trng = Trng::try_new().unwrap();
    esp_println::println!("[microfips] trng ready");

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let mut transport = L2capTransport::new();
    if transport.wait_ready().await.is_err() {
        esp_println::println!("[microfips] ERROR: L2CAP transport init failed");
        loop {
            embassy_time::Timer::after(embassy_time::Duration::from_millis(
                RECV_RETRY_DELAY_MS,
            ))
            .await;
        }
    }
    esp_println::println!("[microfips] L2CAP transport ready");

    let peer_pub = match transport.take_peer_pub() {
        Some(pk) => pk,
        None => {
            esp_println::println!("[microfips] ERROR: no peer pubkey from exchange");
            loop {
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RECV_RETRY_DELAY_MS,
                ))
                .await;
            }
        }
    };
    esp_println::println!("[microfips] pubkey exchange complete; starting node");

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_SECRET, peer_pub);
    node.set_raw_framing(true);

    let fsp = build_demo_fsp(resp_eph, init_eph);
    let mut handler = EspHandler { led: &mut led, fsp };

    esp_println::println!("[microfips] Node running (L2CAP)...");
    node.run(&mut handler).await;
}
