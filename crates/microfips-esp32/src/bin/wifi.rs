#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::panic::PanicInfo;

use esp_hal::gpio::Level;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use microfips_core::identity::VPS_PEER_PUB;
use microfips_protocol::node::Node;
use rand_core::RngCore;

use microfips_esp32::control;
use microfips_esp32::config::{ESP32_SECRET, PANIC_BLINK_CYCLES};
use microfips_esp32::handler::{build_demo_fsp, EspHandler};
use microfips_esp32::led::Led;
use microfips_esp32::logger;
use microfips_esp_transport::node_info::NodeIdentity;
use microfips_esp32::rng::EspRng;
use microfips_esp32::wifi_transport::build_wifi_transport;

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
async fn main(spawner: embassy_executor::Spawner) {
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

    let identity = NodeIdentity::from_secret(&ESP32_SECRET);
    logger::init();
    log::info!("WiFi mode starting");

    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let transport = build_wifi_transport(spawner, peripherals.WIFI, &mut trng).await;

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32_SECRET, VPS_PEER_PUB);
    node.set_raw_framing(true);

    let fsp = build_demo_fsp(resp_eph, init_eph, 1u64.to_le_bytes());
    let mut handler = EspHandler { led: &mut led, fsp };

    control::init_control(&identity, "wifi");
    spawner.spawn(control::control_task()).ok();

    log::info!("Node running over WiFi...");
    node.run(&mut handler).await;
}
