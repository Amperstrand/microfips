#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::panic::PanicInfo;

use esp_hal::rng::{Trng, TrngSource};
use esp_hal::{interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};

use microfips_esp32s3::config::ESP32S3_SECRET;
use microfips_esp32s3::logger;
use microfips_esp32s3::rng::EspRng;
use microfips_esp32s3::wifi_transport::build_wifi_transport;

struct EspHandler;

impl NodeHandler for EspHandler {
    async fn on_event(&mut self, event: NodeEvent) {
        log::info!("event: {:?}", event);
    }

    fn on_message(&mut self, _msg_type: u8, _payload: &[u8], _resp: &mut [u8]) -> HandleResult {
        HandleResult::None
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    let _sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut trng = Trng::try_new().unwrap();

    logger::init();
    log::info!("WiFi mode starting");

    let transport = build_wifi_transport(spawner, peripherals.WIFI, &mut trng).await;

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, ESP32S3_SECRET, DEFAULT_PEER_PUB);
    node.set_raw_framing(true);

    let mut handler = EspHandler;
    log::info!("Node running over WiFi...");
    node.run(&mut handler).await;
}
