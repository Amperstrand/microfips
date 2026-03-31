#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::ToString;

esp_bootloader_esp_idf::esp_app_desc!();

use embassy_net::StackResources;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_println as _;
use esp_println::println;
use esp_radio::wifi::{ClientConfig, Config as WifiConfig, ModeConfig, WifiController, WifiDevice};

use microfips_core::noise;

include!(concat!(env!("OUT_DIR"), "/secrets.rs"));

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.uninit().write($val)
    }};
}

#[embassy_executor::task]
async fn wifi_connection_task(mut controller: WifiController<'static>) {
    println!("WiFi: connection task started");
    loop {
        println!("WiFi: about to connect...");
        match controller.connect_async().await {
            Ok(()) => {
                println!("WiFi: connected");
                let _ = controller.disconnect_async().await;
                println!("WiFi: disconnected");
            }
            Err(e) => {
                println!("WiFi: connect failed {:?}", e);
            }
        }
        Timer::after(Duration::from_secs(5)).await;
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, WifiDevice<'static>>) {
    runner.run().await;
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    esp_alloc::heap_allocator!(#[ram(reclaimed)] size: 64 * 1024);
    esp_alloc::heap_allocator!(size: 36 * 1024);

    println!("=== microfips-esp32 WiFi test ===");
    println!("WIFI_SSID={:?} FIPS_HOST={:?}", WIFI_SSID, FIPS_HOST);

    let my_pub = noise::ecdh_pubkey(&DEVICE_SECRET).unwrap();
    println!("DEVICE pubkey: {:02x?}", &my_pub[..8]);

    let radio = mk_static!(esp_radio::Controller, esp_radio::init().expect("esp_radio::init failed"));

    let client_config = ClientConfig::default()
        .with_ssid(WIFI_SSID.to_string())
        .with_password(WIFI_PASS.to_string());
    let mode_config = ModeConfig::Client(client_config);
    let wifi_config = WifiConfig::default();

    println!("WiFi: initializing...");
    let (mut wifi_ctrl, interfaces) = esp_radio::wifi::new(
        radio,
        peripherals.WIFI,
        wifi_config,
    ).expect("wifi::new failed");

    wifi_ctrl.set_config(&mode_config).expect("set_config failed");
    println!("WiFi: calling start_async...");
    wifi_ctrl.start_async().await.expect("start_async failed");
    println!("WiFi: started");

    let wifi_interface = interfaces.sta;

    let net_config = embassy_net::Config::dhcpv4(Default::default());
    let rng = Rng::new();
    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (stack, runner) = embassy_net::new(
        wifi_interface,
        net_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    spawner.spawn(wifi_connection_task(wifi_ctrl)).expect("spawn connection task");
    spawner.spawn(net_task(runner)).expect("spawn net task");

    println!("WiFi: waiting for DHCP...");
    stack.wait_config_up().await;

    if let Some(config) = stack.config_v4() {
        println!("WiFi: GOT IP: {}", config.address);
    }

    println!("WiFi: milestone 1 COMPLETE -- connected + DHCP");

    loop {
        Timer::after(Duration::from_secs(10)).await;
    }
}
