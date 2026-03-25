#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Ipv6Address, Ipv6Cidr, Stack, StackResources, StaticConfigV6};
use embassy_net::Config as NetConfig;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::time::Hertz;
use embassy_stm32::usb::Driver;
use embassy_stm32::{bind_interrupts, peripherals, usb, Config};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::Builder;
use embassy_time::{Duration, Timer};
use static_cell::StaticCell;

use {defmt_rtt as _, panic_probe as _};

mod slip;
mod slip_net;
mod identity;
mod noise;

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
});

const MCU_IPV6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const FIPS_UDP_PORT: u16 = 2121;

static NET_RESOURCES: StaticCell<StackResources<2>> = StaticCell::new();

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    info!("microfips starting...");

    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hse = Some(Hse {
            freq: Hertz(8_000_000),
            mode: HseMode::Bypass,
        });
        config.rcc.pll_src = PllSource::HSE;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL168,
            divp: Some(PllPDiv::DIV2),
            divq: Some(PllQDiv::DIV7),
            divr: None,
        });
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.sys = Sysclk::PLL1_P;
        config.rcc.mux.clk48sel = mux::Clk48sel::PLL1_Q;
    }
    let p = embassy_stm32::init(config);

    let mut led = Output::new(p.PG6, Level::Low, Speed::Low);

    let mut ep_out_buffer = [0u8; 256];
    let mut usb_config = embassy_stm32::usb::Config::default();
    usb_config.vbus_detection = false;

    let driver = Driver::new_fs(p.USB_OTG_FS, Irqs, p.PA12, p.PA11, &mut ep_out_buffer, usb_config);

    let mut usb_config = embassy_usb::Config::new(0xc0de, 0xcafe);
    usb_config.manufacturer = Some("Amperstrand");
    usb_config.product = Some("microfips");
    usb_config.serial_number = Some("stm32f469i-disc");

    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];
    let mut cdc_state = State::new();

    let mut builder = Builder::new(
        driver,
        usb_config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut [],
        &mut control_buf,
    );

    let mut class = CdcAcmClass::new(&mut builder, &mut cdc_state, 64);

    let mut usb = builder.build();

    let mut net_state = slip_net::SlipNetState::<3, 3>::new();
    let (net_device, mut net_runner) = slip_net::new(&mut net_state);

    let net_config = NetConfig::ipv6_static(StaticConfigV6 {
        address: Ipv6Cidr::new(MCU_IPV6, 64),
        gateway: None,
        dns_servers: heapless::Vec::new(),
    });

    let net_resources = NET_RESOURCES.init(StackResources::new());
    let (stack, mut net_stack_runner) = embassy_net::new(net_device, net_config, net_resources, 0xdeadbeefcafe);

    let usb_fut = usb.run();

    let blink_fut = async {
        loop {
            led.set_high();
            Timer::after(Duration::from_millis(500)).await;
            led.set_low();
            Timer::after(Duration::from_millis(500)).await;
        }
    };

    let udp_fut = udp_echo_task(stack);

    let net_fut = async {
        join(
            net_stack_runner.run(),
            join(net_runner.run(&mut class), udp_fut),
        )
        .await;
    };

    join(usb_fut, join(blink_fut, net_fut)).await;
}

async fn udp_echo_task(stack: Stack<'static>) {
    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx_buffer = [0u8; 1024];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_buffer = [0u8; 1024];

    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buffer, &mut tx_meta, &mut tx_buffer);
    socket.bind(FIPS_UDP_PORT).unwrap();
    info!("UDP echo listening on port {}", FIPS_UDP_PORT);

    let mut buf = [0u8; 1024];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, meta)) => {
                info!("UDP rx {} bytes from {}", len, meta.endpoint);
                if let Err(e) = socket.send_to(&buf[..len], meta.endpoint).await {
                    warn!("UDP tx error: {:?}", e);
                }
            }
            Err(e) => {
                warn!("UDP recv error: {:?}", e);
            }
        }
    }
}
