#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use defmt::*;
use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Ipv6Address, Ipv6Cidr, Stack, StackResources, StaticConfigV6};
use embassy_net::Config as NetConfig;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::rng::Rng;
use embassy_stm32::time::Hertz;
use embassy_stm32::usb::Driver;
use embassy_stm32::{bind_interrupts, peripherals, rng, usb, Config};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::Builder;
use embassy_time::{Duration, Timer};
use smoltcp::wire::{IpEndpoint, Ipv6Address as SmoltcpIpv6};
use static_cell::StaticCell;

use {defmt_rtt as _, panic_probe as _};

mod slip_net;

use microfips_core::fmp;
use microfips_core::noise;

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

const MCU_IPV6: Ipv6Address = Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const FIPS_UDP_PORT: u16 = 2121;
const HEARTBEAT_INTERVAL_SECS: u64 = 10;
const HANDSHAKE_RETRY_SECS: u64 = 5;

const MCU_SECRET: [u8; 32] = [
    0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4,
    0xee, 0xb5, 0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7,
    0x84, 0x3f, 0x83, 0x2e,
];

const VPS_PUB: [u8; 33] = [
    0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4,
    0xf5, 0x73, 0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a,
    0x2a, 0x3a, 0x03, 0x7d, 0x21,
];

static NET_RESOURCES: StaticCell<StackResources<2>> = StaticCell::new();
static GLOBAL_RNG: StaticCell<Rng<'static, peripherals::RNG>> = StaticCell::new();
static SEND_COUNTER: AtomicU32 = AtomicU32::new(0);

fn timestamp_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

fn next_send_counter() -> u64 {
    SEND_COUNTER.fetch_add(1, Ordering::Relaxed) as u64
}

fn vps_endpoint() -> IpEndpoint {
    IpEndpoint::new(
        embassy_net::IpAddress::Ipv6(SmoltcpIpv6::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
        FIPS_UDP_PORT,
    )
}

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

    let rng = GLOBAL_RNG.init(Rng::new(p.RNG, Irqs));

    let mut led = Output::new(p.PG6, Level::Low, Speed::Low);

    let my_pub = noise::ecdh_pubkey(&MCU_SECRET).unwrap();
    info!("MCU pubkey: {:02x}", my_pub);

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

    let fips_fut = fips_link_task(stack, rng);

    let net_fut = async {
        join(
            net_stack_runner.run(),
            join(net_runner.run(&mut class), fips_fut),
        )
        .await;
    };

    join(usb_fut, join(blink_fut, net_fut)).await;
}

#[derive(Debug, Clone, Copy)]
enum LinkError {
    SendFailed,
    RecvTimeout,
    InvalidMessage,
    DecryptFailed,
    PeerDisconnected,
}

impl defmt::Format for LinkError {
    fn format(&self, f: defmt::Formatter) {
        match self {
            LinkError::SendFailed => defmt::write!(f, "SendFailed"),
            LinkError::RecvTimeout => defmt::write!(f, "RecvTimeout"),
            LinkError::InvalidMessage => defmt::write!(f, "InvalidMessage"),
            LinkError::DecryptFailed => defmt::write!(f, "DecryptFailed"),
            LinkError::PeerDisconnected => defmt::write!(f, "PeerDisconnected"),
        }
    }
}

async fn fips_link_task(stack: Stack<'static>, rng: &'static mut Rng<'static, peripherals::RNG>) {
    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx_buffer = [0u8; 2048];
    let mut tx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_buffer = [0u8; 2048];

    let mut socket = UdpSocket::new(stack, &mut rx_meta, &mut rx_buffer, &mut tx_meta, &mut tx_buffer);
    socket.bind(FIPS_UDP_PORT).unwrap();
    info!("FIPS link task listening on UDP :{}", FIPS_UDP_PORT);

    let my_pub = noise::ecdh_pubkey(&MCU_SECRET).unwrap();

    loop {
        info!("Starting FIPS handshake...");
        match do_handshake(&my_pub, rng, &mut socket).await {
            Ok((k_send, k_recv, their_idx, our_idx)) => {
                info!("Handshake OK! their_idx={:08x} our_idx={:08x}", their_idx, our_idx);

                let result = steady_state(&k_send, &k_recv, their_idx, our_idx, &mut socket).await;
                match result {
                    Ok(()) => info!("Peer disconnected gracefully"),
                    Err(e) => warn!("Peer session ended: {}", e),
                }

                info!("Session ended, retrying in {}s", HANDSHAKE_RETRY_SECS);
                Timer::after(Duration::from_secs(HANDSHAKE_RETRY_SECS)).await;
            }
            Err(e) => {
                warn!("Handshake failed: {}, retrying in {}s", e, HANDSHAKE_RETRY_SECS);
                Timer::after(Duration::from_secs(HANDSHAKE_RETRY_SECS)).await;
            }
        }
    }
}

async fn do_handshake(
    my_pub: &[u8; 33],
    rng: &mut Rng<'static, peripherals::RNG>,
    socket: &mut UdpSocket<'_>,
) -> Result<([u8; 32], [u8; 32], u32, u32), LinkError> {
    let mut eph_bytes = [0u8; 32];
    rng.fill_bytes(&mut eph_bytes);

    let (mut state, e_pub) = noise::NoiseIkInitiator::new(&eph_bytes, &MCU_SECRET, &VPS_PUB)
        .map_err(|_| LinkError::InvalidMessage)?;
    info!("Ephemeral pubkey: {:02x}", e_pub);

    let epoch: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let mut noise_msg1 = [0u8; 256];
    let noise_len = state
        .write_message1(my_pub, &epoch, &mut noise_msg1)
        .map_err(|_| LinkError::InvalidMessage)?;
    info!("Noise msg1: {} bytes", noise_len);

    let mut fmp_msg1 = [0u8; 256];
    let fmp_len = fmp::build_msg1(0, &noise_msg1[..noise_len], &mut fmp_msg1);

    let ep = vps_endpoint();
    info!("Sending FMP msg1 to {}", ep);
    socket.send_to(&fmp_msg1[..fmp_len], ep).await.map_err(|_| LinkError::SendFailed)?;

    let mut recv_buf = [0u8; 2048];
    let (len, _meta) = socket.recv_from(&mut recv_buf).await.map_err(|_| LinkError::RecvTimeout)?;

    info!("Received {} bytes", len);

    let msg = fmp::parse_message(&recv_buf[..len]).ok_or(LinkError::InvalidMessage)?;
    match msg {
        fmp::FmpMessage::Msg2 {
            sender_idx,
            receiver_idx,
            noise_payload,
        } => {
            info!("Got msg2: sender={:08x} receiver={:08x} noise={}B", sender_idx, receiver_idx, noise_payload.len());

            let received_epoch = state.read_message2(noise_payload).map_err(|_| LinkError::DecryptFailed)?;
            info!("Received epoch: {:02x}", received_epoch);

            let (k_send, k_recv) = state.finalize();
            info!("Transport keys derived");

            Ok((k_send, k_recv, sender_idx, receiver_idx))
        }
        _ => {
            warn!("Unexpected message type (not msg2)");
            Err(LinkError::InvalidMessage)
        }
    }
}

async fn steady_state(
    k_send: &[u8; 32],
    k_recv: &[u8; 32],
    their_idx: u32,
    our_idx: u32,
    socket: &mut UdpSocket<'_>,
) -> Result<(), LinkError> {
    let mut recv_buf = [0u8; 2048];

    loop {
        let hb = embassy_futures::select::select(
            Timer::after(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)),
            socket.recv_from(&mut recv_buf),
        )
        .await;

        match hb {
            embassy_futures::select::Either::First(()) => {
                if let Err(e) = send_heartbeat(k_send, their_idx, our_idx, socket).await {
                    warn!("Heartbeat failed: {}", e);
                }
            }
            embassy_futures::select::Either::Second(result) => {
                let (len, _meta) = result.map_err(|_| LinkError::RecvTimeout)?;
                match handle_fmp_frame(k_recv, &recv_buf[..len], our_idx) {
                    Ok(()) => {}
                    Err(LinkError::PeerDisconnected) => return Ok(()),
                    Err(e) => warn!("Frame error: {}", e),
                }
            }
        }
    }
}

async fn send_heartbeat(
    k_send: &[u8; 32],
    their_idx: u32,
    our_idx: u32,
    socket: &mut UdpSocket<'_>,
) -> Result<(), LinkError> {
    let msg_type = fmp::MSG_HEARTBEAT;
    let counter = next_send_counter();

    let mut out = [0u8; 256];
    let frame_len = fmp::build_established(
        our_idx,
        their_idx,
        0,
        msg_type,
        timestamp_ms(),
        &[],
        k_send,
        counter,
        &mut out,
    );

    info!("Heartbeat sent (counter={})", counter);
    socket.send_to(&out[..frame_len], vps_endpoint()).await.map_err(|_| LinkError::SendFailed)?;
    Ok(())
}

fn handle_fmp_frame(k_recv: &[u8; 32], data: &[u8], our_idx: u32) -> Result<(), LinkError> {
    let msg = fmp::parse_message(data).ok_or(LinkError::InvalidMessage)?;

    match msg {
        fmp::FmpMessage::Established {
            sender_idx: _,
            receiver_idx,
            epoch: _,
            encrypted,
        } => {
            if receiver_idx != our_idx {
                return Err(LinkError::InvalidMessage);
            }

            let outer_header = &data[..fmp::ESTABLISHED_HEADER_SIZE];
            let mut decrypted = [0u8; 2048];
            let dec_len = noise::aead_decrypt(k_recv, 0, outer_header, encrypted, &mut decrypted)
                .map_err(|_| LinkError::DecryptFailed)?;

            if dec_len < fmp::INNER_HEADER_SIZE {
                return Err(LinkError::InvalidMessage);
            }

            let _timestamp = u32::from_le_bytes(decrypted[..4].try_into().unwrap_or([0; 4]));
            let link_msg_type = decrypted[4];

            match link_msg_type {
                fmp::MSG_HEARTBEAT => {
                    info!("Heartbeat received");
                }
                fmp::MSG_DISCONNECT => {
                    info!("Disconnect received");
                    return Err(LinkError::PeerDisconnected);
                }
                t => {
                    info!("Link msg 0x{:02x} ({}B payload)", t, dec_len - 4);
                }
            }

            Ok(())
        }
        _ => Err(LinkError::InvalidMessage),
    }
}


