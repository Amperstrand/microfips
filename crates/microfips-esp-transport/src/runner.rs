use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::rng::{Trng, TrngSource};
use rand_core::RngCore;

use microfips_core::identity::{STM32_NODE_ADDR, STM32_NPUB};
use microfips_protocol::node::Node;

use crate::config::DEVICE_NSEC;
use crate::handler::build_demo_fsp;
use crate::led::Led;
use crate::rng::EspRng;

#[derive(Default)]
pub struct NodeOpts {
    pub raw_framing: bool,
    pub peer_sent_first: bool,
}

pub fn make_led(gpio2: esp_hal::peripherals::GPIO2<'static>) -> Led {
    Led(Output::new(gpio2, Level::Low, OutputConfig::default()))
}

pub fn init_trng(
    rng_periph: esp_hal::peripherals::RNG<'static>,
    adc1: esp_hal::peripherals::ADC1<'static>,
) -> (TrngSource<'static>, Trng) {
    let trng_source = TrngSource::new(rng_periph, adc1);
    let trng = Trng::try_new().unwrap();
    (trng_source, trng)
}

pub async fn run_node<T: microfips_protocol::transport::Transport>(
    transport: T,
    _trng_source: TrngSource<'static>,
    mut trng: Trng,
    led: &mut Led,
    peer_pub: [u8; 33],
    opts: NodeOpts,
) -> ! {
    let mut resp_eph = [0u8; 32];
    trng.fill_bytes(&mut resp_eph);
    let mut init_eph = [0u8; 32];
    trng.fill_bytes(&mut init_eph);

    let rng = EspRng(trng);
    let mut node = Node::new(transport, rng, DEVICE_NSEC, peer_pub);

    if opts.raw_framing {
        node.set_raw_framing(true);
    }
    if opts.peer_sent_first {
        node.set_peer_sent_first(true);
    }

    let fsp = build_demo_fsp(
        &DEVICE_NSEC,
        resp_eph,
        init_eph,
        &STM32_NPUB,
        STM32_NODE_ADDR,
        1u64.to_le_bytes(),
    );
    let mut handler = crate::handler::SharedEspHandler { led, fsp };

    node.run(&mut handler).await;
    #[allow(unreachable_code)]
    #[allow(clippy::empty_loop)]
    loop {}
}
