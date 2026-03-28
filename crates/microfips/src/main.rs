#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use defmt_rtt as _;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_futures::yield_now;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::rng::Rng;
use embassy_stm32::usb::Driver;
use embassy_stm32::{Config, bind_interrupts, peripherals, rng, usb};
use embassy_time::{Duration, Timer};
use embassy_usb::Builder;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use static_cell::StaticCell;

use microfips_core::fmp;
use microfips_core::noise;
use noise::EPOCH_SIZE;

static PANIC_LINE: AtomicU32 = AtomicU32::new(0);
#[used]
static _PANIC_LINE_KEEP: &AtomicU32 = &PANIC_LINE;

static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
static STAT_USB_ERR: AtomicU32 = AtomicU32::new(0);
static STAT_STATE: AtomicU32 = AtomicU32::new(0);
static STAT_RECV_PKT: AtomicU32 = AtomicU32::new(0);
static STAT_RECV_FRAME: AtomicU32 = AtomicU32::new(0);

const S_BOOT: u32 = 0;
const S_USB_READY: u32 = 1;
const S_MSG1_SENT: u32 = 2;
const S_HANDSHAKE_OK: u32 = 3;
const S_HB_TX: u32 = 4;
const S_HB_RX: u32 = 5;
const S_ERR: u32 = 6;
const S_DISCONNECTED: u32 = 7;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(loc) = info.location() {
        PANIC_LINE.store(loc.line(), Ordering::Relaxed);
    }
    STAT_STATE.store(S_ERR, Ordering::Relaxed);
    loop {
        cortex_m::asm::delay(500_000);
        cortex_m::asm::delay(500_000);
    }
}

bind_interrupts!(struct Irqs {
    OTG_FS => usb::InterruptHandler<peripherals::USB_OTG_FS>;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

const HB_SECS: u64 = 10;
const RETRY_SECS: u64 = 3;
const CONNECT_DELAY_MS: u64 = 500;
const RECV_TIMEOUT_SECS: u64 = 10;
const CDC_PKT: usize = 64;

const MCU_SECRET: [u8; 32] = [
    0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4, 0xee, 0xb5,
    0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7, 0x84, 0x3f, 0x83, 0x2e,
];

const VPS_PUB: [u8; 33] = [
    0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4, 0xf5, 0x73,
    0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a, 0x2a, 0x3a, 0x03, 0x7d,
    0x21,
];

static GLOBAL_RNG: StaticCell<Rng<'static, peripherals::RNG>> = StaticCell::new();
static EP_OUT_BUF: StaticCell<[u8; 1024]> = StaticCell::new();
static SEND_COUNTER: AtomicU32 = AtomicU32::new(0);
static PRE_MSG1: StaticCell<[u8; fmp::MSG1_WIRE_SIZE]> = StaticCell::new();
static PRE_NOISE_ST: StaticCell<noise::NoiseIkInitiator> = StaticCell::new();

fn next_ctr() -> u64 {
    SEND_COUNTER.fetch_add(1, Ordering::Relaxed) as u64
}

struct Leds {
    green: Output<'static>,
    orange: Output<'static>,
    red: Output<'static>,
    blue: Output<'static>,
}

impl Leds {
    fn set_state(&mut self, state: u32) {
        STAT_STATE.store(state, Ordering::Relaxed);
        match state {
            S_BOOT => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            S_USB_READY => {
                self.green.set_high();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            S_MSG1_SENT => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_low();
            }
            S_HANDSHAKE_OK => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_high();
            }
            S_HB_TX => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_low();
                self.blue.set_low();
            }
            S_HB_RX => {
                self.green.set_high();
                self.orange.set_high();
                self.red.set_high();
                self.blue.set_high();
            }
            S_ERR => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_high();
                self.blue.set_low();
            }
            S_DISCONNECTED => {
                self.green.set_low();
                self.orange.set_low();
                self.red.set_low();
                self.blue.set_low();
            }
            _ => {}
        }
    }

    fn blink_green_once(&mut self) {
        self.green.set_high();
        cortex_m::asm::delay(8_000_000);
        self.green.set_low();
        cortex_m::asm::delay(8_000_000);
    }
}

#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.pll_src = PllSource::HSI;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV8,
            mul: PllMul::MUL168,
            divp: Some(PllPDiv::DIV2),
            divq: Some(PllQDiv::DIV7),
            divr: None,
        });
        config.rcc.sys = Sysclk::PLL1_P;
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.mux.clk48sel = mux::Clk48sel::PLL1_Q;
    }
    let p = embassy_stm32::init(config);

    let mut leds = Leds {
        green: Output::new(p.PG6, Level::Low, Speed::Low),
        orange: Output::new(p.PD4, Level::Low, Speed::Low),
        red: Output::new(p.PD5, Level::Low, Speed::Low),
        blue: Output::new(p.PK3, Level::Low, Speed::Low),
    };

    leds.blink_green_once();
    leds.blink_green_once();

    let rng = GLOBAL_RNG.init(Rng::new(p.RNG, Irqs));

    let my_pub = noise::ecdh_pubkey(&MCU_SECRET).unwrap();

    leds.blink_green_once();

    let mut eph = [0u8; 32];
    rng.fill_bytes(&mut eph);
    let (mut noise_st, _e_pub) =
        noise::NoiseIkInitiator::new(&eph, &MCU_SECRET, &VPS_PUB).expect("noise init");
    let epoch: [u8; EPOCH_SIZE] = [0x01, 0, 0, 0, 0, 0, 0, 0];
    let mut n1 = [0u8; 256];
    let n1len = noise_st
        .write_message1(&my_pub, &epoch, &mut n1)
        .expect("write_message1");
    let mut f1 = [0u8; 256];
    let f1len = fmp::build_msg1(0, &n1[..n1len], &mut f1);
    let pre_msg1: [u8; fmp::MSG1_WIRE_SIZE] = f1[..f1len].try_into().expect("msg1 size");
    let pre_msg1 = PRE_MSG1.init(pre_msg1);
    let pre_noise_st = PRE_NOISE_ST.init(noise_st);

    leds.blink_green_once();

    let ep_out_buf = EP_OUT_BUF.init([0u8; 1024]);
    let mut usb_cfg = embassy_stm32::usb::Config::default();
    usb_cfg.vbus_detection = false;

    let driver = Driver::new_fs(p.USB_OTG_FS, Irqs, p.PA12, p.PA11, ep_out_buf, usb_cfg);

    let mut usb_cfg = embassy_usb::Config::new(0xc0de, 0xcafe);
    usb_cfg.manufacturer = Some("Amperstrand");
    usb_cfg.product = Some("microfips");
    usb_cfg.serial_number = Some("stm32f469i-disc");

    let mut cfg_desc = [0; 256];
    let mut bos_desc = [0; 256];
    let mut ctl_buf = [0; 64];
    let mut cdc_st = State::new();

    let mut builder = Builder::new(
        driver,
        usb_cfg,
        &mut cfg_desc,
        &mut bos_desc,
        &mut [],
        &mut ctl_buf,
    );

    let mut class = CdcAcmClass::new(&mut builder, &mut cdc_st, CDC_PKT as u16);
    let mut usb = builder.build();

    let usb_fut = usb.run();
    let fips_fut = fips_task(&mut class, &mut leds, pre_msg1, pre_noise_st);

    join(usb_fut, fips_fut).await;
}

#[derive(defmt::Format)]
enum Err {
    Disconnected,
    Timeout,
    Invalid,
    Decrypt,
    PeerDC,
}

impl From<EndpointError> for Err {
    fn from(v: EndpointError) -> Self {
        match v {
            EndpointError::BufferOverflow => panic!("overflow"),
            EndpointError::Disabled => Err::Disconnected,
        }
    }
}

async fn cdc_write<'d, T: embassy_stm32::usb::Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    data: &[u8],
) -> Result<(), Err> {
    let mut off = 0;
    while off < data.len() {
        let end = core::cmp::min(off + CDC_PKT, data.len());
        class.write_packet(&data[off..end]).await?;
        off = end;
    }
    if !data.is_empty() && data.len() % CDC_PKT == 0 {
        class.write_packet(&[]).await?;
    }
    Ok(())
}

async fn cdc_send_frame<'d, T: embassy_stm32::usb::Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    payload: &[u8],
) -> Result<(), Err> {
    let hdr = (payload.len() as u16).to_le_bytes();
    cdc_write(class, &hdr).await?;
    cdc_write(class, payload).await
}

async fn fips_task<'d, T: embassy_stm32::usb::Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    leds: &mut Leds,
    pre_msg1: &'static [u8; fmp::MSG1_WIRE_SIZE],
    pre_noise_st: &'static noise::NoiseIkInitiator,
) {
    let mut rbuf = [0u8; 2048];
    let mut rpos: usize;
    let mut rlen: usize;

    loop {
        class.wait_connection().await;
        Timer::after(Duration::from_millis(CONNECT_DELAY_MS)).await;
        leds.set_state(S_USB_READY);

        rpos = 0;
        rlen = 0;

        match handshake(
            class,
            pre_msg1,
            pre_noise_st,
            &mut rbuf,
            &mut rpos,
            &mut rlen,
        )
        .await
        {
            Ok((ks, kr, them, _us)) => {
                leds.set_state(S_HANDSHAKE_OK);
                Timer::after(Duration::from_millis(500)).await;
                let _ = steady(class, leds, &ks, &kr, them, &mut rbuf, &mut rpos, &mut rlen).await;
                leds.set_state(S_DISCONNECTED);
            }
            Err(_) => {
                leds.set_state(S_ERR);
            }
        }
        Timer::after(Duration::from_secs(RETRY_SECS)).await;
    }
}

async fn handshake<'d, T: embassy_stm32::usb::Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    pre_msg1: &[u8; fmp::MSG1_WIRE_SIZE],
    pre_noise_st: &noise::NoiseIkInitiator,
    rbuf: &mut [u8],
    rpos: &mut usize,
    rlen: &mut usize,
) -> Result<([u8; 32], [u8; 32], u32, u32), Err> {
    cdc_send_frame(class, pre_msg1).await?;
    STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
    yield_now().await;

    let mut mb = [0u8; 2048];
    loop {
        let ml = recv_frame(class, rbuf, rpos, rlen, &mut mb).await?;
        let m = fmp::parse_message(&mb[..ml]).ok_or(Err::Invalid)?;
        match m {
            fmp::FmpMessage::Msg2 {
                sender_idx,
                receiver_idx,
                noise_payload,
            } => {
                yield_now().await;
                let mut st = pre_noise_st.clone();
                st.read_message2(noise_payload).map_err(|_| Err::Decrypt)?;
                yield_now().await;
                let (ks, kr) = st.finalize();
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                return Ok((ks, kr, sender_idx, receiver_idx));
            }
            _ => continue,
        }
    }
}

async fn recv_frame<'d, T: embassy_stm32::usb::Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    rbuf: &mut [u8],
    rpos: &mut usize,
    rlen: &mut usize,
    out: &mut [u8],
) -> Result<usize, Err> {
    loop {
        if *rpos < *rlen {
            if *rlen - *rpos < 2 {
            } else {
                let ml = u16::from_le_bytes([rbuf[*rpos], rbuf[*rpos + 1]]) as usize;
                if ml == 0 || ml > 1500 {
                    *rpos = *rlen;
                } else if *rlen - *rpos - 2 < ml {
                } else {
                    let s = *rpos + 2;
                    let e = s + ml;
                    let l = ml.min(out.len());
                    out[..l].copy_from_slice(&rbuf[s..s + l]);
                    *rpos = e;
                    if *rpos >= *rlen {
                        *rpos = 0;
                        *rlen = 0;
                    }
                    STAT_RECV_FRAME.fetch_add(1, Ordering::Relaxed);
                    return Ok(l);
                }
            }
        }

        compact(rbuf, rpos, rlen);
        let mut rx = [0u8; CDC_PKT];
        match embassy_futures::select::select(
            class.read_packet(&mut rx),
            Timer::after(Duration::from_secs(RECV_TIMEOUT_SECS)),
        )
        .await
        {
            embassy_futures::select::Either::First(Ok(n)) => {
                STAT_RECV_PKT.fetch_add(1, Ordering::Relaxed);
                if *rlen + n > rbuf.len() {
                    *rlen = 0;
                    *rpos = 0;
                    continue;
                }
                rbuf[*rlen..*rlen + n].copy_from_slice(&rx[..n]);
                *rlen += n;
            }
            embassy_futures::select::Either::First(Err(e)) => {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                return Err(e.into());
            }
            embassy_futures::select::Either::Second(()) => return Err(Err::Timeout),
        }
    }
}

fn compact(buf: &mut [u8], pos: &mut usize, len: &mut usize) {
    if *pos > 0 && *pos < *len {
        let remaining = *len - *pos;
        buf.copy_within(*pos..*len, 0);
        *pos = 0;
        *len = remaining;
    }
}

async fn steady<'d, T: embassy_stm32::usb::Instance + 'd>(
    class: &mut CdcAcmClass<'d, Driver<'d, T>>,
    leds: &mut Leds,
    ks: &[u8; 32],
    kr: &[u8; 32],
    them: u32,
    rbuf: &mut [u8],
    rpos: &mut usize,
    rlen: &mut usize,
) -> Result<(), Err> {
    let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);

    loop {
        let mut rx = [0u8; CDC_PKT];
        let rx_fut = class.read_packet(&mut rx);
        let hb_fut = Timer::at(next_hb);
        match embassy_futures::select::select(rx_fut, hb_fut).await {
            embassy_futures::select::Either::First(Ok(n)) => {
                if *rlen + n > rbuf.len() {
                    *rlen = 0;
                    *rpos = 0;
                    continue;
                }
                rbuf[*rlen..*rlen + n].copy_from_slice(&rx[..n]);
                *rlen += n;

                while *rpos < *rlen {
                    if *rlen - *rpos < 2 {
                        break;
                    }
                    let ml = u16::from_le_bytes([rbuf[*rpos], rbuf[*rpos + 1]]) as usize;
                    if ml == 0 || ml > 1500 {
                        *rpos = *rlen;
                        break;
                    }
                    if *rlen - *rpos - 2 < ml {
                        break;
                    }
                    let s = *rpos + 2;
                    let e = s + ml;
                    if let Err(Err::PeerDC) = handle(kr, leds, &rbuf[s..e]) {
                        return Ok(());
                    }
                    *rpos = e;
                }
                if *rpos >= *rlen {
                    *rpos = 0;
                    *rlen = 0;
                }
                if embassy_time::Instant::now() >= next_hb {
                    next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
                    let c = next_ctr();
                    let ts = embassy_time::Instant::now().as_millis() as u32;
                    let mut out = [0u8; 256];
                    let fl =
                        fmp::build_established(them, c, fmp::MSG_HEARTBEAT, ts, &[], ks, &mut out);
                    let _ = cdc_send_frame(class, &out[..fl]).await;
                    STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
                    leds.set_state(S_HB_TX);
                    leds.set_state(S_HANDSHAKE_OK);
                }
            }
            embassy_futures::select::Either::First(Err(e)) => {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                return Err(e.into());
            }
            embassy_futures::select::Either::Second(()) => {
                next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
                let c = next_ctr();
                let ts = embassy_time::Instant::now().as_millis() as u32;
                let mut out = [0u8; 256];
                let fl = fmp::build_established(them, c, fmp::MSG_HEARTBEAT, ts, &[], ks, &mut out);
                let _ = cdc_send_frame(class, &out[..fl]).await;
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
                leds.set_state(S_HB_TX);
                leds.set_state(S_HANDSHAKE_OK);
            }
        }
    }
}

fn handle(kr: &[u8; 32], leds: &mut Leds, data: &[u8]) -> Result<(), Err> {
    let m = fmp::parse_message(data).ok_or(Err::Invalid)?;
    match m {
        fmp::FmpMessage::Established {
            counter, encrypted, ..
        } => {
            let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
            let mut dec = [0u8; 2048];
            let dl = noise::aead_decrypt(kr, counter, hdr, encrypted, &mut dec)
                .map_err(|_| Err::Decrypt)?;
            if dl < fmp::INNER_HEADER_SIZE {
                return Err(Err::Invalid);
            }
            match dec[4] {
                fmp::MSG_HEARTBEAT => {
                    STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
                    leds.set_state(S_HB_RX);
                }
                fmp::MSG_DISCONNECT => {
                    return Err(Err::PeerDC);
                }
                _ => {}
            }
            Ok(())
        }
        _ => Err(Err::Invalid),
    }
}
