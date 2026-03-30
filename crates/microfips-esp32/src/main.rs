#![no_std]
#![no_main]

esp_bootloader_esp_idf::esp_app_desc!();

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::gpio::{Level, Output};
use esp_hal::rng::Trng;
use esp_hal::uart::{Config, RxConfig, Uart};
use esp_hal::{Async, interrupt::software::SoftwareInterruptControl, timer::timg::TimerGroup};
use esp_println as _;

use microfips_core::fmp;
use microfips_core::fsp::{FspSession, handle_fsp_datagram};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_core::noise;

const ESP32_SECRET: &[u8; 32] = &[
    0x12, 0x3c, 0x2c, 0x30, 0x1a, 0x7b, 0x37, 0x33,
    0x9c, 0x42, 0x32, 0xd8, 0x29, 0x0a, 0xb4, 0x7a,
    0x0a, 0x30, 0x4b, 0x52, 0x27, 0x48, 0xba, 0x83,
    0xdb, 0xdd, 0xe3, 0x9f, 0xce, 0xda, 0x38, 0xd8,
];

const HB_SECS: u64 = 10;
const RECV_TIMEOUT_MS: u64 = 30_000;
const RETRY_SECS: u64 = 3;
const CONNECT_DELAY_MS: u64 = 500;

#[used]
static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);

struct Led(Output<'static>);

impl Led {
    fn set_state(&mut self, state: u32) {
        match state {
            0 => self.0.set_low(),
            2 => self.0.set_high(),
            _ => {}
        }
    }
}

struct UartTransport {
    tx: esp_hal::uart::UartTx<'static, Async>,
    rx: esp_hal::uart::UartRx<'static, Async>,
}

#[derive(Debug)]
struct UartError;

impl UartTransport {
    async fn send(&mut self, data: &[u8]) -> Result<(), UartError> {
        use embedded_io_async::Write;
        self.tx.write_all(data).await.map_err(|_| UartError)?;
        self.tx.flush().map_err(|_| UartError)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UartError> {
        use embedded_io_async::Read;
        Read::read(&mut self.rx, buf).await.map_err(|_| UartError)
    }
}

struct EspHandler<'a> {
    led: &'a mut Led,
    fsp_session: FspSession,
    fsp_ephemeral: [u8; 32],
    fsp_epoch: [u8; 8],
}

impl EspHandler<'_> {
    fn on_event(&mut self, event: u32) {
        match event {
            2 => {
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(2);
            }
            3 => {
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(3);
                self.fsp_session.reset();
                self.fsp_epoch = [0x01, 0, 0, 0, 0, 0, 0, 0];
            }
            4 => {
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
            }
            5 => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> usize {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return 0;
        }
        match handle_fsp_datagram(
            &mut self.fsp_session,
            &ESP32_SECRET,
            &self.fsp_ephemeral,
            &self.fsp_epoch,
            payload,
            resp,
        ) {
            Ok(microfips_core::fsp::FspHandlerResult::SendDatagram(len)) => len,
            _ => 0,
        }
    }
}

async fn send_frame(transport: &mut UartTransport, payload: &[u8]) -> Result<(), ()> {
    let hdr = (payload.len() as u16).to_le_bytes();
    transport.send(&hdr).await.map_err(|_| ())?;
    transport.send(payload).await.map_err(|_| ())
}

async fn recv_frame(
    transport: &mut UartTransport,
    rbuf: &mut [u8; 2048],
    rpos: &mut usize,
    rlen: &mut usize,
    out: &mut [u8],
    timeout_ms: u64,
) -> Result<usize, ()> {
    loop {
        let need_more = if *rpos < *rlen {
            if *rlen - *rpos < 2 {
                true
            } else {
                let ml = u16::from_le_bytes([rbuf[*rpos], rbuf[*rpos + 1]]) as usize;
                if ml == 0 || ml > 1500 {
                    *rpos = *rlen;
                    true
                } else if *rlen - *rpos - 2 < ml {
                    true
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
                    return Ok(l);
                }
            }
        } else {
            true
        };

        if need_more {
            let avail = *rlen - *rpos;
            if avail > 0 {
                rbuf.copy_within(*rpos..*rlen, 0);
                *rlen -= *rpos;
                *rpos = 0;
            } else {
                *rpos = 0;
                *rlen = 0;
            }
            let mut rx = [0u8; 256];
            match select(
                transport.recv(&mut rx),
                Timer::after(Duration::from_millis(timeout_ms)),
            )
            .await
            {
                Either::First(Ok(n)) => {
                    if *rlen + n > rbuf.len() {
                        *rlen = 0;
                        *rpos = 0;
                        continue;
                    }
                    rbuf[*rlen..*rlen + n].copy_from_slice(&rx[..n]);
                    *rlen += n;
                }
            Either::First(Err(_)) => {
                Timer::after(Duration::from_millis(100)).await;
                continue;
            }
                Either::Second(()) => return Err(()),
            }
        }
    }
}

async fn run_fips(
    transport: &mut UartTransport,
    rng: &mut Trng,
    handler: &mut EspHandler<'_>,
) -> ! {
    loop {
        let _ = session(transport, rng, handler).await;
        Timer::after(Duration::from_secs(RETRY_SECS)).await;
    }
}

async fn session(
    transport: &mut UartTransport,
    rng: &mut Trng,
    handler: &mut EspHandler<'_>,
) -> Result<(), ()> {
    Timer::after(Duration::from_millis(CONNECT_DELAY_MS)).await;

    let my_pub = noise::ecdh_pubkey(&ESP32_SECRET).unwrap();

    let mut eph = [0u8; 32];
    rand_core::RngCore::fill_bytes(rng, &mut eph);
    let (mut noise_st, _e_pub) =
        noise::NoiseIkInitiator::new(&eph, &ESP32_SECRET, &DEFAULT_PEER_PUB).unwrap();

    let epoch: [u8; noise::EPOCH_SIZE] = [0x01, 0, 0, 0, 0, 0, 0, 0];

    let mut n1 = [0u8; 256];
    let n1len = noise_st.write_message1(&my_pub, &epoch, &mut n1).unwrap();

    let mut f1 = [0u8; 256];
    let f1len = fmp::build_msg1(0, &n1[..n1len], &mut f1).unwrap();
    send_frame(transport, &f1[..f1len]).await?;
    handler.on_event(2);

    let mut rbuf = [0u8; 2048];
    let mut rpos = 0usize;
    let mut rlen = 0usize;
    let mut mb = [0u8; 2048];
    let ml = recv_frame(transport, &mut rbuf, &mut rpos, &mut rlen, &mut mb, RECV_TIMEOUT_MS).await?;

    let m = fmp::parse_message(&mb[..ml]).ok_or(())?;
    let (st, sender_idx) = match m {
        fmp::FmpMessage::Msg2 {
            sender_idx,
            noise_payload,
            ..
        } => {
            let mut st = noise_st.clone();
            st.read_message2(noise_payload).map_err(|_| ())?;
            (st, sender_idx)
        }
        _ => return Err(()),
    };

    let (ks, kr) = st.finalize();
    handler.on_event(3);

    let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
    let mut send_ctr: u64 = 0;
    let mut resp_buf = [0u8; 256];
    let mut rpos: usize = 0;
    let mut rlen: usize = 0;

    send_heartbeat(transport, &ks, sender_idx, &mut send_ctr).await;
    handler.on_event(4);

    loop {
        let mut rx = [0u8; 256];
        let rx_fut = transport.recv(&mut rx);
        let hb_fut = Timer::at(next_hb);

        match select(rx_fut, hb_fut).await {
            Either::First(Ok(n)) => {
                if rlen + n > rbuf.len() {
                    rlen = 0;
                    rpos = 0;
                    continue;
                }
                rbuf[rlen..rlen + n].copy_from_slice(&rx[..n]);
                rlen += n;

                while rpos < rlen {
                    if rlen - rpos < 2 {
                        break;
                    }
                    let frame_len =
                        u16::from_le_bytes([rbuf[rpos], rbuf[rpos + 1]]) as usize;
                    if frame_len == 0 || frame_len > 1500 {
                        rpos = rlen;
                        break;
                    }
                    if rlen - rpos - 2 < frame_len {
                        break;
                    }
                    let s = rpos + 2;
                    let e = s + frame_len;

                    let data = &rbuf[s..e];
                    let m = match fmp::parse_message(data) {
                        Some(m) => m,
                        None => {
                            rpos = e;
                            continue;
                        }
                    };

                    match m {
                        fmp::FmpMessage::Established {
                            counter, encrypted, ..
                        } => {
                            let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
                            let mut dec = [0u8; 2048];
                            let dl = match noise::aead_decrypt(&kr, counter, hdr, encrypted, &mut dec)
                            {
                                Ok(l) => l,
                                Err(_) => {
                                    rpos = e;
                                    continue;
                                }
                            };
                            if dl < fmp::INNER_HEADER_SIZE {
                                rpos = e;
                                continue;
                            }
                            let msg_type = dec[4];
                            match msg_type {
                                fmp::MSG_HEARTBEAT => {
                                    handler.on_event(5);
                                }
                                fmp::MSG_DISCONNECT => return Ok(()),
                                _ => {
                                    let payload = &dec[fmp::INNER_HEADER_SIZE..dl];
                                    let resp_len =
                                        handler.on_message(msg_type, payload, &mut resp_buf);
                                    if resp_len > 0 {
                                        let c = send_ctr;
                                        send_ctr += 1;
                                        let ts = embassy_time::Instant::now().as_millis() as u32;
                                        let mut out = [0u8; 256];
                                        let fl = fmp::build_established(
                                            sender_idx,
                                            c,
                                            fmp::MSG_SESSION_DATAGRAM,
                                            ts,
                                            &resp_buf[..resp_len],
                                            &ks,
                                            &mut out,
                                        );
                                        if let Some(fl) = fl {
                                            let _ = send_frame(transport, &out[..fl]).await;
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    rpos = e;
                }
                if rpos >= rlen {
                    rpos = 0;
                    rlen = 0;
                }
                if embassy_time::Instant::now() >= next_hb {
                    next_hb = send_heartbeat(transport, &ks, sender_idx, &mut send_ctr).await;
                    handler.on_event(4);
                }
            }
            Either::First(Err(_)) => {
                Timer::after(Duration::from_millis(100)).await;
                continue;
            }
            Either::Second(()) => {
                next_hb = send_heartbeat(transport, &ks, sender_idx, &mut send_ctr).await;
                handler.on_event(4);
            }
        }
    }
}

async fn send_heartbeat(
    transport: &mut UartTransport,
    ks: &[u8; 32],
    them: u32,
    ctr: &mut u64,
) -> embassy_time::Instant {
    let c = *ctr;
    *ctr += 1;
    let ts = embassy_time::Instant::now().as_millis() as u32;
    let mut out = [0u8; 256];
    let fl = fmp::build_established(them, c, fmp::MSG_HEARTBEAT, ts, &[], ks, &mut out);
    if let Some(fl) = fl {
        let _ = send_frame(transport, &out[..fl]).await;
    }
    embassy_time::Instant::now() + Duration::from_secs(HB_SECS)
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let _sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let mut led = Led(Output::new(peripherals.GPIO2, Level::Low, esp_hal::gpio::OutputConfig::default()));

    let _trng_source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().unwrap();

    let mut fsp_ephemeral = [0u8; 32];
    trng.read(&mut fsp_ephemeral);
    let mut rng = trng;

    let uart_config = Config::default()
        .with_rx(RxConfig::default().with_fifo_full_threshold(64))
        .with_baudrate(115200);
    let uart = Uart::new(peripherals.UART0, uart_config)
        .unwrap()
        .with_tx(peripherals.GPIO1)
        .with_rx(peripherals.GPIO3)
        .into_async();
    let (rx, tx) = uart.split();
    let mut transport = UartTransport { tx, rx };

    let mut handler = EspHandler {
        led: &mut led,
        fsp_session: FspSession::new(),
        fsp_ephemeral,
        fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
    };

    run_fips(&mut transport, &mut rng, &mut handler).await;
}
