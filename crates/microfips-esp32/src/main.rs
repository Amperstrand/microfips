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
use microfips_core::fsp::{
    FspInitiatorSession, FspInitiatorState, SESSION_DATAGRAM_BODY_SIZE,
    build_fsp_encrypted, build_fsp_header, build_session_datagram_body,
    fsp_prepend_inner_header, parse_fsp_encrypted_header, FSP_HEADER_SIZE, FSP_MSG_DATA,
};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_core::noise;

const ESP32_SECRET: &[u8; 32] = &[
    0x12, 0x3c, 0x2c, 0x30, 0x1a, 0x7b, 0x37, 0x33,
    0x9c, 0x42, 0x32, 0xd8, 0x29, 0x0a, 0xb4, 0x7a,
    0x0a, 0x30, 0x4b, 0x52, 0x27, 0x48, 0xba, 0x83,
    0xdb, 0xdd, 0xe3, 0x9f, 0xce, 0xda, 0x38, 0xd8,
];

const STM32_PEER_PUB: &[u8; 33] = &[
    0x02, 0x63, 0x56, 0x96, 0xdc, 0x5f, 0x7c, 0xcb,
    0x68, 0xdf, 0x79, 0x36, 0x2c, 0x9e, 0xdf, 0x35,
    0xe3, 0x5e, 0x61, 0x6d, 0x7a, 0xe8, 0x6f, 0xce,
    0xe2, 0x68, 0xa2, 0xf7, 0x49, 0x45, 0x2b, 0x68,
    0x42,
];

const IK_EPHEMERAL: [u8; 32] = [0xAA; 32];
const FSP_EPHEMERAL: [u8; 32] = [0xBB; 32];

const ESP32_NODE_ADDR: [u8; 16] = [
    0x14, 0x01, 0x81, 0xa5, 0x85, 0x59, 0x4a, 0xaa,
    0xac, 0x84, 0x1f, 0xb5, 0x43, 0x05, 0x76, 0x75,
];

const STM32_NODE_ADDR: [u8; 16] = [
    0x24, 0x49, 0x21, 0xe6, 0x60, 0x6a, 0xc5, 0x8f,
    0x4b, 0x14, 0x53, 0x13, 0x36, 0x3f, 0xbb, 0x1c,
];

const HB_SECS: u64 = 10;
const RECV_TIMEOUT_MS: u64 = 30_000;
const RETRY_SECS: u64 = 3;
const CONNECT_DELAY_MS: u64 = 500;
const FSP_START_DELAY_SECS: u64 = 5;
const FSP_RETRY_SECS: u64 = 8;
const FSP_EPOCH: [u8; 8] = [0x02, 0, 0, 0, 0, 0, 0, 0];

#[used]
static STAT_MSG1_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_MSG2_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_HB_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_FSP_SETUP_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_FSP_ACK_RX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_FSP_MSG3_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_FSP_ESTABLISHED: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_PING_TX: AtomicU32 = AtomicU32::new(0);
#[used]
static STAT_PONG_RX: AtomicU32 = AtomicU32::new(0);

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
    fsp: Option<FspInitiatorSession>,
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

    fn init_fsp(&mut self) {
        self.fsp = FspInitiatorSession::new(
            ESP32_SECRET,
            &FSP_EPHEMERAL,
            STM32_PEER_PUB,
        ).ok();
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

fn send_fsp_datagram_frame(
    sender_idx: u32,
    ctr: &mut u64,
    dg_body: &[u8; SESSION_DATAGRAM_BODY_SIZE],
    fsp_payload: &[u8],
    ik_k_send: &[u8; 32],
    out: &mut [u8],
) -> Option<usize> {
    let ts = embassy_time::Instant::now().as_millis() as u32;
    let c = *ctr;
    *ctr += 1;

    let mut dg = [0u8; 256];
    dg[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(dg_body);
    let pl = fsp_payload.len().min(dg.len() - SESSION_DATAGRAM_BODY_SIZE);
    dg[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + pl].copy_from_slice(&fsp_payload[..pl]);
    let dg_len = SESSION_DATAGRAM_BODY_SIZE + pl;

    fmp::build_established(
        sender_idx,
        c,
        fmp::MSG_SESSION_DATAGRAM,
        ts,
        &dg[..dg_len],
        ik_k_send,
        out,
    )
}

async fn run_fips(
    transport: &mut UartTransport,
    _rng: &mut Trng,
    handler: &mut EspHandler<'_>,
) -> ! {
    loop {
        let _ = session(transport, handler).await;
        Timer::after(Duration::from_secs(RETRY_SECS)).await;
    }
}

async fn session(
    transport: &mut UartTransport,
    handler: &mut EspHandler<'_>,
) -> Result<(), ()> {
    Timer::after(Duration::from_millis(CONNECT_DELAY_MS)).await;

    let my_pub = noise::ecdh_pubkey(ESP32_SECRET).unwrap();

    let (mut noise_st, _e_pub) =
        noise::NoiseIkInitiator::new(&IK_EPHEMERAL, ESP32_SECRET, &DEFAULT_PEER_PUB).unwrap();

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

    let dg_body = build_session_datagram_body(&ESP32_NODE_ADDR, &STM32_NODE_ADDR);

    let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
    let mut fsp_start = embassy_time::Instant::now() + Duration::from_secs(FSP_START_DELAY_SECS);
    let mut fsp_retry = embassy_time::Instant::now() + Duration::from_secs(FSP_START_DELAY_SECS + FSP_RETRY_SECS);
    let mut send_ctr: u64 = 0;
    let mut fsp_ctr: u64 = 0;
    let mut rpos: usize = 0;
    let mut rlen: usize = 0;

    handler.init_fsp();
    send_heartbeat(transport, &ks, sender_idx, &mut send_ctr).await;
    handler.on_event(4);

    loop {
        let mut rx = [0u8; 256];
        let rx_fut = transport.recv(&mut rx);
        let hb_fut = Timer::at(next_hb.min(fsp_start).min(fsp_retry));

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
                                fmp::MSG_SESSION_DATAGRAM => {
                                    let payload = &dec[fmp::INNER_HEADER_SIZE..dl];
                                    if let Some(ref mut fsp) = handler.fsp {
                                        handle_incoming_fsp(
                                            fsp,
                                            payload,
                                            &dg_body,
                                            sender_idx,
                                            &mut send_ctr,
                                            &mut fsp_ctr,
                                            &ks,
                                            transport,
                                        ).await;
                                    }
                                }
                                _ => {}
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
                let now = embassy_time::Instant::now();
                if now >= next_hb {
                    next_hb = send_heartbeat(transport, &ks, sender_idx, &mut send_ctr).await;
                    handler.on_event(4);
                    if let Some(ref fsp) = handler.fsp {
                        if fsp.state() == FspInitiatorState::Established {
                            do_send_ping(
                                transport, fsp, &dg_body, sender_idx,
                                &mut send_ctr, &mut fsp_ctr, &ks,
                            ).await;
                        }
                    }
                }
                if now >= fsp_retry {
                    fsp_retry = embassy_time::Instant::now() + Duration::from_secs(FSP_RETRY_SECS);
                    if let Some(ref mut fsp) = handler.fsp {
                        if fsp.state() == FspInitiatorState::AwaitingAck {
                            fsp.reset();
                        }
                    }
                }
                if now >= fsp_start {
                    fsp_start = embassy_time::Instant::now() + Duration::from_secs(3600);
                    fsp_retry = embassy_time::Instant::now() + Duration::from_secs(FSP_RETRY_SECS);
                    if let Some(ref mut fsp) = handler.fsp {
                        if fsp.state() == FspInitiatorState::Idle {
                            do_fsp_setup(
                                fsp,
                                &dg_body,
                                sender_idx,
                                &mut send_ctr,
                                &ks,
                                transport,
                            ).await;
                        }
                    }
                }
            }
            Either::First(Err(_)) => {
                Timer::after(Duration::from_millis(100)).await;
                continue;
            }
            Either::Second(()) => {
                let now = embassy_time::Instant::now();
                if now >= next_hb {
                    next_hb = send_heartbeat(transport, &ks, sender_idx, &mut send_ctr).await;
                    handler.on_event(4);
                    if let Some(ref fsp) = handler.fsp {
                        if fsp.state() == FspInitiatorState::Established {
                            do_send_ping(
                                transport, fsp, &dg_body, sender_idx,
                                &mut send_ctr, &mut fsp_ctr, &ks,
                            ).await;
                        }
                    }
                }
                if now >= fsp_retry {
                    fsp_retry = embassy_time::Instant::now() + Duration::from_secs(FSP_RETRY_SECS);
                    if let Some(ref mut fsp) = handler.fsp {
                        if fsp.state() == FspInitiatorState::AwaitingAck {
                            fsp.reset();
                        }
                    }
                }
                if now >= fsp_start {
                    fsp_start = embassy_time::Instant::now() + Duration::from_secs(3600);
                    fsp_retry = embassy_time::Instant::now() + Duration::from_secs(FSP_RETRY_SECS);
                    if let Some(ref mut fsp) = handler.fsp {
                        if fsp.state() == FspInitiatorState::Idle {
                            do_fsp_setup(
                                fsp,
                                &dg_body,
                                sender_idx,
                                &mut send_ctr,
                                &ks,
                                transport,
                            ).await;
                        }
                    }
                }
            }
        }
    }
}

async fn do_fsp_setup(
    fsp: &mut FspInitiatorSession,
    dg_body: &[u8; SESSION_DATAGRAM_BODY_SIZE],
    sender_idx: u32,
    ctr: &mut u64,
    ik_k_send: &[u8; 32],
    transport: &mut UartTransport,
) {
    let mut setup_buf = [0u8; 512];
    let setup_len = match fsp.build_setup(&ESP32_NODE_ADDR, &STM32_NODE_ADDR, &mut setup_buf) {
        Ok(l) => l,
        Err(_) => return,
    };
    STAT_FSP_SETUP_TX.fetch_add(1, Ordering::Relaxed);

    let mut dg = [0u8; 1024];
    dg[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(dg_body);
    let pl = setup_len.min(dg.len() - SESSION_DATAGRAM_BODY_SIZE);
    dg[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + pl].copy_from_slice(&setup_buf[..pl]);
    let dg_len = SESSION_DATAGRAM_BODY_SIZE + pl;

    let mut fmp_out = [0u8; 1024];
    if let Some(fmp_len) = fmp::build_established(
        sender_idx,
        *ctr,
        fmp::MSG_SESSION_DATAGRAM,
        embassy_time::Instant::now().as_millis() as u32,
        &dg[..dg_len],
        ik_k_send,
        &mut fmp_out,
    ) {
        *ctr += 1;
        let _ = send_frame(transport, &fmp_out[..fmp_len]).await;
    }
}

async fn handle_incoming_fsp(
    fsp: &mut FspInitiatorSession,
    payload: &[u8],
    dg_body: &[u8; SESSION_DATAGRAM_BODY_SIZE],
    sender_idx: u32,
    ctr: &mut u64,
    _fsp_ctr: &mut u64,
    ik_k_send: &[u8; 32],
    transport: &mut UartTransport,
) {
    if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
        return;
    }
    let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
    if fsp_data.is_empty() {
        return;
    }
    let fsp_phase = fsp_data[0] & 0x0F;

    match fsp.state() {
        FspInitiatorState::AwaitingAck => {
            if fsp_phase == 0x02 {
                if fsp.handle_ack(fsp_data).is_ok() {
                    STAT_FSP_ACK_RX.fetch_add(1, Ordering::Relaxed);
                    let mut msg3_buf = [0u8; 512];
                    if let Ok(msg3_len) = fsp.build_msg3(&FSP_EPOCH, &mut msg3_buf) {
                        STAT_FSP_MSG3_TX.fetch_add(1, Ordering::Relaxed);
                        let mut fmp_out = [0u8; 1024];
                        if let Some(fmp_len) = send_fsp_datagram_frame(
                            sender_idx,
                            ctr,
                            dg_body,
                            &msg3_buf[..msg3_len],
                            ik_k_send,
                            &mut fmp_out,
                        ) {
                            let _ = send_frame(transport, &fmp_out[..fmp_len]).await;
                        }
                        STAT_FSP_ESTABLISHED.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        FspInitiatorState::Established => {
            if fsp_phase == 0x00 {
                let Some((flags, counter, header, encrypted)) =
                    parse_fsp_encrypted_header(fsp_data)
                else {
                    return;
                };
                if flags & 0x04 != 0 {
                    return;
                }
                let (_k_recv, _k_send) = fsp.session_keys().unwrap();
                let mut dec = [0u8; 512];
                if let Ok(dl) = noise::aead_decrypt(&_k_send, counter, header, encrypted, &mut dec) {
                    if let Some((_ts2, _msg_type2, _flags2, payload2)) =
                        fsp_strip_inner_header(&dec[..dl])
                    {
                        if payload2 == b"PONG" {
                            STAT_PONG_RX.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn fsp_strip_inner_header(data: &[u8]) -> Option<(u32, u8, u8, &[u8])> {
    microfips_core::fsp::fsp_strip_inner_header(data)
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

async fn do_send_ping(
    transport: &mut UartTransport,
    fsp: &FspInitiatorSession,
    dg_body: &[u8; SESSION_DATAGRAM_BODY_SIZE],
    sender_idx: u32,
    ctr: &mut u64,
    fsp_ctr: &mut u64,
    ik_k_send: &[u8; 32],
) {
    let (_k_recv, k_send) = match fsp.session_keys() {
        Some(keys) => keys,
        None => return,
    };
    STAT_PING_TX.fetch_add(1, Ordering::Relaxed);

    let ping = b"PING";
    let ts = embassy_time::Instant::now().as_millis() as u32;
    let mut plaintext = [0u8; 512];
    let inner = fsp_prepend_inner_header(ts, FSP_MSG_DATA, 0x00, ping, &mut plaintext);
    let header = build_fsp_header(*fsp_ctr, 0x00, (inner + noise::TAG_SIZE) as u16);
    let mut ciphertext = [0u8; 512];
    let cl = noise::aead_encrypt(
        &k_send,
        *fsp_ctr,
        &header,
        &plaintext[..inner],
        &mut ciphertext,
    )
    .unwrap();
    *fsp_ctr += 1;
    let mut pkt = [0u8; 512];
    build_fsp_encrypted(&header, &ciphertext[..cl], &mut pkt);
    let fsp_payload = &pkt[..FSP_HEADER_SIZE + cl];

    let mut fmp_out = [0u8; 1024];
    if let Some(fmp_len) = send_fsp_datagram_frame(
        sender_idx,
        ctr,
        dg_body,
        fsp_payload,
        ik_k_send,
        &mut fmp_out,
    ) {
        let _ = send_frame(transport, &fmp_out[..fmp_len]).await;
    }
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    let _sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0);

    let mut led = Led(Output::new(peripherals.GPIO2, Level::Low, esp_hal::gpio::OutputConfig::default()));

    let _trng_source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let _trng = Trng::try_new().unwrap();

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
        fsp: None,
    };

    run_fips(&mut transport, &mut Trng::try_new().unwrap(), &mut handler).await;
}
