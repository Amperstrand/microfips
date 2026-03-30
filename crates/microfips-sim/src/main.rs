#![allow(clippy::needless_borrows_for_generic_args, clippy::needless_borrow, dead_code, clippy::collapsible_if)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Instant, Timer};
use k256::SecretKey;
use rand::RngCore;

use microfips_core::fmp;
use microfips_core::fsp::{
    self, FspInitiatorSession, FspInitiatorState, FspSession, SESSION_DATAGRAM_BODY_SIZE,
};
use microfips_core::identity::{NodeAddr, load_peer_pub, load_secret};
use microfips_core::noise;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;

// ---------------------------------------------------------------------------
// UdpTransport: raw FMP over UDP (no length-prefix framing)
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum UdpError {
    Io(std::io::Error),
}

struct UdpTransport {
    socket: UdpSocket,
    peer: std::net::SocketAddr,
}

impl UdpTransport {
    fn new(peer: std::net::SocketAddr) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("UDP bind failed");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(120)))
            .ok();
        Self { socket, peer }
    }
}

impl Transport for UdpTransport {
    type Error = UdpError;

    async fn wait_ready(&mut self) -> Result<(), UdpError> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), UdpError> {
        if data.len() >= 4 {
            let phase = data[0] & 0x0F;
            let extra = if phase == 0x00 && data.len() >= 9 {
                format!(" msg=0x{:02x}", data[8])
            } else {
                String::new()
            };
            eprintln!(
                "[UDP] TX {}B phase=0x{:01x}{} first4={:02x?}",
                data.len(),
                phase,
                extra,
                &data[..data.len().min(16)]
            );
        }
        self.socket.send_to(data, self.peer).map_err(UdpError::Io)?;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UdpError> {
        loop {
            match self.socket.recv_from(buf) {
                Ok((n, _addr)) => {
                    if n >= 4 {
                        let phase = buf[0] & 0x0F;
                        eprintln!(
                            "[UDP] RX {}B phase=0x{:01x} first4={:02x?}",
                            n,
                            phase,
                            &buf[..n.min(16)]
                        );
                    }
                    return Ok(n);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    Timer::after(Duration::from_millis(1)).await;
                }
                Err(e) => return Err(UdpError::Io(e)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SimTransport: TCP/stdio for the protocol crate's Transport trait.
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[allow(dead_code)]
enum SimError {
    Io(std::io::Error),
    Eof,
}

enum SimConnector {
    Listen(TcpListener),
    Connect(String),
    Stdio,
}

struct SimTransport {
    connector: SimConnector,
    rx: Arc<Mutex<VecDeque<u8>>>,
    writer: Option<Box<dyn Write + Send>>,
    eof: Arc<AtomicBool>,
    shutdown_handle: Option<TcpStream>,
}

impl SimTransport {
    fn new(connector: SimConnector) -> Self {
        Self {
            connector,
            rx: Arc::new(Mutex::new(VecDeque::new())),
            writer: None,
            eof: Arc::new(AtomicBool::new(false)),
            shutdown_handle: None,
        }
    }

    fn spawn_reader(&self, mut reader: impl Read + Send + 'static) {
        let rx = self.rx.clone();
        let eof = self.eof.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        eof.store(true, Ordering::Relaxed);
                        break;
                    }
                    Ok(n) => {
                        rx.lock().unwrap().extend(&buf[..n]);
                    }
                }
            }
        });
    }

    fn setup_tcp(&mut self, stream: TcpStream) -> Result<(), SimError> {
        let reader = stream.try_clone().map_err(SimError::Io)?;
        self.shutdown_handle = Some(stream.try_clone().map_err(SimError::Io)?);
        self.spawn_reader(reader);
        self.writer = Some(Box::new(stream));
        Ok(())
    }
}

impl Transport for SimTransport {
    type Error = SimError;

    async fn wait_ready(&mut self) -> Result<(), SimError> {
        if let Some(old) = self.shutdown_handle.take() {
            let _ = old.shutdown(std::net::Shutdown::Both);
        }
        match &self.connector {
            SimConnector::Listen(listener) => {
                self.rx = Arc::new(Mutex::new(VecDeque::new()));
                self.eof = Arc::new(AtomicBool::new(false));
                let (stream, addr) = listener.accept().map_err(SimError::Io)?;
                eprintln!("[SIM] connection from {}", addr);
                self.setup_tcp(stream)
            }
            SimConnector::Connect(addr) => {
                self.rx = Arc::new(Mutex::new(VecDeque::new()));
                self.eof = Arc::new(AtomicBool::new(false));
                eprintln!("[SIM] connecting to {}...", addr);
                let stream = TcpStream::connect(addr.as_str()).map_err(SimError::Io)?;
                eprintln!("[SIM] connected");
                self.setup_tcp(stream)
            }
            SimConnector::Stdio => {
                if self.writer.is_none() {
                    self.spawn_reader(std::io::stdin());
                    self.writer = Some(Box::new(std::io::stdout()));
                } else {
                    self.rx.lock().unwrap().clear();
                    self.eof.store(false, Ordering::Relaxed);
                }
                Ok(())
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), SimError> {
        let writer = self.writer.as_mut().ok_or(SimError::Eof)?;
        writer.write_all(data).map_err(SimError::Io)?;
        writer.flush().map_err(SimError::Io)?;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, SimError> {
        loop {
            {
                let mut rx = self.rx.lock().unwrap();
                if !rx.is_empty() {
                    let n = rx.len().min(buf.len());
                    for (i, byte) in rx.drain(..n).enumerate() {
                        buf[i] = byte;
                    }
                    return Ok(n);
                }
            }
            if self.eof.load(Ordering::Relaxed) {
                return Err(SimError::Eof);
            }
            Timer::after(Duration::from_millis(1)).await;
        }
    }
}

// ---------------------------------------------------------------------------
// LeafHandler: FSP responder (same role as STM32 firmware)
// ---------------------------------------------------------------------------

struct LeafHandler {
    fsp_session: FspSession,
    fsp_ephemeral: [u8; 32],
    fsp_epoch: [u8; 8],
    secret: [u8; 32],
}

impl LeafHandler {
    fn new(secret: [u8; 32]) -> Self {
        let mut eph = [0u8; 32];
        rand::rng().fill_bytes(&mut eph);
        Self {
            fsp_session: FspSession::new(),
            fsp_ephemeral: eph,
            fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
            secret,
        }
    }
}

impl NodeHandler for LeafHandler {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => eprintln!("[LEAF] transport ready"),
            NodeEvent::Msg1Sent => eprintln!("[LEAF] MSG1 sent"),
            NodeEvent::HandshakeOk => {
                self.fsp_session.reset();
                self.fsp_epoch = [0x01, 0, 0, 0, 0, 0, 0, 0];
                eprintln!("[LEAF] handshake complete (FSP responder ready)")
            }
            NodeEvent::HeartbeatSent => {}
            NodeEvent::HeartbeatRecv => {}
            NodeEvent::Disconnected => eprintln!("[LEAF] session ended, reconnecting"),
            NodeEvent::Error => eprintln!("[LEAF] handshake error, retrying"),
        }
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        match fsp::handle_fsp_datagram(
            &mut self.fsp_session,
            &self.secret,
            &self.fsp_ephemeral,
            &self.fsp_epoch,
            payload,
            resp,
        ) {
            Ok(fsp::FspHandlerResult::None) => HandleResult::None,
            Ok(fsp::FspHandlerResult::SendDatagram(len)) => {
                eprintln!("[LEAF] sending {}B response", len);
                HandleResult::SendDatagram(len)
            }
            Err(e) => {
                eprintln!("[LEAF] FSP error: {:?}", e);
                HandleResult::None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FspInitiatorHandler: FSP initiator (same role as ESP32 firmware)
// ---------------------------------------------------------------------------

const FSP_START_DELAY_SECS: u64 = 5;
const FSP_RETRY_SECS: u64 = 8;

struct FspInitiatorHandler {
    fsp: Option<FspInitiatorSession>,
    fsp_timer: Option<Instant>,
    target_addr: [u8; 16],
    my_addr: [u8; 16],
    secret: [u8; 32],
    target_pub: [u8; 33],
    test_ping: bool,
}

impl FspInitiatorHandler {
    fn new(
        secret: [u8; 32],
        target_pub: [u8; 33],
        target_addr: [u8; 16],
        my_addr: [u8; 16],
        test_ping: bool,
    ) -> Self {
        Self {
            fsp: None,
            fsp_timer: None,
            target_addr,
            my_addr,
            secret,
            target_pub,
            test_ping,
        }
    }

    fn ensure_fsp(&mut self) {
        if self.fsp.is_none() {
            let mut fsp_eph = [0u8; 32];
            rand::rng().fill_bytes(&mut fsp_eph);
            self.fsp = FspInitiatorSession::new(&self.secret, &fsp_eph, &self.target_pub).ok();
        }
    }
}

impl NodeHandler for FspInitiatorHandler {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => eprintln!("[INIT] transport ready"),
            NodeEvent::Msg1Sent => eprintln!("[INIT] MSG1 sent"),
            NodeEvent::HandshakeOk => {
                self.ensure_fsp();
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_START_DELAY_SECS));
                eprintln!(
                    "[INIT] handshake complete, FSP setup in {}s",
                    FSP_START_DELAY_SECS
                )
            }
            NodeEvent::HeartbeatSent => {}
            NodeEvent::HeartbeatRecv => {}
            NodeEvent::Disconnected => {
                self.fsp = None;
                self.fsp_timer = None;
                eprintln!("[INIT] session ended, reconnecting")
            }
            NodeEvent::Error => {
                self.fsp = None;
                self.fsp_timer = None;
                eprintln!("[INIT] handshake error, retrying")
            }
        }
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        let fsp = match &mut self.fsp {
            Some(f) => f,
            None => return HandleResult::None,
        };
        if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
            return HandleResult::None;
        }
        let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
        if fsp_data.is_empty() {
            return HandleResult::None;
        }
        let fsp_phase = fsp_data[0] & 0x0F;

        match fsp.state() {
            FspInitiatorState::AwaitingAck => {
                if fsp_phase == 0x02 {
                    if fsp.handle_ack(fsp_data).is_ok() {
                        eprintln!("[INIT] FSP ACK received");
                        let fsp_epoch = [0x02, 0, 0, 0, 0, 0, 0, 0];
                        let mut msg3_buf = [0u8; 512];
                        if let Ok(msg3_len) = fsp.build_msg3(&fsp_epoch, &mut msg3_buf) {
                            eprintln!("[INIT] FSP established! Sending MSG3");
                            let dg_body =
                                fsp::build_session_datagram_body(&self.my_addr, &self.target_addr);
                            let dg_len = SESSION_DATAGRAM_BODY_SIZE + msg3_len;
                            resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                            resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
                                .copy_from_slice(&msg3_buf[..msg3_len]);
                            return HandleResult::SendDatagram(dg_len);
                        }
                    }
                }
            }
            FspInitiatorState::AwaitingEstablished => {
                eprintln!("[INIT] FSP fully established!");
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(2));
            }
            FspInitiatorState::Established => {
                if fsp_phase == 0x00 {
                    let Some((flags, counter, header, encrypted)) =
                        fsp::parse_fsp_encrypted_header(fsp_data)
                    else {
                        return HandleResult::None;
                    };
                    if flags & fsp::FLAG_UNENCRYPTED != 0 {
                        return HandleResult::None;
                    }
                    let (k_recv, _k_send) = match fsp.session_keys() {
                        Some(keys) => keys,
                        None => return HandleResult::None,
                    };
                    let mut dec = [0u8; 512];
                    if let Ok(dl) =
                        noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut dec)
                    {
                        if let Some((_ts, _mt, _flags, inner_payload)) =
                            fsp::fsp_strip_inner_header(&dec[..dl])
                        {
                            if inner_payload == b"PONG" {
                                eprintln!("[INIT] *** PONG received from target! ***");
                                if self.test_ping {
                                    std::process::exit(0);
                                }
                            } else {
                                eprintln!(
                                    "[INIT] FSP data: {}B: {:?}",
                                    inner_payload.len(),
                                    &inner_payload[..inner_payload.len().min(64)]
                                );
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        HandleResult::None
    }

    fn poll_at(&self) -> Option<Instant> {
        eprintln!(
            "[INIT] poll_at called, fsp_timer={:?}",
            self.fsp_timer.map(|t| t.as_millis())
        );
        self.fsp_timer
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        eprintln!("[INIT] on_tick called, fsp={}", self.fsp.is_some());
        let fsp = match &mut self.fsp {
            Some(f) => f,
            None => return HandleResult::None,
        };

        match fsp.state() {
            FspInitiatorState::Idle => {
                let dg_body = fsp::build_session_datagram_body(&self.my_addr, &self.target_addr);
                let mut setup_buf = [0u8; 512];
                let setup_len =
                    match fsp.build_setup(&self.my_addr, &self.target_addr, &mut setup_buf) {
                        Ok(l) => l,
                        Err(_) => return HandleResult::None,
                    };
                eprintln!(
                    "[INIT] Sending FSP SessionSetup ({}B) to {}",
                    setup_len,
                    hex::encode(&self.target_addr)
                );
                let dg_len = SESSION_DATAGRAM_BODY_SIZE + setup_len;
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + setup_len]
                    .copy_from_slice(&setup_buf[..setup_len]);
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::SendDatagram(dg_len)
            }
            FspInitiatorState::AwaitingAck => {
                eprintln!("[INIT] FSP ACK timeout, resetting session");
                fsp.reset();
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::None
            }
            FspInitiatorState::AwaitingEstablished => {
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::None
            }
            FspInitiatorState::Established => {
                let dg_body = fsp::build_session_datagram_body(&self.my_addr, &self.target_addr);
                let (_k_recv, k_send) = fsp.session_keys().unwrap();
                let ping = b"PING";
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u32;
                let mut plaintext = [0u8; 512];
                let il = fsp::fsp_prepend_inner_header(
                    ts,
                    fsp::FSP_MSG_DATA,
                    0x00,
                    ping,
                    &mut plaintext,
                );
                let header = fsp::build_fsp_header(0, 0x00, (il + noise::TAG_SIZE) as u16);
                let mut ciphertext = [0u8; 512];
                let cl =
                    noise::aead_encrypt(&k_send, 0, &header, &plaintext[..il], &mut ciphertext)
                        .unwrap();
                let fsp_total = fsp::FSP_HEADER_SIZE + cl;
                let dg_len = SESSION_DATAGRAM_BODY_SIZE + fsp_total;
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + fsp::FSP_HEADER_SIZE]
                    .copy_from_slice(&header);
                resp[SESSION_DATAGRAM_BODY_SIZE + fsp::FSP_HEADER_SIZE
                    ..SESSION_DATAGRAM_BODY_SIZE + fsp_total]
                    .copy_from_slice(&ciphertext[..cl]);
                eprintln!("[INIT] Sent PING to target ({}B datagram)", dg_len);
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(10));
                HandleResult::SendDatagram(dg_len)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Embassy executor helper for std context
// ---------------------------------------------------------------------------

fn block_on<F: std::future::Future + Send + 'static>(f: F) -> F::Output
where
    F::Output: Send + 'static,
{
    use embassy_executor::Executor;
    use std::pin::Pin;

    let executor: &'static mut Executor = Box::leak(Box::new(Executor::new()));

    let result: Arc<Mutex<Option<F::Output>>> = Arc::new(Mutex::new(None));
    let result_clone = result.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();

    let boxed: Pin<Box<dyn std::future::Future<Output = ()> + Send>> = Box::pin(async move {
        let output = f.await;
        *result_clone.lock().unwrap() = Some(output);
        done_clone.store(true, Ordering::Relaxed);
    });

    #[embassy_executor::task(pool_size = 1)]
    async fn run_task(fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        fut.await
    }

    let done_check = done.clone();
    executor.run_until(
        |spawner| {
            spawner.spawn(run_task(boxed).unwrap());
        },
        move || done_check.load(Ordering::Relaxed),
    );

    result.lock().unwrap().take().unwrap()
}

// ---------------------------------------------------------------------------
// Hardcoded leaf node identities
//
// All secrets are deterministic: 31 zero bytes + last byte N.
// These are valid secp256k1 private keys (generator * N).
// ---------------------------------------------------------------------------

/// SIM-A identity secret key: 31 zero bytes + 0x03 (secp256k1 generator * 3).
/// npub:    npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266
/// pubkey:  02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
/// addr:    7c79f3071e28344e8153bf6c73c294eb
const SIM_A_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];

/// SIM-B identity secret key: 31 zero bytes + 0x04 (secp256k1 generator * 4).
/// npub:    npub1ujfahuwppkq0xkq7fyzfxzc5qnxxcyuspms8tpr5l222h6xye5fsccv64k
/// pubkey:  02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
/// addr:    36be1ea4d814af2888b895065a0b2538
const SIM_B_SECRET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
];

/// SIM-A compressed pubkey (for FSP initiator targeting SIM-A).
const SIM_A_PUBKEY: [u8; 33] = [
    0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
    0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36,
    0xf9,
];

/// SIM-A node_addr (target for SIM-B initiator).
const SIM_A_TARGET: [u8; 16] = [
    0x7c, 0x79, 0xf3, 0x07, 0x1e, 0x28, 0x34, 0x4e, 0x81, 0x53, 0xbf, 0x6c, 0x73, 0xc2, 0x94, 0xeb,
];

/// SIM-B node_addr (unused currently — no initiator targets SIM-B).
#[allow(dead_code)]
const SIM_B_TARGET: [u8; 16] = [
    0x36, 0xbe, 0x1e, 0xa4, 0xd8, 0x14, 0xaf, 0x28, 0x88, 0xb8, 0x95, 0x06, 0x5a, 0x0b, 0x25, 0x38,
];

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn keygen_from(secret: &[u8; 32]) {
    let _ = SecretKey::from_slice(secret).expect("invalid key");
    let pubkey = noise::ecdh_pubkey(secret).expect("pubkey failed");
    println!("FIPS_SECRET={}", hex::encode(secret));
    println!("FIPS_PUB={}", hex::encode(pubkey));
    let pub_normalized = noise::parity_normalize(&pubkey);
    let x_only = &pub_normalized[1..];
    let addr = NodeAddr::from_pubkey_x(x_only.try_into().unwrap());
    let npub = bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), x_only)
        .expect("bech32");
    println!("NPUB={}", npub);
    println!("NODE_ADDR={}", hex::encode(addr.as_bytes()));
}

fn keygen() {
    let mut rng = rand::rng();
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    keygen_from(&secret);
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  microfips-sim --keygen");
    eprintln!("  microfips-sim --udp <fips_addr:port> [--initiator --target <node_addr_hex>]");
    eprintln!("  microfips-sim --sim-a                  Use hardcoded SIM-A identity (responder)");
    eprintln!(
        "  microfips-sim --sim-b                  Use hardcoded SIM-B identity (initiator→SIM-A)"
    );
    eprintln!();
    eprintln!("Environment variables:");
    eprintln!("  FIPS_SECRET   64 hex chars (identity secret key, fallback)");
    eprintln!("  FIPS_PEER_PUB  66 hex chars (peer's compressed pubkey, fallback)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --udp <addr>    Connect directly to FIPS via UDP (no bridge needed)");
    eprintln!("  --initiator    Act as FSP initiator (default: responder)");
    eprintln!("  --target <hex> Target NodeAddr for FSP session (16 bytes hex)");
    eprintln!("  --keygen       Generate a new keypair and print env vars");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--keygen") {
        keygen();
        return;
    }

    if let Some(pos) = args.iter().position(|a| a == "--derive") {
        let hex_str = args.get(pos + 1).expect("--derive requires a hex secret");
        let bytes = hex::decode(hex_str).expect("invalid hex");
        let secret: [u8; 32] = bytes.try_into().expect("secret must be 32 bytes");
        keygen_from(&secret);
        return;
    }

    if args.len() < 3 || args.get(1).map(|a| a.as_str()) != Some("--udp") {
        print_usage();
        std::process::exit(1);
    }

    let fips_addr = args.get(2).expect("--udp requires an address");
    let use_sim_a = args.iter().any(|a| a == "--sim-a");
    let use_sim_b = args.iter().any(|a| a == "--sim-b");
    let test_ping = args.iter().any(|a| a == "--test-ping");
    let is_initiator = args.iter().any(|a| a == "--initiator") || use_sim_b;
    let target_arg = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1));

    let target_addr = if use_sim_b {
        SIM_A_TARGET
    } else {
        match target_arg {
            Some(hex_str) => match hex::decode(hex_str) {
                Ok(bytes) if bytes.len() == 16 => {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => {
                    eprintln!("ERROR: --target must be 16 bytes (32 hex chars)");
                    std::process::exit(1);
                }
            },
            None if is_initiator => {
                eprintln!("ERROR: --initiator requires --target <node_addr_hex>");
                std::process::exit(1);
            }
            None => [0u8; 16],
        }
    };

    let secret = if use_sim_a {
        SIM_A_SECRET
    } else if use_sim_b {
        SIM_B_SECRET
    } else {
        load_secret()
    };
    let peer_pub = load_peer_pub();
    let my_pub = noise::ecdh_pubkey(&secret).unwrap();
    let pub_normalized = noise::parity_normalize(&my_pub);
    let x_only = &pub_normalized[1..];
    let my_addr = NodeAddr::from_pubkey_x(x_only.try_into().unwrap());

    eprintln!("[SIM] microfips leaf node starting");
    let npub = bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), &x_only)
        .expect("bech32 encode");
    eprintln!("[SIM] npub: {}", npub);
    eprintln!("[SIM] node_addr: {}", hex::encode(my_addr.as_bytes()));
    eprintln!("[SIM] FIPS: {}", fips_addr);
    eprintln!(
        "[SIM] mode: {}",
        if is_initiator {
            "initiator"
        } else {
            "responder"
        }
    );
    if is_initiator {
        eprintln!("[SIM] target: {}", hex::encode(&target_addr));
    }

    use std::net::ToSocketAddrs;
    let peer: std::net::SocketAddr = fips_addr
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .next()
        .expect("no addresses resolved");
    let transport = UdpTransport::new(peer);
    let mut node = Node::new(transport, rand_core::OsRng, secret, peer_pub);
    node.set_raw_framing(true);

    block_on(async move {
        if is_initiator {
            let mut handler = FspInitiatorHandler::new(
                secret,
                SIM_A_PUBKEY,
                target_addr,
                *my_addr.as_bytes(),
                test_ping,
            );
            node.run(&mut handler).await;
        } else {
            let mut handler = LeafHandler::new(secret);
            node.run(&mut handler).await;
        }
    });
}
