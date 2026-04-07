#![allow(
    clippy::needless_borrows_for_generic_args,
    clippy::needless_borrow,
    clippy::collapsible_if
)]

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Instant, Timer};
use k256::SecretKey;
use rand::RngCore;

use microfips_core::identity::{load_peer_pub, load_secret, NodeAddr};
use microfips_core::noise;
use microfips_http_demo::DemoService;
use microfips_protocol::fsp_handler::FspDualHandler;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;
use microfips_service::{
    decode_response, encode_request, FspServiceAdapter, ServiceMethod, ServiceStatus,
};

// ---------------------------------------------------------------------------
// UdpTransport: raw FMP over UDP (no length-prefix framing)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct UdpError;

struct UdpTransport {
    socket: UdpSocket,
    peer: std::net::SocketAddr,
    label: &'static str,
}

impl UdpTransport {
    fn new(peer: std::net::SocketAddr, label: &'static str) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").expect("UDP bind failed");
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(120)))
            .ok();
        Self {
            socket,
            peer,
            label,
        }
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
            log::info!(
                "[{} → FIPS] TX {}B phase=0x{:01x}{}",
                self.label,
                data.len(),
                phase,
                extra,
            );
            log::debug!(
                "[{} → FIPS] TX first bytes: {:02x?}",
                self.label,
                &data[..data.len().min(16)]
            );
        }
        self.socket.send_to(data, self.peer).map_err(|_| UdpError)?;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UdpError> {
        loop {
            match self.socket.recv_from(buf) {
                Ok((n, _addr)) => {
                    if n >= 4 {
                        let phase = buf[0] & 0x0F;
                        log::info!("[FIPS → {}] RX {}B phase=0x{:01x}", self.label, n, phase,);
                        log::debug!(
                            "[FIPS → {}] RX first bytes: {:02x?}",
                            self.label,
                            &buf[..n.min(16)]
                        );
                    }
                    return Ok(n);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    Timer::after(Duration::from_millis(1)).await;
                }
                Err(_) => return Err(UdpError),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SimHandler: thin wrapper around FspDualHandler for sim-specific logging
// ---------------------------------------------------------------------------

struct SimHandler {
    inner: FspDualHandler<FspServiceAdapter<DemoService>>,
    is_initiator: bool,
    test_http: bool,
    label: &'static str,
}

impl SimHandler {
    fn new_responder(secret: [u8; 32], label: &'static str) -> Self {
        let mut eph = [0u8; 32];
        rand::rng().fill_bytes(&mut eph);
        Self {
            inner: FspDualHandler::new_responder(
                secret,
                eph,
                FspServiceAdapter::new(DemoService::new()),
            ),
            is_initiator: false,
            test_http: false,
            label,
        }
    }

    fn new_initiator(
        secret: [u8; 32],
        target_pub: &[u8; 33],
        target_addr: [u8; 16],
        test_ping: bool,
        test_http: bool,
        label: &'static str,
    ) -> Self {
        let mut resp_eph = [0u8; 32];
        rand::rng().fill_bytes(&mut resp_eph);
        let mut init_eph = [0u8; 32];
        rand::rng().fill_bytes(&mut init_eph);
        let mut inner = FspDualHandler::new_dual(
            secret,
            resp_eph,
            init_eph,
            target_pub,
            target_addr,
            FspServiceAdapter::new(DemoService::new()),
        );
        inner.test_ping = test_ping && !test_http;
        Self {
            inner,
            is_initiator: true,
            test_http,
            label,
        }
    }

    fn is_established(&self) -> bool {
        self.inner
            .initiator
            .as_ref()
            .is_some_and(|i| i.state() == microfips_core::fsp::FspInitiatorState::Established)
    }

    fn my_addr(&self) -> Option<[u8; 16]> {
        let pub_key = noise::ecdh_pubkey(&self.inner.secret).ok()?;
        let normalized = noise::parity_normalize(&pub_key);
        let x_only: [u8; 32] = normalized[1..].try_into().ok()?;
        Some(NodeAddr::from_pubkey_x(&x_only).0)
    }

    fn is_http_response(&self, payload: &[u8]) -> bool {
        if payload.len() < microfips_core::fsp::SESSION_DATAGRAM_BODY_SIZE {
            return false;
        }
        let fsp_data = &payload[microfips_core::fsp::SESSION_DATAGRAM_BODY_SIZE..];
        if fsp_data.is_empty() {
            return false;
        }
        let Some((_flags, counter, header, encrypted)) =
            microfips_core::fsp::parse_fsp_encrypted_header(fsp_data)
        else {
            return false;
        };
        let (k_recv, _) = match self.inner.initiator.as_ref().and_then(|i| i.session_keys()) {
            Some(k) => k,
            None => return false,
        };
        let mut dec = [0u8; 512];
        let Ok(dl) = noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut dec) else {
            return false;
        };
        let Some((_ts, _mt, _flags, inner_payload)) =
            microfips_core::fsp::fsp_strip_inner_header(&dec[..dl])
        else {
            return false;
        };
        decode_response(inner_payload)
            .map(|response| response.status == ServiceStatus::OK)
            .unwrap_or(false)
    }
}

impl NodeHandler for SimHandler {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => log::info!("[{}] transport ready", self.label),
            NodeEvent::Msg1Sent => log::info!("[{} → FIPS] MSG1 sent", self.label),
            NodeEvent::HandshakeOk => {
                self.inner.on_event_default(event);
                log::info!(
                    "[{}] handshake complete (FSP {})",
                    self.label,
                    if self.is_initiator {
                        "initiator"
                    } else {
                        "responder"
                    }
                )
            }
            NodeEvent::HeartbeatSent => {}
            NodeEvent::HeartbeatRecv => {}
            NodeEvent::Disconnected => {
                log::info!("[{}] session ended, reconnecting", self.label)
            }
            NodeEvent::Error => {
                log::warn!("[{}] handshake error, retrying", self.label)
            }
        }
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        let result = self.inner.on_message(msg_type, payload, resp);
        if result == HandleResult::Disconnect {
            log::info!(
                "[{}] *** test {} success, exiting ***",
                self.label,
                if self.test_http { "http" } else { "ping" }
            );
            std::process::exit(0);
        }
        if self.test_http && self.is_established() && self.is_http_response(payload) {
            log::info!("[{}] *** test http success, exiting ***", self.label);
            std::process::exit(0);
        }
        if let HandleResult::SendDatagram(len) = result {
            log::info!("[{} → FIPS] TX datagram response {}B", self.label, len);
        }
        result
    }

    fn poll_at(&self) -> Option<Instant> {
        self.inner.poll_at()
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        if self.test_http && self.is_established() {
            let target_addr = match &self.inner.target_addr {
                Some(a) => *a,
                None => return HandleResult::None,
            };
            let my_addr = match self.my_addr() {
                Some(a) => a,
                None => return HandleResult::None,
            };
            let fsp = match &mut self.inner.initiator {
                Some(f) => f,
                None => return HandleResult::None,
            };
            let dg_body = microfips_core::fsp::build_session_datagram_body(&my_addr, &target_addr);
            let (_k_recv, k_send) = match fsp.session_keys() {
                Some(k) => k,
                None => return HandleResult::None,
            };
            let send_ctr = fsp.next_send_counter();
            let mut request = [0u8; 128];
            let request_len = match encode_request(ServiceMethod::Get, "/health", b"", &mut request)
            {
                Ok(len) => len,
                Err(_) => return HandleResult::None,
            };
            let ts = 0u32;
            let mut fsp_packet = [0u8; 512];
            let fsp_total = match microfips_core::fsp::build_fsp_data_message(
                send_ctr,
                ts,
                &request[..request_len],
                &k_send,
                &mut fsp_packet,
            ) {
                Ok(len) => len,
                Err(_) => return HandleResult::None,
            };
            let dg_len = microfips_core::fsp::SESSION_DATAGRAM_BODY_SIZE + fsp_total;
            resp[..microfips_core::fsp::SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
            resp[microfips_core::fsp::SESSION_DATAGRAM_BODY_SIZE..dg_len]
                .copy_from_slice(&fsp_packet[..fsp_total]);
            self.inner.fsp_timer = Some(Instant::now() + Duration::from_secs(10));
            log::info!("[{} → FIPS] TX service GET /health {}B", self.label, dg_len);
            return HandleResult::SendDatagram(dg_len);
        }

        let result = self.inner.on_tick(resp);
        if let HandleResult::SendDatagram(len) = result {
            if self
                .inner
                .initiator
                .as_ref()
                .is_some_and(|i| i.state() == microfips_core::fsp::FspInitiatorState::Established)
            {
                log::info!(
                    "[{} → FIPS] TX {} {}B",
                    self.label,
                    if self.test_http { "HTTP GET" } else { "PING" },
                    len
                );
            } else {
                log::info!("[{} → FIPS] FSP action {}B", self.label, len);
            }
        }
        result
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

    let output = result.lock().unwrap().take().unwrap();
    output
}

// ---------------------------------------------------------------------------
// Leaf node identities (from keys.json)
// ---------------------------------------------------------------------------

const SIM_A_SECRET: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_sim-a"));
const SIM_B_SECRET: [u8; 32] = microfips_core::hex::hex_bytes_32(env!("DEVICE_SECRET_HEX_sim-b"));
const SIM_A_PUBKEY: [u8; 33] = microfips_core::hex::hex_bytes_33(env!("DEVICE_PUBKEY_HEX_sim-a"));
const STM32_PUBKEY: [u8; 33] = microfips_core::hex::hex_bytes_33(env!("DEVICE_PUBKEY_HEX_stm32"));
const ESP32_PUBKEY: [u8; 33] = microfips_core::hex::hex_bytes_33(env!("DEVICE_PUBKEY_HEX_esp32"));
const SIM_A_TARGET: [u8; 16] = microfips_core::hex::hex_bytes_16(env!("DEVICE_NODE_ADDR_sim-a"));

#[allow(dead_code)]
const ESP32_TARGET: [u8; 16] = microfips_core::hex::hex_bytes_16(env!("DEVICE_NODE_ADDR_esp32"));

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
    eprintln!("  --test-http    Send HTTP GET and exit on HTTP/1.1 200 response");
    eprintln!("  --test-ping    Send PING and exit on PONG response");
    eprintln!("  --keygen       Generate a new keypair and print env vars");
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
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

    let use_sim_a = args.iter().any(|a| a == "--sim-a");
    let use_sim_b = args.iter().any(|a| a == "--sim-b");

    let node_label: &'static str = if use_sim_a {
        "SIM-A"
    } else if use_sim_b {
        "SIM-B"
    } else {
        "SIM"
    };

    if args.len() < 3 || args.get(1).map(|a| a.as_str()) != Some("--udp") {
        print_usage();
        std::process::exit(1);
    }

    let fips_addr = args.get(2).expect("--udp requires an address");
    let test_ping = args.iter().any(|a| a == "--test-ping");
    let test_http = args.iter().any(|a| a == "--test-http");
    let test_ping = test_ping && !test_http;
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
                    log::error!("[{}] --target must be 16 bytes (32 hex chars)", node_label);
                    std::process::exit(1);
                }
            },
            None if is_initiator => {
                log::error!(
                    "[{}] --initiator requires --target <node_addr_hex>",
                    node_label
                );
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

    let stm32_target: [u8; 16] = [
        0x13, 0x2f, 0x39, 0xa9, 0x8c, 0x31, 0xba, 0xad, 0xdb, 0xa6, 0x52, 0x5f, 0x5d, 0x43, 0xf2,
        0x95,
    ];
    let fsp_target_pub = if use_sim_b {
        SIM_A_PUBKEY
    } else if let Some(hex_str) = target_arg {
        match hex::decode(hex_str) {
            Ok(ref bytes) if *bytes == SIM_A_TARGET => SIM_A_PUBKEY,
            Ok(ref bytes) if *bytes == stm32_target => STM32_PUBKEY,
            Ok(ref bytes) if *bytes == ESP32_TARGET => ESP32_PUBKEY,
            _ => {
                log::warn!(
                    "[{}] unknown target NodeAddr, FSP will fail (no pubkey mapping)",
                    node_label
                );
                SIM_A_PUBKEY
            }
        }
    } else {
        SIM_A_PUBKEY
    };

    log::info!("[{}] microfips leaf node starting", node_label);
    let npub = bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), &x_only)
        .expect("bech32 encode");
    log::info!("[{}] npub: {}", node_label, npub);
    log::info!(
        "[{}] node_addr: {}",
        node_label,
        hex::encode(my_addr.as_bytes())
    );
    log::info!("[{}] FIPS: {}", node_label, fips_addr);
    log::info!(
        "[{}] mode: {}",
        node_label,
        if is_initiator {
            "initiator"
        } else {
            "responder"
        }
    );
    if is_initiator {
        log::info!("[{}] target: {}", node_label, hex::encode(&target_addr));
    }

    use std::net::ToSocketAddrs;
    let peer: std::net::SocketAddr = fips_addr
        .to_socket_addrs()
        .expect("DNS resolution failed")
        .next()
        .expect("no addresses resolved");
    let transport = UdpTransport::new(peer, node_label);
    let mut node = Node::new(transport, rand_core::OsRng, secret, peer_pub);
    node.set_raw_framing(true);

    block_on(async move {
        if is_initiator {
            let mut handler = SimHandler::new_initiator(
                secret,
                &fsp_target_pub,
                target_addr,
                test_ping,
                test_http,
                node_label,
            );
            node.run(&mut handler).await;
        } else {
            let mut handler = SimHandler::new_responder(secret, node_label);
            node.run(&mut handler).await;
        }
    });
}
