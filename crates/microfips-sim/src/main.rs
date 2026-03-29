use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use embassy_time::{Duration, Timer};

use microfips_core::noise;
use microfips_protocol::node::{HandleResult, Node, NodeEvent, NodeHandler};
use microfips_protocol::transport::Transport;

const DEFAULT_SECRET: [u8; 32] = [
    0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4, 0xee, 0xb5,
    0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7, 0x84, 0x3f, 0x83, 0x2e,
];

const DEFAULT_PEER_PUB: [u8; 33] = [
    0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4, 0xf5, 0x73,
    0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a, 0x2a, 0x3a, 0x03, 0x7d,
    0x21,
];

fn load_secret() -> [u8; 32] {
    match std::env::var("FIPS_SECRET") {
        Ok(h) => {
            let b = hex::decode(h.trim()).expect("FIPS_SECRET: invalid hex");
            assert!(
                b.len() == 32,
                "FIPS_SECRET: must be 32 bytes (64 hex chars)"
            );
            b.try_into().unwrap()
        }
        Err(_) => DEFAULT_SECRET,
    }
}

fn load_peer_pub() -> [u8; 33] {
    match std::env::var("FIPS_PEER_PUB") {
        Ok(h) => {
            let b = hex::decode(h.trim()).expect("FIPS_PEER_PUB: invalid hex");
            assert!(
                b.len() == 33,
                "FIPS_PEER_PUB: must be 33 bytes (66 hex chars)"
            );
            b.try_into().unwrap()
        }
        Err(_) => DEFAULT_PEER_PUB,
    }
}

// ---------------------------------------------------------------------------
// SimTransport: wraps TCP or stdio for the protocol crate's Transport trait.
//
// A background reader thread pumps bytes from the underlying Read source into
// a shared VecDeque. Transport::recv polls the buffer, yielding to the
// embassy executor when no data is available. This lets Node's select-based
// steady-state loop interleave recv with heartbeat timers.
// ---------------------------------------------------------------------------

#[derive(Debug)]
#[allow(dead_code)] // Io variant's inner field is used via Debug trait (Transport::Error: Debug)
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
    /// Kept to shut down old TCP connections before reconnecting, which
    /// unblocks the reader thread so it can exit cleanly.
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
        // Shut down previous TCP connection so the old reader thread exits.
        if let Some(old) = self.shutdown_handle.take() {
            let _ = old.shutdown(std::net::Shutdown::Both);
        }

        match &self.connector {
            SimConnector::Listen(listener) => {
                // Fresh buffers per session to avoid races with the old reader.
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
                    // Stdio can't truly reconnect; clear stale data and retry.
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
// SimHandler: bridges protocol events to stderr logging
// ---------------------------------------------------------------------------

struct SimHandler;

impl NodeHandler for SimHandler {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => eprintln!("[SIM] transport ready"),
            NodeEvent::Msg1Sent => eprintln!("[SIM] MSG1 sent"),
            NodeEvent::HandshakeOk => eprintln!("[SIM] handshake complete!"),
            NodeEvent::HeartbeatSent => eprintln!("[SIM] sent heartbeat"),
            NodeEvent::HeartbeatRecv => eprintln!("[SIM] received heartbeat"),
            NodeEvent::Disconnected => eprintln!("[SIM] session ended"),
            NodeEvent::Error => eprintln!("[SIM] handshake error"),
        }
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], _resp: &mut [u8]) -> HandleResult {
        eprintln!(
            "[SIM] received msg type 0x{:02x}, {}B payload",
            msg_type,
            payload.len()
        );
        HandleResult::None
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

    // Intentional leak: this is called exactly once from main() and the executor
    // must live for the program's duration (Node::run never returns).
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
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut listen_port: Option<u16> = None;
    let mut tcp_addr: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--listen" {
            i += 1;
            listen_port = args.get(i).and_then(|s| s.parse().ok());
        } else if args[i] != "--" {
            tcp_addr = Some(args[i].clone());
        }
        i += 1;
    }

    let secret = load_secret();
    let peer_pub = load_peer_pub();
    let my_pub = noise::ecdh_pubkey(&secret).unwrap();
    eprintln!("[SIM] microfips simulator starting");
    eprintln!("[SIM] local pubkey: {}", hex::encode(my_pub));
    eprintln!("[SIM] peer pubkey:  {}", hex::encode(peer_pub));

    let transport = if let Some(port) = listen_port {
        eprintln!("[SIM] mode: listen, port: {}", port);
        let listener = TcpListener::bind(("0.0.0.0", port)).expect("failed to listen");
        eprintln!("[SIM] listening on 0.0.0.0:{}", port);
        SimTransport::new(SimConnector::Listen(listener))
    } else if let Some(addr) = tcp_addr {
        eprintln!("[SIM] mode: tcp, target: {}", addr);
        SimTransport::new(SimConnector::Connect(addr))
    } else {
        eprintln!("[SIM] mode: stdio (reading from stdin, writing to stdout)");
        eprintln!("[SIM] usage: microfips-sim [--listen PORT | tcp_addr]");
        SimTransport::new(SimConnector::Stdio)
    };

    let rng = rand_core::OsRng;
    let mut node = Node::new(transport, rng, secret, peer_pub);
    let mut handler = SimHandler;

    block_on(async move {
        node.run(&mut handler).await;
    });
}
