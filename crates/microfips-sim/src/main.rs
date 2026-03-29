use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use microfips_core::fmp;
use microfips_core::noise;
use rand::RngCore;

const HB_SECS: u64 = 10;
const RECV_TIMEOUT_SECS: u64 = 30;

const MCU_SECRET: [u8; 32] = [
    0xac, 0x68, 0xaf, 0x89, 0x46, 0x2e, 0x7e, 0xd2, 0x6f, 0xf6, 0x70, 0xc1, 0x86, 0xb4, 0xee, 0xb5,
    0x3c, 0x4e, 0x82, 0xd7, 0x2c, 0x8e, 0xf6, 0xce, 0xc4, 0xe6, 0x76, 0xc7, 0x84, 0x3f, 0x83, 0x2e,
];

const VPS_PUB: [u8; 33] = [
    0x02, 0x0e, 0x7a, 0x0d, 0xa0, 0x1a, 0x25, 0x5c, 0xde, 0x10, 0x6a, 0x20, 0x2e, 0xf4, 0xf5, 0x73,
    0x67, 0x6e, 0xf9, 0xe2, 0x4f, 0x1c, 0x81, 0x76, 0xd0, 0x3a, 0xe8, 0x3a, 0x2a, 0x3a, 0x03, 0x7d,
    0x21,
];

static SEND_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_ctr() -> u64 {
    SEND_COUNTER.fetch_add(1, Ordering::Relaxed)
}

struct Framed<R> {
    reader: R,
    rbuf: Vec<u8>,
    rpos: usize,
}

impl<R: Read> Framed<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            rbuf: Vec::with_capacity(4096),
            rpos: 0,
        }
    }

    fn compact(&mut self) {
        if self.rpos > 0 && self.rpos < self.rbuf.len() {
            let remaining = self.rbuf.len() - self.rpos;
            self.rbuf.copy_within(self.rpos.., 0);
            self.rpos = 0;
            self.rbuf.truncate(remaining);
        }
    }

    fn recv_frame(&mut self, timeout: Duration) -> std::io::Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.rpos < self.rbuf.len() {
                if self.rbuf.len() - self.rpos < 2 {
                    self.compact();
                    continue;
                }
                let ml =
                    u16::from_le_bytes([self.rbuf[self.rpos], self.rbuf[self.rpos + 1]]) as usize;
                if ml == 0 || ml > 1500 || self.rbuf.len() - self.rpos - 2 < ml {
                    self.rpos = self.rbuf.len();
                    self.compact();
                    continue;
                }
                let s = self.rpos + 2;
                let e = s + ml;
                let frame = self.rbuf[s..e].to_vec();
                self.rpos = e;
                if self.rpos >= self.rbuf.len() {
                    self.rpos = 0;
                    self.rbuf.clear();
                }
                return Ok(frame);
            }
            self.compact();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "recv timeout",
                ));
            }
            let mut chunk = [0u8; 2048];
            match self.reader.read(&mut chunk) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "eof",
                    ));
                }
                Ok(n) => {
                    if self.rbuf.len() + n > self.rbuf.capacity() {
                        eprintln!("WARN: rx buffer overflow, clearing");
                        self.rbuf.clear();
                        self.rpos = 0;
                        continue;
                    }
                    self.rbuf.extend_from_slice(&chunk[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

fn send_frame(w: &mut impl Write, payload: &[u8]) -> std::io::Result<()> {
    let hdr = (payload.len() as u16).to_le_bytes();
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

fn sim_err(e: noise::NoiseError) -> Box<dyn std::error::Error> {
    format!("{:?}", e).into()
}

#[allow(clippy::type_complexity)]
fn handshake<R: Read, W: Write>(
    framed: &mut Framed<R>,
    out: &mut W,
) -> Result<([u8; 32], [u8; 32], u32, u32), Box<dyn std::error::Error>> {
    let my_pub = noise::ecdh_pubkey(&MCU_SECRET).map_err(sim_err)?;

    let mut rng = rand::rng();
    let mut eph = [0u8; 32];
    rng.fill_bytes(&mut eph);

    let (mut st, _ep) =
        noise::NoiseIkInitiator::new(&eph, &MCU_SECRET, &VPS_PUB).map_err(sim_err)?;

    let epoch: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];

    let mut n1 = [0u8; 256];
    let n1len = st
        .write_message1(&my_pub, &epoch, &mut n1)
        .map_err(sim_err)?;

    let mut f1 = [0u8; 256];
    let f1len = fmp::build_msg1(0, &n1[..n1len], &mut f1).unwrap();

    eprintln!("[SIM] sending MSG1 ({}B)", f1len);
    send_frame(out, &f1[..f1len])?;

    eprintln!("[SIM] waiting for MSG2...");
    let mb = framed.recv_frame(Duration::from_secs(RECV_TIMEOUT_SECS))?;
    eprintln!("[SIM] received frame ({}B)", mb.len());

    let m = fmp::parse_message(&mb).ok_or("failed to parse FMP message")?;
    match m {
        fmp::FmpMessage::Msg2 {
            sender_idx,
            receiver_idx,
            noise_payload,
        } => {
            eprintln!(
                "[SIM] MSG2: sender={}, receiver={}, noise={}B",
                sender_idx,
                receiver_idx,
                noise_payload.len()
            );
            st.read_message2(noise_payload).map_err(sim_err)?;
            let (ks, kr) = st.finalize();
            eprintln!("[SIM] handshake complete! ks={:02x?}", &ks[..8]);
            Ok((ks, kr, sender_idx, receiver_idx))
        }
        other => Err(format!("expected MSG2, got {:?}", other).into()),
    }
}

fn steady<R: Read, W: Write>(
    framed: &mut Framed<R>,
    out: &mut W,
    ks: &[u8; 32],
    kr: &[u8; 32],
    them: u32,
    _us: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut next_hb = Instant::now() + Duration::from_secs(HB_SECS);
    let mut hb_count = 0u32;

    loop {
        let recv_result = framed.recv_frame(Duration::from_secs(HB_SECS));

        match recv_result {
            Ok(frame) => {
                handle_frame(kr, &frame)?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                eprintln!("[SIM] connection closed by peer");
                return Ok(());
            }
            Err(e) => {
                eprintln!("[SIM] recv error: {}", e);
                return Err(e.into());
            }
        }

        if Instant::now() >= next_hb {
            next_hb = Instant::now() + Duration::from_secs(HB_SECS);
            let c = next_ctr();
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u32;
            let mut hb_out = [0u8; 256];
            let fl = fmp::build_established(them, c, fmp::MSG_HEARTBEAT, ts, &[], ks, &mut hb_out);
            send_frame(out, &hb_out[..fl])?;
            hb_count += 1;
            eprintln!("[SIM] sent heartbeat #{} ({}B)", hb_count, fl);
        }
    }
}

fn handle_frame(kr: &[u8; 32], data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let m = fmp::parse_message(data).ok_or("failed to parse FMP message")?;
    match m {
        fmp::FmpMessage::Established {
            receiver_idx,
            counter,
            encrypted,
        } => {
            eprintln!(
                "[SIM] ESTABLISHED: receiver={}, counter={}, enc_len={}",
                receiver_idx,
                counter,
                encrypted.len(),
            );
            let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
            let mut dec = [0u8; 2048];
            let dl = noise::aead_decrypt(kr, counter, hdr, encrypted, &mut dec).map_err(sim_err)?;
            if dl < fmp::INNER_HEADER_SIZE {
                return Err("decrypted message too short".into());
            }
            match dec[4] {
                fmp::MSG_HEARTBEAT => {
                    eprintln!("[SIM] received heartbeat");
                }
                fmp::MSG_DISCONNECT => {
                    eprintln!("[SIM] received disconnect");
                    return Err("peer disconnected".into());
                }
                t => {
                    eprintln!(
                        "[SIM] received msg type 0x{:02x}, {}B payload",
                        t,
                        dl - fmp::INNER_HEADER_SIZE
                    );
                }
            }
            Ok(())
        }
        other => {
            eprintln!(
                "[SIM] ignoring non-ESTABLISHED in steady state: {:?}",
                other
            );
            Ok(())
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut listen_port: Option<u16> = None;
    let mut tcp_addr: Option<&str> = None;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--listen" {
            i += 1;
            listen_port = args.get(i).and_then(|s| s.parse().ok());
        } else if args[i] != "--" {
            tcp_addr = Some(&args[i]);
        }
        i += 1;
    }

    let my_pub = noise::ecdh_pubkey(&MCU_SECRET).unwrap();
    eprintln!("[SIM] microfips simulator starting");
    eprintln!("[SIM] local pubkey: {}", hex::encode(my_pub));

    if let Some(port) = listen_port {
        eprintln!("[SIM] mode: listen, port: {}", port);
        let listener = TcpListener::bind(("0.0.0.0", port)).expect("failed to listen");
        eprintln!("[SIM] listening on 0.0.0.0:{}", port);
        loop {
            match listener.accept() {
                Ok((stream, addr)) => {
                    eprintln!("[SIM] connection from {}", addr);
                    let mut reader = stream.try_clone().expect("clone tcp");
                    reader
                        .set_read_timeout(Some(Duration::from_secs(HB_SECS)))
                        .expect("set read timeout");
                    let mut writer = stream;
                    let mut framed = Framed::new(&mut reader);

                    loop {
                        eprintln!("[SIM] --- starting handshake attempt ---");
                        match handshake(&mut framed, &mut writer) {
                            Ok((ks, kr, them, us)) => {
                                eprintln!("[SIM] handshake success! us={}, them={}", us, them);
                                match steady(&mut framed, &mut writer, &ks, &kr, them, us) {
                                    Ok(()) => {
                                        eprintln!("[SIM] steady state ended (peer closed)");
                                    }
                                    Err(e) => {
                                        eprintln!("[SIM] steady state error: {}", e);
                                    }
                                }
                                break;
                            }
                            Err(e) => {
                                eprintln!("[SIM] handshake failed: {}", e);
                                eprintln!("[SIM] will retry after 3s...");
                                std::thread::sleep(Duration::from_secs(3));
                            }
                        }
                    }
                    eprintln!("[SIM] session ended, waiting for new connection...");
                }
                Err(e) => {
                    eprintln!("[SIM] accept error: {}", e);
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    } else if let Some(addr) = tcp_addr {
        eprintln!("[SIM] mode: tcp, target: {}", addr);
        loop {
            eprintln!("[SIM] connecting to {}...", addr);
            match TcpStream::connect(addr) {
                Ok(stream) => {
                    eprintln!("[SIM] connected");
                    let mut reader = stream.try_clone().expect("clone tcp");
                    reader
                        .set_read_timeout(Some(Duration::from_secs(HB_SECS)))
                        .expect("set read timeout");
                    let mut writer = stream;
                    let mut framed = Framed::new(&mut reader);

                    loop {
                        eprintln!("[SIM] --- starting handshake attempt ---");
                        match handshake(&mut framed, &mut writer) {
                            Ok((ks, kr, them, us)) => {
                                eprintln!("[SIM] handshake success! us={}, them={}", us, them);
                                match steady(&mut framed, &mut writer, &ks, &kr, them, us) {
                                    Ok(()) => {
                                        eprintln!("[SIM] steady state ended (peer closed)");
                                    }
                                    Err(e) => {
                                        eprintln!("[SIM] steady state error: {}", e);
                                    }
                                }
                                break;
                            }
                            Err(e) => {
                                eprintln!("[SIM] handshake failed: {}", e);
                                eprintln!("[SIM] will retry after 3s...");
                                std::thread::sleep(Duration::from_secs(3));
                            }
                        }
                    }
                    eprintln!("[SIM] session ended, reconnecting in 3s...");
                    std::thread::sleep(Duration::from_secs(3));
                }
                Err(e) => {
                    eprintln!("[SIM] connect failed: {}, retrying in 3s...", e);
                    std::thread::sleep(Duration::from_secs(3));
                }
            }
        }
    } else {
        eprintln!("[SIM] mode: stdio (reading from stdin, writing to stdout)");
        eprintln!("[SIM] usage: microfips-sim [--listen PORT | tcp_addr]");
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        let reader = stdin.lock();
        let mut writer = stdout.lock();
        let mut framed = Framed::new(reader);

        loop {
            eprintln!("[SIM] --- starting handshake attempt ---");
            match handshake(&mut framed, &mut writer) {
                Ok((ks, kr, them, us)) => {
                    eprintln!("[SIM] handshake success! us={}, them={}", us, them);
                    match steady(&mut framed, &mut writer, &ks, &kr, them, us) {
                        Ok(()) => {
                            eprintln!("[SIM] steady state ended (peer closed)");
                        }
                        Err(e) => {
                            eprintln!("[SIM] steady state error: {}", e);
                        }
                    }
                    eprintln!("[SIM] will retry after 3s...");
                    std::thread::sleep(Duration::from_secs(3));
                }
                Err(e) => {
                    eprintln!("[SIM] handshake failed: {}", e);
                    eprintln!("[SIM] will retry after 3s...");
                    std::thread::sleep(Duration::from_secs(3));
                }
            }
        }
    }
}
