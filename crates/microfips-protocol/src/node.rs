use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;
use crate::framing;
use crate::transport::{CryptoRng, Transport};

pub const HB_SECS: u64 = 10;
pub const RECV_TIMEOUT_MS: u64 = 30_000;
pub const RETRY_SECS: u64 = 3;
pub const CONNECT_DELAY_MS: u64 = 500;

pub struct Node<T: Transport, R: CryptoRng> {
    transport: T,
    rng: R,
    secret: [u8; 32],
    peer_pub: [u8; 33],
    rbuf: [u8; 2048],
    rpos: usize,
    rlen: usize,
}

impl<T: Transport, R: CryptoRng> Node<T, R> {
    pub fn new(transport: T, rng: R, secret: [u8; 32], peer_pub: [u8; 33]) -> Self {
        Self {
            transport,
            rng,
            secret,
            peer_pub,
            rbuf: [0u8; 2048],
            rpos: 0,
            rlen: 0,
        }
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub async fn run(&mut self) -> ! {
        loop {
            let _ = self.session().await;
            Timer::after(Duration::from_secs(RETRY_SECS)).await;
        }
    }

    async fn session(&mut self) -> Result<(), ProtocolError> {
        self.transport.wait_ready().await.map_err(|_| ProtocolError::Disconnected)?;
        Timer::after(Duration::from_millis(CONNECT_DELAY_MS)).await;

        self.rpos = 0;
        self.rlen = 0;

        let (ks, kr, them) = self.handshake().await?;
        self.steady(&ks, &kr, them).await
    }

    async fn handshake(&mut self) -> Result<([u8; 32], [u8; 32], u32), ProtocolError> {
        use microfips_core::fmp;
        use microfips_core::noise;

        let my_pub = noise::ecdh_pubkey(&self.secret).unwrap();

        let mut eph = [0u8; 32];
        self.rng.fill_bytes(&mut eph);
        let (mut noise_st, _e_pub) =
            noise::NoiseIkInitiator::new(&eph, &self.secret, &self.peer_pub)
                .expect("noise init");

        let epoch: [u8; noise::EPOCH_SIZE] = [0x01, 0, 0, 0, 0, 0, 0, 0];

        let mut n1 = [0u8; 256];
        let n1len = noise_st
            .write_message1(&my_pub, &epoch, &mut n1)
            .expect("write_message1");

        let mut f1 = [0u8; 256];
        let f1len = fmp::build_msg1(0, &n1[..n1len], &mut f1);

        self.send_frame(&f1[..f1len]).await?;

        let mut mb = [0u8; 2048];
        loop {
            let ml = self.recv_frame(&mut mb, RECV_TIMEOUT_MS as u32).await?;
            let m = fmp::parse_message(&mb[..ml]).ok_or(ProtocolError::InvalidMessage)?;
            match m {
                fmp::FmpMessage::Msg2 {
                    sender_idx,
                    noise_payload,
                    ..
                } => {
                    let mut st = noise_st.clone();
                    st.read_message2(noise_payload)
                        .map_err(|_| ProtocolError::DecryptFailed)?;
                    let (ks, kr) = st.finalize();
                    return Ok((ks, kr, sender_idx));
                }
                _ => continue,
            }
        }
    }

    async fn steady(
        &mut self,
        ks: &[u8; 32],
        kr: &[u8; 32],
        them: u32,
    ) -> Result<(), ProtocolError> {
        let mut next_hb = embassy_time::Instant::now() + Duration::from_secs(HB_SECS);
        let mut send_ctr: u64 = 0;

        loop {
            let mut rx = [0u8; 256];
            let rx_fut = self.transport.recv(&mut rx);
            let hb_fut = Timer::at(next_hb);

            match select(rx_fut, hb_fut).await {
                Either::First(Ok(n)) => {
                    if self.rlen + n > self.rbuf.len() {
                        self.rlen = 0;
                        self.rpos = 0;
                        continue;
                    }
                    self.rbuf[self.rlen..self.rlen + n].copy_from_slice(&rx[..n]);
                    self.rlen += n;

            while self.rpos < self.rlen {
                        if self.rlen - self.rpos < 2 {
                            break;
                        }
                        let ml = u16::from_le_bytes([
                            self.rbuf[self.rpos],
                            self.rbuf[self.rpos + 1],
                        ]) as usize;
                        if ml == 0 || ml > framing::MAX_FRAME {
                            self.rpos = self.rlen;
                            break;
                        }
                        if self.rlen - self.rpos - 2 < ml {
                            break;
                        }
                        let s = self.rpos + 2;
                        let e = s + ml;
                        match self.handle_frame(kr, &self.rbuf[s..e]) {
                            FrameResult::PeerDC => return Ok(()),
                            FrameResult::Ok | FrameResult::Skipped => {}
                        }
                        self.rpos = e;
                    }
                    if self.rpos >= self.rlen {
                        self.rpos = 0;
                        self.rlen = 0;
                    }
                    if embassy_time::Instant::now() >= next_hb {
                        next_hb =
                            self.send_heartbeat(ks, them, &mut send_ctr).await;
                    }
                }
                Either::First(Err(_)) => {
                    return Err(ProtocolError::Disconnected);
                }
                Either::Second(()) => {
                    next_hb = self.send_heartbeat(ks, them, &mut send_ctr).await;
                }
            }
        }
    }

    fn handle_frame(&self, kr: &[u8; 32], data: &[u8]) -> FrameResult {
        use microfips_core::fmp;

        let m = match fmp::parse_message(data) {
            Some(m) => m,
            None => return FrameResult::Skipped,
        };

        match m {
            fmp::FmpMessage::Established {
                counter, encrypted, ..
            } => {
                let hdr = &data[..fmp::ESTABLISHED_HEADER_SIZE];
                let mut dec = [0u8; 2048];
                let dl =
                    match microfips_core::noise::aead_decrypt(
                        kr, counter, hdr, encrypted, &mut dec,
                    ) {
                        Ok(l) => l,
                        Err(_) => return FrameResult::Skipped,
                    };
                if dl < fmp::INNER_HEADER_SIZE {
                    return FrameResult::Skipped;
                }
                match dec[4] {
                    fmp::MSG_HEARTBEAT => FrameResult::Ok,
                    fmp::MSG_DISCONNECT => FrameResult::PeerDC,
                    _ => FrameResult::Skipped,
                }
            }
            _ => FrameResult::Skipped,
        }
    }

    async fn send_heartbeat(
        &mut self,
        ks: &[u8; 32],
        them: u32,
        ctr: &mut u64,
    ) -> embassy_time::Instant {
        use microfips_core::fmp;

        let c = *ctr;
        *ctr += 1;
        let ts = embassy_time::Instant::now().as_millis() as u32;
        let mut out = [0u8; 256];
        let fl = fmp::build_established(them, c, fmp::MSG_HEARTBEAT, ts, &[], ks, &mut out);

        let _ = self.send_frame(&out[..fl]).await;

        embassy_time::Instant::now() + Duration::from_secs(HB_SECS)
    }

    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
        let hdr = (payload.len() as u16).to_le_bytes();
        self.transport
            .send(&hdr)
            .await
            .map_err(|_| ProtocolError::Disconnected)?;
        self.transport
            .send(payload)
            .await
            .map_err(|_| ProtocolError::Disconnected)
    }

    async fn recv_frame(
        &mut self,
        out: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, ProtocolError> {
        loop {
            let need_more = if self.rpos < self.rlen {
                if self.rlen - self.rpos < 2 {
                    true
                } else {
                    let ml = u16::from_le_bytes([
                        self.rbuf[self.rpos],
                        self.rbuf[self.rpos + 1],
                    ]) as usize;
                    if ml == 0 || ml > framing::MAX_FRAME {
                        self.rpos = self.rlen;
                        true
                    } else if self.rlen - self.rpos - 2 < ml {
                        true
                    } else {
                        let s = self.rpos + 2;
                        let e = s + ml;
                        let l = ml.min(out.len());
                        out[..l].copy_from_slice(&self.rbuf[s..s + l]);
                        self.rpos = e;
                        if self.rpos >= self.rlen {
                            self.rpos = 0;
                            self.rlen = 0;
                        }
                        return Ok(l);
                    }
                }
            } else {
                true
            };

            if need_more {
                framing::compact(&mut self.rbuf, &mut self.rpos, &mut self.rlen);
                let mut rx = [0u8; 256];
                match select(
                    self.transport.recv(&mut rx),
                    Timer::after(Duration::from_millis(timeout_ms as u64)),
                )
                .await
                {
                    Either::First(Ok(n)) => {
                        if self.rlen + n > self.rbuf.len() {
                            self.rlen = 0;
                            self.rpos = 0;
                            continue;
                        }
                        self.rbuf[self.rlen..self.rlen + n].copy_from_slice(&rx[..n]);
                        self.rlen += n;
                    }
                    Either::First(Err(_)) => {
                        return Err(ProtocolError::Disconnected);
                    }
                    Either::Second(()) => return Err(ProtocolError::Timeout),
                }
            }
        }
    }
}

enum FrameResult {
    Ok,
    PeerDC,
    Skipped,
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_executor::Executor;
    use std::sync::LazyLock;

    fn block_on<F: std::future::Future + Send + 'static>(f: F) -> F::Output
    where
        F::Output: Send + 'static,
    {
        use embassy_executor::task;
        use std::boxed::Box;
        use std::sync::{Arc, Mutex};

        let executor: &'static mut Executor = Box::leak(Box::new(Executor::new()));

        let result: Arc<Mutex<Option<F::Output>>> = Arc::new(Mutex::new(None));
        let result_clone = result.clone();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done_clone = done.clone();
        let boxed: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
            Box::pin(async move {
                let output = f.await;
                *result_clone.lock().unwrap() = Some(output);
                done_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            });

        #[task(pool_size = 64)]
        async fn run_boxed(fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
            fut.await
        }

        let done_check = done.clone();

        executor.run_until(
            |spawner| {
                spawner.spawn(run_boxed(boxed).unwrap());
            },
            move || done_check.load(std::sync::atomic::Ordering::Relaxed),
        );

        result.lock().unwrap().take().unwrap()
    }

    struct TestRng {
        bytes: std::sync::Mutex<std::vec::Vec<u8>>,
    }

    impl TestRng {
        fn new(data: &[u8]) -> Self {
            Self {
                bytes: std::sync::Mutex::new(data.to_vec()),
            }
        }
    }

    impl CryptoRng for TestRng {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            let mut bytes = self.bytes.lock().unwrap();
            let n = buf.len().min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            bytes.drain(..n);
        }
    }

    fn inner() -> &'static crate::transport::mock::MockTransportInner {
        static INNER: LazyLock<crate::transport::mock::MockTransportInner> =
            LazyLock::new(crate::transport::mock::MockTransportInner::new);
        &*INNER
    }

    fn fresh_inner() -> &'static crate::transport::mock::MockTransportInner {
        let r = inner();
        r.reset();
        r
    }

    #[test]
    fn test_send_frame_works() {
        let transport = crate::transport::mock::MockTransport::new(fresh_inner());

        block_on(async {
            let mut node = Node::new(
                transport,
                TestRng::new(&[0u8; 32]),
                [0u8; 32],
                [0u8; 33],
            );
            node.send_frame(b"hello").await.unwrap();

            let tx = inner().tx.lock().unwrap();
            let expected: std::vec::Vec<u8> = {
                let mut v = (5u16).to_le_bytes().to_vec();
                v.extend_from_slice(b"hello");
                v
            };
            assert_eq!(*tx, expected);
        });
    }

    #[test]
    fn test_recv_frame_from_buffer() {
        fresh_inner();
        let transport = crate::transport::mock::MockTransport::new(inner());

        block_on(async {
            let mut node = Node::new(
                transport,
                TestRng::new(&[0u8; 32]),
                [0u8; 32],
                [0u8; 33],
            );

            let frame: std::vec::Vec<u8> = {
                let mut v = (3u16).to_le_bytes().to_vec();
                v.extend_from_slice(b"abc");
                v
            };
            inner().rx.lock().unwrap().extend_from_slice(&frame);

            let mut out = [0u8; 256];
            let n = node.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 3);
            assert_eq!(&out[..3], b"abc");
        });
    }
}
