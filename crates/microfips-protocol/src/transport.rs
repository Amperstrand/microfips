use core::fmt::Debug;
use core::future::Future;

use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;
use crate::framing;

pub trait CryptoRng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

pub trait Transport {
    type Error: Debug;

    fn wait_ready(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
    fn send(&mut self, data: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>>;
}

pub struct FrameWriter<T: Transport> {
    transport: T,
}

impl<T: Transport> FrameWriter<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub async fn send_frame(&mut self, payload: &[u8]) -> Result<(), ProtocolError> {
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

    pub fn into_inner(self) -> T {
        self.transport
    }
}

pub struct FrameReader<T: Transport> {
    transport: T,
    rbuf: [u8; 2048],
    rpos: usize,
    rlen: usize,
}

impl<T: Transport> FrameReader<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            rbuf: [0u8; 2048],
            rpos: 0,
            rlen: 0,
        }
    }

    pub async fn recv_frame(
        &mut self,
        out: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize, ProtocolError> {
        loop {
            let need_more = if self.rpos < self.rlen {
                if self.rlen - self.rpos < 2 {
                    true
                } else {
                    let ml = u16::from_le_bytes([self.rbuf[self.rpos], self.rbuf[self.rpos + 1]])
                        as usize;
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

    pub fn into_inner(self) -> T {
        self.transport
    }
}

#[cfg(any(test, feature = "std"))]
pub mod mock {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::vec::Vec;

    use embassy_time::{Duration, Timer};

    use crate::error::ProtocolError;

    #[derive(Debug)]
    pub struct MockTransportInner {
        pub tx: Mutex<Vec<u8>>,
        pub rx: Mutex<Vec<u8>>,
        closed: AtomicBool,
    }

    impl MockTransportInner {
        pub fn new() -> Self {
            Self {
                tx: Mutex::new(Vec::new()),
                rx: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
            }
        }

        pub fn reset(&self) {
            self.tx.lock().unwrap().clear();
            self.rx.lock().unwrap().clear();
            self.closed.store(false, Ordering::Relaxed);
        }

        pub fn pump(&self, other: &Self) {
            let tx = self.tx.lock().unwrap();
            if !tx.is_empty() {
                other.rx.lock().unwrap().extend_from_slice(&tx);
            }
            drop(tx);
            self.tx.lock().unwrap().clear();
        }

        pub fn close(&self) {
            self.closed.store(true, Ordering::Relaxed);
        }
    }

    impl Default for MockTransportInner {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Debug)]
    pub struct MockTransport {
        inner: &'static MockTransportInner,
    }

    impl MockTransport {
        pub fn new(inner: &'static MockTransportInner) -> Self {
            Self { inner }
        }
    }

    impl super::Transport for MockTransport {
        type Error = ProtocolError;

        async fn wait_ready(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            self.inner.tx.lock().unwrap().extend_from_slice(data);
            self.inner.rx.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.inner.closed.load(Ordering::Relaxed) {
                return Err(ProtocolError::Disconnected);
            }
            loop {
                {
                    let rx = self.inner.rx.lock().unwrap();
                    if !rx.is_empty() {
                        let n = rx.len().min(buf.len());
                        buf[..n].copy_from_slice(&rx[..n]);
                        drop(rx);
                        self.inner.rx.lock().unwrap().drain(..n);
                        return Ok(n);
                    }
                }
                Timer::after(Duration::from_millis(1)).await;
                if self.inner.closed.load(Ordering::Relaxed) {
                    return Err(ProtocolError::Disconnected);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use embassy_executor::Executor;

    use super::{FrameReader, FrameWriter, ProtocolError};
    use crate::transport::mock::{MockTransport, MockTransportInner};
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

    fn inner() -> &'static MockTransportInner {
        static INNER: LazyLock<MockTransportInner> = LazyLock::new(MockTransportInner::new);
        &*INNER
    }

    fn fresh_inner() -> &'static MockTransportInner {
        let r = inner();
        r.reset();
        r
    }

    #[test]
    fn test_send_recv_frame_roundtrip() {
        fresh_inner();
        let writer = MockTransport::new(inner());
        let reader = MockTransport::new(inner());

        block_on(async {
            let mut fw = FrameWriter::new(writer);
            let mut fr = FrameReader::new(reader);

            let payload = b"hello world";
            fw.send_frame(payload).await.unwrap();

            let mut out = [0u8; 256];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, payload.len());
            assert_eq!(&out[..n], payload);
        });
    }

    #[test]
    fn test_frame_71_bytes() {
        fresh_inner();
        let writer = MockTransport::new(inner());
        let reader = MockTransport::new(inner());

        block_on(async {
            let mut fw = FrameWriter::new(writer);
            let mut fr = FrameReader::new(reader);

            let payload = [0xABu8; 71];
            fw.send_frame(&payload).await.unwrap();

            let mut out = [0u8; 256];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 71);
            assert_eq!(out[..71], [0xABu8; 71]);
        });
    }

    #[test]
    fn test_frame_128_bytes() {
        fresh_inner();
        let writer = MockTransport::new(inner());
        let reader = MockTransport::new(inner());

        block_on(async {
            let mut fw = FrameWriter::new(writer);
            let mut fr = FrameReader::new(reader);

            let payload = [0xCDu8; 128];
            fw.send_frame(&payload).await.unwrap();

            let mut out = [0u8; 256];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 128);
            assert_eq!(out[..128], [0xCDu8; 128]);
        });
    }

    #[test]
    fn test_multiple_frames_sequential() {
        fresh_inner();
        let writer = MockTransport::new(inner());
        let reader = MockTransport::new(inner());

        block_on(async {
            let mut fw = FrameWriter::new(writer);
            let mut fr = FrameReader::new(reader);

            fw.send_frame(b"first").await.unwrap();
            fw.send_frame(&[0x42u8; 200]).await.unwrap();

            let mut out = [0u8; 256];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 5);
            assert_eq!(&out[..5], b"first");

            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 200);
            assert_eq!(out[..200], [0x42u8; 200]);
        });
    }

    #[test]
    fn test_recv_timeout() {
        fresh_inner();
        let reader = MockTransport::new(inner());

        block_on(async {
            let mut fr = FrameReader::new(reader);
            let mut out = [0u8; 64];
            let result = fr.recv_frame(&mut out, 10).await;
            assert_eq!(result, Err(ProtocolError::Timeout));
        });
    }

    #[test]
    fn test_large_frame_near_max() {
        fresh_inner();
        let writer = MockTransport::new(inner());
        let reader = MockTransport::new(inner());

        block_on(async {
            let mut fw = FrameWriter::new(writer);
            let mut fr = FrameReader::new(reader);

            let payload = [0x55u8; 1400];
            fw.send_frame(&payload).await.unwrap();

            let mut out = [0u8; 1500];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 1400);
            assert_eq!(out[..1400], [0x55u8; 1400]);
        });
    }
}
