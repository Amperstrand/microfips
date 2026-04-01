use core::fmt::Debug;
use core::future::Future;

use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;
use crate::framing;

pub use rand_core::{CryptoRng, RngCore};

pub trait Transport {
    type Error: Debug;

    fn wait_ready(&mut self) -> impl Future<Output = Result<(), Self::Error>>;
    fn send(&mut self, data: &[u8]) -> impl Future<Output = Result<(), Self::Error>>;
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<usize, Self::Error>>;
}

/// Canonical frame writer: wraps a [`Transport`] with length-prefixed framing.
///
/// Wire format: `[2-byte LE length][payload]`. This is the standard framing
/// used by both the USB CDC link (MCU↔host) and the TCP tunnel (host↔VPS).
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

/// Canonical frame reader: reassembles length-prefixed frames from a [`Transport`].
///
/// Handles partial reads, multi-packet frames, and buffered data across calls.
/// Wire format: `[2-byte LE length][payload]`.
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
pub mod channel {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;

    use embassy_time::{Duration, Timer};

    use crate::error::ProtocolError;

    #[derive(Debug)]
    struct ChannelInner {
        a_to_b: Mutex<Vec<u8>>,
        b_to_a: Mutex<Vec<u8>>,
        a_closed: AtomicBool,
        b_closed: AtomicBool,
    }

    impl ChannelInner {
        fn new() -> Self {
            Self {
                a_to_b: Mutex::new(Vec::new()),
                b_to_a: Mutex::new(Vec::new()),
                a_closed: AtomicBool::new(false),
                b_closed: AtomicBool::new(false),
            }
        }
    }

    #[derive(Debug)]
    enum Side {
        A,
        B,
    }

    #[derive(Debug)]
    pub struct ChannelTransport {
        inner: Arc<ChannelInner>,
        side: Side,
        max_chunk: usize,
    }

    impl ChannelTransport {
        fn new(inner: Arc<ChannelInner>, side: Side) -> Self {
            Self {
                inner,
                side,
                max_chunk: 256,
            }
        }

        pub fn set_max_chunk(&mut self, max: usize) {
            self.max_chunk = max;
        }

        pub fn close(&mut self) {
            match self.side {
                Side::A => self.inner.a_closed.store(true, Ordering::Relaxed),
                Side::B => self.inner.b_closed.store(true, Ordering::Relaxed),
            }
        }
    }

    impl super::Transport for ChannelTransport {
        type Error = ProtocolError;

        async fn wait_ready(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            let closed = match self.side {
                Side::A => &self.inner.a_closed,
                Side::B => &self.inner.b_closed,
            };
            if closed.load(Ordering::Relaxed) {
                return Err(ProtocolError::Disconnected);
            }
            let buf = match self.side {
                Side::A => &self.inner.a_to_b,
                Side::B => &self.inner.b_to_a,
            };
            buf.lock().unwrap().extend_from_slice(data);
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            let rx_buf = match self.side {
                Side::A => &self.inner.b_to_a,
                Side::B => &self.inner.a_to_b,
            };
            let my_closed = match self.side {
                Side::A => &self.inner.a_closed,
                Side::B => &self.inner.b_closed,
            };
            let peer_closed = match self.side {
                Side::A => &self.inner.b_closed,
                Side::B => &self.inner.a_closed,
            };
            loop {
                if my_closed.load(Ordering::Relaxed) {
                    return Err(ProtocolError::Disconnected);
                }
                let n = {
                    let mut guard = rx_buf.lock().unwrap();
                    if guard.is_empty() {
                        0
                    } else {
                        let n = guard.len().min(buf.len().min(self.max_chunk));
                        buf[..n].copy_from_slice(&guard[..n]);
                        guard.drain(..n);
                        n
                    }
                };
                if n > 0 {
                    return Ok(n);
                }
                if peer_closed.load(Ordering::Relaxed) {
                    return Err(ProtocolError::Disconnected);
                }
                Timer::after(Duration::from_millis(1)).await;
            }
        }
    }

    pub fn pair() -> (ChannelTransport, ChannelTransport) {
        let inner = Arc::new(ChannelInner::new());
        (
            ChannelTransport::new(inner.clone(), Side::A),
            ChannelTransport::new(inner, Side::B),
        )
    }
}

#[cfg(test)]
mod tests {
    use embassy_futures::join::join;

    use super::Transport;
    use super::{FrameReader, FrameWriter, ProtocolError};
    use crate::test_helpers::block_on;
    use crate::transport::channel::{pair as channel_pair, ChannelTransport};
    use crate::transport::mock::{MockTransport, MockTransportInner};
    use std::sync::LazyLock;

    fn inner() -> &'static MockTransportInner {
        static INNER: LazyLock<MockTransportInner> = LazyLock::new(MockTransportInner::new);
        &INNER
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

    fn channel() -> (ChannelTransport, ChannelTransport) {
        channel_pair()
    }

    async fn roundtrip_ble_chunk(max_chunk: usize, payload: &[u8]) {
        let (a, mut b) = channel();
        b.set_max_chunk(max_chunk);

        let mut fw = FrameWriter::new(a);
        let mut fr = FrameReader::new(b);
        let mut out = [0u8; 256];

        let (send_res, recv_res) = join(
            fw.send_frame(payload),
            fr.recv_frame(&mut out, 1000),
        )
        .await;

        send_res.unwrap();
        let n = recv_res.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&out[..n], payload);
    }

    #[test]
    fn test_ble_default_mtu_chunk_20() {
        block_on(async {
            roundtrip_ble_chunk(20, &[0x20u8; 114]).await;
        });
    }

    #[test]
    fn test_ble_mid_range_chunk_50() {
        block_on(async {
            roundtrip_ble_chunk(50, &[0x50u8; 114]).await;
        });
    }

    #[test]
    fn test_ble_negotiated_mtu_chunk_252() {
        block_on(async {
            roundtrip_ble_chunk(252, &[0xFCu8; 114]).await;
        });
    }

    #[test]
    fn test_channel_bidirectional() {
        let (mut a, mut b) = channel();
        block_on(async move {
            a.send(b"hello from a").await.unwrap();
            let mut buf = [0u8; 64];
            let n = b.recv(&mut buf).await.unwrap();
            assert_eq!(n, 12);
            assert_eq!(&buf[..12], b"hello from a");

            b.send(b"hello from b").await.unwrap();
            let mut buf = [0u8; 64];
            let n = a.recv(&mut buf).await.unwrap();
            assert_eq!(n, 12);
            assert_eq!(&buf[..12], b"hello from b");
        });
    }

    #[test]
    fn test_channel_close_propagates() {
        let (mut a, mut b) = channel();
        block_on(async move {
            a.send(b"before close").await.unwrap();
            a.close();
            let mut buf = [0u8; 64];
            let n = b.recv(&mut buf).await.unwrap();
            assert_eq!(n, 12);
            assert_eq!(&buf[..12], b"before close");
            let result = b.recv(&mut buf).await;
            assert_eq!(result, Err(ProtocolError::Disconnected));
        });
    }

    #[test]
    fn test_channel_max_chunk_limits_recv() {
        let (mut a, mut b) = channel();
        b.set_max_chunk(3);
        block_on(async move {
            a.send(b"abcdef").await.unwrap();
            let mut buf = [0u8; 64];
            let n1 = b.recv(&mut buf).await.unwrap();
            assert_eq!(n1, 3);
            assert_eq!(&buf[..3], b"abc");
            let n2 = b.recv(&mut buf).await.unwrap();
            assert_eq!(n2, 3);
            assert_eq!(&buf[..3], b"def");
        });
    }

    #[test]
    fn test_frame_split_three_reads() {
        let (a, mut b) = channel();
        b.set_max_chunk(64);
        block_on(async move {
            let mut fw = FrameWriter::new(a);
            let mut fr = FrameReader::new(b);

            let payload = [0xAAu8; 200];
            fw.send_frame(&payload).await.unwrap();

            let mut out = [0u8; 256];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 200);
            assert_eq!(out[..200], [0xAAu8; 200]);
        });
    }

    #[test]
    fn test_frame_header_then_body_reads() {
        let (a, mut b) = channel();
        b.set_max_chunk(2);
        block_on(async move {
            let mut fw = FrameWriter::new(a);
            let mut fr = FrameReader::new(b);

            let payload = [0xBBu8; 100];
            fw.send_frame(&payload).await.unwrap();

            let mut out = [0u8; 256];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 100);
            assert_eq!(out[..100], [0xBBu8; 100]);
        });
    }

    #[test]
    fn test_two_frames_in_single_read() {
        let (a, b) = channel();
        block_on(async move {
            let mut fw = FrameWriter::new(a);
            let mut fr = FrameReader::new(b);

            fw.send_frame(b"abc").await.unwrap();
            fw.send_frame(&[0xDDu8; 50]).await.unwrap();

            let mut out = [0u8; 256];
            let n1 = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n1, 3);
            assert_eq!(&out[..3], b"abc");

            let n2 = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n2, 50);
            assert_eq!(out[..50], [0xDDu8; 50]);
        });
    }

    #[test]
    fn test_frame_max_size() {
        let (a, mut b) = channel();
        b.set_max_chunk(600);
        block_on(async move {
            let mut fw = FrameWriter::new(a);
            let mut fr = FrameReader::new(b);

            let payload = [0xCCu8; 1500];
            fw.send_frame(&payload).await.unwrap();

            let mut out = [0u8; 1600];
            let n = fr.recv_frame(&mut out, 1000).await.unwrap();
            assert_eq!(n, 1500);
            assert_eq!(out[..1500], [0xCCu8; 1500]);
        });
    }
}
