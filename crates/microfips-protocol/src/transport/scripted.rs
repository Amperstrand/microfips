//! Test-only mock transport. Closest upstream: fips v0.4.0 `src/transport/loopback.rs`.

use std::boxed::Box;
use std::collections::VecDeque;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use embassy_time::{Duration, Timer};

use crate::error::ProtocolError;

/// Matcher function type for ExpectSend steps.
type SendMatcher = Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// A single step in a scripted sequence.
pub enum Step {
    /// Expect send() to be called with data matching this pattern.
    /// `matcher` receives the sent data and returns Ok(()) if acceptable,
    /// or Err(description) if unexpected.
    ExpectSend(SendMatcher),
    /// Provide data on the next recv() call.
    Recv(Vec<u8>),
    /// Delay before the next recv() returns (simulates network latency).
    DelayMs(u64),
    /// Close the transport — recv() returns Disconnected error.
    Close,
}

/// A transport that follows a pre-programmed script of send/recv steps.
/// Steps are consumed in order. If the script runs out, recv() blocks forever.
pub struct ScriptedTransport {
    steps: VecDeque<Step>,
    sent_data: Vec<Vec<u8>>,
}

impl ScriptedTransport {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: steps.into(),
            sent_data: Vec::new(),
        }
    }

    pub fn recv_bytes(data: &[u8]) -> Self {
        Self::new(vec![Step::Recv(data.to_vec())])
    }

    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    pub fn sent_data(&self) -> &[Vec<u8>] {
        &self.sent_data
    }

    pub fn into_sent_data(self) -> Vec<Vec<u8>> {
        self.sent_data
    }
}

impl super::Transport for ScriptedTransport {
    type Error = ProtocolError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.sent_data.push(data.to_vec());

        if let Some(Step::ExpectSend(_)) = self.steps.front() {
            let Some(Step::ExpectSend(matcher)) = self.steps.pop_front() else {
                unreachable!();
            };
            matcher(data).map_err(|_| ProtocolError::InvalidMessage)?;
        }

        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            match self.steps.pop_front() {
                Some(Step::Recv(mut data)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    if n < data.len() {
                        let rest = data.split_off(n);
                        self.steps.push_front(Step::Recv(rest));
                    }
                    return Ok(n);
                }
                Some(Step::DelayMs(ms)) => Timer::after(Duration::from_millis(ms)).await,
                Some(Step::Close) => return Err(ProtocolError::Disconnected),
                Some(step @ Step::ExpectSend(_)) => {
                    self.steps.push_front(step);
                    Timer::after(Duration::from_millis(1)).await;
                }
                None => Timer::after(Duration::from_millis(1)).await,
            }
        }
    }
}

/// High-level builder for scripted protocol scenarios.
#[derive(Default)]
pub struct ScriptedPeer {
    steps: Vec<Step>,
}

impl ScriptedPeer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn expect_send<F>(mut self, matcher: F) -> Self
    where
        F: Fn(&[u8]) -> Result<(), String> + Send + Sync + 'static,
    {
        self.steps.push(Step::ExpectSend(Box::new(matcher)));
        self
    }

    pub fn expect_send_bytes(self, expected: &[u8]) -> Self {
        let expected = expected.to_vec();
        self.expect_send(move |actual| {
            if actual == expected.as_slice() {
                Ok(())
            } else {
                Err(format!(
                    "unexpected send: expected {:?}, got {:?}",
                    expected, actual
                ))
            }
        })
    }

    pub fn expect_frame_send(self, payload: &[u8]) -> Self {
        let header = (payload.len() as u16).to_le_bytes();
        self.expect_send_bytes(&header).expect_send_bytes(payload)
    }

    pub fn recv(mut self, data: &[u8]) -> Self {
        self.steps.push(Step::Recv(data.to_vec()));
        self
    }

    pub fn recv_frame(self, payload: &[u8]) -> Self {
        let mut framed = (payload.len() as u16).to_le_bytes().to_vec();
        framed.extend_from_slice(payload);
        self.recv(&framed)
    }

    pub fn delay_ms(mut self, ms: u64) -> Self {
        self.steps.push(Step::DelayMs(ms));
        self
    }

    pub fn close(mut self) -> Self {
        self.steps.push(Step::Close);
        self
    }

    pub fn build(self) -> ScriptedTransport {
        ScriptedTransport::new(self.steps)
    }
}

#[cfg(test)]
mod tests {
    use super::{ScriptedPeer, ScriptedTransport, Step};
    use crate::error::ProtocolError;
    use crate::node::{Node, NodeEvent};
    use crate::test_harness::{
        build_established_frame, build_handshake_fixture, deterministic_secret, success_timing,
        timeout_timing, wait_for_events, RecordingHandler, TestRng,
    };
    use crate::test_helpers::block_on;
    use crate::transport::Transport;
    use embassy_futures::select::{select, Either};
    use microfips_core::noise::ecdh_pubkey;
    use microfips_core::wire;

    use std::boxed::Box;
    use std::time::Instant as StdInstant;
    use std::vec;

    #[test]
    fn test_scripted_recv_returns_data() {
        let mut transport = ScriptedTransport::recv_bytes(&[1, 2, 3]);

        block_on(async move {
            let mut buf = [0u8; 8];
            let n = transport.recv(&mut buf).await.unwrap();
            assert_eq!(n, 3);
            assert_eq!(&buf[..n], &[1, 2, 3]);
        });
    }

    #[test]
    fn test_scripted_send_captures_data() {
        let mut transport = ScriptedTransport::empty();

        block_on(async move {
            transport.send(&[9, 8, 7]).await.unwrap();
            assert_eq!(transport.sent_data(), &[vec![9, 8, 7]]);
        });
    }

    #[test]
    fn test_scripted_close_returns_error() {
        let mut transport = ScriptedTransport::new(vec![Step::Close]);

        block_on(async move {
            let mut buf = [0u8; 8];
            assert_eq!(
                transport.recv(&mut buf).await,
                Err(ProtocolError::Disconnected)
            );
        });
    }

    #[test]
    fn test_scripted_multiple_steps() {
        let mut transport = ScriptedTransport::new(vec![
            Step::Recv(vec![1, 2]),
            Step::ExpectSend(Box::new(|data| {
                if data == [3, 4] {
                    Ok(())
                } else {
                    Err("unexpected send".into())
                }
            })),
            Step::Recv(vec![5, 6]),
        ]);

        block_on(async move {
            let mut buf = [0u8; 8];
            let n1 = transport.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n1], &[1, 2]);
            transport.send(&[3, 4]).await.unwrap();
            let n2 = transport.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n2], &[5, 6]);
            assert_eq!(transport.sent_data(), &[vec![3, 4]]);
        });
    }

    #[test]
    fn test_scripted_delay() {
        let mut transport = ScriptedTransport::new(vec![Step::DelayMs(10), Step::Recv(vec![0xAA])]);

        block_on(async move {
            let started = StdInstant::now();
            let mut buf = [0u8; 4];
            let n = transport.recv(&mut buf).await.unwrap();
            assert_eq!(n, 1);
            assert_eq!(buf[0], 0xAA);
            assert!(started.elapsed() >= std::time::Duration::from_millis(10));
        });
    }

    #[test]
    fn test_scripted_peer_successful_handshake() {
        let initiator_secret = deterministic_secret(1);
        let responder_secret = deterministic_secret(2);
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let seed = [0x11; 32];
        let fixture =
            build_handshake_fixture(seed, initiator_secret, responder_secret, 1u64.to_le_bytes());

        let peer = ScriptedPeer::new()
            .expect_frame_send(&fixture.msg1)
            .recv_frame(&fixture.msg2);
        #[cfg(feature = "noise-xx")]
        let peer = peer.expect_frame_send(&fixture.msg3);
        let transport = peer.close().build();

        let mut node = Node::with_timing(
            transport,
            TestRng::new(&seed),
            initiator_secret,
            responder_pub,
            success_timing(),
        );
        let mut handler = RecordingHandler::new();
        let events = handler.events.clone();

        block_on(async move {
            let outcome = select(
                node.run(&mut handler),
                wait_for_events(events.clone(), |seen| {
                    seen.contains(&NodeEvent::HandshakeOk)
                        && seen.contains(&NodeEvent::Disconnected)
                }),
            )
            .await;
            assert!(matches!(outcome, Either::Second(())));

            let seen = events.lock().unwrap().clone();
            assert!(seen.contains(&NodeEvent::Connected));
            assert!(seen.contains(&NodeEvent::Msg1Sent));
            assert!(seen.contains(&NodeEvent::HandshakeOk));
            assert!(seen.contains(&NodeEvent::Disconnected));
        });
    }

    #[test]
    fn test_scripted_peer_heartbeat_exchange() {
        let initiator_secret = deterministic_secret(3);
        let responder_secret = deterministic_secret(4);
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let seed = [0x22; 32];
        let fixture =
            build_handshake_fixture(seed, initiator_secret, responder_secret, 1u64.to_le_bytes());
        let peer_heartbeat = build_established_frame(
            fixture.responder_sender_idx,
            0,
            wire::MSG_HEARTBEAT,
            &[],
            &fixture.initiator_kr,
        );
        let node_heartbeat = build_established_frame(
            fixture.responder_sender_idx,
            0,
            wire::MSG_HEARTBEAT,
            &[],
            &fixture.initiator_ks,
        );

        let peer = ScriptedPeer::new()
            .expect_frame_send(&fixture.msg1)
            .recv_frame(&fixture.msg2);
        #[cfg(feature = "noise-xx")]
        let peer = peer.expect_frame_send(&fixture.msg3);
        let transport = peer
            .recv_frame(&peer_heartbeat)
            .expect_frame_send(&node_heartbeat)
            .close()
            .build();

        let mut node = Node::with_timing(
            transport,
            TestRng::new(&seed),
            initiator_secret,
            responder_pub,
            success_timing(),
        );
        let mut handler = RecordingHandler::new();
        let events = handler.events.clone();

        block_on(async move {
            let outcome = select(
                node.run(&mut handler),
                wait_for_events(events.clone(), |seen| {
                    seen.contains(&NodeEvent::HandshakeOk)
                        && seen.contains(&NodeEvent::HeartbeatRecv)
                        && seen.contains(&NodeEvent::HeartbeatSent)
                }),
            )
            .await;
            assert!(matches!(outcome, Either::Second(())));

            let seen = events.lock().unwrap().clone();
            assert!(seen.contains(&NodeEvent::HeartbeatRecv));
            assert!(seen.contains(&NodeEvent::HeartbeatSent));
        });
    }

    #[test]
    fn test_scripted_peer_timeout_handling() {
        let initiator_secret = deterministic_secret(5);
        let responder_secret = deterministic_secret(6);
        let responder_pub = ecdh_pubkey(&responder_secret).unwrap();
        let seed = [0x33; 32];
        let fixture =
            build_handshake_fixture(seed, initiator_secret, responder_secret, 1u64.to_le_bytes());

        let transport = ScriptedPeer::new()
            .expect_frame_send(&fixture.msg1)
            .expect_frame_send(&fixture.msg1)
            .build();

        let mut node = Node::with_timing(
            transport,
            TestRng::new(&seed),
            initiator_secret,
            responder_pub,
            timeout_timing(),
        );
        let mut handler = RecordingHandler::new();
        let events = handler.events.clone();

        block_on(async move {
            let outcome = select(
                node.run(&mut handler),
                wait_for_events(events.clone(), |seen| seen.contains(&NodeEvent::Error)),
            )
            .await;
            assert!(matches!(outcome, Either::Second(())));

            let seen = events.lock().unwrap().clone();
            assert!(seen.contains(&NodeEvent::Connected));
            assert!(seen.contains(&NodeEvent::Msg1Sent));
            assert!(seen.contains(&NodeEvent::Error));
        });
    }
}
