use embassy_time::{Duration, Instant};

use microfips_core::fmp;
use microfips_core::fsp::{
    FspInitiatorSession, FspInitiatorState, FspSession, FspSessionState, FSP_HEADER_SIZE,
    FSP_INNER_HEADER_SIZE, SESSION_DATAGRAM_BODY_SIZE,
};
use microfips_core::noise;

use crate::node::{HandleResult, NodeEvent, NodeHandler};

const FSP_START_DELAY_SECS: u64 = 5;
const FSP_RETRY_SECS: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FspAppResult {
    None,
    Reply { msg_type: u8, len: usize },
    Disconnect,
}

pub trait FspAppHandler {
    fn on_fsp_message(&mut self, msg_type: u8, payload: &[u8], response: &mut [u8]) -> FspAppResult;
}

pub struct NoopFspApp;

impl FspAppHandler for NoopFspApp {
    fn on_fsp_message(
        &mut self,
        _msg_type: u8,
        _payload: &[u8],
        _response: &mut [u8],
    ) -> FspAppResult {
        FspAppResult::None
    }
}

pub struct FspDualHandler<A = NoopFspApp, const APP_BUF: usize = 1024> {
    pub secret: [u8; 32],
    pub fsp_session: FspSession,
    pub fsp_ephemeral: [u8; 32],
    pub fsp_epoch: [u8; 8],
    pub initiator: Option<FspInitiatorSession>,
    pub target_addr: Option<[u8; 16]>,
    pub fsp_timer: Option<Instant>,
    pub test_ping: bool,
    pub app: A,
    app_buf: [u8; APP_BUF],
}

impl<A, const APP_BUF: usize> FspDualHandler<A, APP_BUF> {
    pub fn new_responder(secret: [u8; 32], ephemeral: [u8; 32], app: A) -> Self {
        Self {
            secret,
            fsp_session: FspSession::new(),
            fsp_ephemeral: ephemeral,
            fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
            initiator: None,
            target_addr: None,
            fsp_timer: None,
            test_ping: false,
            app,
            app_buf: [0u8; APP_BUF],
        }
    }

    /// Create a dual-mode handler: can both respond to incoming FSP sessions
    /// AND initiate outgoing FSP sessions to a specific target.
    ///
    /// Uses separate ephemeral keys for responder and initiator paths
    /// (cryptographic requirement — reusing the same ephemeral in both
    /// directions leaks key material).
    pub fn new_dual(
        secret: [u8; 32],
        responder_ephemeral: [u8; 32],
        initiator_ephemeral: [u8; 32],
        target_pub: &[u8; 33],
        target_addr: [u8; 16],
        app: A,
    ) -> Self {
        let initiator = FspInitiatorSession::new(&secret, &initiator_ephemeral, target_pub).ok();
        Self {
            secret,
            fsp_session: FspSession::new(),
            fsp_ephemeral: responder_ephemeral,
            fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
            initiator,
            target_addr: Some(target_addr),
            fsp_timer: None,
            test_ping: false,
            app,
            app_buf: [0u8; APP_BUF],
        }
    }

    pub fn on_event_default(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => {}
            NodeEvent::Msg1Sent => {}
            NodeEvent::HandshakeOk => {
                self.fsp_session.reset();
                self.fsp_epoch = [0x01, 0, 0, 0, 0, 0, 0, 0];
                if self.initiator.is_some() {
                    self.fsp_timer =
                        Some(Instant::now() + Duration::from_secs(FSP_START_DELAY_SECS));
                }
            }
            NodeEvent::HeartbeatSent => {}
            NodeEvent::HeartbeatRecv => {}
            NodeEvent::Disconnected => {
                self.initiator = None;
                self.fsp_timer = None;
            }
            NodeEvent::Error => {
                self.initiator = None;
                self.fsp_timer = None;
            }
        }
    }

    fn handle_responder(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult
    where
        A: FspAppHandler,
    {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        if payload.len() < SESSION_DATAGRAM_BODY_SIZE {
            return HandleResult::None;
        }

        let Ok(src_addr) = payload[3..19].try_into() else {
            return HandleResult::None;
        };
        let Ok(dst_addr) = payload[19..35].try_into() else {
            return HandleResult::None;
        };
        let reply_body = microfips_core::fsp::build_session_datagram_body(&dst_addr, &src_addr);
        let fsp_data = &payload[SESSION_DATAGRAM_BODY_SIZE..];
        if fsp_data.is_empty() {
            return HandleResult::None;
        }

        match fsp_data[0] & 0x0F {
            0x01 => {
                if resp.len() <= SESSION_DATAGRAM_BODY_SIZE {
                    return HandleResult::None;
                }
                let ack_len = match self.fsp_session.handle_setup(
                    &self.secret,
                    &self.fsp_ephemeral,
                    &self.fsp_epoch,
                    fsp_data,
                    &mut resp[SESSION_DATAGRAM_BODY_SIZE..],
                ) {
                    Ok(len) => len,
                    Err(microfips_core::fsp::FspSessionError::InvalidState) => {
                        self.fsp_session.reset();
                        match self.fsp_session.handle_setup(
                            &self.secret,
                            &self.fsp_ephemeral,
                            &self.fsp_epoch,
                            fsp_data,
                            &mut resp[SESSION_DATAGRAM_BODY_SIZE..],
                        ) {
                            Ok(len) => len,
                            Err(_) => return HandleResult::None,
                        }
                    }
                    Err(_) => return HandleResult::None,
                };
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&reply_body);
                HandleResult::SendDatagram(SESSION_DATAGRAM_BODY_SIZE + ack_len)
            }
            0x03 => {
                if self.fsp_session.handle_msg3(fsp_data).is_err() {
                    return HandleResult::None;
                }
                HandleResult::None
            }
            0x00 => {
                if self.fsp_session.state() != FspSessionState::Established {
                    return HandleResult::None;
                }
                let Some((flags, counter, header, encrypted)) =
                    microfips_core::fsp::parse_fsp_encrypted_header(fsp_data)
                else {
                    return HandleResult::None;
                };
                if flags & microfips_core::fsp::FLAG_UNENCRYPTED != 0 {
                    return HandleResult::None;
                }

                let Some((k_recv, k_send)) = self.fsp_session.session_keys() else {
                    return HandleResult::None;
                };
                let Ok(decrypted_len) =
                    noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut self.app_buf)
                else {
                    return HandleResult::None;
                };
                let Some((_ts, inner_msg_type, _inner_flags, inner_payload)) =
                    microfips_core::fsp::fsp_strip_inner_header(&self.app_buf[..decrypted_len])
                else {
                    return HandleResult::None;
                };

                let app_offset = SESSION_DATAGRAM_BODY_SIZE + FSP_HEADER_SIZE + FSP_INNER_HEADER_SIZE;
                if resp.len() <= app_offset {
                    return HandleResult::None;
                }
                let app_result =
                    self.app
                        .on_fsp_message(inner_msg_type, inner_payload, &mut resp[app_offset..]);
                match app_result {
                    FspAppResult::None => HandleResult::None,
                    FspAppResult::Disconnect => HandleResult::Disconnect,
                    FspAppResult::Reply { msg_type, len } => {
                        let plaintext_len = microfips_core::fsp::fsp_prepend_inner_header(
                            0,
                            msg_type,
                            0x00,
                            &resp[app_offset..app_offset + len],
                            &mut self.app_buf,
                        );
                        if plaintext_len == 0 {
                            return HandleResult::None;
                        }
                        let send_ctr = self.fsp_session.next_send_counter();
                        let header = microfips_core::fsp::build_fsp_header(
                            send_ctr,
                            0x00,
                            (plaintext_len + microfips_core::noise::TAG_SIZE) as u16,
                        );
                        let ciphertext_offset = SESSION_DATAGRAM_BODY_SIZE + FSP_HEADER_SIZE;
                        let max_ciphertext =
                            resp.len().saturating_sub(ciphertext_offset);
                        if max_ciphertext < plaintext_len + microfips_core::noise::TAG_SIZE {
                            return HandleResult::None;
                        }
                        let Ok(ciphertext_len) = noise::aead_encrypt(
                            &k_send,
                            send_ctr,
                            &header,
                            &self.app_buf[..plaintext_len],
                            &mut resp[ciphertext_offset
                                ..ciphertext_offset + plaintext_len + microfips_core::noise::TAG_SIZE],
                        ) else {
                            return HandleResult::None;
                        };
                        resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&reply_body);
                        resp[SESSION_DATAGRAM_BODY_SIZE..ciphertext_offset].copy_from_slice(&header);
                        HandleResult::SendDatagram(ciphertext_offset + ciphertext_len)
                    }
                }
            }
            _ => HandleResult::None,
        }
    }

    fn handle_initiator(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        let target_addr = match &self.target_addr {
            Some(a) => *a,
            None => return HandleResult::None,
        };
        let my_addr = match self.my_addr() {
            Some(a) => a,
            None => return HandleResult::None,
        };
        let fsp = match &mut self.initiator {
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
            FspInitiatorState::Idle => {}
            FspInitiatorState::AwaitingAck => {
                if fsp_phase == 0x02 {
                    if let Ok(()) = fsp.handle_ack(fsp_data) {
                        let fsp_epoch = [0x02, 0, 0, 0, 0, 0, 0, 0];
                        let mut msg3_buf = [0u8; 512];
                        if let Ok(msg3_len) = fsp.build_msg3(&fsp_epoch, &mut msg3_buf) {
                            let dg_body = microfips_core::fsp::build_session_datagram_body(
                                &my_addr,
                                &target_addr,
                            );
                            let dg_len = SESSION_DATAGRAM_BODY_SIZE + msg3_len;
                            resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                            resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
                                .copy_from_slice(&msg3_buf[..msg3_len]);
                            self.fsp_timer = Some(Instant::now() + Duration::from_secs(2));
                            return HandleResult::SendDatagram(dg_len);
                        }
                    }
                }
            }
            FspInitiatorState::AwaitingEstablished => {
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
            }
            FspInitiatorState::Established => {
                if fsp_phase == 0x00 {
                    let Some((flags, counter, header, encrypted)) =
                        microfips_core::fsp::parse_fsp_encrypted_header(fsp_data)
                    else {
                        return HandleResult::None;
                    };
                    if flags & microfips_core::fsp::FLAG_UNENCRYPTED != 0 {
                        return HandleResult::None;
                    }
                    let (k_recv, _) = match fsp.session_keys() {
                        Some(keys) => keys,
                        None => return HandleResult::None,
                    };
                    let mut dec = [0u8; 512];
                    let Ok(dl) = noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut dec)
                    else {
                        return HandleResult::None;
                    };
                    let Some((_ts, _mt, _flags, inner_payload)) =
                        microfips_core::fsp::fsp_strip_inner_header(&dec[..dl])
                    else {
                        return HandleResult::None;
                    };
                    if inner_payload == b"PONG" && self.test_ping {
                        return HandleResult::Disconnect;
                    }
                }
            }
        }
        HandleResult::None
    }

    fn my_addr(&self) -> Option<[u8; 16]> {
        let pub_key = noise::ecdh_pubkey(&self.secret).ok()?;
        let normalized = noise::parity_normalize(&pub_key);
        let x_only: [u8; 32] = normalized[1..].try_into().ok()?;
        Some(microfips_core::identity::NodeAddr::from_pubkey_x(&x_only).0)
    }

    fn send_ping(&mut self, resp: &mut [u8]) -> HandleResult {
        let target_addr = match &self.target_addr {
            Some(a) => *a,
            None => return HandleResult::None,
        };
        let my_addr = match self.my_addr() {
            Some(a) => a,
            None => return HandleResult::None,
        };
        let fsp = match &mut self.initiator {
            Some(f) => f,
            None => return HandleResult::None,
        };
        let dg_body = microfips_core::fsp::build_session_datagram_body(&my_addr, &target_addr);
        let (_k_recv, k_send) = match fsp.session_keys() {
            Some(k) => k,
            None => return HandleResult::None,
        };
        let send_ctr = fsp.next_send_counter();
        let ping = b"PING";
        let ts = 0u32;
        let mut fsp_packet = [0u8; 512];
        let fsp_total = match microfips_core::fsp::build_fsp_data_message(
            send_ctr,
            ts,
            ping,
            &k_send,
            &mut fsp_packet,
        ) {
            Ok(len) => len,
            Err(_) => return HandleResult::None,
        };
        let dg_len = SESSION_DATAGRAM_BODY_SIZE + fsp_total;
        resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
        resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + fsp_total]
            .copy_from_slice(&fsp_packet[..fsp_total]);
        self.fsp_timer = Some(Instant::now() + Duration::from_secs(10));
        HandleResult::SendDatagram(dg_len)
    }
}

impl<A: FspAppHandler, const APP_BUF: usize> NodeHandler for FspDualHandler<A, APP_BUF> {
    async fn on_event(&mut self, event: NodeEvent) {
        self.on_event_default(event);
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        let r = self.handle_responder(msg_type, payload, resp);
        if r != HandleResult::None {
            return r;
        }
        self.handle_initiator(msg_type, payload, resp)
    }

    fn poll_at(&self) -> Option<Instant> {
        self.fsp_timer
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        let target_addr = match &self.target_addr {
            Some(a) => *a,
            None => return HandleResult::None,
        };
        let my_addr = match self.my_addr() {
            Some(a) => a,
            None => return HandleResult::None,
        };
        let fsp = match &mut self.initiator {
            Some(f) => f,
            None => return HandleResult::None,
        };

        match fsp.state() {
            FspInitiatorState::Idle => {
                let dg_body =
                    microfips_core::fsp::build_session_datagram_body(&my_addr, &target_addr);
                let mut setup_buf = [0u8; 512];
                let setup_len = match fsp.build_setup(&my_addr, &target_addr, &mut setup_buf) {
                    Ok(l) => l,
                    Err(_) => return HandleResult::None,
                };
                let dg_len = SESSION_DATAGRAM_BODY_SIZE + setup_len;
                resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + setup_len]
                    .copy_from_slice(&setup_buf[..setup_len]);
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::SendDatagram(dg_len)
            }
            FspInitiatorState::AwaitingAck => {
                fsp.reset();
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::None
            }
            FspInitiatorState::AwaitingEstablished => {
                self.fsp_timer = Some(Instant::now() + Duration::from_secs(FSP_RETRY_SECS));
                HandleResult::None
            }
            FspInitiatorState::Established => self.send_ping(resp),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use microfips_core::identity::DEFAULT_SECRET;
    use microfips_core::noise::ecdh_pubkey;

    fn test_target_pub() -> [u8; 33] {
        ecdh_pubkey(&[0x22; 32]).unwrap()
    }

    #[test]
    fn dual_handler_starts_timer_after_handshake() {
        let mut handler = FspDualHandler::new_dual(
            DEFAULT_SECRET,
            [0x11; 32],
            [0x22; 32],
            &test_target_pub(),
            [0x33; 16],
            NoopFspApp,
        );
        assert_eq!(handler.fsp_timer, None);
        handler.on_event_default(NodeEvent::HandshakeOk);
        assert!(handler.fsp_timer.is_some());
    }

    #[test]
    fn responder_handler_does_not_start_timer_after_handshake() {
        let mut handler = FspDualHandler::new_responder(DEFAULT_SECRET, [0x11; 32], NoopFspApp);
        handler.on_event_default(NodeEvent::HandshakeOk);
        assert_eq!(handler.fsp_timer, None);
    }

    #[test]
    fn on_tick_from_idle_builds_session_setup() {
        let mut handler = FspDualHandler::new_dual(
            DEFAULT_SECRET,
            [0x11; 32],
            [0x22; 32],
            &test_target_pub(),
            [0x33; 16],
            NoopFspApp,
        );
        let mut resp = [0u8; 512];
        let result = handler.on_tick(&mut resp);
        match result {
            HandleResult::SendDatagram(len) => {
                assert!(len > SESSION_DATAGRAM_BODY_SIZE);
                assert_eq!(
                    handler.initiator.as_ref().unwrap().state(),
                    FspInitiatorState::AwaitingAck
                );
                assert!(handler.fsp_timer.is_some());
            }
            other => panic!("unexpected on_tick result: {:?}", other),
        }
    }
}
