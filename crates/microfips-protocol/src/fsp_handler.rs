use embassy_time::{Duration, Instant};

use microfips_core::fmp;
use microfips_core::fsp::{
    FspInitiatorSession, FspInitiatorState, FspSession, FSP_MSG_DATA, SESSION_DATAGRAM_BODY_SIZE,
};
use microfips_core::noise;

use crate::node::{HandleResult, NodeEvent, NodeHandler};

const FSP_START_DELAY_SECS: u64 = 5;
const FSP_RETRY_SECS: u64 = 8;

pub struct FspDualHandler {
    pub secret: [u8; 32],
    pub fsp_session: FspSession,
    pub fsp_ephemeral: [u8; 32],
    pub fsp_epoch: [u8; 8],
    pub initiator: Option<FspInitiatorSession>,
    pub target_addr: Option<[u8; 16]>,
    pub fsp_timer: Option<Instant>,
    pub test_ping: bool,
}

impl FspDualHandler {
    pub fn new_responder(secret: [u8; 32], ephemeral: [u8; 32]) -> Self {
        Self {
            secret,
            fsp_session: FspSession::new(),
            fsp_ephemeral: ephemeral,
            fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
            initiator: None,
            target_addr: None,
            fsp_timer: None,
            test_ping: false,
        }
    }

    pub fn new_initiator(
        secret: [u8; 32],
        initiator_ephemeral: [u8; 32],
        target_pub: &[u8; 33],
        target_addr: [u8; 16],
    ) -> Self {
        let initiator = FspInitiatorSession::new(&secret, &initiator_ephemeral, target_pub).ok();
        Self {
            secret,
            fsp_session: FspSession::new(),
            fsp_ephemeral: [0u8; 32],
            fsp_epoch: [0x01, 0, 0, 0, 0, 0, 0, 0],
            initiator,
            target_addr: Some(target_addr),
            fsp_timer: None,
            test_ping: false,
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
        }
    }

    pub fn ensure_initiator(&mut self, initiator_ephemeral: [u8; 32], target_pub: &[u8; 33]) {
        if self.initiator.is_none() {
            self.initiator =
                FspInitiatorSession::new(&self.secret, &initiator_ephemeral, target_pub).ok();
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

    fn handle_responder(
        &mut self,
        msg_type: u8,
        payload: &[u8],
        resp: &mut [u8],
    ) -> HandleResult {
        if msg_type != fmp::MSG_SESSION_DATAGRAM {
            return HandleResult::None;
        }
        match microfips_core::fsp::handle_fsp_datagram(
            &mut self.fsp_session,
            &self.secret,
            &self.fsp_ephemeral,
            &self.fsp_epoch,
            payload,
            resp,
        ) {
            Ok(microfips_core::fsp::FspHandlerResult::None) => HandleResult::None,
            Ok(microfips_core::fsp::FspHandlerResult::SendDatagram(len)) => {
                HandleResult::SendDatagram(len)
            }
            Err(_) => HandleResult::None,
        }
    }

    fn handle_initiator(
        &mut self,
        msg_type: u8,
        payload: &[u8],
        resp: &mut [u8],
    ) -> HandleResult {
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
                if fsp_phase == 0x02
                    && let Ok(()) = fsp.handle_ack(fsp_data)
                {
                    let fsp_epoch = [0x02, 0, 0, 0, 0, 0, 0, 0];
                    let mut msg3_buf = [0u8; 512];
                    if let Ok(msg3_len) = fsp.build_msg3(&fsp_epoch, &mut msg3_buf) {
                        let dg_body = microfips_core::fsp::build_session_datagram_body(
                            &my_addr, &target_addr,
                        );
                        let dg_len = SESSION_DATAGRAM_BODY_SIZE + msg3_len;
                        resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
                        resp[SESSION_DATAGRAM_BODY_SIZE
                            ..SESSION_DATAGRAM_BODY_SIZE + msg3_len]
                            .copy_from_slice(&msg3_buf[..msg3_len]);
                        self.fsp_timer =
                            Some(Instant::now() + Duration::from_secs(2));
                        return HandleResult::SendDatagram(dg_len);
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
                    let Ok(dl) =
                        noise::aead_decrypt(&k_recv, counter, header, encrypted, &mut dec)
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
        let dg_body =
            microfips_core::fsp::build_session_datagram_body(&my_addr, &target_addr);
        let (_k_recv, k_send) = match fsp.session_keys() {
            Some(k) => k,
            None => return HandleResult::None,
        };
        let send_ctr = fsp.next_send_counter();
        let ping = b"PING";
        let ts = 0u32;
        let mut plaintext = [0u8; 512];
        let il = microfips_core::fsp::fsp_prepend_inner_header(
            ts,
            FSP_MSG_DATA,
            0x00,
            ping,
            &mut plaintext,
        );
        let header =
            microfips_core::fsp::build_fsp_header(send_ctr, 0x00, (il + noise::TAG_SIZE) as u16);
        let mut ciphertext = [0u8; 512];
        let cl = match noise::aead_encrypt(&k_send, send_ctr, &header, &plaintext[..il], &mut ciphertext) {
            Ok(l) => l,
            Err(_) => return HandleResult::None,
        };
        let fsp_total = microfips_core::fsp::FSP_HEADER_SIZE + cl;
        let dg_len = SESSION_DATAGRAM_BODY_SIZE + fsp_total;
        resp[..SESSION_DATAGRAM_BODY_SIZE].copy_from_slice(&dg_body);
        resp[SESSION_DATAGRAM_BODY_SIZE..SESSION_DATAGRAM_BODY_SIZE + microfips_core::fsp::FSP_HEADER_SIZE]
            .copy_from_slice(&header);
        resp[SESSION_DATAGRAM_BODY_SIZE + microfips_core::fsp::FSP_HEADER_SIZE
            ..SESSION_DATAGRAM_BODY_SIZE + fsp_total]
            .copy_from_slice(&ciphertext[..cl]);
        self.fsp_timer = Some(Instant::now() + Duration::from_secs(10));
        HandleResult::SendDatagram(dg_len)
    }
}

impl NodeHandler for FspDualHandler {
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
                let setup_len =
                    match fsp.build_setup(&my_addr, &target_addr, &mut setup_buf) {
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
