use core::sync::atomic::Ordering;

use microfips_http_demo::DemoService;
use microfips_protocol::fsp_handler::FspDualHandler;
use microfips_protocol::node::{HandleResult, NodeEvent, NodeHandler};
use microfips_service::FspServiceAdapter;

use crate::config::{LED_OFF, LED_ON};
use crate::led::Led;
use crate::stats::{
    STAT_DATA_RX, STAT_DATA_TX, STAT_HB_RX, STAT_HB_TX, STAT_MSG1_TX, STAT_MSG2_RX, STAT_STATE,
};

pub type EspFspHandler = FspDualHandler<FspServiceAdapter<DemoService>>;

pub fn build_demo_fsp(
    secret: &[u8; 32],
    responder_ephemeral: [u8; 32],
    initiator_ephemeral: [u8; 32],
    peer_pub: &[u8; 33],
    peer_addr: [u8; 16],
) -> EspFspHandler {
    FspDualHandler::new_dual(
        *secret,
        responder_ephemeral,
        initiator_ephemeral,
        peer_pub,
        peer_addr,
        FspServiceAdapter::new(DemoService::new()),
    )
}

pub struct SharedEspHandler<'a> {
    pub led: &'a mut Led,
    pub fsp: EspFspHandler,
}

impl NodeHandler for SharedEspHandler<'_> {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => {
                STAT_STATE.store(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::Msg1Sent => {
                STAT_STATE.store(2, Ordering::Relaxed);
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::HandshakeOk => {
                STAT_STATE.store(3, Ordering::Relaxed);
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::HeartbeatSent => {
                STAT_STATE.store(4, Ordering::Relaxed);
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::HeartbeatRecv => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Disconnected => {
                STAT_STATE.store(5, Ordering::Relaxed);
                self.led.set_state(LED_OFF);
            }
            NodeEvent::Error => {
                STAT_STATE.store(6, Ordering::Relaxed);
                self.led.set_state(LED_OFF);
            }
        }
        self.fsp.on_event_default(event);
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != 0x00 {
            return HandleResult::None;
        }
        STAT_DATA_RX.fetch_add(1, Ordering::Relaxed);
        let result = self.fsp.on_message(msg_type, payload, resp);
        if let HandleResult::SendDatagram(_) = result {
            STAT_DATA_TX.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn poll_at(&self) -> Option<embassy_time::Instant> {
        self.fsp.poll_at()
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        let result = self.fsp.on_tick(resp);
        if let HandleResult::SendDatagram(_) = result {
            STAT_DATA_TX.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
