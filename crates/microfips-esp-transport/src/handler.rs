use core::sync::atomic::Ordering;

use microfips_http_demo::DemoService;
use microfips_protocol::fsp_handler::FspDualHandler;
use microfips_protocol::node::{HandleResult, NodeEvent, NodeHandler};
use microfips_service::FspServiceAdapter;

use crate::config::{LED_OFF, LED_ON};
use crate::led::Led;
use crate::stats::STATS;

pub type EspFspHandler = FspDualHandler<FspServiceAdapter<DemoService>>;
pub type EspHandler<'a> = SharedEspHandler<'a>;

pub fn build_demo_fsp(
    secret: &[u8; 32],
    responder_ephemeral: [u8; 32],
    initiator_ephemeral: [u8; 32],
    peer_pub: &[u8; 33],
    peer_addr: [u8; 16],
    fsp_epoch: [u8; 8],
) -> EspFspHandler {
    FspDualHandler::new_dual(
        *secret,
        responder_ephemeral,
        initiator_ephemeral,
        peer_pub,
        peer_addr,
        fsp_epoch,
        FspServiceAdapter::new(DemoService::new()),
    )
}

/// Convenience wrapper that uses `crate::config::DEVICE_NSEC` and STM32 peer defaults.
pub fn build_demo_fsp_default(
    responder_ephemeral: [u8; 32],
    initiator_ephemeral: [u8; 32],
    fsp_epoch: [u8; 8],
) -> EspFspHandler {
    use microfips_core::identity::{STM32_NODE_ADDR, STM32_NPUB};
    build_demo_fsp(
        &crate::config::DEVICE_NSEC,
        responder_ephemeral,
        initiator_ephemeral,
        &STM32_NPUB,
        STM32_NODE_ADDR,
        fsp_epoch,
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
                STATS.state.store(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::Msg1Sent => {
                STATS.state.store(2, Ordering::Relaxed);
                STATS.msg1_tx.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::HandshakeOk => {
                STATS.state.store(3, Ordering::Relaxed);
                STATS.msg2_rx.fetch_add(1, Ordering::Relaxed);
                self.led.set_state(LED_ON);
            }
            NodeEvent::HeartbeatSent => {
                STATS.state.store(4, Ordering::Relaxed);
                STATS.hb_tx.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::HeartbeatRecv => {
                STATS.hb_rx.fetch_add(1, Ordering::Relaxed);
            }
            NodeEvent::Disconnected => {
                STATS.state.store(5, Ordering::Relaxed);
                self.led.set_state(LED_OFF);
            }
            NodeEvent::Error => {
                STATS.state.store(6, Ordering::Relaxed);
                self.led.set_state(LED_OFF);
            }
        }
        self.fsp.on_event_default(event);
    }

    fn on_message(&mut self, msg_type: u8, payload: &[u8], resp: &mut [u8]) -> HandleResult {
        if msg_type != 0x00 {
            return HandleResult::None;
        }
        STATS.data_rx.fetch_add(1, Ordering::Relaxed);
        let result = self.fsp.on_message(msg_type, payload, resp);
        if let HandleResult::SendDatagram(_) = result {
            STATS.data_tx.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn poll_at(&self) -> Option<embassy_time::Instant> {
        self.fsp.poll_at()
    }

    fn on_tick(&mut self, resp: &mut [u8]) -> HandleResult {
        let result = self.fsp.on_tick(resp);
        if let HandleResult::SendDatagram(_) = result {
            STATS.data_tx.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
