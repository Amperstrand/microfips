use core::sync::atomic::Ordering;

use embassy_time::{Duration, Timer};
#[cfg(feature = "http-demo")]
use microfips_http_demo::DemoService;
use microfips_protocol::fsp_handler::FspDualHandler;
use microfips_protocol::node::{HandleResult, NodeEvent, NodeHandler};
#[cfg(feature = "http-demo")]
use microfips_service::FspServiceAdapter;
use microfips_service::{ServiceError, ServiceReply, ServiceRequest};

use crate::config::{
    S_DISCONNECTED, S_ERR, S_HANDSHAKE_OK, S_HB_RX, S_HB_TX, S_MSG1_SENT, S_USB_READY,
};
use crate::led::Leds;
use crate::stats::{
    STAT_DATA_RX, STAT_DATA_TX, STAT_HB_RX, STAT_HB_TX, STAT_MSG1_TX, STAT_MSG2_RX,
};

/// (#260 P1) Without the http-demo feature the firmware carries a
/// minimal no-alloc service: every request answers 503 SERVICE
/// UNAVAILABLE — the demo endpoints were the only routes, and they
/// are alloc-only (format!/Vec). The no_std firmware never had a
/// global allocator to run them; this makes the linker-level truth
/// explicit.
#[cfg(not(feature = "http-demo"))]
pub struct NoService;

#[cfg(not(feature = "http-demo"))]
impl microfips_service::ServiceHandler for NoService {
    fn handle(
        &mut self,
        _req: ServiceRequest<'_>,
        _out: &mut [u8],
    ) -> Result<ServiceReply, ServiceError> {
        Err(ServiceError::NotFound)
    }
    fn on_peer(&mut self, _peer: &microfips_service::PeerContext) {}
}

#[cfg(not(feature = "http-demo"))]
pub type ServiceCore = microfips_service::FspServiceAdapter<NoService>;
#[cfg(feature = "http-demo")]
pub type ServiceCore = microfips_service::FspServiceAdapter<DemoService>;

pub struct FipsHandler<'a> {
    pub leds: &'a mut Leds,
    pub fsp: FspDualHandler<ServiceCore>,
}

impl NodeHandler for FipsHandler<'_> {
    async fn on_event(&mut self, event: NodeEvent) {
        match event {
            NodeEvent::Connected => {
                self.leds.set_state(S_USB_READY);
            }
            NodeEvent::Msg1Sent => {
                STAT_MSG1_TX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_MSG1_SENT);
                embassy_futures::yield_now().await;
            }
            NodeEvent::HandshakeOk => {
                STAT_MSG2_RX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HANDSHAKE_OK);
                self.fsp.on_event_default(event);
                Timer::after(Duration::from_millis(500)).await;
            }
            NodeEvent::HeartbeatSent => {
                STAT_HB_TX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HB_TX);
            }
            NodeEvent::HeartbeatRecv => {
                STAT_HB_RX.fetch_add(1, Ordering::Relaxed);
                self.leds.set_state(S_HB_RX);
            }
            NodeEvent::Disconnected => {
                self.leds.set_state(S_DISCONNECTED);
            }
            NodeEvent::Error => {
                self.leds.set_state(S_ERR);
            }
        }
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
}
