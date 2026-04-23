use crate::config::{ESP32_SECRET, STM32_NODE_ADDR, STM32_PEER_PUB};
pub use microfips_esp_transport::handler::{EspFspHandler, SharedEspHandler as EspHandler};

pub fn build_demo_fsp(
    responder_ephemeral: [u8; 32],
    initiator_ephemeral: [u8; 32],
) -> EspFspHandler {
    microfips_esp_transport::handler::build_demo_fsp(
        &ESP32_SECRET,
        responder_ephemeral,
        initiator_ephemeral,
        &STM32_PEER_PUB,
        STM32_NODE_ADDR,
    )
}
