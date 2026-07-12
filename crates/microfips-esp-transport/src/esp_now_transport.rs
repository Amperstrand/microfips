//! ESP-NOW transport for FIPS protocol.
//!
//! Stub implementation: the Transport trait is satisfied but the actual
//! ESP-NOW radio calls are TODO. esp-radio 0.18 does not expose a public
//! constructor for `EspNow` (its `new_internal` is `pub(crate)`), so real
//! radio init is blocked until a future esp-radio release or a fork.

use core::fmt::Debug;

use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, signal::Signal};
use microfips_protocol::transport::Transport;

/// ESP-NOW transport error.
#[derive(Debug)]
pub struct EspNowError;

/// ESP-NOW transport implementation (stub).
pub struct EspNowTransport {
    /// Signal for received data
    rx_signal: Signal<CriticalSectionRawMutex, [u8; 250]>,
    /// Peer MAC address for unicast communication
    peer_mac: [u8; 6],
}

impl EspNowTransport {
    /// Create a new ESP-NOW transport (stub).
    pub fn new() -> Self {
        Self {
            rx_signal: Signal::new(),
            peer_mac: [0xFF; 6], // Broadcast by default
        }
    }

    /// Set the peer MAC address for unicast communication.
    pub fn set_peer_mac(&mut self, mac: [u8; 6]) {
        self.peer_mac = mac;
    }

    /// Send data via ESP-NOW.
    async fn send_esp_now(&self, data: &[u8]) -> Result<(), EspNowError> {
        // TODO: Implement actual ESP-NOW send using esp-radio's EspNow::send_async.
        // Blocked: esp-radio 0.18 `EspNow::new_internal()` is pub(crate).
        log::debug!("ESP-NOW send: {} bytes (stub)", data.len());
        Ok(())
    }

    /// Receive data via ESP-NOW.
    async fn recv_esp_now(&mut self) -> Result<[u8; 250], EspNowError> {
        // Wait for signal from ESP-NOW receive callback
        let data = self.rx_signal.wait().await;
        log::debug!("ESP-NOW recv: {} bytes (stub)", data.len());
        Ok(data)
    }
}

impl Transport for EspNowTransport {
    type Error = EspNowError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if data.len() > 250 {
            log::warn!("ESP-NOW send truncated: {} bytes > 250 max", data.len());
        }
        self.send_esp_now(data).await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let received = self.recv_esp_now().await?;
        let len = core::cmp::min(buf.len(), received.len());
        buf[..len].copy_from_slice(&received[..len]);
        Ok(len)
    }
}
