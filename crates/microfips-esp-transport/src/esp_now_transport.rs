//! ESP-NOW transport for FIPS protocol.
//!
//! Carries FMP frames as fragmented ESP-NOW payloads (see
//! `microfips_esp_common::espnow_frag`): datagram semantics, no IP stack,
//! no access point. The node broadcasts its handshake until the first frame
//! arrives from the far side, then locks onto that MAC and switches to
//! unicast (which gains MAC-level ACK/retry). The MAC is only a routing
//! hint — the Noise IK handshake against the pinned peer npub proves
//! identity, exactly like mDNS discovery on the WiFi transport.

use esp_radio::esp_now::{
    EspNow, EspNowError as RadioError, EspNowManager, EspNowReceiver, EspNowSender,
    EspNowWifiInterface, PeerInfo, BROADCAST_ADDRESS,
};
use esp_radio::wifi::WifiController;
use microfips_esp_common::espnow_frag::{Fragmenter, SrcReassembler, ESP_NOW_MAX_PAYLOAD};
use microfips_protocol::transport::Transport;

/// ESP-NOW transport error.
#[derive(Debug)]
pub struct EspNowTransportError;

/// Broadcast sends on one channel before hopping to the next during
/// discovery. A gateway associated to an AP is pinned to the AP's channel,
/// which this node cannot know in advance — sweeping finds it.
const SENDS_PER_CHANNEL: u8 = 2;
/// Sweep 1..=13 (ETSI); the extra channels are region-gated anyway.
const SWEEP_MAX_CHANNEL: u8 = 13;

pub struct EspNowTransport {
    manager: EspNowManager<'static>,
    sender: EspNowSender<'static>,
    receiver: EspNowReceiver<'static>,
    fragmenter: Fragmenter,
    reassembler: SrcReassembler,
    /// MAC of the far side, learned from its first frame. `None` = broadcast.
    peer_mac: Option<[u8; 6]>,
    /// `wait_ready` calls so far; >0 means the previous session ended.
    sessions: u32,
    /// Current radio channel; advanced by the discovery sweep.
    channel: u8,
    /// Broadcasts sent on the current channel while unlocked.
    unlocked_sends: u8,
    /// Keeps the WiFi driver alive — dropping it stops the radio.
    /// `None` when someone else (e.g. the hybrid transport) owns it.
    _wifi_controller: Option<&'static WifiController<'static>>,
}

impl EspNowTransport {
    /// Wrap an initialized ESP-NOW interface. `channel` must match the far
    /// side (both radios are unassociated, so nothing else pins it).
    pub fn new(
        esp_now: EspNow<'static>,
        wifi_controller: &'static WifiController<'static>,
        channel: u8,
    ) -> Self {
        if let Err(_e) = esp_now.set_channel(channel) {
            #[cfg(feature = "log")]
            log::error!("ESP-NOW: set_channel({}) failed: {:?}", channel, _e);
        }
        let mut transport = Self::new_shared(esp_now, channel);
        transport._wifi_controller = Some(wifi_controller);
        transport
    }

    /// Like [`Self::new`], but without taking the WiFi controller and
    /// without touching the channel — for embedding in a transport that
    /// manages the controller (and possibly an association) itself.
    pub(crate) fn new_shared(esp_now: EspNow<'static>, channel: u8) -> Self {
        let (manager, sender, receiver) = esp_now.split();
        Self {
            manager,
            sender,
            receiver,
            fragmenter: Fragmenter::new(),
            reassembler: SrcReassembler::new(),
            peer_mac: None,
            sessions: 0,
            channel,
            unlocked_sends: 0,
            _wifi_controller: None,
        }
    }

    /// Forget the locked peer and restart broadcast discovery (the channel
    /// sweep resumes from the current channel).
    pub(crate) fn reset_discovery(&mut self) {
        self.peer_mac = None;
        self.unlocked_sends = 0;
    }

    fn lock_peer(&mut self, mac: [u8; 6]) {
        if !self.manager.peer_exists(&mac) {
            let result = self.manager.add_peer(PeerInfo {
                interface: EspNowWifiInterface::Station,
                peer_address: mac,
                lmk: None,
                channel: None,
                encrypt: false,
            });
            if let Err(_e) = result {
                #[cfg(feature = "log")]
                log::error!("ESP-NOW: add_peer failed: {:?}, staying on broadcast", _e);
                return;
            }
        }
        #[cfg(feature = "log")]
        log::info!(
            "ESP-NOW: peer locked {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        );
        self.peer_mac = Some(mac);
    }
}

impl Transport for EspNowTransport {
    type Error = EspNowTransportError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        if self.sessions > 0 {
            // The previous session died. The far side may have moved to a
            // different device — fall back to broadcast and re-learn the
            // MAC from its next frame.
            if self.peer_mac.take().is_some() {
                // Resume the sweep from the current channel — the peer most
                // likely reappears where it was.
                self.unlocked_sends = 0;
                #[cfg(feature = "log")]
                log::info!("ESP-NOW: session ended, reverting to broadcast discovery");
            }
        }
        self.sessions = self.sessions.wrapping_add(1);
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let dst = self.peer_mac.unwrap_or(BROADCAST_ADDRESS);
        let Some(fragments) = self.fragmenter.fragments(data) else {
            #[cfg(feature = "log")]
            log::warn!("ESP-NOW: dropping oversize frame ({} bytes)", data.len());
            return Err(EspNowTransportError);
        };
        for (header, chunk) in fragments {
            let mut payload = [0u8; ESP_NOW_MAX_PAYLOAD];
            payload[..header.len()].copy_from_slice(&header);
            payload[header.len()..header.len() + chunk.len()].copy_from_slice(chunk);
            self.sender
                .send_async(&dst, &payload[..header.len() + chunk.len()])
                .await
                .map_err(|_e: RadioError| {
                    #[cfg(feature = "log")]
                    log::warn!("ESP-NOW: send failed: {:?}", _e);
                    EspNowTransportError
                })?;
        }
        // Discovery sweep: while no peer is locked, hop channels between
        // broadcasts so a gateway pinned to an unknown AP channel is found.
        if self.peer_mac.is_none() {
            self.unlocked_sends = self.unlocked_sends.saturating_add(1);
            if self.unlocked_sends >= SENDS_PER_CHANNEL {
                self.unlocked_sends = 0;
                self.channel = if self.channel >= SWEEP_MAX_CHANNEL {
                    1
                } else {
                    self.channel + 1
                };
                if self.manager.set_channel(self.channel).is_ok() {
                    #[cfg(feature = "log")]
                    log::info!(
                        "ESP-NOW: discovery sweep, hopping to channel {}",
                        self.channel
                    );
                }
            }
        }
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        loop {
            let received = self.receiver.receive_async().await;
            let src = received.info.src_address;
            if let Some(mac) = self.peer_mac {
                if src != mac {
                    continue;
                }
            }
            let n = match self.reassembler.push(src, received.data()) {
                Some(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    n
                }
                None => continue,
            };
            if self.peer_mac.is_none() {
                self.lock_peer(src);
            }
            return Ok(n);
        }
    }
}
