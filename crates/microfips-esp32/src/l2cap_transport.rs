#![cfg(feature = "l2cap")]

use core::sync::atomic::Ordering;

use embassy_futures::select::{select, Either};
use microfips_core::identity::DEFAULT_PEER_PUB;
use microfips_protocol::transport::Transport;

use crate::config::{ESP32_SECRET, L2CAP_FRAME_CAP, RECV_RETRY_DELAY_MS};
use crate::l2cap_host::{
    l2cap_conn_gen, l2cap_host_task, l2cap_link_up, l2cap_recv_frame, l2cap_send_frame,
    l2cap_task_started, wait_for_l2cap_link,
};

#[derive(Debug, Clone, Copy)]
pub enum L2capError {
    Disconnected,
    FrameTooLarge,
    InitFailed,
}

pub struct L2capTransport {
    peer_pub: Option<[u8; 33]>,
    last_conn_gen: u32,
}

impl L2capTransport {
    pub fn new() -> Self {
        Self {
            peer_pub: None,
            last_conn_gen: 0,
        }
    }

    pub fn peer_pub(&self) -> [u8; 33] {
        self.peer_pub.unwrap_or(DEFAULT_PEER_PUB)
    }
}

impl Transport for L2capTransport {
    type Error = L2capError;

    async fn wait_ready(&mut self) -> Result<(), L2capError> {
        if !l2cap_task_started().swap(true, Ordering::Relaxed) {
            let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
            spawner
                .spawn(l2cap_host_task())
                .map_err(|_| L2capError::InitFailed)?;
        }

        loop {
            let conn_gen = l2cap_conn_gen();
            if l2cap_link_up() {
                if conn_gen != self.last_conn_gen {
                    esp_println::println!("[l2cap] conn gen {}, doing pubkey exchange", conn_gen);
                    let local_pub =
                        microfips_core::noise::ecdh_pubkey(&ESP32_SECRET).map_err(|_| L2capError::InitFailed)?;

                    let mut tx = [0u8; 33];
                    tx[0] = 0x00;
                    tx[1..].copy_from_slice(&local_pub[1..33]);
                    let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
                    frame
                        .extend_from_slice(&tx)
                        .map_err(|_| L2capError::FrameTooLarge)?;
                    l2cap_send_frame(frame).await;

                    let resp = embassy_time::with_timeout(
                        embassy_time::Duration::from_secs(15),
                        l2cap_recv_frame(),
                    )
                    .await
                    .map_err(|_| L2capError::Disconnected)?;

                    if resp.len() != 33 || resp[0] != 0x00 {
                        esp_println::println!(
                            "[l2cap] pubkey exchange: bad response (len={}, prefix={:02x})",
                            resp.len(),
                            resp.first().copied().unwrap_or(0)
                        );
                        return Err(L2capError::Disconnected);
                    }

                    let mut peer_pub = [0u8; 33];
                    peer_pub[0] = 0x02;
                    peer_pub[1..33].copy_from_slice(&resp[1..33]);
                    self.peer_pub = Some(peer_pub);
                    self.last_conn_gen = conn_gen;
                    esp_println::println!("[l2cap] pubkey exchange complete");
                }
                return Ok(());
            }
            wait_for_l2cap_link().await;
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), L2capError> {
        if !l2cap_link_up() {
            return Err(L2capError::Disconnected);
        }
        if data.len() > L2CAP_FRAME_CAP {
            return Err(L2capError::FrameTooLarge);
        }

        let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
        frame
            .extend_from_slice(data)
            .map_err(|_| L2capError::FrameTooLarge)?;
        l2cap_send_frame(frame).await;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, L2capError> {
        loop {
            if !l2cap_link_up() {
                return Err(L2capError::Disconnected);
            }
            match select(
                l2cap_recv_frame(),
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RECV_RETRY_DELAY_MS,
                )),
            )
            .await
            {
                Either::First(frame) => {
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    return Ok(n);
                }
                Either::Second(()) => continue,
            }
        }
    }
}
