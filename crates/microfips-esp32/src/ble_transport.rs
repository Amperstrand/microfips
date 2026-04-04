#![cfg(feature = "ble")]

use core::sync::atomic::Ordering;

use embassy_futures::select::{select, Either};
use microfips_protocol::transport::Transport;

use crate::ble_host::{
    ble_host_task, ble_link_up, ble_task_started, recv_frame, send_frame, wait_for_link,
};
use crate::config::{BLE_MAX_FRAME, RECV_RETRY_DELAY_MS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleError {
    Disconnected,
    FrameTooLarge,
    InitFailed,
}

pub struct BleTransport {
    tx_buf: [u8; 256],
    tx_len: usize,
}

impl BleTransport {
    pub fn new() -> Self {
        Self {
            tx_buf: [0u8; 256],
            tx_len: 0,
        }
    }
}

impl Transport for BleTransport {
    type Error = BleError;

    async fn wait_ready(&mut self) -> Result<(), BleError> {
        if !ble_task_started().swap(true, Ordering::Relaxed) {
            let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
            spawner
                .spawn(ble_host_task())
                .map_err(|_| BleError::InitFailed)?;
        }

        if ble_link_up() {
            return Ok(());
        }

        wait_for_link().await;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), BleError> {
        if !ble_link_up() {
            return Err(BleError::Disconnected);
        }
        if self.tx_len + data.len() > self.tx_buf.len() {
            self.tx_len = 0;
            return Err(BleError::FrameTooLarge);
        }

        self.tx_buf[self.tx_len..self.tx_len + data.len()].copy_from_slice(data);
        self.tx_len += data.len();

        if self.tx_len < 2 {
            return Ok(());
        }

        let payload_len = u16::from_le_bytes([self.tx_buf[0], self.tx_buf[1]]) as usize;
        let frame_len = 2 + payload_len;
        if frame_len > BLE_MAX_FRAME {
            self.tx_len = 0;
            return Err(BleError::FrameTooLarge);
        }
        if self.tx_len < frame_len {
            return Ok(());
        }

        let mut frame = heapless::Vec::<u8, BLE_MAX_FRAME>::new();
        frame
            .extend_from_slice(&self.tx_buf[..frame_len])
            .map_err(|_| BleError::FrameTooLarge)?;
        send_frame(frame).await;

        let remaining = self.tx_len - frame_len;
        if remaining > 0 {
            self.tx_buf.copy_within(frame_len..self.tx_len, 0);
        }
        self.tx_len = remaining;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, BleError> {
        loop {
            if !ble_link_up() {
                return Err(BleError::Disconnected);
            }
            match select(
                recv_frame(),
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
