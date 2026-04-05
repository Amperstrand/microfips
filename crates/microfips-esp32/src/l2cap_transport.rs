#![cfg(feature = "l2cap")]

use core::sync::atomic::Ordering;

use embassy_futures::select::{select, Either};
use microfips_protocol::transport::Transport;

use crate::config::{L2CAP_FRAME_CAP, RECV_RETRY_DELAY_MS};
use crate::l2cap_host::{
    l2cap_host_task, l2cap_link_up, l2cap_recv_frame, l2cap_send_frame, l2cap_task_started,
    wait_for_l2cap_link,
};

#[derive(Debug, Clone, Copy)]
pub enum L2capError {
    Disconnected,
    FrameTooLarge,
    InitFailed,
}

pub struct L2capTransport;

impl Transport for L2capTransport {
    type Error = L2capError;

    async fn wait_ready(&mut self) -> Result<(), L2capError> {
        if !l2cap_task_started().swap(true, Ordering::Relaxed) {
            let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
            spawner
                .spawn(l2cap_host_task())
                .map_err(|_| L2capError::InitFailed)?;
        }

        if l2cap_link_up() {
            return Ok(());
        }

        loop {
            wait_for_l2cap_link().await;
            if l2cap_link_up() {
                return Ok(());
            }
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
