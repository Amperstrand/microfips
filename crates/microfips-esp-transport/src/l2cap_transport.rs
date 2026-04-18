#![cfg(feature = "l2cap")]

use core::marker::PhantomData;
use core::sync::atomic::Ordering;

use embassy_futures::select::{select, Either};
use microfips_protocol::transport::Transport;

use crate::config::{L2CAP_FRAME_CAP, RECV_RETRY_DELAY_MS};

pub trait L2capHostAdapter {
    fn task_started() -> &'static core::sync::atomic::AtomicBool;
    fn link_up() -> bool;
    async fn spawn_host_task() -> Result<(), ()>;
    async fn wait_for_l2cap_ready() -> [u8; 33];
    async fn send_frame(frame: heapless::Vec<u8, L2CAP_FRAME_CAP>) -> Result<(), ()>;
    async fn recv_frame() -> heapless::Vec<u8, L2CAP_FRAME_CAP>;
}

#[derive(Debug, Clone, Copy)]
pub enum L2capError {
    Disconnected,
    FrameTooLarge,
    InitFailed,
}

pub struct SharedL2capTransport<H> {
    peer_pub: Option<[u8; 33]>,
    _host: PhantomData<H>,
}

impl<H> SharedL2capTransport<H> {
    pub fn new() -> Self {
        Self {
            peer_pub: None,
            _host: PhantomData,
        }
    }

    pub fn take_peer_pub(&mut self) -> Option<[u8; 33]> {
        self.peer_pub.take()
    }
}

impl<H: L2capHostAdapter> SharedL2capTransport<H> {
    pub async fn wait_for_peer_pub(&mut self) -> Result<[u8; 33], L2capError> {
        self.wait_ready().await?;
        self.take_peer_pub().ok_or(L2capError::InitFailed)
    }
}

impl<H: L2capHostAdapter> Transport for SharedL2capTransport<H> {
    type Error = L2capError;

    async fn wait_ready(&mut self) -> Result<(), L2capError> {
        log::debug!("wait_ready: link_up={}", H::link_up());
        if !H::task_started().swap(true, Ordering::Relaxed) {
            H::spawn_host_task()
                .await
                .map_err(|_| L2capError::InitFailed)?;
        }

        if H::link_up() {
            log::debug!("wait_ready: link already up");
            return Ok(());
        }

        self.peer_pub = None;

        loop {
            let pk = H::wait_for_l2cap_ready().await;
            self.peer_pub = Some(pk);
            if H::link_up() {
                return Ok(());
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), L2capError> {
        if !H::link_up() {
            return Err(L2capError::Disconnected);
        }
        if data.len() > L2CAP_FRAME_CAP {
            return Err(L2capError::FrameTooLarge);
        }

        let mut frame = heapless::Vec::<u8, L2CAP_FRAME_CAP>::new();
        frame
            .extend_from_slice(data)
            .map_err(|_| L2capError::FrameTooLarge)?;
        H::send_frame(frame).await.map_err(|_| L2capError::Disconnected)?;
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, L2capError> {
        loop {
            if !H::link_up() {
                return Err(L2capError::Disconnected);
            }
            match select(
                H::recv_frame(),
                embassy_time::Timer::after(embassy_time::Duration::from_millis(
                    RECV_RETRY_DELAY_MS,
                )),
            )
            .await
            {
                Either::First(frame) => {
                    debug_assert!(
                        buf.len() >= L2CAP_FRAME_CAP,
                        "L2CAP frame truncated: buf is {}B but L2CAP_FRAME_CAP is {}B. \
                         RECV_BUF_SIZE in node.rs must be >= L2CAP_FRAME_CAP. \
                         See PR #57 Codex review.",
                        buf.len(),
                        L2CAP_FRAME_CAP,
                    );
                    let n = frame.len().min(buf.len());
                    buf[..n].copy_from_slice(&frame[..n]);
                    return Ok(n);
                }
                Either::Second(()) => continue,
            }
        }
    }
}

use crate::l2cap_host::{
    l2cap_host_task, l2cap_link_up, l2cap_recv_frame, l2cap_send_frame, l2cap_task_started,
    wait_for_l2cap_ready,
};

pub struct EspL2capHost;

impl L2capHostAdapter for EspL2capHost {
    fn task_started() -> &'static core::sync::atomic::AtomicBool {
        l2cap_task_started()
    }

    fn link_up() -> bool {
        l2cap_link_up()
    }

    async fn spawn_host_task() -> Result<(), ()> {
        let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
        spawner.spawn(l2cap_host_task()).map_err(|_| ())
    }

    async fn wait_for_l2cap_ready() -> [u8; 33] {
        wait_for_l2cap_ready().await
    }

    async fn send_frame(frame: heapless::Vec<u8, L2CAP_FRAME_CAP>) -> Result<(), ()> {
        l2cap_send_frame(frame).await
    }

    async fn recv_frame() -> heapless::Vec<u8, L2CAP_FRAME_CAP> {
        l2cap_recv_frame().await
    }
}

pub type L2capTransport = SharedL2capTransport<EspL2capHost>;
