#![cfg(feature = "l2cap")]

use microfips_esp_transport::l2cap_transport::{L2capHostAdapter, SharedL2capTransport};

use crate::l2cap_host::{
    l2cap_host_task, l2cap_link_up, l2cap_recv_frame, l2cap_send_frame, l2cap_task_started,
    wait_for_l2cap_ready,
};

pub use microfips_esp_transport::l2cap_transport::L2capError;

pub struct Esp32L2capHost;

impl L2capHostAdapter for Esp32L2capHost {
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

    async fn wait_for_l2cap_ready() -> ([u8; 33], u8) {
        wait_for_l2cap_ready().await
    }

    async fn send_frame(frame: heapless::Vec<u8, 512>) {
        l2cap_send_frame(frame).await;
    }

    async fn recv_frame() -> heapless::Vec<u8, 512> {
        l2cap_recv_frame().await
    }
}

pub type L2capTransport = SharedL2capTransport<Esp32L2capHost>;
