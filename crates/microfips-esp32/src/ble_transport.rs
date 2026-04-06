#![cfg(feature = "ble")]

use microfips_esp_transport::ble_transport::{BleHostAdapter, SharedBleTransport};

use crate::ble_host::{
    ble_host_task, ble_link_up, ble_task_started, recv_frame, send_frame, wait_for_link,
};

pub use microfips_esp_transport::ble_transport::BleError;

pub struct Esp32BleHost;

impl BleHostAdapter for Esp32BleHost {
    fn task_started() -> &'static core::sync::atomic::AtomicBool {
        ble_task_started()
    }

    fn link_up() -> bool {
        ble_link_up()
    }

    async fn spawn_host_task() -> Result<(), ()> {
        let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
        spawner.spawn(ble_host_task()).map_err(|_| ())
    }

    async fn wait_for_link() {
        wait_for_link().await;
    }

    async fn send_frame(frame: heapless::Vec<u8, 256>) {
        send_frame(frame).await;
    }

    async fn recv_frame() -> heapless::Vec<u8, 256> {
        recv_frame().await
    }
}

pub type BleTransport = SharedBleTransport<Esp32BleHost>;
