use esp_hal::usb_serial_jtag::{UsbSerialJtagRx, UsbSerialJtagTx};
use esp_hal::Async;
use microfips_protocol::transport::Transport;

use crate::config::{RECV_RETRY_DELAY_MS, WAIT_READY_DELAY_MS};

pub struct UsbTransport {
    pub tx: UsbSerialJtagTx<'static, Async>,
    pub rx: UsbSerialJtagRx<'static, Async>,
}

#[derive(Debug)]
pub struct UsbError;

impl Transport for UsbTransport {
    type Error = UsbError;

    async fn wait_ready(&mut self) -> Result<(), UsbError> {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(WAIT_READY_DELAY_MS)).await;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), UsbError> {
        use embedded_io_async::Write;

        self.tx.write_all(data).await.map_err(|_| UsbError)?;
        self.tx.flush().await.map_err(|_| UsbError)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UsbError> {
        use embedded_io_async::Read;

        loop {
            match Read::read(&mut self.rx, buf).await {
                Ok(n) => return Ok(n),
                Err(_) => {
                    embassy_time::Timer::after(embassy_time::Duration::from_millis(
                        RECV_RETRY_DELAY_MS,
                    ))
                    .await;
                }
            }
        }
    }
}
