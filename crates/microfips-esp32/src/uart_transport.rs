use esp_hal::uart::{UartRx, UartTx};
use esp_hal::Async;
use microfips_protocol::transport::Transport;

use crate::config::{RECV_RETRY_DELAY_MS, WAIT_READY_DELAY_MS};

pub struct UartTransport {
    pub tx: UartTx<'static, Async>,
    pub rx: UartRx<'static, Async>,
}

#[derive(Debug)]
pub struct UartError;

impl Transport for UartTransport {
    type Error = UartError;

    async fn wait_ready(&mut self) -> Result<(), UartError> {
        embassy_time::Timer::after(embassy_time::Duration::from_millis(WAIT_READY_DELAY_MS)).await;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), UartError> {
        use embedded_io_async::Write;

        self.tx.write_all(data).await.map_err(|_| UartError)?;
        self.tx.flush().map_err(|_| UartError)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, UartError> {
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
