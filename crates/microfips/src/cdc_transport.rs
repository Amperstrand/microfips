use core::sync::atomic::Ordering;

use embassy_stm32::{peripherals, usb::Driver};
use embassy_usb::class::cdc_acm::CdcAcmClass;
use embassy_usb::driver::EndpointError;
use microfips_protocol::transport::Transport;

use crate::config::CDC_PKT;
use crate::stats::{STAT_RECV_PKT, STAT_USB_ERR};

pub struct CdcTransport<'d> {
    pub class: &'d mut CdcAcmClass<'d, Driver<'d, peripherals::USB_OTG_FS>>,
}

impl Transport for CdcTransport<'_> {
    type Error = EndpointError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        self.class.wait_connection().await;
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let mut off = 0;
        while off < data.len() {
            let end = core::cmp::min(off + CDC_PKT, data.len());
            match self.class.write_packet(&data[off..end]).await {
                Ok(()) => {}
                Err(e) => {
                    STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }
            off = end;
        }

        if !data.is_empty() && data.len().is_multiple_of(CDC_PKT) {
            self.class.write_packet(&[]).await.inspect_err(|_| {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
            })?;
        }

        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.class.read_packet(buf).await {
            Ok(n) => {
                STAT_RECV_PKT.fetch_add(1, Ordering::Relaxed);
                Ok(n)
            }
            Err(e) => {
                STAT_USB_ERR.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }
}
