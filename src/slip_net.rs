use defmt::{error, info, warn};

use embassy_futures::select::{Either, select};
use embassy_net_driver_channel as ch;
use embassy_net_driver_channel::driver::LinkState;
use embassy_time::{Duration, Timer};
use embassy_usb::class::cdc_acm::CdcAcmClass;

use microfips_core::slip::SlipDecoder;

const MTU: usize = 1500;

pub type Device<'d> = embassy_net_driver_channel::Device<'d, MTU>;

pub struct SlipNetState<const N_RX: usize, const N_TX: usize> {
    ch_state: ch::State<MTU, N_RX, N_TX>,
}

impl<const N_RX: usize, const N_TX: usize> SlipNetState<N_RX, N_TX> {
    pub const fn new() -> Self {
        Self {
            ch_state: ch::State::new(),
        }
    }
}

pub struct SlipNetRunner<'d> {
    ch: ch::Runner<'d, MTU>,
}

#[derive(Debug, PartialEq)]
pub enum NetError {
    Disconnected,
}

impl<'d> SlipNetRunner<'d> {
    pub async fn run<'a, T: embassy_stm32::usb::Instance>(
        &mut self,
        class: &mut CdcAcmClass<'a, embassy_stm32::usb::Driver<'a, T>>,
    ) -> ! {
        let mut rx_buf = [0u8; 256];
        let mut frame_buf = [0u8; MTU];
        let mut enc_buf = [0u8; MTU * 2];
        let mut decoder = SlipDecoder::new();
        let mut diag_timer = embassy_time::Ticker::every(Duration::from_secs(5));

        loop {
            info!("SLIP net: waiting for USB connection...");
            class.wait_connection().await;
            info!("SLIP net: USB connected! Sending immediate test");
            let test = [0xC0u8, 0xAA, 0xBB, 0xCC, 0xC0];
            match class.write_packet(&test).await {
                Ok(()) => info!("SLIP net: IMMEDIATE TEST TX OK"),
                Err(e) => error!("SLIP net: IMMEDIATE TEST TX FAILED: {:?}", e),
            }
            info!("SLIP net: link UP");
            self.ch.set_link_state(LinkState::Up);

            while self.ch.try_tx_buf().is_some() {
                warn!("SLIP net: draining stale TX packet");
                self.ch.tx_done();
            }

            let result = self.run_connected(class, &mut rx_buf, &mut frame_buf, &mut enc_buf, &mut decoder, &mut diag_timer).await;

            match result {
                Err(NetError::Disconnected) => info!("SLIP net: USB disconnected"),
                Ok(()) => unreachable!(),
            }

            self.ch.set_link_state(LinkState::Down);
            decoder.reset();
        }
    }

    async fn run_connected<'a, T: embassy_stm32::usb::Instance>(
        &mut self,
        class: &mut CdcAcmClass<'a, embassy_stm32::usb::Driver<'a, T>>,
        rx_buf: &mut [u8; 256],
        frame_buf: &mut [u8; MTU],
        enc_buf: &mut [u8; MTU * 2],
        decoder: &mut SlipDecoder,
        diag_timer: &mut embassy_time::Ticker,
    ) -> Result<(), NetError> {
        loop {
            match select(
                select(class.read_packet(rx_buf), self.ch.tx_buf()),
                diag_timer.next(),
            )
            .await
            {
                Either::First(Either::First(Ok(n))) => {
                    info!("SLIP net: USB rx {} bytes", n);
                    for &byte in &rx_buf[..n] {
                        match decoder.feed(byte, frame_buf) {
                            Ok(Some(frame)) => {
                                info!("SLIP net: decoded frame {}B", frame.len());
                                if let Some(buf) = self.ch.try_rx_buf() {
                                    let len = frame.len().min(buf.len());
                                    buf[..len].copy_from_slice(&frame[..len]);
                                    self.ch.rx_done(len);
                                } else {
                                    warn!("RX channel full, dropping frame");
                                }
                            }
                            Ok(None) => {}
                            Err(microfips_core::slip::DecodeError::FrameTooLong) => {
                                warn!("SLIP decode error, resetting");
                                decoder.reset();
                            }
                        }
                    }
                }
                Either::First(Either::First(Err(_))) => return Err(NetError::Disconnected),
                Either::First(Either::Second(pkt)) => {
                    info!("SLIP net: TX pkt {}B", pkt.len());
                    let enc_len = SlipDecoder::encode(pkt, enc_buf);
                    match class.write_packet(&enc_buf[..enc_len]).await {
                        Ok(()) => info!("SLIP net: USB tx {}B OK", enc_len),
                        Err(e) => error!("SLIP net: USB tx FAILED: {:?}", e),
                    }
                    self.ch.tx_done();
                }
                Either::Second(()) => {
                    info!("SLIP net: diag tick, sending test bytes");
                    let test = [0xC0u8, 0x01, 0xC0];
                    match class.write_packet(&test).await {
                        Ok(()) => info!("SLIP net: test tx OK"),
                        Err(e) => error!("SLIP net: test tx FAILED: {:?}", e),
                    }
                }
            }
        }
    }
}

pub fn new<'a, const N_RX: usize, const N_TX: usize>(
    state: &'a mut SlipNetState<N_RX, N_TX>,
) -> (Device<'a>, SlipNetRunner<'a>) {
    let (runner, device) = ch::new(&mut state.ch_state, ch::driver::HardwareAddress::Ip);
    (device, SlipNetRunner { ch: runner })
}
