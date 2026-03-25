use defmt::{info, warn};

use embassy_futures::select::{Either, select};
use embassy_net_driver_channel as ch;
use embassy_net_driver_channel::driver::LinkState;
use embassy_usb::class::cdc_acm::CdcAcmClass;

use crate::slip::SlipDecoder;

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

        loop {
            class.wait_connection().await;
            info!("SLIP net: USB connected");
            self.ch.set_link_state(LinkState::Up);

            let result = self.run_connected(class, &mut rx_buf, &mut frame_buf, &mut enc_buf, &mut decoder).await;

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
    ) -> Result<(), NetError> {
        loop {
            match select(class.read_packet(rx_buf), self.ch.tx_buf()).await {
                Either::First(Ok(n)) => {
                    for &byte in &rx_buf[..n] {
                        match decoder.feed(byte, frame_buf) {
                            Ok(Some(frame)) => {
                                if let Some(buf) = self.ch.try_rx_buf() {
                                    let len = frame.len().min(buf.len());
                                    buf[..len].copy_from_slice(&frame[..len]);
                                    self.ch.rx_done(len);
                                } else {
                                    warn!("RX channel full, dropping frame");
                                }
                            }
                            Ok(None) => {}
                            Err(crate::slip::DecodeError::FrameTooLong) => {
                                warn!("SLIP decode error, resetting");
                                decoder.reset();
                            }
                        }
                    }
                }
                Either::First(Err(_)) => return Err(NetError::Disconnected),
                Either::Second(pkt) => {
                    let enc_len = SlipDecoder::encode(pkt, enc_buf);
                    class.write_packet(&enc_buf[..enc_len]).await.map_err(|_| NetError::Disconnected)?;
                    self.ch.tx_done();
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
