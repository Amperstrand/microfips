use embassy_net::udp::UdpSocket;
use embassy_net::IpEndpoint;
use microfips_protocol::transport::Transport;

#[derive(Debug)]
pub enum UdpTransportError {
    Send,
    Recv,
}

pub struct UdpTransport<'a> {
    pub socket: UdpSocket<'a>,
    pub peer: IpEndpoint,
}

impl Transport for UdpTransport<'_> {
    type Error = UdpTransportError;

    async fn wait_ready(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.socket
            .send_to(data, self.peer)
            .await
            .map_err(|_| UdpTransportError::Send)
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let (n, _) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|_| UdpTransportError::Recv)?;
        Ok(n)
    }
}
