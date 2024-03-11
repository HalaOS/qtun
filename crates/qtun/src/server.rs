use std::{io, net::SocketAddr};

use rasi::{executor::spawn, net::TcpStream};
use rasi_ext::net::quic::QuicListener;

use crate::{
    config::{make_config, QuicTunnelConfig},
    utils::tunnel_copy,
};

/// Qtun server type.
pub struct QtunServer {
    raddrs: Vec<SocketAddr>,
    quic_listener: QuicListener,
}

impl QtunServer {
    /// Create client instance with [`QuicTunnelConfig`].
    pub async fn new(tunnel_config: QuicTunnelConfig) -> io::Result<Self> {
        let quic_config = make_config(&tunnel_config);

        let quic_listener =
            QuicListener::bind(tunnel_config.laddrs.as_slice(), quic_config).await?;

        Ok(Self {
            quic_listener,
            raddrs: tunnel_config.raddrs,
        })
    }

    pub async fn run(&self) -> io::Result<()> {
        while let Some(conn) = self.quic_listener.accept().await {
            log::info!("Quic server: accept newly connection, {}", conn);

            let raddrs = self.raddrs.clone();

            spawn(async move {
                while let Some(quic_stream) = conn.stream_accept().await {
                    let tcp_stream = match TcpStream::connect(raddrs.as_slice()).await {
                        Ok(tcp_stream) => tcp_stream,
                        Err(err) => {
                            log::error!(
                                "Quic server: create tcp stream to {:?} with error, {}",
                                raddrs,
                                err
                            );
                            continue;
                        }
                    };

                    let raddr = match tcp_stream.peer_addr() {
                        Ok(raddr) => raddr,
                        Err(err) => {
                            log::error!("Quic server: get tunnel peer_addr with error, {}", err);
                            continue;
                        }
                    };

                    let debug_info = format!("tunnel: {} => {}", quic_stream, raddr);

                    let (tcp_read, tcp_write) = tcp_stream.split();
                    let quic_read = quic_stream.clone();
                    let quic_write = quic_stream;

                    // create forward tunnel.
                    spawn(tunnel_copy(debug_info.clone(), quic_read, tcp_write));
                    // create backward tunnel.
                    spawn(tunnel_copy(debug_info, tcp_read, quic_write));
                }

                log::info!("Quic server: connection closed, {}", conn);
            });
        }

        todo!()
    }
}
