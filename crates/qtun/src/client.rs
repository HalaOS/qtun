use std::io;

use rasi::{executor::spawn, net::TcpListener};
use rasi_ext::net::quic::QuicConnPool;

use crate::{
    config::{make_config, QuicTunnelConfig},
    utils::tunnel_copy,
};

/// Qtun client type.
pub struct QtunClient {
    /// The tcp socket listener for client side.
    tcp_listener: TcpListener,
    /// Forward quic connection pool.
    conn_pool: QuicConnPool,
}

impl QtunClient {
    /// Create client instance with [`QuicTunnelConfig`].
    pub async fn new(tunnel_config: QuicTunnelConfig) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(tunnel_config.laddrs.as_slice()).await?;

        let quic_config = make_config(&tunnel_config);

        let conn_pool = QuicConnPool::new(None, tunnel_config.raddrs.as_slice(), quic_config)?;

        Ok(QtunClient {
            tcp_listener,
            conn_pool,
        })
    }

    pub async fn run(&self) -> io::Result<()> {
        loop {
            let (conn, raddr) = self.tcp_listener.accept().await?;

            log::info!("Qtun client: newly inbound connection from {:?}", raddr);

            let stream = match self.conn_pool.stream_open().await {
                Ok(stream) => stream,
                Err(err) => {
                    log::error!("Qtun client: open tunnel with error, {}", err);
                    continue;
                }
            };

            let debug_info = format!("tunnel: {} => {}", raddr, stream);

            let (tcp_read, tcp_write) = conn.split();
            let quic_read = stream.clone();
            let quic_write = stream;

            // create forward tunnel.
            spawn(tunnel_copy(debug_info.clone(), tcp_read, quic_write));
            // create backward tunnel.
            spawn(tunnel_copy(debug_info, quic_read, tcp_write));
        }
    }
}
