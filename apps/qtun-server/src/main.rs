use std::io;

use clap::Parser;
use futures::executor::block_on;
use hala_qtun::{config::QuicTunnelConfig, server::QtunServer};
use rasi_default::{
    executor::register_futures_executor, net::register_mio_network, time::register_mio_timer,
};

fn main() {
    pretty_env_logger::init_timed();

    register_futures_executor().unwrap();
    register_mio_network();
    register_mio_timer();

    block_on(async move {
        match run_server().await {
            Ok(()) => {
                log::info!("QtunServer: stop server loop.");
            }
            Err(err) => {
                log::error!("QtunServer: stop server loop with error, {}", err);
            }
        }
    })
}

async fn run_server() -> io::Result<()> {
    let tunnel_config = QuicTunnelConfig::parse();

    let server = QtunServer::new(tunnel_config).await?;

    server.run().await
}
