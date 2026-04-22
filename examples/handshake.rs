use std::net::SocketAddr;

use bitcoin_p2p::{
    handshake::ConnectionConfig,
    net::{ConnectionExt, TimeoutParams},
};

fn main() {
    let mut args = std::env::args();
    let _ = args.next();
    let peer = args
        .next()
        .expect("Usage: provide a socket address to a bitcoin peer");
    let socket_addr = peer.parse::<SocketAddr>().expect("invalid socket address");

    let (_, _, metadata) = ConnectionConfig::new()
        .user_agent("/bitcoin-p2p-example:0.1.0/".to_string())
        .decrease_version_requirement(70013)
        .open_connection(socket_addr, TimeoutParams::default())
        .expect("connection failed.");
    println!(
        "Established a connection with {socket_addr}. They offer: {}; Height: {}, Time difference in seconds: {}",
        metadata.feeler_data().services,
        metadata.feeler_data().reported_height,
        metadata.feeler_data().net_time_difference
    );
}
