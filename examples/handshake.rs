use std::net::SocketAddr;

use bitcoin_p2p::{handshake::ConnectionConfig, net::ConnectionExt};
use p2p::{
    message_network::{ClientSoftwareVersion, UserAgent, UserAgentVersion},
    ProtocolVersion,
};

const VERSION: ClientSoftwareVersion = ClientSoftwareVersion::SemVer {
    major: 0,
    minor: 1,
    revision: 0,
};
const AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(VERSION);

fn main() {
    let mut args = std::env::args();
    let _ = args.next();
    let peer = args
        .next()
        .expect("Usage: provide a socket address to a bitcoin peer");
    let socket_addr = peer.parse::<SocketAddr>().expect("invalid socket address");

    let user_agent = UserAgent::new("rust-example", AGENT_VERSION);
    let (_, _, metadata) = ConnectionConfig::new()
        .user_agent(user_agent)
        .decrease_version_requirement(ProtocolVersion::BIP0031_VERSION)
        .open_connection(socket_addr)
        .expect("connection failed.");
    println!(
        "Established a connection with {socket_addr}. They offer: {}; Height: {}, Time difference in seconds: {}",
        metadata.feeler_data().services,
        metadata.feeler_data().reported_height,
        metadata.feeler_data().net_time_difference
    );
}
