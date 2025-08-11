use std::net::SocketAddrV4;

use bitcoin::Network;
use corepc_node::{P2P, exe_path};

use bitcoin_p2p::net::ConnectionExt;
use bitcoin_p2p::handshake::ConnectionConfig;

#[derive(Debug, Clone)]
struct TestNodeBuilder<'a> {
    conf: corepc_node::Conf<'a>,
}

impl<'a> TestNodeBuilder<'a> {
    fn new() -> Self {
        let mut conf = corepc_node::Conf::default();
        conf.p2p = P2P::Yes;
        conf.args.push("--listen=1");
        conf.args.push("--rest=1");
        conf.args.push("--server=1");
        Self { conf }
    }

    #[allow(unused)]
    fn push_arg(mut self, arg: &'a str) -> Self {
        self.conf.args.push(arg);
        self
    }

    fn start(self) -> (corepc_node::Node, SocketAddrV4) {
        let path = exe_path().unwrap();
        let bitcoind = corepc_node::Node::with_conf(path, &self.conf).unwrap();
        let socket_addr = bitcoind.params.p2p_socket.unwrap();
        (bitcoind, socket_addr)
    }
}

#[test]
fn does_handshake() {
    let (mut bitcoind, socket_addr) = TestNodeBuilder::new().start();
    let _ = ConnectionConfig::new()
        .change_network(Network::Regtest)
        .open_connection(socket_addr.into())
        .unwrap();
    bitcoind.stop().unwrap();
}
