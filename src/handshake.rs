use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use bitcoin::p2p::{
    message::{CommandString, NetworkMessage},
    message_compact_blocks::SendCmpct,
    message_network::VersionMessage,
    Address, ServiceFlags,
};
use bitcoin::Network;

use crate::{FeelerData, Preferences};

const NETWORK: Network = Network::Bitcoin;
const SERVICES: ServiceFlags = ServiceFlags::NONE;

fn useless_address() -> Address {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let socket_addr = SocketAddr::new(ip, 1);
    Address::new(&socket_addr, ServiceFlags::NONE)
}

/// Version of the Bitcoin protocol.
pub type ProtocolVersion = u32;

trait ProtocolVersionExt {
    const WTXID_RELAY_VERSION: u32 = 70016;
    const SENDHEADERS_VERSION: u32 = 70012;
    const MIN_PEER_PROTO_VERSION: u32 = 31800;
}

impl ProtocolVersionExt for u32 {}

/// Build a connection according to a list of preferences
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    our_version: ProtocolVersion,
    our_services: ServiceFlags,
    expected_version: ProtocolVersion,
    expected_services: ServiceFlags,
    send_cmpct: SendCmpct,
    user_agent: String,
    our_height: i32,
    fee_filter: i64,
    network: Network,
    request_addr: bool,
}

impl ConnectionConfig {
    /// Start a new connection on the bitcoin network
    pub fn new() -> Self {
        Self {
            our_version: ProtocolVersion::WTXID_RELAY_VERSION,
            our_services: SERVICES,
            expected_version: ProtocolVersion::WTXID_RELAY_VERSION,
            expected_services: SERVICES,
            send_cmpct: SendCmpct {
                send_compact: false,
                version: 0,
            },
            user_agent: "/bitcoin-p2p:0.1.0/".to_string(),
            our_height: 0,
            fee_filter: 0,
            network: NETWORK,
            request_addr: false,
        }
    }

    /// Change the network
    pub fn change_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    /// Fetch the current network
    pub fn network(&self) -> Network {
        self.network
    }

    /// Request the peer gossip new addresses at the beginning of the connection
    pub fn request_addr(mut self) -> Self {
        self.request_addr = true;
        self
    }

    /// Decrease the minimum accepted version
    pub fn decrease_version_requirement(mut self, protocol_version: ProtocolVersion) -> Self {
        self.expected_version = protocol_version;
        self
    }

    /// Set the requirement of what services the peer needs
    pub fn set_service_requirement(mut self, service_flags: ServiceFlags) -> Self {
        self.expected_services = service_flags;
        self
    }

    /// Offer services to the peer
    pub fn offer_services(mut self, service_flags: ServiceFlags) -> Self {
        self.our_services = service_flags;
        self
    }

    /// Set a custom user agent describing this software
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = user_agent;
        self
    }

    /// Advertise a compact block version
    pub fn send_cmpct(mut self, send_cmpct: SendCmpct) -> Self {
        self.send_cmpct = send_cmpct;
        self
    }

    /// Report a block chain height other than zero
    pub fn our_height(mut self, height: i32) -> Self {
        self.our_height = height;
        self
    }

    /// Advertise the minimum fee rate required to gossip transactions in sat/kilobyte
    pub fn fee_filter(mut self, fee_filter: i64) -> Self {
        self.fee_filter = fee_filter;
        self
    }

    pub(crate) fn build_our_version(&self, unix_time: Duration, nonce: u64) -> VersionMessage {
        VersionMessage {
            version: self.our_version,
            services: self.our_services,
            timestamp: unix_time.as_secs() as i64,
            receiver: useless_address(),
            sender: useless_address(),
            nonce,
            user_agent: self.user_agent.clone(),
            start_height: self.our_height,
            relay: false,
        }
    }

    pub(crate) fn start_handshake(
        self,
        unix_time: Duration,
        network_message: NetworkMessage,
        nonce: u64,
    ) -> Result<(InitializedHandshake, Vec<NetworkMessage>), Error> {
        let version = match network_message {
            NetworkMessage::Version(version) => version,
            e => return Err(Error::IrrelevantMessage(e.command())),
        };
        let mut suggested_messages = Vec::new();
        if version.nonce.eq(&nonce) {
            return Err(Error::ConnectionToSelf);
        }
        if version.version < self.expected_version
            || version.version < ProtocolVersion::MIN_PEER_PROTO_VERSION
        {
            return Err(Error::TooLowVersion(version.version));
        }
        if !version.services.has(self.expected_services) {
            return Err(Error::MissingService(version.services));
        }
        let effective_version = std::cmp::min(self.our_version, version.version);
        if effective_version >= ProtocolVersion::WTXID_RELAY_VERSION {
            suggested_messages.push(NetworkMessage::WtxidRelay);
        }
        // Weird case where this number is not a constant in Bitcoin Core
        if effective_version >= 70016 {
            suggested_messages.push(NetworkMessage::SendAddrV2);
        }
        if effective_version >= ProtocolVersion::SENDHEADERS_VERSION {
            suggested_messages.push(NetworkMessage::SendHeaders);
        }
        let net_time_difference = unix_time.as_secs_f64() as i64 - version.timestamp;
        let feeler = FeelerData {
            effective_version,
            services: version.services,
            net_time_difference,
            reported_height: version.start_height,
            nonce,
        };
        let handshake = InitializedHandshake {
            feeler,
            their_preferences: Preferences::default(),
            send_cmpct: self.send_cmpct,
            fee_filter: self.fee_filter,
            request_addr: self.request_addr,
        };
        Ok((handshake, suggested_messages))
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InitializedHandshake {
    feeler: FeelerData,
    their_preferences: Preferences,
    fee_filter: i64,
    send_cmpct: SendCmpct,
    request_addr: bool,
}

impl InitializedHandshake {
    pub(crate) fn negotiate(
        &mut self,
        message: NetworkMessage,
    ) -> Result<Option<(CompletedHandshake, Vec<NetworkMessage>)>, Error> {
        match message {
            NetworkMessage::Verack => {
                let verack = NetworkMessage::Verack;
                let fee_filter = NetworkMessage::FeeFilter(self.fee_filter);
                let send_cmpct = NetworkMessage::SendCmpct(self.send_cmpct);
                let mut messages = vec![verack, send_cmpct, fee_filter];
                if self.request_addr {
                    messages.push(NetworkMessage::GetAddr);
                }
                Ok(Some((
                    CompletedHandshake {
                        feeler: self.feeler,
                        their_preferences: self.their_preferences,
                    },
                    messages,
                )))
            }
            NetworkMessage::WtxidRelay => {
                self.their_preferences.sendwtxid = true;
                Ok(None)
            }
            NetworkMessage::SendAddrV2 => {
                self.their_preferences.sendaddrv2 = true;
                Ok(None)
            }
            NetworkMessage::SendCmpct(cmpct) => {
                self.their_preferences.sendcmpct = cmpct;
                Ok(None)
            }
            NetworkMessage::SendHeaders => {
                self.their_preferences.sendheaders = true;
                Ok(None)
            }
            e => Err(Error::IrrelevantMessage(e.command())),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompletedHandshake {
    pub(crate) feeler: FeelerData,
    pub(crate) their_preferences: Preferences,
}

/// Errors that occur during a handshake
#[derive(Debug, Clone)]
pub enum Error {
    /// The peer send some irrelevant message
    IrrelevantMessage(CommandString),
    /// A circular connection was made
    ConnectionToSelf,
    /// The version the peer advertises is too low
    TooLowVersion(ProtocolVersion),
    /// The peer is missing a required service
    MissingService(ServiceFlags),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ConnectionToSelf => write!(f, "connected to self."),
            Error::TooLowVersion(version) => write!(f, "too low version: {version:?}"),
            Error::IrrelevantMessage(irrelevant) => write!(f, "irrelevant message: {irrelevant}"),
            Error::MissingService(services) => write!(f, "missing services: {services}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use bitcoin::p2p::{message::NetworkMessage, message_network::VersionMessage, ServiceFlags};

    use super::{useless_address, ConnectionConfig, ProtocolVersion, ProtocolVersionExt};

    fn build_mock_version(
        with_version: ProtocolVersion,
        with_services: ServiceFlags,
    ) -> VersionMessage {
        VersionMessage {
            version: with_version,
            services: with_services,
            timestamp: 222222222,
            receiver: useless_address(),
            sender: useless_address(),
            nonce: 42,
            user_agent: "hello".into(),
            start_height: 0,
            relay: false,
        }
    }

    #[test]
    fn test_outbound_handshake() {
        let mock = build_mock_version(ProtocolVersion::WTXID_RELAY_VERSION, ServiceFlags::NONE);
        let connection_config = ConnectionConfig::new();
        let nonce = 43;
        let system_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let (mut init_handshake, messages) = connection_config
            .start_handshake(system_time, NetworkMessage::Version(mock), nonce)
            .unwrap();
        let mut message_iter = messages.into_iter();
        let nxt = message_iter.next().unwrap();
        assert!(matches!(nxt, NetworkMessage::WtxidRelay));
        let nxt = message_iter.next().unwrap();
        assert!(matches!(nxt, NetworkMessage::SendAddrV2));
        let nxt = message_iter.next().unwrap();
        assert!(matches!(nxt, NetworkMessage::SendHeaders));
        assert!(message_iter.next().is_none());
        let message = NetworkMessage::WtxidRelay;
        let nego = init_handshake.negotiate(message).unwrap();
        assert!(nego.is_none());
        let message = NetworkMessage::SendAddrV2;
        let nego = init_handshake.negotiate(message).unwrap();
        assert!(nego.is_none());
        let message = NetworkMessage::Verack;
        let (completed, messages) = init_handshake.negotiate(message).unwrap().unwrap();
        let mut message_iter = messages.into_iter();
        let verack = message_iter.next().unwrap();
        assert!(matches!(verack, NetworkMessage::Verack));
        let cmpct = message_iter.next().unwrap();
        assert!(matches!(cmpct, NetworkMessage::SendCmpct(_)));
        let fee_filter = message_iter.next().unwrap();
        assert!(matches!(fee_filter, NetworkMessage::FeeFilter(_)));
        assert!(completed.their_preferences.sendwtxid);
        assert!(completed.their_preferences.sendaddrv2);
        assert!(!completed.their_preferences.sendheaders);
    }

    #[test]
    fn test_reject_low_version() {
        let mock = build_mock_version(70015, ServiceFlags::NONE);
        let connection_config = ConnectionConfig::new();
        let nonce = 43;
        let system_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(connection_config
            .start_handshake(system_time, NetworkMessage::Version(mock), nonce,)
            .is_err())
    }

    #[test]
    fn test_reject_missing_services() {
        let mock = build_mock_version(ProtocolVersion::WTXID_RELAY_VERSION, ServiceFlags::NONE);
        let connection_config =
            ConnectionConfig::new().set_service_requirement(ServiceFlags::NETWORK);
        let nonce = 43;
        let system_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(connection_config
            .start_handshake(system_time, NetworkMessage::Version(mock), nonce,)
            .is_err())
    }

    #[test]
    fn test_change_version_ok() {
        let mock = build_mock_version(ProtocolVersion::SENDHEADERS_VERSION, ServiceFlags::NONE);
        let connection_config = ConnectionConfig::new()
            .decrease_version_requirement(ProtocolVersion::SENDHEADERS_VERSION);
        let nonce = 43;
        let system_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert!(connection_config
            .start_handshake(system_time, NetworkMessage::Version(mock), nonce,)
            .is_ok())
    }

    #[test]
    fn test_gets_addr() {
        let mock = build_mock_version(ProtocolVersion::WTXID_RELAY_VERSION, ServiceFlags::NONE);
        let connection_config = ConnectionConfig::new().request_addr();
        let nonce = 43;
        let system_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let (mut init_handshake, _) = connection_config
            .start_handshake(system_time, NetworkMessage::Version(mock), nonce)
            .unwrap();
        let (_, messages) = init_handshake
            .negotiate(NetworkMessage::Verack)
            .unwrap()
            .unwrap();
        assert!(matches!(messages.last().unwrap(), NetworkMessage::GetAddr));
    }
}
