use std::{fmt::Display, sync::Arc, time::Duration};

use bitcoin::{FeeRate, Network};
use p2p::{
    Address, ProtocolVersion, ServiceFlags,
    message::{CommandString, NetworkMessage},
    message_compact_blocks::SendCmpct,
    message_network::{Alert, ClientSoftwareVersion, UserAgent, UserAgentVersion, VersionMessage},
};

use crate::{FeelerData, Preferences};

const NETWORK: Network = Network::Bitcoin;
const UNREACHABLE: Address = Address::useless();
const AGENT_VERSION: UserAgentVersion = UserAgentVersion::new(ClientSoftwareVersion::SemVer {
    major: 0,
    minor: 1,
    revision: 0,
});
const CLIENT_NAME: &str = "SwiftSync";
const SERVICES: ServiceFlags = ServiceFlags::NONE;
const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::WTXID_RELAY_VERSION;

#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    our_version: ProtocolVersion,
    our_services: ServiceFlags,
    expected_version: ProtocolVersion,
    expected_services: ServiceFlags,
    send_cmpct: SendCmpct,
    user_agent: UserAgent,
    our_height: i32,
    fee_filter: FeeRate,
    network: Network,
}

impl ConnectionConfig {
    pub fn new() -> Self {
        let user_agent = UserAgent::new(CLIENT_NAME, AGENT_VERSION);
        Self {
            our_version: PROTOCOL_VERSION,
            our_services: SERVICES,
            expected_version: PROTOCOL_VERSION,
            expected_services: SERVICES,
            send_cmpct: SendCmpct {
                send_compact: false,
                version: 0,
            },
            user_agent,
            our_height: 0,
            fee_filter: FeeRate::BROADCAST_MIN,
            network: NETWORK,
        }
    }

    pub fn change_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn decrease_version_requirement(mut self, protocol_version: ProtocolVersion) -> Self {
        self.expected_version = protocol_version;
        self
    }

    pub fn set_service_requirement(mut self, service_flags: ServiceFlags) -> Self {
        self.expected_services = service_flags;
        self
    }

    pub fn offer_services(mut self, service_flags: ServiceFlags) -> Self {
        self.our_services = service_flags;
        self
    }

    pub fn user_agent(mut self, user_agent: UserAgent) -> Self {
        self.user_agent = user_agent;
        self
    }

    pub fn send_cmpct(mut self, send_cmpct: SendCmpct) -> Self {
        self.send_cmpct = send_cmpct;
        self
    }

    pub fn our_height(mut self, height: i32) -> Self {
        self.our_height = height;
        self
    }

    pub fn fee_filter(mut self, fee_filter: FeeRate) -> Self {
        self.fee_filter = fee_filter;
        self
    }

    pub(crate) fn build_our_version(&self, unix_time: Duration, nonce: u64) -> VersionMessage {
        VersionMessage {
            version: self.our_version,
            services: self.our_services,
            timestamp: unix_time.as_secs() as i64,
            receiver: UNREACHABLE,
            sender: UNREACHABLE,
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
        origin: Origin,
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
        if matches!(origin, Origin::Inbound) {
            let version = NetworkMessage::Version(self.build_our_version(unix_time, nonce));
            suggested_messages.push(version);
        }
        let effective_version = std::cmp::min(self.our_version, version.version);
        if effective_version > ProtocolVersion::WTXID_RELAY_VERSION {
            suggested_messages.push(NetworkMessage::WtxidRelay);
        }
        // Weird case where this number is not a constant in Bitcoin Core
        if effective_version > ProtocolVersion::from_nonstandard(70016) {
            suggested_messages.push(NetworkMessage::SendAddrV2);
        }
        if effective_version > ProtocolVersion::SENDHEADERS_VERSION {
            suggested_messages.push(NetworkMessage::SendHeaders);
        } else {
            suggested_messages.push(NetworkMessage::Alert(Alert::final_alert()));
        }
        let net_time_difference = unix_time.as_secs_f64() as i64 - version.timestamp;
        let feeler = FeelerData {
            effective_version,
            services: version.services,
            net_time_difference,
            reported_height: version.start_height,
        };
        let preferences = Arc::new(Preferences::default());
        let handshake = InitializedHandshake {
            feeler,
            their_preferences: preferences,
            send_cmpct: self.send_cmpct,
            fee_filter: self.fee_filter,
        };
        Ok((handshake, suggested_messages))
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Inbound,
    OutBound,
}

#[derive(Debug, Clone)]
pub(crate) struct InitializedHandshake {
    feeler: FeelerData,
    their_preferences: Arc<Preferences>,
    fee_filter: FeeRate,
    send_cmpct: SendCmpct,
}

impl InitializedHandshake {
    pub(crate) fn negotiate(
        &self,
        message: NetworkMessage,
    ) -> Result<Option<(CompletedHandshake, Vec<NetworkMessage>)>, Error> {
        match message {
            NetworkMessage::Verack => {
                let fee_filter = NetworkMessage::FeeFilter(self.fee_filter);
                let send_cmpct = NetworkMessage::SendCmpct(self.send_cmpct);
                let messages = vec![send_cmpct, fee_filter];
                Ok(Some((
                    CompletedHandshake {
                        feeler: self.feeler,
                        their_preferences: Arc::clone(&self.their_preferences),
                    },
                    messages,
                )))
            }
            NetworkMessage::WtxidRelay => {
                self.their_preferences.prefers_wtxid();
                Ok(None)
            }
            NetworkMessage::SendAddrV2 => {
                self.their_preferences.prefers_addrv2();
                Ok(None)
            }
            NetworkMessage::SendCmpct(cmpct) => {
                self.their_preferences.prefers_cmpct(cmpct.version);
                Ok(None)
            }
            NetworkMessage::SendHeaders => {
                self.their_preferences.prefers_header_announcment();
                Ok(None)
            }
            e => Err(Error::IrrelevantMessage(e.command())),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CompletedHandshake {
    pub(crate) feeler: FeelerData,
    pub(crate) their_preferences: Arc<Preferences>,
}

#[derive(Debug, Clone)]
pub enum Error {
    IrrelevantMessage(CommandString),
    ConnectionToSelf,
    TooLowVersion(ProtocolVersion),
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
