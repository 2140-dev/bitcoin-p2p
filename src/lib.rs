//! Bitcoin Peer-to-Peer connections.
#![warn(missing_docs)]
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bitcoin::Network;
use p2p::{message_compact_blocks::SendCmpct, ProtocolVersion, ServiceFlags};

pub extern crate p2p;

/// Automated version negotiation with remote peers
pub mod handshake;
/// Networking extensions
pub mod net;
/// Tools for validating messages and data
pub mod validation;

/// The static data related to a connection. Note that this is referred to as "feeler" data because
/// it may be used to collect data on very short-lived connections.
#[derive(Debug, Clone, Copy)]
pub struct FeelerData {
    /// The lowest common version of the connection.
    pub effective_version: ProtocolVersion,
    /// The service flags they advertise.
    pub services: ServiceFlags,
    /// The net time difference between our time and what they report.
    pub net_time_difference: i64,
    /// The reported height of their block chain.
    pub reported_height: i32,
    /// The nonce used to create this connection.
    pub nonce: u64,
}

/// The peer's preferences during this connection. These are updated automatically as the peer
/// shares information.
#[derive(Debug, Clone, Copy)]
pub struct Preferences {
    /// Announce blocks to this peer by block header.
    pub sendheaders: bool,
    /// Send `Addrv2` addresses.
    pub sendaddrv2: bool,
    /// Compact block relay preferences.
    pub sendcmpct: SendCmpct,
    /// Advertise transactions by WTXID.
    pub sendwtxid: bool,
}

impl Preferences {
    fn new() -> Self {
        Self {
            sendheaders: false,
            sendaddrv2: false,
            sendcmpct: SendCmpct {
                send_compact: false,
                version: 0x00,
            },
            sendwtxid: false,
        }
    }
}

impl Default for Preferences {
    fn default() -> Self {
        Self::new()
    }
}

/// Data collected during a connection that is continually updated in the background
#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    feeler: FeelerData,
    their_preferences: Arc<Mutex<Preferences>>,
    timed_messages: Arc<Mutex<TimedMessages>>,
    start_time: Instant,
    outbound_ping_state: Arc<Mutex<OutboundPing>>,
}

impl ConnectionMetrics {
    /// Static data about the peer
    pub fn feeler_data(&self) -> &FeelerData {
        &self.feeler
    }

    /// Their current preferences for message exchange, if not currently being mutated.
    pub fn their_preferences(&self) -> Option<Preferences> {
        let pref = self.their_preferences.lock().ok();
        pref.as_deref().copied()
    }

    /// The message rate for a time-sensitive message
    pub fn message_rate(&self, timed_message: TimedMessage) -> Option<MessageRate> {
        let lock = self.timed_messages.lock().ok()?;
        Some(*lock.message_rate(timed_message))
    }

    /// Time the connection has remained open.
    pub fn connection_time(&self, now: Instant) -> Duration {
        now.duration_since(self.start_time)
    }

    /// Has the connection failed to respond to a ping after the given duration.
    pub fn ping_timed_out(&self, timeout: Duration) -> bool {
        if let Ok(lock) = self.outbound_ping_state.lock() {
            match *lock {
                OutboundPing::Waiting { nonce: _, then } => return then.elapsed() > timeout,
                _ => return false,
            }
        }
        false
    }
}

/// The rate at which a peer sends a particular message
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum MessageRate {
    /// No message of this type has been received.
    NoneReceived,
    /// The total count of messages along with the first message of this type.
    Ongoing {
        /// Total count of messages
        count: f64,
        /// The time of the first message
        start: Instant,
    },
}

impl MessageRate {
    fn new() -> Self {
        Self::NoneReceived
    }

    fn add_single_message(&mut self, now: Instant) {
        self.add_messages(1, now);
    }

    fn add_messages(&mut self, num_messages: usize, now: Instant) {
        if num_messages == 0 {
            return;
        }
        let num_messages = num_messages.try_into().unwrap_or(u32::MAX);
        let num_message_float_repr = num_messages.into();
        match self {
            Self::NoneReceived => {
                *self = Self::Ongoing {
                    count: num_message_float_repr,
                    start: now,
                }
            }
            Self::Ongoing { count, start: _ } => *count += num_message_float_repr,
        }
    }

    /// The messages per second, recorded at the current time
    pub fn messages_per_secs(&self, now: Instant) -> Option<f64> {
        match self {
            Self::NoneReceived => None,
            Self::Ongoing { count, start } => {
                Some(*count / now.duration_since(*start).as_secs_f64())
            }
        }
    }

    /// The total number of these messages sent
    pub fn total_count(&self) -> u32 {
        match self {
            Self::NoneReceived => 0,
            Self::Ongoing { count, start: _ } => *count as u32,
        }
    }
}

/// A time-sensitive message
#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub enum TimedMessage {
    /// Block headers
    BlockHeaders,
    /// Compact block filters
    CFilters,
    /// Bitcoin blocks
    Block,
    /// Potential peers on the network
    Addr,
}

#[derive(Debug, Clone)]
struct TimedMessages(HashMap<TimedMessage, MessageRate>);

impl TimedMessages {
    fn new() -> Self {
        let mut map = HashMap::with_capacity(4);
        for key in [
            TimedMessage::BlockHeaders,
            TimedMessage::CFilters,
            TimedMessage::Block,
            TimedMessage::Addr,
        ] {
            map.insert(key, MessageRate::new());
        }
        Self(map)
    }

    fn add_single(&mut self, message: TimedMessage, now: Instant) {
        let val = self
            .0
            .get_mut(&message)
            .expect("all timed messages are in the map");
        val.add_single_message(now);
    }

    fn add_many(&mut self, message: TimedMessage, num_messages: usize, now: Instant) {
        let val = self
            .0
            .get_mut(&message)
            .expect("all timed messages are in the map");
        val.add_messages(num_messages, now);
    }

    fn message_rate(&self, message: TimedMessage) -> &MessageRate {
        self.0
            .get(&message)
            .expect("all timed messages are in the map")
    }
}

impl Default for TimedMessages {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
enum OutboundPing {
    Waiting { nonce: u64, then: Instant },
    LastReceived { then: Instant },
}

/// DNS seed provider
pub trait SeedsExt {
    /// List DNS seeds
    fn seeds(&self) -> Vec<&str>;
}

impl SeedsExt for Network {
    fn seeds(&self) -> Vec<&str> {
        match self {
            Self::Bitcoin => vec![
                "seed.bitcoin.sipa.be",
                "dnsseed.bluematt.me",
                "dnsseed.bitcoin.dashjr.org",
                "seed.bitcoinstats.com",
                "seed.bitcoin.jonasschnelli.ch",
                "seed.btc.petertodd.org",
                "seed.bitcoin.sprovoost.nl",
                "dnsseed.emzy.de",
                "seed.bitcoin.wiz.biz",
            ],
            Self::Signet => vec![
                "seed.signet.bitcoin.sprovoost.nl",
                "seed.signet.achownodes.xyz",
            ],
            Self::Regtest => vec![],
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::{MessageRate, TimedMessage, TimedMessages};

    #[test]
    fn test_message_rate() {
        let now = Instant::now();
        let later = now.checked_add(Duration::from_secs(10)).unwrap();
        let mut rate = MessageRate::new();
        rate.add_messages(0, now);
        assert!(matches!(rate, MessageRate::NoneReceived));
        rate.add_single_message(now);
        rate.add_messages(9, later);
        assert_eq!(rate.messages_per_secs(later).unwrap(), 1.);
        rate.add_messages(10, later);
        assert_eq!(rate.messages_per_secs(later).unwrap(), 2.);
    }

    #[test]
    fn test_timed_messages() {
        let now = Instant::now();
        let later = now.checked_add(Duration::from_secs(10)).unwrap();
        let mut timed_messages = TimedMessages::new();
        timed_messages.add_many(TimedMessage::Addr, 1_000, now);
        let msg_per_secs = timed_messages
            .message_rate(TimedMessage::Addr)
            .messages_per_secs(later)
            .unwrap();
        assert_eq!(100., msg_per_secs);
        assert!(
            timed_messages
                .message_rate(TimedMessage::Addr)
                .total_count()
                == 1_000
        );
    }
}
