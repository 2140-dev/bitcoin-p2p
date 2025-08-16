use std::{
    fmt::Display,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        mpsc::{self, SendError},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bitcoin::{
    consensus::{self, DeserializeError},
    key::rand::random,
};
use p2p::{
    message::{NetworkMessage, RawNetworkMessage, V1MessageHeader},
    Magic, NetworkExt,
};

use crate::{
    handshake::{self, CompletedHandshake, ConnectionConfig},
    ConnectionMetrics, OutboundPing, Preferences, TimedMessage, TimedMessages,
};

pub const READ_TIMEOUT: Duration = Duration::from_secs(60);
pub const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Open or begin a connection to an inbound or outbound peer.
pub trait ConnectionExt: Send + Sync {
    /// Facilitate a version handshake on a potentially open connection. One use for this method is
    /// to begin a handshake over an existing Socks5 proxy.
    fn handshake(
        self,
        tcp_stream: TcpStream,
        timeout_params: TimeoutParams,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error>;

    /// Listen for inbound connections on the specified socket address.
    fn listen(
        self,
        bind: impl Into<SocketAddr>,
        timeout_params: TimeoutParams,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error>;

    /// Open an outbound connection to the specified socket address.
    fn open_connection(
        self,
        to: impl Into<SocketAddr>,
        timeout_params: TimeoutParams,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error>;
}

impl ConnectionExt for ConnectionConfig {
    fn open_connection(
        self,
        to: impl Into<SocketAddr>,
        timeout_params: TimeoutParams,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error> {
        let tcp_stream = TcpStream::connect(to.into())?;
        tcp_stream.set_read_timeout(timeout_params.read)?;
        tcp_stream.set_write_timeout(timeout_params.write)?;
        Self::handshake(self, tcp_stream, timeout_params)
    }

    fn listen(
        self,
        bind: impl Into<SocketAddr>,
        timeout_params: TimeoutParams,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error> {
        let listener = TcpListener::bind(bind.into())?;
        let (tcp_stream, _) = listener.accept()?;
        tcp_stream.set_read_timeout(timeout_params.read)?;
        tcp_stream.set_write_timeout(timeout_params.write)?;
        Self::handshake(self, tcp_stream, timeout_params)
    }

    fn handshake(
        self,
        mut tcp_stream: TcpStream,
        timeout_params: TimeoutParams,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error> {
        let system_time = SystemTime::now();
        let unix_time = system_time
            .duration_since(UNIX_EPOCH)
            .expect("time cannot go backwards.");
        let nonce = random();
        let version = self.build_our_version(unix_time, nonce);
        let mut write_half = WriteTransport::V1(self.network().default_network_magic());
        let mut read_half = ReadTransport::V1(self.network().default_network_magic());
        write_half.write_message(NetworkMessage::Version(version), &mut tcp_stream)?;
        let (handshake, messages) = match read_half.read_message(&mut tcp_stream)? {
            Some(message) => self.start_handshake(unix_time, message, nonce)?,
            None => return Err(Error::MissingVersion),
        };
        for message in messages {
            write_half.write_message(message, &mut tcp_stream)?;
        }
        loop {
            if let Some(message) = read_half.read_message(&mut tcp_stream)? {
                match handshake.negotiate(message)? {
                    Some((completed_handshake, responses)) => {
                        for response in responses {
                            write_half.write_message(response, &mut tcp_stream)?;
                        }
                        let timed_messages = Arc::new(Mutex::new(TimedMessages::new()));
                        let outbound_ping = Arc::new(Mutex::new(OutboundPing::LastReceived {
                            then: Instant::now(),
                        }));
                        let CompletedHandshake {
                            feeler,
                            their_preferences,
                        } = completed_handshake;
                        let live_connection = ConnectionMetrics {
                            feeler,
                            their_preferences: Arc::clone(&their_preferences),
                            timed_messages: Arc::clone(&timed_messages),
                            start_time: Instant::now(),
                            outbound_ping_state: Arc::clone(&outbound_ping),
                        };
                        let (tx, rx) = mpsc::channel();
                        let tcp_stream_clone = tcp_stream.try_clone()?;
                        let open_writer = OpenWriter {
                            tcp_stream: tcp_stream_clone,
                            transport: write_half,
                            receiver: rx,
                            outbound_ping_state: Arc::clone(&outbound_ping),
                            ping_interval: timeout_params.ping_interval,
                        };
                        let write_handle =
                            std::thread::spawn(move || open_writer.maintain_connection());
                        let writer = ConnectionWriter {
                            sender: tx,
                            task_handle: write_handle,
                        };
                        let reader = ConnectionReader {
                            tcp_stream,
                            transport: read_half,
                            their_preferences,
                            timed_messages,
                            outbound_ping_state: Arc::clone(&outbound_ping),
                        };
                        return Ok((writer, reader, live_connection));
                    }
                    None => continue,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutParams {
    read: Option<Duration>,
    write: Option<Duration>,
    ping_interval: Duration,
}

impl TimeoutParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn read_timeout(&mut self, timeout: Duration) {
        self.read = Some(timeout)
    }

    pub fn write_timeout(&mut self, timeout: Duration) {
        self.write = Some(timeout)
    }

    pub fn ping_interval(&mut self, every: Duration) {
        self.ping_interval = every
    }
}

impl Default for TimeoutParams {
    fn default() -> Self {
        Self {
            read: Some(READ_TIMEOUT),
            write: None,
            ping_interval: PING_INTERVAL,
        }
    }
}

/// Send messages to an open connection.
#[derive(Debug)]
pub struct ConnectionWriter {
    sender: mpsc::Sender<NetworkMessage>,
    task_handle: JoinHandle<Result<(), io::Error>>,
}

impl ConnectionWriter {
    /// Send a network message to this peer. Errors indicate that the connection is terminated and
    /// no further messages will succeed.
    #[allow(clippy::result_large_err)]
    pub fn send_message(
        &self,
        network_message: NetworkMessage,
    ) -> Result<(), SendError<NetworkMessage>> {
        self.sender.send(network_message)
    }

    /// In the event of a failed message, investigate IO related failures if the connection was not
    /// closed gracefully.
    pub fn take_errors(self) -> Option<io::Error> {
        self.task_handle.join().ok()?.err()
    }
}

#[derive(Debug)]
struct OpenWriter {
    tcp_stream: TcpStream,
    transport: WriteTransport,
    receiver: mpsc::Receiver<NetworkMessage>,
    outbound_ping_state: Arc<Mutex<OutboundPing>>,
    ping_interval: Duration,
}

impl OpenWriter {
    fn maintain_connection(mut self) -> Result<(), std::io::Error> {
        loop {
            let message = self.receiver.recv_timeout(Duration::from_secs(1));
            match message {
                Ok(network_message) => {
                    self.transport
                        .write_message(network_message, &mut self.tcp_stream)?;
                }
                Err(e) => match e {
                    mpsc::RecvTimeoutError::Timeout => continue,
                    _ => return Ok(()),
                },
            }
            if let Ok(mut ping) = self.outbound_ping_state.lock() {
                match *ping {
                    OutboundPing::LastReceived { then } => {
                        if then.elapsed() > self.ping_interval {
                            let nonce: u64 = random();
                            self.transport
                                .write_message(NetworkMessage::Ping(nonce), &mut self.tcp_stream)?;

                            *ping = OutboundPing::Waiting {
                                nonce,
                                then: Instant::now(),
                            }
                        }
                    }
                    OutboundPing::Waiting { nonce: _, then: _ } => continue,
                }
            }
            // Do traffic shaping or gossip addrs
        }
    }
}

/// Read messages from an open connection.
#[derive(Debug)]
pub struct ConnectionReader {
    tcp_stream: TcpStream,
    transport: ReadTransport,
    their_preferences: Arc<Preferences>,
    timed_messages: Arc<Mutex<TimedMessages>>,
    outbound_ping_state: Arc<Mutex<OutboundPing>>,
}

impl ConnectionReader {
    /// Wait for a message while blocking the current thread of execution.
    pub fn read_message(&mut self) -> Result<Option<NetworkMessage>, Error> {
        let message = self.transport.read_message(&mut self.tcp_stream)?;
        if let Some(message) = &message {
            match message {
                NetworkMessage::SendHeaders => self.their_preferences.prefers_header_announcment(),
                NetworkMessage::SendCmpct(cmpct) => {
                    self.their_preferences.prefers_cmpct(cmpct.version)
                }
                NetworkMessage::Block(_) => {
                    if let Ok(mut lock) = self.timed_messages.lock() {
                        lock.add_single(TimedMessage::Block, Instant::now());
                    }
                }
                NetworkMessage::Headers(_) => {
                    if let Ok(mut lock) = self.timed_messages.lock() {
                        lock.add_single(TimedMessage::BlockHeaders, Instant::now());
                    }
                }
                NetworkMessage::CFilter(_) => {
                    if let Ok(mut lock) = self.timed_messages.lock() {
                        lock.add_single(TimedMessage::CFilters, Instant::now());
                    }
                }
                NetworkMessage::Addr(list) => {
                    if let Ok(mut lock) = self.timed_messages.lock() {
                        lock.add_many(TimedMessage::Addr, list.0.len(), Instant::now());
                    }
                }
                NetworkMessage::AddrV2(list) => {
                    if let Ok(mut lock) = self.timed_messages.lock() {
                        lock.add_many(TimedMessage::Addr, list.0.len(), Instant::now());
                    }
                }
                NetworkMessage::Pong(pong) => {
                    // There are bigger problems with this connection if the lock fails, so it is
                    // okay to ignore the nonce.
                    if let Ok(mut lock) = self.outbound_ping_state.lock() {
                        if let OutboundPing::Waiting { nonce, then: _ } = *lock {
                            if *pong == nonce {
                                *lock = OutboundPing::LastReceived {
                                    then: Instant::now(),
                                };
                            }
                        }
                    }
                }
                _ => (),
            }
        }
        Ok(message)
    }
}

#[derive(Debug)]
enum WriteTransport {
    V1(Magic),
}

impl WriteTransport {
    fn write_message<W: Write>(
        &mut self,
        network_message: NetworkMessage,
        writer: &mut W,
    ) -> Result<(), io::Error> {
        match self {
            WriteTransport::V1(magic) => {
                let raw = RawNetworkMessage::new(*magic, network_message);
                let bytes = consensus::serialize(&raw);
                writer.write_all(&bytes)?;
                writer.flush()?;
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
enum ReadTransport {
    V1(Magic),
}

impl ReadTransport {
    fn read_message<R: Read>(&mut self, reader: &mut R) -> Result<Option<NetworkMessage>, Error> {
        match self {
            ReadTransport::V1(magic) => {
                let mut message_buf = vec![0; 24];
                reader.read_exact(&mut message_buf)?;
                let message_header = consensus::deserialize::<V1MessageHeader>(&message_buf)?;
                if message_header.magic != *magic {
                    return Err(Error::UnexpectedMagic(message_header.magic));
                }
                // Will panic on machines with under 32 bit precision
                let mut contents_buf = vec![0; message_header.length as usize];
                reader.read_exact(&mut contents_buf)?;
                message_buf.extend_from_slice(&contents_buf);
                let message = consensus::deserialize::<RawNetworkMessage>(&message_buf)?;
                Ok(Some(message.into_payload()))
            }
        }
    }
}

/// Errors that occur during a connection.
#[derive(Debug)]
pub enum Error {
    /// A message was not deserialized according to protocol specifications.
    Deserialize(DeserializeError),
    /// An IO related error occurred.
    Io(io::Error),
    /// An error occurred during the version handshake.
    Handshake(handshake::Error),
    /// The peer sent magic that does not belong to the current network.
    UnexpectedMagic(Magic),
    /// The peer did not send a version message.
    MissingVersion,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Deserialize(d) => d.fmt(f),
            Error::Io(e) => e.fmt(f),
            Error::Handshake(e) => e.fmt(f),
            Error::UnexpectedMagic(magic) => write!(f, "unexpected network magic: {magic}"),
            Error::MissingVersion => write!(f, "missing version message."),
        }
    }
}

impl std::error::Error for Error {}

impl From<DeserializeError> for Error {
    fn from(value: DeserializeError) -> Self {
        Self::Deserialize(value)
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<handshake::Error> for Error {
    fn from(value: handshake::Error) -> Self {
        Self::Handshake(value)
    }
}
