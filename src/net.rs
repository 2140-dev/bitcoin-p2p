use std::{
    fmt::Display,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        mpsc::{self, SendError},
    },
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bitcoin::{
    consensus::{self, DeserializeError},
    key::rand::random,
};
use p2p::{
    Magic, NetworkExt,
    message::{NetworkMessage, RawNetworkMessage, V1MessageHeader},
};

use crate::{
    FeelerData, MessageRate, Preferences, TimedMessage, TimedMessages,
    handshake::{self, CompletedHandshake, ConnectionConfig},
};

pub trait ConnectionExt: Send + Sync {
    fn handshake(
        self,
        tcp_stream: TcpStream,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error>;

    fn listen(
        self,
        bind: impl Into<SocketAddr>,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error>;

    fn open_connection(
        self,
        to: impl Into<SocketAddr>,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error>;
}

impl ConnectionExt for ConnectionConfig {
    fn open_connection(
        self,
        to: impl Into<SocketAddr>,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error> {
        let tcp_stream = TcpStream::connect(to.into())?;
        Self::handshake(self, tcp_stream)
    }

    fn listen(
        self,
        bind: impl Into<SocketAddr>,
    ) -> Result<(ConnectionWriter, ConnectionReader, ConnectionMetrics), Error> {
        let listener = TcpListener::bind(bind.into())?;
        let (tcp_stream, _) = listener.accept()?;
        Self::handshake(self, tcp_stream)
    }

    fn handshake(
        self,
        mut tcp_stream: TcpStream,
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
                        let CompletedHandshake {
                            feeler,
                            their_preferences,
                        } = completed_handshake;
                        let live_connection = ConnectionMetrics {
                            feeler,
                            their_preferences: Arc::clone(&their_preferences),
                            timed_messages: Arc::clone(&timed_messages),
                        };
                        let (tx, rx) = mpsc::channel();
                        let tcp_stream_clone = tcp_stream.try_clone()?;
                        let open_writer = OpenWriter {
                            tcp_stream: tcp_stream_clone,
                            transport: write_half,
                            receiver: rx,
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
                        };
                        return Ok((writer, reader, live_connection));
                    }
                    None => continue,
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionMetrics {
    feeler: FeelerData,
    their_preferences: Arc<Preferences>,
    timed_messages: Arc<Mutex<TimedMessages>>,
}

impl ConnectionMetrics {
    pub fn feeler_data(&self) -> &FeelerData {
        &self.feeler
    }

    pub fn their_preferences(&self) -> &Preferences {
        self.their_preferences.as_ref()
    }

    pub fn message_rate(&self, timed_message: TimedMessage) -> Option<MessageRate> {
        let lock = self.timed_messages.lock().ok()?;
        Some(*lock.message_rate(timed_message))
    }
}

#[derive(Debug)]
pub struct ConnectionWriter {
    sender: mpsc::Sender<NetworkMessage>,
    task_handle: JoinHandle<Result<(), io::Error>>,
}

impl ConnectionWriter {
    #[allow(clippy::result_large_err)]
    pub fn send_message(
        &self,
        network_message: NetworkMessage,
    ) -> Result<(), SendError<NetworkMessage>> {
        self.sender.send(network_message)
    }

    pub fn take_errors(self) -> Option<io::Error> {
        self.task_handle.join().ok()?.err()
    }
}

#[derive(Debug)]
struct OpenWriter {
    tcp_stream: TcpStream,
    transport: WriteTransport,
    receiver: mpsc::Receiver<NetworkMessage>,
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
            // Do traffic shaping or send ping
        }
    }
}

#[derive(Debug)]
pub struct ConnectionReader {
    tcp_stream: TcpStream,
    transport: ReadTransport,
    their_preferences: Arc<Preferences>,
    timed_messages: Arc<Mutex<TimedMessages>>,
}

impl ConnectionReader {
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
                _ => (),
            }
        }
        Ok(message)
    }
}

#[derive(Debug)]
pub enum WriteTransport {
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
pub enum ReadTransport {
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

#[derive(Debug)]
pub enum Error {
    Deserialize(DeserializeError),
    Io(io::Error),
    Handshake(handshake::Error),
    UnexpectedMagic(Magic),
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
