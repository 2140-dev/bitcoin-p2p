use std::{
    fmt::Display,
    hash::{DefaultHasher, Hash, Hasher},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::SystemTime,
};

use bitcoin::Network;

const BITCOIN_SEEDS: [&str; 9] = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me",
    "dnsseed.bitcoin.dashjr.org",
    "seed.bitcoinstats.com",
    "seed.bitcoin.jonasschnelli.ch",
    "seed.btc.petertodd.org",
    "seed.bitcoin.sprovoost.nl",
    "dnsseed.emzy.de",
    "seed.bitcoin.wiz.biz",
];

const SIGNET_SEEDS: [&str; 2] = [
    "seed.signet.bitcoin.sprovoost.nl",
    "seed.signet.achownodes.xyz",
];

const LOCAL_HOST: &str = "0.0.0.0:0";
const HEADER_BYTES: usize = 12;

const RECURSIVE_FLAGS: [u8; 2] = [
    0x01, 0x00, // Default flags with recursive resolver
];

const QTYPE: [u8; 4] = [
    0x00, 0x01, // QType: A Record
    0x00, 0x01, // IN
];

const COUNTS: [u8; 6] = [
    0x00, 0x00, // ANCOUNT
    0x00, 0x00, // NSCOUNT
    0x00, 0x00, // ARCOUNT
];

const A_RECORD: u16 = 0x01;
const A_CLASS: u16 = 0x01;
const EXPECTED_RDATA_LEN: u16 = 0x04;

/// Query DNS seeds to find potential peers.
pub trait DnsQueryExt {
    /// Return as many potential peers as possible, potentially zero.
    fn query_dns_seeds(&self, resolver: impl Into<SocketAddr>) -> Vec<IpAddr>;
}

impl DnsQueryExt for Network {
    fn query_dns_seeds(&self, resolver: impl Into<SocketAddr>) -> Vec<IpAddr> {
        let resolver = resolver.into();
        match self {
            Network::Bitcoin => do_dns_query(&BITCOIN_SEEDS, resolver),
            Network::Signet => do_dns_query(&SIGNET_SEEDS, resolver),
            _ => Vec::new(),
        }
    }
}

fn do_dns_query(seeds: &[&str], resolver: SocketAddr) -> Vec<IpAddr> {
    let mut vals = Vec::new();
    for seed in seeds {
        let query = DnsQuery::new(seed, resolver);
        if let Ok(hosts) = query.lookup() {
            vals.extend(&hosts);
        }
    }
    vals
}

#[derive(Debug)]
struct DnsQuery {
    message_id: [u8; 2],
    message: Vec<u8>,
    question: Vec<u8>,
    resolver: SocketAddr,
}

impl DnsQuery {
    fn new(seed: &str, dns_resolver: SocketAddr) -> Self {
        // Build a header
        let message_id = rand_bytes();
        let mut message = message_id.to_vec();
        message.extend(RECURSIVE_FLAGS);
        message.push(0x00); // QDCOUNT
        message.push(0x01); // QDCOUNT
        message.extend(COUNTS);
        let mut question = encode_qname(seed, None);
        question.extend(QTYPE);
        message.extend_from_slice(&question);
        Self {
            message_id,
            message,
            question,
            resolver: dns_resolver,
        }
    }

    fn lookup(self) -> Result<Vec<IpAddr>, Error> {
        let sock = std::net::UdpSocket::bind(LOCAL_HOST)?;
        sock.connect(self.resolver)?;
        sock.send(&self.message)?;
        let mut response_buf = [0u8; 512];
        let (amt, _src) = sock.recv_from(&mut response_buf)?;
        if amt < HEADER_BYTES {
            return Err(Error::MalformedHeader);
        }
        let ips = self.parse_message(&response_buf[..amt])?;
        Ok(ips)
    }

    fn parse_message(&self, mut response: &[u8]) -> Result<Vec<IpAddr>, Error> {
        let mut ips = Vec::with_capacity(10);
        let mut buf: [u8; 2] = [0, 0];
        response.read_exact(&mut buf)?; // Read 2 bytes
        if self.message_id != buf {
            return Err(Error::MessageId);
        }
        // Read flags and ignore
        response.read_exact(&mut buf)?; // Read 4 bytes
        response.read_exact(&mut buf)?; // Read 6 bytes
        let _qdcount = u16::from_be_bytes(buf);
        response.read_exact(&mut buf)?; // Read 8 bytes
        let ancount = u16::from_be_bytes(buf);
        response.read_exact(&mut buf)?; // Read 10 bytes
        let _nscount = u16::from_be_bytes(buf);
        response.read_exact(&mut buf)?; // Read 12 bytes
        let _arcount = u16::from_be_bytes(buf);
        // The question should be repeated back to us
        let mut buf: Vec<u8> = vec![0; self.question.len()];
        response.read_exact(&mut buf)?;
        if self.question != buf {
            return Err(Error::Question);
        }
        for _ in 0..ancount {
            let mut buf: [u8; 2] = [0, 0];
            // Read the compressed NAME field of the record and ignore
            response.read_exact(&mut buf)?;
            // Read the TYPE
            response.read_exact(&mut buf)?;
            let atype = u16::from_be_bytes(buf);
            // Read the CLASS
            response.read_exact(&mut buf)?;
            let aclass = u16::from_be_bytes(buf);
            let mut buf: [u8; 4] = [0, 0, 0, 0];
            // Read the TTL
            response.read_exact(&mut buf)?;
            let _ttl = u32::from_be_bytes(buf);
            let mut buf: [u8; 2] = [0, 0];
            // Read the RDLENGTH
            response.read_exact(&mut buf)?;
            let rdlength = u16::from_be_bytes(buf);
            // Read RDATA
            let mut rdata: Vec<u8> = vec![0; rdlength as usize];
            response.read_exact(&mut rdata)?;
            if atype == A_RECORD && aclass == A_CLASS && rdlength == EXPECTED_RDATA_LEN {
                ips.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )))
            }
        }
        Ok(ips)
    }
}

#[derive(Debug)]
enum Error {
    MessageId,
    MalformedHeader,
    Question,
    Io(std::io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Question => write!(f, "question section was not repeated back."),
            Self::MalformedHeader => write!(f, "the response header was undersized."),
            Self::MessageId => write!(f, "the response ID does not match the request."),
            Self::Io(io) => write!(f, "std::io error: {io}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

impl std::error::Error for Error {}

fn encode_qname<S: AsRef<str>>(hostname: S, filter: Option<S>) -> Vec<u8> {
    let mut qname = Vec::new();
    let str = hostname.as_ref();
    if let Some(filter) = filter {
        let prefix = filter.as_ref();
        qname.push(prefix.len() as u8);
        qname.extend(prefix.as_bytes());
    }
    for label in str.split(".") {
        qname.push(label.len() as u8);
        qname.extend(label.as_bytes());
    }
    qname.push(0x00);
    qname
}

fn rand_bytes() -> [u8; 2] {
    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    let mut hash = hasher.finish();
    hash ^= hash << 13;
    hash ^= hash >> 17;
    hash ^= hash << 5;
    hash.to_be_bytes()[..2].try_into().expect("trivial cast")
}
