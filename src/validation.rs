use bitcoin::p2p::message::NetworkMessage;

const MAX_INV_SIZE: usize = 50_000;
const MAX_LOCATOR_HASHES: usize = 101;

/// Validate messages from peers.
pub trait ValidationExt {
    /// This message is only involved in version negotiation.
    fn is_handshake_message(&self) -> bool;
    /// Is a message valid but discouraged to send.
    fn is_discouraged(&self) -> bool;
    /// Is the data present in a message invalid.
    fn is_malformed(&self) -> bool;
}

impl ValidationExt for NetworkMessage {
    fn is_handshake_message(&self) -> bool {
        matches!(
            self,
            NetworkMessage::Verack
                | NetworkMessage::Version(_)
                | NetworkMessage::SendAddrV2
                | NetworkMessage::WtxidRelay
        )
    }

    fn is_discouraged(&self) -> bool {
        if matches!(
            self,
            NetworkMessage::FilterClear
                | NetworkMessage::FilterLoad(_)
                | NetworkMessage::FilterAdd(_)
                | NetworkMessage::MemPool
        ) {
            return true;
        }
        match self {
            NetworkMessage::Addr(addr) => addr.len() > MAX_INV_SIZE,
            NetworkMessage::AddrV2(addr) => addr.len() > MAX_INV_SIZE,
            NetworkMessage::Inv(inv) => inv.len() > MAX_INV_SIZE,
            NetworkMessage::GetData(inv) => inv.len() > MAX_INV_SIZE,
            NetworkMessage::GetBlocks(getblocks) => {
                getblocks.locator_hashes.len() > MAX_LOCATOR_HASHES
            }
            NetworkMessage::GetHeaders(getheaders) => {
                getheaders.locator_hashes.len() > MAX_LOCATOR_HASHES
            }
            _ => false,
        }
    }

    fn is_malformed(&self) -> bool {
        false
    }
}

macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl bitcoin::consensus::Encodable for $thing {
            #[inline]
            fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, bitcoin::io::Error> {
                let mut len = 0;
                $(len += self.$field.consensus_encode(w)?;)+
                Ok(len)
            }
        }

        impl bitcoin::consensus::Decodable for $thing {

            #[inline]
            fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, bitcoin::consensus::encode::Error> {
                Ok($thing {
                    $($field: bitcoin::consensus::Decodable::consensus_decode_from_finite_reader(r)?),+
                })
            }

            #[inline]
            fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<$thing, bitcoin::consensus::encode::Error> {
                let mut r = bitcoin::io::Read::take(r, bitcoin::consensus::encode::MAX_VEC_SIZE as u64);
                Ok($thing {
                    $($field: bitcoin::consensus::Decodable::consensus_decode(&mut r)?),+
                })
            }
        }
    );
}
pub(crate) use impl_consensus_encoding;
