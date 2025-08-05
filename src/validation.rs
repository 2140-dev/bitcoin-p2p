use bitcoin::block::HeaderExt;
use p2p::message::NetworkMessage;

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
            NetworkMessage::Addr(addr) => addr.0.len() > MAX_INV_SIZE,
            NetworkMessage::AddrV2(addr) => addr.0.len() > MAX_INV_SIZE,
            NetworkMessage::Inv(inv) => inv.0.len() > MAX_INV_SIZE,
            NetworkMessage::GetData(inv) => inv.0.len() > MAX_INV_SIZE,
            NetworkMessage::GetBlocks(getblocks) => {
                getblocks.locator_hashes.len() > MAX_LOCATOR_HASHES
            }
            NetworkMessage::GetHeaders(getheaders) => {
                getheaders.locator_hashes.len() > MAX_LOCATOR_HASHES
            }
            NetworkMessage::Alert(alert) => !alert.is_final_alert(),
            _ => false,
        }
    }

    fn is_malformed(&self) -> bool {
        match self {
            NetworkMessage::Headers(headers) => {
                !(headers
                    .iter()
                    .zip(headers.iter().skip(1))
                    .all(|(first, second)| first.block_hash().eq(&second.prev_blockhash))
                    && !headers.iter().any(|header| {
                        let target = header.target();
                        let valid_pow = header.validate_pow(target);
                        valid_pow.is_err()
                    }))
            }
            _ => false,
        }
    }
}
