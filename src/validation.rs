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
        false
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::BlockHash;
    use p2p::{
        ProtocolVersion, message::NetworkMessage,
        message_network::Alert,
    };

    use crate::validation::ValidationExt;

    const MALFORMED_BLOCKHASHES: [BlockHash; 102] = [BlockHash::from_byte_array([0; 32]); 102];

    #[test]
    fn test_validation_ext() {
        let verack = NetworkMessage::Verack;
        assert!(verack.is_handshake_message());
        let sendheaders = NetworkMessage::SendHeaders;
        assert!(!sendheaders.is_handshake_message());
        let final_alert = NetworkMessage::Alert(Alert::final_alert());
        assert!(!final_alert.is_discouraged());
        let mempool = NetworkMessage::MemPool;
        assert!(mempool.is_discouraged());
        let getdata = NetworkMessage::GetBlocks(p2p::message_blockdata::GetBlocksMessage {
            version: ProtocolVersion::WTXID_RELAY_VERSION,
            locator_hashes: MALFORMED_BLOCKHASHES.to_vec(),
            stop_hash: BlockHash::from_byte_array([0; 32]),
        });
        assert!(getdata.is_discouraged());
    }
}
