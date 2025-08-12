# Facilitated Bitcoin Peer-to-Peer Messaging

Two bitcoin nodes may exchange a number of messages during the lifetime of a connection, however most of them are related to negotiating services and protocol messages. This crate aims to automate this process, among other quality of life improvements. With the introduction of encrypted messaging over the Bitcoin network, and probable traffic shaping in the near future, connections between two bitcoin peers is made even more complex.

## Goals

- Automate version handshakes when creating inbound or outbound connections
- Hide encryption as an implementation detail
- Automate traffic shaping, pings, and address gossip
- Provide a number of validation extensions, so easily assess a peer
- Maintain connection metrics and metadata to assess a peer

