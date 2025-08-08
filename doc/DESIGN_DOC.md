# Bitcoin p2p facilitator

## Problems
- Automatated responses are not implemented
- Handshake is not implemented
- Their preferences are not recorded
- Message response rate is not logged

## Must happen autonomously (thread/task)
- Response to ping
- Ping
- Traffic shaping
- IP address gossip

## Potential shared state (Mutex)
- Message rate
- Pings
- Number of addrs received
- Protocol version and service flags

## State required in handshake
- Required version we need
- Required services we need
- A fee filter
- Addresses to gossip
- Services they prefer
- Nonce (ingoing/outgoing)
- Conditional messages after version
- Conditional messages after verack
