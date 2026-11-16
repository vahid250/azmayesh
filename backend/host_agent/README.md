# R&MA WireGuard host metering agent

This process runs on the actual VPN host, never in Cloudflare Workers or a browser. It samples server-side counters, sends byte deltas to the HMAC-authenticated backend endpoint, and removes a peer from the live interface when the backend returns HTTP 404 or 409.

## Security boundary
- The backend and host must receive the same random shared secret (minimum 32 characters) through an operator-managed secret store. Never commit it or put it in the Mini App, bot, peer registry, or logs.
- The API URL must use HTTPS. Client-reported counters are never accepted.
- The peer registry maps WireGuard public keys to backend client IDs. It contains no private keys and must be maintained by the trusted provisioning workflow.
- Run under a dedicated OS account with narrowly scoped permission to read counters and remove peers. Protect the registry and SQLite state from untrusted writes.
- SQLite keeps a durable outbox. Retries reuse the exact body and event ID; a baseline is not advanced while a report is pending.
- HTTP 404/409 causes peer removal. Other HTTP statuses and network errors retain the pending report for retry.

## Operating assumptions and limitations
1. Start the agent before enabling customer peers. The first sample is charged from zero.
2. Run exactly one agent per WireGuard interface.
3. Polling is interval-based, not kernel-level byte-perfect shaping. Traffic can continue between a sample and peer removal.
4. If counters decrease after an interface/host restart, the new counter value is counted as a fresh delta.
5. Only peers in the trusted registry are metered.
6. The backend currently rejects a report that exceeds remaining quota rather than accepting a partial interval. The last interval can therefore be under-recorded; the peer is still removed.
7. If wg peer removal fails, a critical error is logged and operator intervention is required. No successful suspension is claimed.

## Peer registry
Create /etc/rma/peers.json through the trusted provisioning system:
    
    {"peers":[{"client_id":123,"public_key":"BASE64_WIREGUARD_PUBLIC_KEY"}]}

Do not place private keys in this file.

## Environment
- RMA_API_BASE_URL: HTTPS backend origin
- RMA_METERING_SHARED_SECRET: out-of-band secret, never committed
- RMA_WG_INTERFACE: interface name, default wg0
- RMA_WG_PEERS_FILE: registry path
- RMA_METERING_STATE_DB: durable SQLite path
- RMA_POLL_INTERVAL_SECONDS: 5-300 seconds, default 15
- RMA_LOG_LEVEL: default INFO

## Operator-run installation outline
1. Install Python 3.12+ and wireguard-tools on the VPN host.
2. Copy this directory to /opt/rma/host_agent; create a dedicated service account and protected registry/state directories.
3. Configure /etc/rma/metering.env with mode 0600.
4. Install the supplied systemd unit only after reviewing the host-specific wg/netlink permission model.
5. Start and verify the agent before enabling customer peers.
6. Test exhaustion using a dedicated test entitlement and test peer before customer rollout.

No service was installed, no secret was generated, and no VPN host was contacted by this change.
