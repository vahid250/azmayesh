# R&MA WireGuard host metering agent

This process runs on the actual VPN host, never in Cloudflare Workers or a browser. It samples server-side counters, sends byte deltas to the HMAC-authenticated backend endpoint, and removes a peer from the live interface when the backend returns a permanent authentication, validation, entitlement, or quota rejection. A pending report is retried with the same event ID; if it remains unacknowledged for the configured outage window (default 120 seconds), the peer is removed to avoid indefinite unmetered traffic.

## Security boundary
- The backend and host must receive the same random shared secret (minimum 32 characters) through an operator-managed secret store. Never commit it or put it in the Mini App, bot, peer registry, or logs.
- The API URL must use HTTPS. Client-reported counters are never accepted.
- The agent retrieves peer IDs, public keys, and allowed IPs from the authenticated backend registry over HTTPS. No private keys are returned to the agent.
- Run under a dedicated OS account with narrowly scoped permission to read counters and remove peers. Protect the registry and SQLite state from untrusted writes.
- SQLite keeps a durable outbox. Retries reuse the exact body and event ID; a baseline is not advanced while a report is pending.
- Permanent HTTP errors cause peer removal. Transient HTTP errors and network errors retain the pending report for bounded retry; the peer is removed if no report is accepted, or the WireGuard counters cannot be sampled, before the outage window expires.

## Operating assumptions and limitations
1. Start the agent before enabling customer peers. The first sample is charged from zero.
2. Run exactly one agent per WireGuard interface. The backend and agent must refer to the same host/interface in the current lab topology.
3. Polling is interval-based, not kernel-level byte-perfect shaping. Traffic can continue between a sample and peer removal.
4. If counters decrease after an interface/host restart, the new counter value is counted as a fresh delta.
5. Only peers in the signed backend registry are managed and metered.
6. The backend currently rejects a report that exceeds remaining quota rather than accepting a partial interval. The last interval can therefore be under-recorded; the peer is still removed.
7. If wg peer removal fails, a critical error is logged and operator intervention is required. No successful suspension is claimed.

## Automatic peer registry
The agent requests `POST /api/v1/internal/metering/peers` every polling cycle. The backend returns peers awaiting registration or already registered, plus explicit removal instructions for revoked, expired, exhausted, or suspended peers. The agent registers pending peers, acknowledges successful registration, removes unauthorized peers, and acknowledges revocation/suspension through the signed `POST /api/v1/internal/metering/peer-status` endpoint. No manually edited peer registry file is required.

The backend's current provisioning path runs `wg` locally. For the first real test, the backend process and this agent must therefore run on the same VPN host and use the same WireGuard interface. Cloudflare Workers must not run this agent or execute `wg` commands.

## Environment
- RMA_API_BASE_URL: HTTPS backend origin
- RMA_METERING_SHARED_SECRET: out-of-band secret, never committed
- RMA_WG_INTERFACE: interface name, default wg0
- RMA_METERING_STATE_DB: durable SQLite path
- RMA_POLL_INTERVAL_SECONDS: 5-300 seconds, default 15
- RMA_METERING_MAX_OUTAGE_SECONDS: disable the peer after this many seconds without an accepted usage report, default 120
- RMA_LOG_LEVEL: default INFO

## Operator-run installation outline
1. Install Python 3.12+ and wireguard-tools on the VPN host.
2. Copy this directory to /opt/rma/host_agent; create a dedicated service account and protected state directory.
3. Configure /etc/rma/metering.env with mode 0600.
4. Install the supplied systemd unit only after reviewing the host-specific wg/netlink permission model.
5. Start and verify the agent before enabling customer peers.
6. Test exhaustion using a dedicated test entitlement and test peer before customer rollout.

No service was installed, no secret was generated, and no VPN host was contacted by this change.
