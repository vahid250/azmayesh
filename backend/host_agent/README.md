# R&MA WireGuard host metering agent

This process runs on the actual VPN host, never in Cloudflare Workers or a browser. It samples server-side counters, sends byte deltas to the HMAC-authenticated backend endpoint, and removes a peer from the live interface when the backend returns a permanent authentication or unknown-client rejection; quota/expiry removals are driven by the authoritative registry. A pending report is retried with the same event ID; if it remains unacknowledged for the configured outage window (default 120 seconds), the peer is removed to avoid indefinite unmetered traffic.

## Security boundary
- The backend and host must receive the same random shared secret (minimum 32 characters) through an operator-managed secret store. Never commit it or put it in the Mini App, bot, peer registry, or logs.
- The API URL must use HTTPS. Client-reported counters are never accepted.
- The agent retrieves peer IDs, public keys, and allowed IPs from the authenticated backend registry over HTTPS. No private keys are returned to the agent.
- Run under a dedicated OS account with only CAP_NET_ADMIN. That capability applies to the process's network namespace, not a single interface; production should isolate the VPN interface and agent in a dedicated network namespace/container. Protect the registry and SQLite state from untrusted writes.
- SQLite keeps a durable outbox. Retries reuse the exact body and event ID; a baseline is not advanced while a report is pending.
- Permanent usage-report rejections (HTTP 400, 401, 403, 404, 409, 410, or 422) quarantine the event in the durable local outbox for operator review and trigger immediate peer removal; they are not silently discarded or automatically retried. Transient HTTP errors and network errors retain the pending report for bounded retry; the peer is removed if no report is accepted, or the WireGuard counters cannot be sampled, before the outage window expires.

## Operating assumptions and limitations
- Registry snapshots reject duplicate assigned IPv4 addresses across active and revoked/suspended peers. IP reuse is intentionally not allowed in one snapshot: first complete revocation/removal and acknowledgement, then assign that address in a later registry cycle to avoid ambiguous source-IP guard ownership.

1. Start the agent before enabling customer peers. The first sample is charged from zero.
2. Run exactly one agent per WireGuard interface. The process holds a Linux `flock` singleton lock (default `/var/lib/rma-meter/agent.lock`, override with `RMA_HOST_AGENT_LOCK`) to prevent duplicate instances from reconciling concurrently. The API's WG_INTERFACE and the agent's RMA_WG_INTERFACE must identify the same interface.
3. Polling is interval-based, not kernel-level byte-perfect shaping. Traffic can continue between a sample and peer removal.
4. If counters decrease after an interface/host restart, the new counter value is counted as a fresh delta.
5. Only peers in the signed backend registry are managed and metered.
6. The backend records the measured final interval for audit, caps entitlement consumption at the purchased quota, and marks the entitlement exhausted. Traffic transferred between the last sample and peer removal can exceed the purchased allowance; this is interval-metering overshoot, not additional billed quota. The last interval can therefore be under-recorded; the peer is still removed.
7. If wg peer removal fails, a critical error is logged and operator intervention is required. No successful suspension is claimed.

## Automatic peer registry
The agent requests `POST /api/v1/internal/metering/peers` every polling cycle. The backend returns peers awaiting registration or already registered, plus explicit removal instructions for revoked, expired, exhausted, or suspended peers. The agent registers pending peers, acknowledges successful registration, removes unauthorized peers, and acknowledges revocation/suspension through the signed `POST /api/v1/internal/metering/peer-status` endpoint. No manually edited peer registry file is required.

The API may run on Cloudflare or another backend host; it does not execute local `wg` commands. The host agent on the VPN server receives pending peer instructions from the authenticated registry, applies them to its local interface, and acknowledges the result. Cloudflare Workers must never run this agent or execute `wg` commands.

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


## Immediate peer-source revocation firewall

The signed registry includes each removed peer's canonical IPv4 `/32` in `remove_peers.allowed_ips`. Before removing a revoked or suspended WireGuard peer, the agent inserts that source address into the pre-provisioned nftables set `inet rma_guard revoked_peer_sources`. The set must be referenced by `input` and `forward` drop rules placed before established-flow accepts, scoped to the WireGuard ingress interface. The agent acknowledges revocation only after the firewall guard and WireGuard peer removal succeed. Re-authorization installs the WireGuard peer first and removes the source guard second.

Required host firewall contract (operator-provisioned; the agent does not create or replace firewall policy):

- `table inet rma_guard`
- `set revoked_peer_sources { type ipv4_addr; }`
- An early `input` drop rule for `iifname "wg0" ip saddr @revoked_peer_sources`
- An early `forward` drop rule for `iifname "wg0" ip saddr @revoked_peer_sources`

Replace `wg0` with the exact configured interface. These rules must execute before any `ct state established,related accept`. The set is restored by the host firewall configuration at boot; the agent reasserts revoked entries from the signed registry on each successful reconciliation. No firewall rules are installed automatically by the agent.


The agent validates both pre-provisioned chains on every add/remove operation: each must contain the configured WireGuard ingress guard and have a base-chain hook priority of `-10` or earlier. Missing, late, or malformed guards prevent revocation ACK and prevent re-authorization from removing the block.

 
If the nftables contract is unavailable during revocation, the agent makes a best-effort immediate WireGuard peer removal as a fallback, marks the local peer disabled, and deliberately withholds the backend ACK. It retries the firewall source guard on subsequent registry polls; the backend state remains pending until both the guard and removal are confirmed. This fallback prevents new authenticated tunnel traffic but is not a substitute for the early firewall guard, which is required to terminate packets from any already tracked flow.
