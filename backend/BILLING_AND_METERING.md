# R&MA billing, entitlement, and usage-metering boundary

## Implemented in the experimental branch

- Plan rows are operator-managed. No commercial prices, currencies, quotas, or trial allowances are seeded by this code.
- Creating an order snapshots the active plan's amount, currency, byte quota, device limit, and duration.
- `Idempotency-Key` is required for order creation and is scoped to the Telegram user.
- A verified settlement event can be recorded only through the internal `confirm_verified_payment` service. There is intentionally no public payment-confirmation endpoint.
- Settlement must match the order amount and currency exactly. One provider event and one successful settlement are accepted per order.
- A successful settlement creates exactly one entitlement.
- WireGuard configuration requests require a current entitlement with remaining quota and an available device slot.
- Usage reports are accepted only from a server-to-server HMAC-signed request. Browser/client-reported byte counters are not trusted.
- Usage event IDs are idempotent. Replayed reports do not debit quota twice.

## Payment integration is not enabled

No payment provider, fiat rail, crypto network, custody model, or jurisdictional payment route is selected here. The API must not treat a client screenshot, redirect, transaction hash, or user-submitted status as payment proof.

A future provider adapter must verify its webhook signature and independently confirm settlement before calling `confirm_verified_payment`. The adapter must also enforce provider-specific replay protection and reconcile provider event IDs.

## Usage metering request

Endpoint:

`POST /api/v1/internal/metering/usage`

Required headers:

- `X-RMA-Timestamp`: Unix timestamp in seconds (10 digits)
- `X-RMA-Event-Id`: stable unique identifier for this metering interval
- `X-RMA-Signature`: lowercase or uppercase hex HMAC-SHA256 digest

Body:

```json
{"client_id":123,"bytes_used":4096}
```

The shared secret must contain at least 32 characters and must be set only in the backend secret store and on the trusted VPN metering host. Never put it in the Mini App, browser JavaScript, Telegram messages, or Git.

The API resolves the supplied WireGuard client to its owning entitlement; callers cannot choose an arbitrary entitlement ID. The signed canonical message is the following UTF-8 text, with newline separators and no trailing newline:

```text
POST
/api/v1/internal/metering/usage
<timestamp>
<event_id>
<lowercase-hex-sha256-of-exact-request-body>
```

The signature is:

`hex(HMAC-SHA256(shared_secret, canonical_message))`

The host registry endpoint uses the same headers and canonical format with method `POST`, path `/api/v1/internal/metering/peers`, a fresh `registry-...` event ID, and request body `{"interface":"wg0"}` (with the actual configured interface name). Its response is delivered over HTTPS and contains only currently authorized public peer metadata; no private keys are returned.

Requests outside a five-minute clock window are rejected. The request body is limited to 4 KiB. The event ID is unique in the usage ledger. `bytes_used` must be the positive byte delta for that interval, not a cumulative counter. Retries must reuse the same event ID and exact body.

## Host-side WireGuard agent (experimental)

A host-side agent now exists under `backend/host_agent/`. It samples `wg show <interface> dump`, computes RX+TX byte deltas, stores counters and pending reports in a durable SQLite outbox, signs requests using the backend's HMAC format, retries with the same event ID/body, and removes a peer using `wg set <interface> peer <public-key> remove` on permanent authentication, validation, entitlement, or quota rejection. It also removes the peer after the configured bounded outage window (default 120 seconds) if no usage report is accepted or WireGuard counters cannot be sampled.

The agent now obtains its peer registry from the signed backend endpoint `POST /api/v1/internal/metering/peers`. The backend returns only registered peers whose entitlement is active, unexpired, and has remaining quota. The agent reconciles its previously managed peers with this list and removes peers that are no longer authorized. The systemd unit and environment example are templates only. The service has not been installed on a VPN host, and no shared secret has been generated or configured.

The agent is interval-based, not kernel-level byte-perfect shaping. A peer can transfer additional bytes between a sample and removal. The backend rejects an interval that exceeds remaining quota rather than accepting a partial interval, so the final interval may be under-recorded. Transient API/network failures are retried with a durable outbox, then fail closed by removing the peer after the configured outage window. If peer removal fails, the agent logs a critical error; monitoring and operator response are required.

## Important operational limit

The host agent is implemented and locally testable, but live quota enforcement remains unverified until the agent is installed on the actual VPN host, the backend and agent are configured for the same interface, permissions are reviewed, and exhaustion is tested against a dedicated test peer. It must not be treated as production-ready yet.

## Not production-ready

- No payment provider adapter or public webhook exists.
- No plan catalogue is seeded; plans must not be activated until pricing and legal/payment decisions are approved.
- No production VPN metering agent is deployed; automatic peer suspension is implemented in the experimental host agent but has not been verified on a real host.
- Production configuration issuance remains fail-closed.
