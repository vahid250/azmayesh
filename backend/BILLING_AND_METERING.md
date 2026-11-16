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

Requests outside a five-minute clock window are rejected. The request body is limited to 4 KiB. The event ID is unique in the usage ledger. `bytes_used` must be the positive byte delta for that interval, not a cumulative counter. Retries must reuse the same event ID and exact body.

## Important operational limit

This endpoint records usage and enforces the entitlement quota in the ledger. It does not yet remove a WireGuard peer, throttle a tunnel, or stop packets on the VPN server when quota is exhausted. A future trusted server agent must treat a quota-exceeded response as a signal to enforce the limit on the actual VPN interface and report the enforcement result.

## Not production-ready

- No payment provider adapter or public webhook exists.
- No plan catalogue is seeded; plans must not be activated until pricing and legal/payment decisions are approved.
- No production VPN metering agent is deployed.
- No automatic peer suspension on quota exhaustion exists.
- Production configuration issuance remains fail-closed.
