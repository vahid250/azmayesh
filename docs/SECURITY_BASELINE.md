# Security baseline and known gaps

## Implemented in this branch
- Pydantic settings require an application secret of at least 32 characters.
- Telegram Mini App HMAC validation uses the documented WebAppData derivation, constant-time digest comparison, required user/auth_date fields, and a bounded age window.
- CORS origins are explicit and credentials are disabled.
- Sensitive configuration fields are represented as encrypted-at-rest columns; Fernet helper authenticates ciphertext.
- Config issuance endpoint fails closed (503).

## Deliberately not implemented yet
- Durable login sessions, revocation, CSRF strategy, and user upsert.
- Payment verification, order ledger, quotas, idempotency, refund accounting, and entitlement policy.
- Global transactional IP allocation with database uniqueness/locking.
- WireGuard peer provisioning and confirmation/rollback.
- Xray/VLESS API provisioning and server reconciliation.
- Migrations (Alembic), integration tests, deployment manifests, observability, rate limiting, abuse controls, and backup/restore drills.
- Telegram bot process and Mini App frontend integration.

Do not deploy this branch as a customer-facing service. Do not enable config issuance until every prerequisite above is implemented and verified.
