# R&MA Phase A — disposable namespace lab

This folder contains a Linux-only, isolated smoke-test topology.

## Files

- `phase-a-lab.sh`: creates/removes the five named network namespaces and their veth links.
- `traffic.py`: standard-library UDP sink and sender; no external Python packages.
- `phase-a-traffic-test.sh`: runs a shared-quota test for A+B and an independent-quota test for C.

## Safety

Run only in a disposable Linux VM. The scripts create no public egress route and do not edit the host firewall or production network. The setup script refuses namespace-name collisions. Cleanup removes only the lab namespaces.

## Run

```bash
sudo ./phase-a-lab.sh up
sudo ./phase-a-lab.sh status
sudo ./phase-a-traffic-test.sh
sudo ./phase-a-lab.sh down
```

The initial quota is 64 kbytes. A and B each attempt 30 UDP datagrams with 1200-byte payloads. A should fit within the cap; B should be constrained by the same named quota. C is tested against a separately reset quota and should deliver all 30 packets.

The test waits for an explicit UDP-sink ready file after the socket is bound, rather than relying only on a fixed startup delay. The receiver still has a bounded two-second run window.

The test deliberately uses broad packet-count acceptance bounds to detect shared-vs-independent behavior, not to certify exact quota byte accounting. UDP sink payload bytes are not the same accounting layer as nftables skb bytes. Exact boundary, packet overhead, bidirectional accounting, concurrency, TCP, MTU, and overshoot remain separate tests.

The `phase-a-static.yml` workflow checks Bash and Python syntax when Phase A files change. Static CI does not execute network namespaces or nftables rules.

A passing local smoke test is not a production approval.


## Stage 8 — durable usage ledger

- `quota-ledger.sql` stores quota periods and idempotent usage events in PostgreSQL.
- `record_quota_usage` atomically applies usage against the account-period cap.
- `phase-a-stage8-test.py` verifies duplicate-event handling, concurrent cap enforcement, restart persistence, and fail-closed behavior.

## Stage 9 — account lifecycle and entitlements

- `quota-account-lifecycle.sql` adds account status, quota plans, subscription windows, and audit events.
- `ensure_current_quota_period` provisions a UTC calendar-month quota from the active subscription without resetting an existing period.
- `record_account_quota_usage` resolves the active entitlement before recording usage.
- `phase-a-stage9-test.py` checks suspension/closure, expiry, monthly rollover, and plan changes.
- Authentication, payment verification, authorization-role hardening, and production deployment remain out of scope for this disposable CI stage.

## Stage 10 — defense-in-depth security architecture

- `STAGE10-SECURITY-ARCHITECTURE.md` defines the trust zones, network boundaries, least-privilege rules, threat-to-control matrix, and staged security acceptance criteria.
- Stage 10 is being developed on the isolated branch `security/phase-10-defense-in-depth`; it does not change the Phase A baseline branch or production infrastructure.
- Sub-stages 10B–10H will add trusted identity binding, database privilege hardening, service/network segmentation, VPN tenant isolation, CI/CD hardening, incident response, and independent review.
- No claim of complete intrusion prevention is made; the objective is to contain compromise and prevent lateral movement.


## Stage 10B — Identity binding and authorization boundary

Stage 10B introduces an issuer+subject to internal-account mapping in
`quota-identity-binding.sql`. The API gateway receives only EXECUTE on the
resolver function; it cannot read or mutate the mapping table. An untrusted
client role cannot execute the resolver. Unknown, revoked, wrong-issuer, and
suspended-account mappings fail closed.

The CI tests Q30–Q35 run against disposable PostgreSQL. They validate SQL
privileges and the identity-binding contract, **not** real JWT verification.
The trusted API must independently verify JWT signature, issuer, audience,
expiry, and other required claims before calling the resolver. The gateway
must not accept identity claims or account IDs from an untrusted request body.
A compromised gateway can still supply fabricated resolver arguments; this
stage is defense in depth, not proof of production authentication.

No production Neon project, credentials, or customer traffic is modified.


## Stage 10C — database privilege hardening

- `quota-db-hardening.sql` separates object ownership from runtime identities, removes PUBLIC and runtime table access, and exposes quota usage only through an identity-scoped SECURITY DEFINER wrapper.
- Forced row-level security scopes subscription, quota-period, quota-event, and audit rows to the wrapper's transaction-local account context. The custom setting is not an authentication credential; direct table access remains revoked.
- `phase-a-stage10c-test.py` verifies owner-role attributes, role membership boundaries, direct table/function denial, tenant RLS, and privilege-escalation rejection (Q36–Q42).
- CI uses a disposable PostgreSQL 16 service. No production database is modified. JWT verification remains the responsibility of the trusted API gateway.

## Stage 10D — stateful firewall revocation

- `phase-a-stage10d-stateful-revocation-test.py` opens a real TCP session across the disposable Edge → API route, proves data transfer, removes the exact NEW-flow allow rule, and applies a temporary revocation guard before the established-state accept rule.
- The test verifies both the already-established session and a fresh connection are blocked, with nftables drop-counter attribution. It writes a JSON evidence artifact.
- This is an isolated test of revocation-guard semantics. It does not yet integrate a production policy controller, automatic rule reconciliation, or conntrack invalidation into the application. No production firewall is modified.
