# R&MA Stage 10D — API and Service Segmentation

Status: design baseline for an isolated CI lab. This document does not deploy or modify production infrastructure.

## Objective

Build and verify explicit network and identity boundaries between public ingress, user API, private control plane, administration, monitoring, VPN data plane, and database services. A successful request through one approved path must not imply reachability to adjacent zones.

## Non-goals

- No production deployment, DNS, firewall, cloud network, database, credentials, or customer traffic changes.
- No arbitrary shell/SQL execution through an admin interface.
- No assumption that a successful namespace test proves cloud-provider or production security.
- No direct management path from user VPN traffic to admin, database, CI, or host services.

## Proposed trust zones

| Zone | Purpose | Allowed inbound |
|---|---|---|
| Public edge | TLS termination, request filtering | Public client traffic only |
| User API | Authenticated user-facing requests | Edge-to-API only |
| Control plane | Account, subscription, policy and node orchestration | Explicit API service identity only |
| Admin plane | Privileged management API | Dedicated authenticated admin path only |
| Monitoring | Health checks, metrics and alerts | Explicit scrape/event paths; read-only by default |
| VPN data plane | User packet forwarding | VPN transport and narrowly scoped node management |
| Database | Durable account, entitlement and quota state | Control-plane database identity only |

## Mandatory network policy

- Default deny between all zones.
- Public edge may reach only the public API listener.
- User API may reach only explicitly declared control-plane endpoints.
- Admin plane must use a separate listener and service identity; user API credentials cannot call admin endpoints.
- Control plane may reach only the required database endpoint and registered VPN-node management endpoint.
- VPN data-plane nodes cannot initiate database, admin-plane, CI, or peer-node management connections.
- Monitoring may read health/metrics endpoints but cannot invoke administrative mutations.
- No public route to database, metrics, SSH, or admin listeners.
- Denied flows must be logged without recording secrets or full sensitive payloads.

## Identity and authorization policy

- Network location alone never authorizes a request.
- Every service-to-service call uses a distinct workload identity with short-lived credentials where supported.
- The API validates token signature, issuer, audience, expiry and required claims before resolving account identity.
- Admin routes use separate roles and stronger authentication than user routes.
- Admin actions are typed allowlisted operations; never accept raw shell, SQL, arbitrary URLs, or arbitrary service names from the browser.
- Mutating admin operations require policy validation, idempotency, audit records and risk-based approval.
- Monitoring endpoints are read-only and return sanitized health state.

## Fail-closed behavior

- Missing or invalid workload identity: reject the request.
- Unknown route or unregistered service: deny.
- Policy engine unavailable: reject mutations; do not silently bypass authorization.
- Database unavailable: quota/accounting-sensitive operations fail closed.
- Monitoring unavailable: dashboard reports UNKNOWN/STALE, never GREEN.
- A failed health probe must not automatically restart or shut down VPN nodes.

## CI acceptance plan (Stage 10D)

The disposable Linux namespace lab must prove both positive and negative cases:

1. Edge-to-user-API approved path succeeds.
2. Edge-to-database and edge-to-admin paths are denied.
3. User API-to-approved-control-plane path succeeds.
4. User API-to-admin and user API-to-database direct paths are denied.
5. Control-plane-to-database approved path succeeds.
6. VPN data-plane-to-database, admin, CI and peer-management paths are denied.
7. Admin plane can reach only the explicit admin API and approved control-plane management endpoint.
8. Monitoring can read health endpoints but cannot invoke mutation endpoints.
9. Unknown destination ports and unregistered service identities are denied.
10. Policy reset/rebuild restores default-deny rules without opening public egress.
11. Failure of identity/policy dependency rejects mutations.
12. Health-state mapping distinguishes HEALTHY, DEGRADED, DOWN and UNKNOWN/STALE.

Each test must record the attempted source zone, destination zone, protocol/port, expected result, actual result, and relevant firewall counter. The test must run in disposable namespaces and must not change host firewall rules.

## Admin dashboard dependency

The future R&MA admin dashboard will consume a dedicated read-only monitoring API. It will not query PostgreSQL directly and will not share credentials with the user API or mutation worker. Each component indicator will include status, last successful probe time, freshness, and a short reason. A stale/missing signal maps to UNKNOWN, not GREEN.

The wallet area is explicitly out of scope and must not be reintroduced into the admin navigation or monitoring inventory.

## Known Stage 10C boundary

Stage 10C passed Q36–Q42 on disposable PostgreSQL. Its identity-scoped quota wrapper still depends on the trusted API verifying JWT claims before calling it. The database cannot infer that caller-supplied issuer/subject values were cryptographically verified. Stage 10D must therefore establish the service identity and network path around that trusted API; it does not turn the SQL wrapper into a JWT verifier.

## Exit criteria

Stage 10D is not complete until the namespace tests above pass, the CI artifact contains the full allow/deny matrix, and the API/admin/monitoring service identities and network paths are documented. No production rollout is implied by passing these lab tests.
