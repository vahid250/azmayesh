# R&MA Stage 10 — Defense-in-Depth and Isolation Architecture

Status: architecture baseline; design only. No production infrastructure, credentials, DNS, firewall, database, or customer traffic is changed by this document.

## Security objective

Contain compromise rather than assume compromise is impossible. Every boundary must have an explicit identity, allowed traffic, owner, telemetry, and a deny-by-default rule. A breach of one component must not automatically grant access to another tenant, the control plane, the accounting database, signing keys, or other VPN nodes.

Security goals:
- Zero-trust access between services; authenticate and authorize every service-to-service request.
- Strong tenant isolation and least privilege.
- Separate management/control plane from VPN data plane.
- Fail closed when identity, policy, quota, or accounting dependencies are unavailable.
- Reproducible builds, reviewed changes, secret minimization, and auditable operations.
- Detect, contain, recover, and rotate credentials after suspected compromise.

No design can guarantee prevention of every intrusion. The acceptance goal is to reduce attack surface, prevent lateral movement, and limit blast radius.

## Proposed trust zones

### Z0 — User device / untrusted network
- Treat clients, local networks, DNS responses, and client-supplied account identifiers as untrusted.
- Never embed database, infrastructure, signing, or provider secrets in mobile clients.
- Device identity is not inferred from IP address alone.
- Client sends a short-lived authenticated session/token; server derives account identity from verified claims.

### Z1 — Public edge
- Terminate TLS at a hardened edge/reverse proxy.
- Apply DDoS controls, request-size limits, connection/time limits, bot/rate controls, and WAF rules where available.
- Expose only required public endpoints; no database, admin panel, SSH, metrics, or internal service ports.
- Use strict host/origin allowlists and safe security headers for browser surfaces.
- Edge filtering is supplemental; backend authorization remains mandatory.

### Z2 — API ingress / application gateway
- Validate token signature, issuer, audience, expiry, and required claims on every request.
- Enforce per-account and per-device rate limits, request schemas, replay/idempotency controls, and abuse limits.
- Derive account_id only from verified server-side identity mapping; ignore or reject client-supplied account_id for privileged operations.
- Route only to explicitly allowlisted internal services.
- No direct client-to-database access.

### Z3 — Identity and authorization service
- Isolate identity/session handling from quota and VPN packet forwarding.
- Use an established identity provider; keep its signing/JWKS trust configuration controlled.
- Separate authentication (who is this?) from authorization (what may they do?).
- Use short-lived access tokens, refresh-token rotation/reuse detection where supported, revocation strategy, and MFA for privileged operators.
- Admin actions require stronger authentication and explicit role checks.
- Managed Neon Auth is only a candidate if project region/configuration and required MFA/feature set fit; do not enable it until verified. Managed Neon Auth documentation currently lists MFA as unavailable, so privileged MFA may require a separate supported IdP or self-managed auth.

### Z4 — Control plane (private)
- Owns account lifecycle, subscriptions, device registration, policy generation, node assignment, and configuration delivery.
- Not reachable from public clients except through Z1/Z2.
- Admin/control APIs use separate service identities and narrowly scoped permissions.
- Changes to routing, firewall, node enrollment, or plans require audit records and preferably approval for high-impact actions.
- Control plane cannot directly expose arbitrary shell/SSH access to data-plane nodes.

### Z5 — VPN data plane (segmented)
- Separate VPN gateways into isolated network segments; no flat east-west network.
- Each node accepts only required ingress (VPN transport) and narrowly defined management traffic from a dedicated management path.
- Per-user or per-tenant traffic is isolated using network namespaces, VRFs, policy routing, cgroups/eBPF or equivalent controls selected after platform validation.
- Default-deny forwarding; explicit allowlists for required flows; anti-spoofing on tenant interfaces.
- Users cannot reach other users, node management ports, control-plane databases, cloud metadata endpoints, or internal admin services.
- Apply independent per-user quotas/rate limits at the data plane, with durable accounting reconciled by the control plane.
- Nodes must not possess broad database credentials or account-wide signing secrets.

### Z6 — Data and accounting plane (private)
- PostgreSQL is not publicly reachable and accepts connections only from the specific backend identity/network path.
- Separate database roles for migrations, application reads/writes, accounting functions, and operations; no shared superuser in application runtime.
- Revoke direct client access to tables and privileged functions.
- Use transaction-scoped identity context only when it is set by a trusted backend after token verification; never trust caller-supplied account_id.
- Enforce row/tenant authorization in the API and, where appropriate, database policies as defense in depth.
- Store append-only security/audit events with restricted update/delete rights.
- Backups and restore credentials are separate from runtime credentials.

### Z7 — Secrets and key management
- Keep secrets out of source, build logs, artifacts, mobile apps, and ordinary environment dumps.
- Separate keys by purpose and environment; use a managed secret store/KMS/HSM where feasible.
- Rotate credentials, revoke compromised keys, and document emergency rotation.
- Prefer short-lived workload identity over static long-lived credentials.
- VPN client configuration and server private keys must be separately scoped; compromise of one user config must not reveal other users' credentials.

### Z8 — Build, CI/CD, and software supply chain
- CI permissions default to read-only; grant write permissions only to the exact job that needs them.
- Pin third-party GitHub Actions to full commit SHAs; review updates.
- Do not expose production secrets to pull-request workflows or untrusted forks.
- Use protected branches, required review/status checks, CODEOWNERS for security-sensitive paths, and environment approvals for deployment.
- Generate and retain build provenance/SBOM; scan dependencies, containers, and secrets.
- Build artifacts are immutable and promoted between environments; production deploy is separate from test CI.

### Z9 — Observability and incident response
- Centralize authentication, authorization, admin, quota-denial, policy-change, node-health, and network-denial events.
- Do not log tokens, private keys, passwords, or full sensitive payloads.
- Alert on unusual login, token reuse, privilege changes, cross-tenant access attempts, unexpected egress, and configuration drift.
- Maintain tested procedures for isolating a node/account, revoking sessions/keys, preserving evidence, restoring service, and notifying affected users as required.

## Mandatory network separation

At minimum, production must have distinct security zones for:
1. Public edge.
2. Application/API ingress.
3. Private control plane.
4. VPN data-plane nodes.
5. Private database/accounting.
6. Management/monitoring.
7. Build/deployment systems.

There must be no direct route from public edge or tenant VPN interfaces to the database, CI system, management plane, or cloud metadata service. Administrative access uses a dedicated identity-aware management path, not the public VPN listener.

## Stage 10 implementation sequence

1. **10A — Threat model and trust-boundary inventory** (this document): enumerate assets, trust zones, attack paths, and blast-radius requirements.
2. **10B — Identity binding and authorization**: verified identity-to-account mapping; reject client-selected account IDs; tests for cross-account access.
3. **10C — Database privilege hardening**: owner/migration role separated from runtime roles; narrow function grants; tenant-safe transaction boundaries; negative permission tests.
4. **10D — API and service segmentation**: private service-to-service paths, default-deny network policy, workload identity, rate limits, fail-closed behavior.
5. **10E — VPN node/tenant isolation**: separate namespaces/VRFs and per-tenant policy; test lateral movement, spoofing, metadata access, and management-plane reachability.
6. **10F — CI/CD and secrets hardening**: SHA-pinned actions, protected deployment environment, secret scanning, SBOM/provenance, least-privilege workflow tokens.
7. **10G — Security telemetry and recovery drills**: alerting, key/session revocation, node quarantine, restore and incident simulations.
8. **10H — Independent security review**: external penetration test and remediation before production launch.

Each substage must include positive tests, negative tests, and evidence artifacts. Passing a lab test is not a production security certification.

## Threat-to-control acceptance matrix

| Threat | Required control | Required negative test |
|---|---|---|
| Stolen user token | Short expiry, revocation/reuse controls, account-scoped authorization | Token for account A cannot read/change account B |
| Forged account_id | Server-side identity mapping | Altered client account_id is ignored/rejected |
| Compromised API process | Narrow service identity and network egress | API cannot connect to admin/management ports or unrelated DB roles |
| Compromised VPN node | Node isolation and scoped credentials | Node cannot query account DB or reach other nodes' management interfaces |
| Malicious tenant traffic | Default-deny, anti-spoofing, per-tenant segmentation | Tenant A cannot reach tenant B, DB, metadata, or control plane |
| Database credential leak | Separate roles, rotation, private network | Runtime role cannot read secrets, alter schema, or bypass tenant boundaries |
| Malicious CI change | Protected branch, pinned actions, minimal permissions | PR workflow cannot access production secrets or deploy |
| Quota/accounting outage | Fail-closed enforcement | No unmetered traffic is admitted when policy/accounting is unavailable |

## Current verified baseline and limitations

- The disposable Phase A lab verified namespace-based traffic isolation, IPv4/IPv6 quota enforcement, anti-spoofing, fail-closed behavior, and topology rebuild in CI.
- Stages 8–9 verified durable quota accounting and account lifecycle/entitlement logic against disposable PostgreSQL.
- These tests do not establish production identity security, production database grants, cloud network segmentation, WAF/DDoS resilience, key management, device security, or independent penetration-test results.
- The current lab's topology rebuild is not a physical host reboot test.
- No production Neon project, cloud network, DNS, credentials, payment system, or customer traffic is modified by Stage 10 design work.

## Definition of done for Stage 10

Stage 10 is not complete until all sub-stages 10A–10H have evidence, negative tests pass, secrets and privileges are reviewed, and an independent security assessment has no unresolved critical/high findings. Production launch additionally requires an approved threat model, recovery drills, and an explicit deployment authorization.
