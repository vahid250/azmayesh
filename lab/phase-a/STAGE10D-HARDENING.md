# R&MA Stage 10D-Hardening — Workload Identity and Fail-Closed Verification

Status: isolated CI implementation. No production deployment or host firewall changes.

## Purpose
Strengthen Stage 10D evidence without weakening existing network policy.

## Checks
- Q10DH-01: trusted client certificate and authorized rma-control workload identity accepted over mutual TLS.
- Q10DH-02: valid certificate with wrong workload identity rejected for mutation (HTTP 403).
- Q10DH-03: unavailable policy dependency rejects mutation (HTTP 503).
- Q10DH-04: certificate issued by an untrusted CA fails the TLS handshake.
- Q10DH-05: public TCP egress to 1.1.1.1:443 denied from every isolated zone.
- Q10DH-06/Q10DH-07: fresh health signal is HEALTHY; stale signal is UNKNOWN/STALE.

## Evidence
A JSON record is written for every check with expected and actual outcome and pass/fail. The workflow uploads JSON and the full console log.

## Important limits
- Certificates are ephemeral test credentials generated inside CI; this does not provision production PKI, certificate rotation, revocation, SPIFFE, or a service mesh.
- Policy outage is exercised through a local test HTTP service, not the future production policy engine.
- Health freshness mapping is deterministic policy logic, not deployed production telemetry.
- Egress checks prove the disposable namespace topology has no public TCP route under this runner. They do not prove cloud-provider or production perimeter behavior.
- No production secrets, user data, VPN server configuration, public endpoint, billing, or wallet feature is introduced.
- Existing Stage 10D baseline remains unchanged; this stage is additive.
