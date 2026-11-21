# R&MA Project Dossier — 2026-11-21

Backup ID: RMA-DOSSIER-2026-11-21-01
Status: dated evidence snapshot; not a claim of complete project history.

## Current verified Stage 10D snapshot
- Repository: https://github.com/vahid250/azmayesh
- PR #6: https://github.com/vahid250/azmayesh/pull/6
- State: OPEN / DRAFT / NOT MERGED. No deployment.
- Branch: security/phase10d-perflow-proof-20261121
- Head: db96d54f7756e98ae0b5a4382ecbe21336dfd8b5
- Base: security/phase-10d-hardening @ 51213a7e8da43e218e26e9d5b94b46b9232f14e8

## CI results on the exact head SHA
- Static Checks: SUCCESS — https://github.com/vahid250/azmayesh/actions/runs/44921481774
- Stage 10D Hardening: SUCCESS — https://github.com/vahid250/azmayesh/actions/runs/44921481931
- Stage 10D Route Matrix: SUCCESS — https://github.com/vahid250/azmayesh/actions/runs/44921481852
- Unique assertions: 48 PASS / 0 FAIL / 0 INCONCLUSIVE (31 Hardening + 17 Route Matrix).

## Evidence summary
- 10 zone-specific deny probes passed with exact tuple drop-counter attribution; observed delta 2 packets per case; temporary rules removed.
- 9 DENY route cases each passed an actual TCP positive control before deny verification; exact drop counters increased and temporary rules were removed.
- 8 ALLOW route cases connected and received OK.
- Trusted SAN URI identity: HTTP 200; wrong SAN URI despite CN spoof: HTTP 403; unavailable policy dependency: HTTP 503 fail-closed; rogue client CA rejected.
- Health freshness boundaries: 29.999s and 30.0s healthy; 30.001s stale; negative age error.

## PR lineage visible in this repository
- PR #1: Stage 10B trusted identity binding / authorization boundary. Q30–Q35 SQL negative tests described; historical CI/artifacts still require independent review.
- PR #2: Stage 10D workload identity, mTLS, fail-closed and egress test harness.
- PR #3: mTLS certificate validation repair (keyUsage and OpenSSL diagnostics).
- PR #4: real TCP Route Matrix (8 allow / 9 deny).
- PR #5: Stage 10D false-positive remediation; remains open/draft.
- PR #6: per-route positive controls and drop-counter evidence; remains open/draft.

## Limitations and safety
- Tests ran in disposable CI namespaces and local TLS harnesses. Egress evidence is against a controlled lab sink, not the public Internet.
- These results do not certify production enforcement, cloud egress, or a deployed VPN.
- No production changes, secrets, spend, merge, or deployment were made.
- PR #5 and #6 remain drafts. Re-review all diffs, required checks and artifacts before any merge decision.
- This snapshot covers the azmayesh test repository and known project context; it is NOT a complete archive of every R&MA product/client repository or every historical test result.

## Raw evidence checksums
- Hardening ZIP SHA-256: 48e4b52e7228bc83e6aa040109cc3eba69603fc581df4df921c69632f425aa50
- Route Matrix ZIP SHA-256: 6c44ff1ea8fbea52aa98fce099a2cc7c6f47da594f8cbf7c301def51627c63e3

## Periodic archive procedure
For every update, create a new dated dossier and evidence package; never overwrite old snapshots. Record commit SHA, PR state, workflow run IDs, artifact IDs, test counts, limitations and SHA-256 hashes. Re-open and verify every archive. Mark unreviewed historical runs explicitly as pending.

Project support mailbox: rma.connect.team@gmail.com
