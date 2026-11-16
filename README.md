# R&MA backend — experimental rebuild

This repository branch is an isolated engineering workspace. It is not a production deployment.

## Safety rules
- Never put Telegram tokens, database passwords, WireGuard private keys, or Reality private keys in Git.
- Configuration issuance is disabled until payment/entitlement checks and real server-side provisioning are implemented and tested.
- No fake latency, fake online status, or simulated successful provisioning is returned as production data.
- Telegram Mini App `initData` is validated server-side with a short age limit.
- The `main` branch is not modified by this work.

## Current scope
This first baseline establishes secure configuration loading, Telegram initData verification, encrypted-at-rest primitives, database models, health endpoints, and tests. It deliberately does not deploy WireGuard/Xray peers or start a Telegram polling bot.

## Local development
1. Copy `.env.example` to `.env` and set a strong random `APP_SECRET`.
2. Install: `python -m pip install -r requirements.txt`
3. Run tests: `pytest -q`
4. Start API: `uvicorn app.main:app --reload`

SQLite is supported for local tests only. Production configuration must use PostgreSQL and a managed secret store.
