# R&MA API on Cloudflare Python Workers

This is the Worker packaging and runtime adapter for the existing FastAPI backend.
It does not deploy anything and does not create Cloudflare resources.

## Current safety defaults

- `MOCK_MODE` is intentionally `true`; generated profiles are test data only.
- The Worker refuses real WireGuard provisioning. The `wg` command and the
  live WireGuard interface must run on a separate server.
- Database-backed API routes fail closed until a Cloudflare Hyperdrive binding
  named `HYPERDRIVE` is configured.
- The Worker does not run Alembic migrations or create tables at startup.
- Telegram tokens, webhook secrets, API keys, and the encryption key must be
  entered as Cloudflare secrets, never committed to Git.

## Before a first deployment

1. Confirm the Cloudflare account supports Python Workers and Hyperdrive on
   the Free plan. No payment method should be added for this project.
2. Create a Hyperdrive configuration pointing to the existing Neon PostgreSQL
   database. Do not paste the database URL into this repository or this file.
3. Add the resulting Hyperdrive configuration ID to the `hyperdrive` array in
   `wrangler.jsonc`, using binding name `HYPERDRIVE`.
4. Add the required secret values in the Cloudflare Worker settings:
   `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, and `ENCRYPTION_KEY`.
   Add `API_KEY` only if the lab API-key path is still needed; production
   authentication should use validated Telegram WebApp initData.
5. Keep `MOCK_MODE=true`. Set `MINI_APP_URL` only after the Pages URL is
   confirmed.
6. Apply reviewed Alembic migrations to Neon separately before enabling
   database-backed API routes.
7. Run the local Worker dry-run and review the CI result before any deployment.

## Local validation

From this directory:

```sh
uv run pywrangler deploy --dry-run
```

This packages the Worker without deploying it. A successful dry-run is a
packaging check, not proof of a live Neon connection or VPN connectivity.
