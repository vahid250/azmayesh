import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import { pathToFileURL } from "node:url";

const frontendDir = path.dirname(new URL(import.meta.url).pathname);
const proxySource = await fs.readFile(path.join(frontendDir, "functions", "api", "[[path]].js"), "utf8");
const proxyModule = await import("data:text/javascript;base64," + Buffer.from(proxySource).toString("base64"));
const dbPath = path.join(os.tmpdir(), "rma-e2e-" + process.pid + ".sqlite");
const encryptionKey = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=";
const apiKey = "rma-e2e-only-secret";
const bearerToken = "proxy-bearer-session-token";

async function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(error => error ? reject(error) : resolve(address.port));
    });
  });
}

const port = await freePort();
const backendOrigin = "http://127.0.0.1:" + port;
const backendDir = path.join(frontendDir, "..", "backend");
const childEnv = {
  ...process.env,
  APP_ENV: "development",
  API_KEY: apiKey,
  MOCK_MODE: "true",
  ENCRYPTION_KEY: encryptionKey,
  DATABASE_URL: "sqlite:///" + dbPath,
  WG_SUBNET: "10.88.0.0/24",
  PYTHONPATH: path.join(frontendDir, "..", "backend")
};
const seedScript = `
import hashlib
from datetime import datetime, timedelta, timezone
from app.database import Base, engine, SessionLocal
from app import models
Base.metadata.create_all(bind=engine)
with SessionLocal() as db:
    order = models.Order(
        telegram_user_id="lab-local",
        plan_code="ci-test-plan",
        idempotency_key="ci-integration-order-key",
        amount_minor=1,
        currency="TEST",
        quota_bytes=1000000,
        max_devices=2,
        duration_days=30,
        status="paid",
    )
    db.add(order)
    db.flush()
    db.add(models.Entitlement(
        order_id=order.id,
        telegram_user_id="lab-local",
        quota_bytes=1000000,
        consumed_bytes=0,
        max_devices=2,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        status="active",
    ))
    now = datetime.now(timezone.utc)
    db.add(models.UserSession(
        telegram_user_id="12345",
        token_hash=hashlib.sha256(b"proxy-bearer-session-token").hexdigest(),
        exchange_key_hash=hashlib.sha256(b"proxy-exchange-key").hexdigest(),
        init_data_hash=hashlib.sha256(b"proxy-init-data").hexdigest(),
        key_version=1,
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(hours=4),
    ))
    db.commit()
`;
const seedResult = spawnSync(
  process.env.PYTHON || "python",
  ["-c", seedScript],
  { env: childEnv, cwd: backendDir, encoding: "utf8" }
);
if (seedResult.status !== 0) {
  throw new Error("Could not seed test entitlement:\\n" + seedResult.stdout + seedResult.stderr);
}

const server = spawn(
  process.env.PYTHON || "python",
  ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", String(port)],
  { env: childEnv, stdio: ["ignore", "pipe", "pipe"] }
);
let serverOutput = "";
server.stdout.on("data", chunk => { serverOutput += chunk.toString(); });
server.stderr.on("data", chunk => { serverOutput += chunk.toString(); });

const originalFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const request = input instanceof Request ? input : new Request(input, init);
  const upstream = new URL(request.url);
  assert.equal(upstream.origin, "https://api.example.test", "proxy must target configured HTTPS origin");
  upstream.protocol = "http:";
  upstream.hostname = "127.0.0.1";
  upstream.port = String(port);
  return originalFetch(new Request(upstream, request));
};

async function waitForBackend() {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) {
      throw new Error("FastAPI exited before becoming ready:\n" + serverOutput);
    }
    try {
      const response = await originalFetch(backendOrigin + "/health");
      if (response.ok) return;
    } catch (_) {}
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error("FastAPI did not become ready:\n" + serverOutput);
}

async function throughPagesProxy(pathname, init = {}) {
  return proxyModule.onRequest({
    request: new Request("https://pages.example" + pathname, init),
    env: { BACKEND_ORIGIN: "https://api.example.test" }
  });
}

try {
  await waitForBackend();

  const health = await throughPagesProxy("/health");
  assert.equal(health.status, 200);
  const healthPayload = await health.json();
  assert.equal(healthPayload.status, "ok");
  assert.equal(healthPayload.mock_mode, true);
  assert.equal(healthPayload.real_provisioning_configured, false);
  assert.equal(healthPayload.connectivity_verified, false);

  const denied = await throughPagesProxy("/api/v1/wireguard/configs", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_name: "Unauthenticated" })
  });
  assert.equal(denied.status, 401, "backend authentication must be enforced through proxy");

  const legacyInitDataDenied = await throughPagesProxy("/api/v1/orders", {
    headers: { "X-Telegram-Init-Data": "unsigned-legacy-payload" }
  });
  assert.equal(legacyInitDataDenied.status, 401, "private routes must no longer accept raw initData");

  const bearerOrders = await throughPagesProxy("/api/v1/orders", {
    headers: { "Authorization": "Bearer " + bearerToken }
  });
  assert.equal(bearerOrders.status, 200, "Pages proxy must preserve Authorization Bearer");
  assert.deepEqual(await bearerOrders.json(), []);

  const created = await throughPagesProxy("/api/v1/wireguard/configs", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": apiKey
    },
    body: JSON.stringify({ client_name: "Proxy integration test" })
  });
  assert.equal(created.status, 200);
  const client = await created.json();
  assert.equal(client.client_name, "Proxy integration test");
  assert.equal(client.state, "generated_mock");
  assert.equal(client.connectivity_verified, false);
  assert.match(client.config, /Endpoint = mock\.invalid:51820/);

  const listed = await throughPagesProxy("/api/v1/wireguard/configs", {
    headers: { "X-API-Key": apiKey }
  });
  assert.equal(listed.status, 200);
  const rows = await listed.json();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, client.id);

  const config = await throughPagesProxy("/api/v1/wireguard/configs/" + client.id + "/config", {
    headers: { "X-API-Key": apiKey }
  });
  assert.equal(config.status, 200);
  const configPayload = await config.json();
  assert.equal(configPayload.config, client.config);

  console.log("Cloudflare Pages proxy -> live FastAPI integration tests passed.");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
} finally {
  globalThis.fetch = originalFetch;
  server.kill("SIGTERM");
  await new Promise(resolve => {
    if (server.exitCode !== null) return resolve();
    server.once("exit", resolve);
    setTimeout(() => {
      if (server.exitCode === null) server.kill("SIGKILL");
      resolve();
    }, 3000).unref();
  });
  await fs.rm(dbPath, { force: true });
  await fs.rm(dbPath + "-journal", { force: true });
}
