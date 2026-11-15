import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const here = path.dirname(new URL(import.meta.url).pathname);
const apiSource = fs.readFileSync(path.join(here, "functions", "api", "[[path]].js"), "utf8");
const healthSource = fs.readFileSync(path.join(here, "functions", "health.js"), "utf8");

async function loadFunction(source) {
  const encoded = Buffer.from(source, "utf8").toString("base64");
  return import("data:text/javascript;base64," + encoded);
}

const api = await loadFunction(apiSource);
const health = await loadFunction(healthSource);

function request(url, init) {
  return new Request(url, init);
}

{
  let called = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { called = true; throw new Error("must not fetch"); };
  try {
    const response = await api.onRequest({
      request: request("https://pages.example/api/v1/items"),
      env: {}
    });
    assert.equal(response.status, 503);
    assert.match((await response.json()).detail, /بک‌اند/);
    assert.equal(called, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

for (const invalidOrigin of [
  "http://api.example.com",
  "https://user:pass@api.example.com",
  "https://api.example.com/private",
  "https://api.example.com/?token=x"
]) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("invalid origin must not fetch"); };
  try {
    const response = await api.onRequest({
      request: request("https://pages.example/api/v1/items"),
      env: { BACKEND_ORIGIN: invalidOrigin }
    });
    assert.equal(response.status, 503, invalidOrigin);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

{
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (upstreamRequest) => {
    captured = upstreamRequest;
    return new Response("upstream-ok", {
      status: 200,
      headers: {
        "Content-Type": "text/plain",
        "Set-Cookie": "session=secret; HttpOnly",
        "Cache-Control": "public, max-age=3600"
      }
    });
  };
  try {
    const response = await api.onRequest({
      request: request("https://pages.example/api/v1/items?limit=5", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Test": "forwarded" },
        body: JSON.stringify({ name: "test" })
      }),
      env: { BACKEND_ORIGIN: "https://api.example.com" }
    });
    assert.equal(captured.url, "https://api.example.com/api/v1/items?limit=5");
    assert.equal(captured.method, "POST");
    assert.equal(captured.headers.get("X-Test"), "forwarded");
    assert.equal(await captured.text(), JSON.stringify({ name: "test" }));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("Set-Cookie"), null);
    assert.equal(await response.text(), "upstream-ok");
  } finally {
    globalThis.fetch = originalFetch;
  }
}

{
  const originalFetch = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), init };
    return Response.json({ status: "ok" });
  };
  try {
    const response = await health.onRequest({
      request: request("https://pages.example/health"),
      env: { BACKEND_ORIGIN: "https://api.example.com" }
    });
    assert.equal(captured.url, "https://api.example.com/health");
    assert.equal(captured.init.method, "GET");
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });
    assert.equal(response.headers.get("Cache-Control"), "no-store");
  } finally {
    globalThis.fetch = originalFetch;
  }
}

console.log("Cloudflare Pages proxy behavior tests passed.");
