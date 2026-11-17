/* R&MA API client.
 * Requires Telegram WebApp context. Never place bot tokens or API keys in this file.
 * Configure <meta name="rma-api-base" content="/api"> in the dashboard.
 */
(function () {
  "use strict";

  function apiBase() {
    const meta = document.querySelector('meta[name="rma-api-base"]');
    const raw = meta ? meta.content.trim() : "/api";
    return raw.replace(/\/+$/, "");
  }

  function telegramInitData() {
    const webApp = window.Telegram && window.Telegram.WebApp;
    const initData = webApp && webApp.initData;
    if (!initData) {
      throw new Error("برای استفاده از پنل، آن را از داخل ربات تلگرام باز کنید.");
    }
    return initData;
  }

  let accessToken = null;
  const EXCHANGE_STORAGE_KEY = "rma.session.exchange.v1";

  function toBase64Url(bytes) {
    let binary = "";
    bytes.forEach(function (byte) { binary += String.fromCharCode(byte); });
    return btoa(binary).replaceAll("=", "").replaceAll("+", "-").replaceAll("/", "_");
  }

  async function sha256Hex(value) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  async function exchangeSession() {
    const initData = telegramInitData();
    const initHash = await sha256Hex(initData);
    let exchangeKey = null;
    try {
      const saved = JSON.parse(sessionStorage.getItem(EXCHANGE_STORAGE_KEY) || "null");
      if (saved && saved.initHash === initHash && typeof saved.exchangeKey === "string") {
        exchangeKey = saved.exchangeKey;
      }
    } catch (_) {}
    if (!exchangeKey) {
      const random = new Uint8Array(32);
      crypto.getRandomValues(random);
      exchangeKey = toBase64Url(random);
      sessionStorage.setItem(EXCHANGE_STORAGE_KEY, JSON.stringify({ initHash: initHash, exchangeKey: exchangeKey }));
    }
    const response = await fetch(apiBase() + "/v1/auth/session", {
      method: "POST",
      headers: { "Accept": "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ init_data: initData, exchange_key: exchangeKey }),
      credentials: "same-origin",
      cache: "no-store"
    });
    const payload = await response.json().catch(function () { return null; });
    if (!response.ok || !payload || !payload.access_token) {
      throw new Error((payload && payload.detail) || ("خطای ورود: " + response.status));
    }
    accessToken = payload.access_token;
    return accessToken;
  }

  async function request(path, options) {
    if (!accessToken) await exchangeSession();
    const headers = new Headers((options && options.headers) || {});
    headers.set("Accept", "application/json");
    headers.set("Authorization", "Bearer " + accessToken);
    if (options && options.body !== undefined) headers.set("Content-Type", "application/json");
    const response = await fetch(apiBase() + path, {
      method: (options && options.method) || "GET",
      headers: headers,
      body: options && options.body !== undefined ? JSON.stringify(options.body) : undefined,
      credentials: "same-origin",
      cache: "no-store"
    });

    let payload;
    try {
      payload = await response.json();
    } catch (_) {
      payload = null;
    }
    if (!response.ok) {
      if (response.status === 401) {
        accessToken = null;
        sessionStorage.removeItem(EXCHANGE_STORAGE_KEY);
      }
      const detail = payload && payload.detail;
      throw new Error(detail || ("خطای سرور: " + response.status));
    }
    return payload;
  }

  window.RMAApi = Object.freeze({
    logout: async function () {
      const token = accessToken;
      accessToken = null;
      sessionStorage.removeItem(EXCHANGE_STORAGE_KEY);
      if (!token) return { revoked: false };
      const response = await fetch(apiBase() + "/v1/auth/logout", {
        method: "POST",
        headers: { "Authorization": "Bearer " + token, "Accept": "application/json" },
        cache: "no-store"
      });
      if (!response.ok) throw new Error("Could not revoke the current session: " + response.status);
      return response.json();
    },
    termsMetadata: function () {
      return fetch(apiBase() + "/v1/public/terms", {
        headers: { "Accept": "application/json" },
        cache: "no-store"
      }).then(function (r) {
        if (!r.ok) throw new Error("Terms metadata unavailable: " + r.status);
        return r.json();
      });
    },
    serviceStatus: function () {
      return fetch(apiBase() + "/v1/public/service-status", {
        headers: { "Accept": "application/json" },
        cache: "no-store"
      }).then(function (r) {
        if (!r.ok) throw new Error("Service status unavailable: " + r.status);
        return r.json();
      });
    },
    health: function () {
      return fetch(apiBase().replace(/\/api$/, "") + "/health", {
        headers: { "Accept": "application/json" },
        cache: "no-store"
      }).then(function (r) {
        if (!r.ok) throw new Error("Backend health check failed: " + r.status);
        return r.json();
      });
    },
    listWireGuardConfigs: function () {
      return request("/v1/wireguard/configs");
    },
    createOrder: function (planCode, idempotencyKey, termsVersion, paymentMethod) {
      return request("/v1/orders", {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: {
          plan_code: planCode,
          payment_method: paymentMethod || "crypto",
          terms_version: termsVersion
        }
      });
    },
    createWireGuardConfig: function (clientName) {
      return request("/v1/wireguard/configs", {
        method: "POST",
        body: { client_name: clientName || "R&MA Client" }
      });
    },
    getWireGuardConfig: function (id) {
      return request("/v1/wireguard/configs/" + encodeURIComponent(id) + "/config");
    },
    getWireGuardStatus: function (id) {
      return request("/v1/wireguard/configs/" + encodeURIComponent(id) + "/status");
    },
    revokeWireGuardConfig: function (id) {
      return request("/v1/wireguard/configs/" + encodeURIComponent(id) + "/revoke", {
        method: "POST"
      });
    }
  });
})();
