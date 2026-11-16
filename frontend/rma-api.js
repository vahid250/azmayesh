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

  async function request(path, options) {
    const initData = telegramInitData();
    const response = await fetch(apiBase() + path, {
      method: (options && options.method) || "GET",
      headers: Object.assign(
        {
          "Accept": "application/json",
          "Content-Type": "application/json",
          "X-Telegram-Init-Data": initData
        },
        (options && options.headers) || {}
      ),
      body: options && options.body ? JSON.stringify(options.body) : undefined,
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
      const detail = payload && payload.detail;
      throw new Error(detail || ("خطای سرور: " + response.status));
    }
    return payload;
  }

  window.RMAApi = Object.freeze({
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
