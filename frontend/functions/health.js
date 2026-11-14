/**
 * Cloudflare Pages Function for the dashboard's /health check.
 * Uses the same BACKEND_ORIGIN setting as the /api proxy.
 */
export async function onRequest({ request, env }) {
  const configuredOrigin = env.BACKEND_ORIGIN;

  if (!configuredOrigin) {
    return jsonError(503, "بک‌اند هنوز راه‌اندازی نشده است.");
  }

  let origin;
  try {
    origin = new URL(configuredOrigin);
  } catch {
    return jsonError(503, "نشانی بک‌اند معتبر نیست.");
  }

  if (
    origin.protocol !== "https:" ||
    origin.username ||
    origin.password ||
    origin.pathname !== "/" ||
    origin.search ||
    origin.hash
  ) {
    return jsonError(503, "تنظیم BACKEND_ORIGIN معتبر نیست.");
  }

  try {
    const upstream = await fetch(new URL("/health", origin.origin), {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "manual"
    });

    const headers = new Headers(upstream.headers);
    headers.set("Cache-Control", "no-store");
    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers
    });
  } catch {
    return jsonError(502, "بک‌اند در دسترس نیست.");
  }
}

function jsonError(status, detail) {
  return new Response(JSON.stringify({ detail }), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
