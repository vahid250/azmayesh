/**
 * Cloudflare Pages Function: same-origin proxy for the R&MA API.
 *
 * Configure BACKEND_ORIGIN in the Pages project's environment variables.
 * Example: https://api.example.com
 * Never put bot tokens, API keys, or private keys in this file.
 */
export async function onRequest({ request, env }) {
  const configuredOrigin = env.BACKEND_ORIGIN;

  if (!configuredOrigin) {
    return jsonError(503, "بک‌اند هنوز به مینی‌اپ متصل نشده است.");
  }

  let backendUrl;
  try {
    backendUrl = new URL(configuredOrigin);
  } catch {
    return jsonError(503, "نشانی بک‌اند به‌درستی پیکربندی نشده است.");
  }

  // Production proxy targets must be an HTTPS origin, not an arbitrary URL.
  if (
    backendUrl.protocol !== "https:" ||
    backendUrl.username ||
    backendUrl.password ||
    backendUrl.pathname !== "/" ||
    backendUrl.search ||
    backendUrl.hash
  ) {
    return jsonError(503, "تنظیم BACKEND_ORIGIN باید فقط یک نشانی HTTPS معتبر باشد.");
  }

  const incomingUrl = new URL(request.url);
  const targetUrl = new URL(
    incomingUrl.pathname + incomingUrl.search,
    backendUrl.origin
  );

  try {
    const upstreamRequest = new Request(targetUrl.toString(), request);
    const upstreamResponse = await fetch(upstreamRequest);
    const headers = new Headers(upstreamResponse.headers);
    headers.set("Cache-Control", "no-store");
    headers.delete("set-cookie");

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers
    });
  } catch {
    return jsonError(502, "ارتباط با بک‌اند برقرار نشد.");
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
