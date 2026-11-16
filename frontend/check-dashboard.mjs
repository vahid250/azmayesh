import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "index.html"), "utf8");
const apiClient = fs.readFileSync(path.join(here, "rma-api.js"), "utf8");
const apiProxy = fs.readFileSync(path.join(here, "functions", "api", "[[path]].js"), "utf8");
const healthProxy = fs.readFileSync(path.join(here, "functions", "health.js"), "utf8");

const required = [
  'name="rma-api-base"',
  'src="/rma-api.js"',
  'id="rmaApiStatusPanel"',
  'id="rmaLabNotice"',
  'id="rmaLoadConfigsBtn"',
  'id="rmaCreateConfigBtn"',
  'id="rmaConfigsList"',
  'id="rmaIssuedConfig"',
  "telegramApp.ready()",
  "telegramApp.expand()",
  'id="rialPaymentOption"',
  'id="cryptoPaymentOption"',
  'id="paymentMethodFeedback"',
  "به‌زودی فعال خواهد شد",
  "درگاه رمزارزی هنوز متصل نشده",
  "برنامه دوره آزمایشی ۳۰ روزه R&amp;MA",
  "100 MB PER REF",
  "servicePaused = status.mode === \"paused\""
];
for (const marker of required) {
  if (!html.includes(marker)) throw new Error("Dashboard integration marker missing: " + marker);
}
if (!html.includes('aria-disabled="true" tabindex="-1" id="selectedPlanCta"')) {
  throw new Error("Demo checkout must remain disabled until billing is implemented.");
}
if (!html.includes('aria-disabled="true" tabindex="-1" id="socialMediaPassBtn"')) {
  throw new Error("Unimplemented social VPN offer must remain disabled.");
}
if (html.includes("کارت‌به‌کارت شتابی هوشمند") || html.includes("کیف پول و تلگرام استارز") || html.includes("امکان پرداخت امن ریالی") || html.includes("۵۰۰MB رایگان")) {
  throw new Error("Unimplemented purchase or free-data offer is presented as active.");
}


if (/[?&]start=/i.test(html)) throw new Error("Unsupported Telegram start payload remains in dashboard.");
if (!html.includes("disableUnimplementedTelegramCommands") || !html.includes('url.searchParams.has("start")')) {
  throw new Error("Runtime guard for unsupported Telegram commands is missing.");
}
if (!html.includes('const webFallbackUrl = "https://t.me/RMA_Connect_Bot";')) {
  throw new Error("Quick launch must use the plain bot URL.");
}
if (!apiClient.includes("X-Telegram-Init-Data") || !apiClient.includes("/v1/public/service-status") || !apiClient.includes("serviceStatus: function ()")) {
  throw new Error("Telegram initData header missing from API client.");
}

const forbiddenDemoClaims = [
  "1 GB PER REF",
  "۱ گیگابایت هدیه (Referral",
  "۴ گیگابایت ترافیک هدیه",
  "به محض زدن دکمه Start توسط دوست شما",
  "READY_TO_SPAWN",
  "~28ms",
  "~29ms",
  "~34ms",
  "~38ms",
  "~39ms",
  "99.8%",
  "1.4 GB / 30 GB",
  "مصرف: ۰ مگابایت",
  "10Gbps",
  "38 ms",
  "100% OFFICIAL",
  "پهنای‌باند نامحدود",
  "پینگ فوق‌پایین",
  "Reality • Anti-DPI TLS",
  "صدور بدون وقفه کانفیگ اختصاصی",
  "3 Online"
];
for (const claim of forbiddenDemoClaims) {
  if (html.includes(claim)) throw new Error("Unverified dashboard claim remains: " + claim);
}

const inlineScripts = [...html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)];
if (inlineScripts.length === 0) throw new Error("No inline scripts found for syntax validation.");
inlineScripts.forEach((match, index) => {
  new vm.Script(match[1], { filename: "dashboard-inline-" + index + ".js" });
});

console.log("Dashboard contract markers and " + inlineScripts.length + " inline script blocks passed.");
