import fs from "node:fs";
import vm from "node:vm";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(here, "index.html"), "utf8");
const apiClient = fs.readFileSync(path.join(here, "rma-api.js"), "utf8");

const required = [
  'name="rma-api-base"',
  'src="/rma-api.js"',
  'id="rmaApiStatusPanel"',
  'id="rmaLoadConfigsBtn"',
  'id="rmaCreateConfigBtn"',
  'id="rmaConfigsList"',
  'id="rmaIssuedConfig"'
];
for (const marker of required) {
  if (!html.includes(marker)) throw new Error("Dashboard integration marker missing: " + marker);
}
if (!apiClient.includes("X-Telegram-Init-Data")) {
  throw new Error("Telegram initData header missing from API client.");
}

const inlineScripts = [...html.matchAll(/<script\b(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)<\/script>/gi)];
if (inlineScripts.length === 0) throw new Error("No inline scripts found for syntax validation.");
inlineScripts.forEach((match, index) => {
  new vm.Script(match[1], { filename: "dashboard-inline-" + index + ".js" });
});

console.log("Dashboard contract markers and " + inlineScripts.length + " inline script blocks passed.");
