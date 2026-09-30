import { isLogLevelEnabled, resolveLogFormat } from "./log.mjs";

export const SHADE_TREE_ART = Object.freeze([
  "              \\ | /",
  "            --  *  --",
  "        .---------------.",
  "     .-'                 '-.",
  "    /_______________________\\",
  "              |||",
  "              |||",
]);

const ROLE_STATE = Object.freeze({
  proxy: "shade ready",
  node: "cover ready",
  elder: "canopy ready",
  heartbeat: "roots reaching",
  registrar: "leaves ready",
});

export function resolveBannerMode(env = process.env) {
  const value = String(env.SHADE_TREE_BANNER || "auto").toLowerCase();
  if (["always", "on", "1", "true"].includes(value)) return "always";
  if (["never", "off", "0", "false"].includes(value)) return "never";
  return "auto";
}

export function shouldShowBanner({ env = process.env, stream = process.stdout } = {}) {
  const mode = resolveBannerMode(env);
  if (mode === "never" || resolveLogFormat(env, stream) === "json") return false;
  if (!isLogLevelEnabled("info", env)) return false;
  if (mode === "always") return true;
  return Boolean(stream?.isTTY && env.TERM !== "dumb" && !env.CI);
}

function safeCell(value) {
  return String(value ?? "").replace(/[\r\n\t\x1b]/g, " ").slice(0, 120);
}

export function renderOperatorBanner({ role, state, rows = [] } = {}) {
  const name = safeCell(role || "shade tree").toUpperCase();
  const status = safeCell(state || ROLE_STATE[String(role || "").toLowerCase()] || "ready");
  const body = [...SHADE_TREE_ART, `          SHADE TREE`, `       ${name} | ${status}`, ""];
  for (const [label, value] of rows) {
    body.push(`  ${safeCell(label).padEnd(11).slice(0, 11)}${safeCell(value)}`);
  }
  return body.join("\n") + "\n";
}

export function printOperatorBanner(options = {}) {
  const stream = options.stream || process.stdout;
  if (!shouldShowBanner({ ...options, stream })) return false;
  stream.write(renderOperatorBanner(options));
  return true;
}
