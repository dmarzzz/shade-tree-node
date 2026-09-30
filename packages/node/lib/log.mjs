// Small, dependency-free operator logging.
//
// SHADE_TREE_LOG_LEVEL  debug | info | warn | error | off   (default: info)
// SHADE_TREE_LOG_FORMAT auto | pretty | text | json          (default: auto)
//
// `auto` is pleasant at a terminal and structured everywhere else: a TTY gets the
// compact pretty format, while systemd, Docker, pipes, and files get one JSON object
// per line. `text` remains the legacy `message key=value` format for scripts that want
// it explicitly. Configuration is read at call time so tests and embedders can change it.

const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40, off: Infinity });
const RESERVED = new Set(["ts", "level", "msg", "component"]);
const SECRET_FIELDS = new Set([
  "secret", "identitysecret", "seed", "seedhex", "privatekey", "privkey",
  "password", "passphrase", "authorization", "proxyauthorization", "cookie",
  "setcookie", "token", "accesstoken", "refreshtoken", "sessiontoken", "idtoken",
  "apikey", "xapikey", "clientsecret", "secretaccesskey", "awssecretaccesskey",
  "shadetreesecret", "shadetreeslashkey", "shadetreegwoperatorkey",
  "shadetreeregisterkey", "shadetreeregistrarkey",
]);
const ANSI = Object.freeze({
  reset: "\x1b[0m",
  dim: "\x1b[2m",
  debug: "\x1b[36m",
  info: "\x1b[32m",
  warn: "\x1b[33m",
  error: "\x1b[31m",
});
const TAG = Object.freeze({ debug: "DBG", info: "INF", warn: "WRN", error: "ERR" });

function normalizedFieldName(key) {
  // Treat snake_case, kebab-case, camelCase, and environment-style names alike.
  // This keeps API_KEY, api-key, apiKey, and apikey on the same redaction path.
  return String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
}

function scrubText(input) {
  return String(input)
    .replace(/\b(https?|wss?):\/\/[^\s/@:]+:[^\s/@]+@/gi, "$1://[redacted]@")
    // Hosted RPC credentials commonly occupy an opaque URL path segment or a
    // provider-specific query parameter. Logs need only the endpoint origin,
    // so remove every path, query, or fragment instead of guessing key names.
    .replace(/\b((?:https?|wss?):\/\/[^/\s?#]+)([/?#][^\s),;\]}>'"]*)/gi,
      (match, origin, suffix) => suffix === "/" ? match : `${origin}/[redacted]`)
    .replace(/([?&](?:api[_-]?key|token|secret|password)=)[^&\s]+/gi, "$1[redacted]")
    .replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1[redacted]");
}

function redact(value, key = "", depth = 0, seen = new WeakSet()) {
  if (SECRET_FIELDS.has(normalizedFieldName(key))) return "[redacted]";
  if (value instanceof Error) return scrubText(value.message || value.name || "Error");
  if (typeof value === "string") return scrubText(value);
  if (typeof value === "bigint") return value.toString();
  if (!value || typeof value !== "object") return value;
  if (depth >= 6) return "[MaxDepth]";
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  if (Array.isArray(value)) return value.map((item) => redact(item, "", depth + 1, seen));
  const out = {};
  for (const [childKey, childValue] of Object.entries(value)) {
    out[childKey] = redact(childValue, childKey, depth + 1, seen);
  }
  return out;
}

export function resolveLogLevel(env = process.env) {
  const value = String(env.SHADE_TREE_LOG_LEVEL || "info").toLowerCase();
  return Object.hasOwn(LEVELS, value) ? value : "info";
}

export function resolveLogFormat(env = process.env, stream = process.stdout) {
  const value = String(env.SHADE_TREE_LOG_FORMAT || "auto").toLowerCase();
  if (value === "auto") return stream?.isTTY && env.TERM !== "dumb" && !env.CI ? "pretty" : "json";
  return ["pretty", "text", "json"].includes(value) ? value : "json";
}

export function isLogLevelEnabled(level, env = process.env) {
  return (LEVELS[level] ?? LEVELS.info) >= LEVELS[resolveLogLevel(env)];
}

function safeStringify(value) {
  try { return JSON.stringify(value); }
  catch { return '{"logError":"unserializable-fields"}'; }
}

function textField(key, value) {
  if (value !== null && typeof value === "object") return `${key}=${safeStringify(value)}`;
  let rendered = value === null || value === undefined ? String(value) : String(value);
  if (rendered === "" || /[\s"]/.test(rendered)) rendered = JSON.stringify(rendered);
  return `${key}=${rendered}`;
}

function textLine(msg, fields) {
  const parts = [String(msg)];
  for (const [key, value] of Object.entries(fields || {})) parts.push(textField(key, value));
  return parts.join(" ");
}

function prettyLine(level, component, msg, fields, stream, env) {
  const time = new Date().toISOString().slice(11, 19);
  const useColor = Boolean(stream?.isTTY && !env.NO_COLOR && env.TERM !== "dumb");
  const levelTag = TAG[level] || level.toUpperCase();
  const role = component ? String(component).padEnd(9).slice(0, 9) : "";
  if (!useColor) return `${time} ${levelTag} ${role}`.trimEnd() + `  ${textLine(msg, fields)}`;
  return `${ANSI.dim}${time}${ANSI.reset} ${ANSI[level]}${levelTag}${ANSI.reset} ${role}  ${textLine(msg, fields)}`;
}

function sink(level) {
  if (level === "error") return console.error;
  if (level === "warn") return console.warn;
  return console.log;
}

function cleanFields(fields) {
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) return {};
  const out = {};
  for (const [key, value] of Object.entries(fields)) {
    if (RESERVED.has(key)) continue;
    out[key] = redact(value, key);
  }
  return out;
}

function emit(component, baseFields, level, msg, fields, env = process.env) {
  if (!isLogLevelEnabled(level, env)) return;
  const allFields = cleanFields({ ...(baseFields || {}), ...(fields || {}) });
  const format = resolveLogFormat(env, process.stdout);
  let line;
  if (format === "json") {
    line = safeStringify({
      ts: new Date().toISOString(),
      level,
      ...(component ? { component } : {}),
      msg: scrubText(msg),
      ...allFields,
    });
  } else if (format === "pretty") {
    line = prettyLine(level, component, scrubText(msg), allFields, process.stdout, env);
  } else {
    line = textLine(scrubText(msg), allFields);
  }
  sink(level)(line);
}

export function createLogger(component = "", baseFields = {}) {
  const name = String(component || "").trim();
  return Object.freeze({
    debug: (msg, fields) => emit(name, baseFields, "debug", msg, fields),
    info: (msg, fields) => emit(name, baseFields, "info", msg, fields),
    warn: (msg, fields) => emit(name, baseFields, "warn", msg, fields),
    error: (msg, fields) => emit(name, baseFields, "error", msg, fields),
    child: (fields = {}) => createLogger(name, { ...baseFields, ...fields }),
    isEnabled: (level) => isLogLevelEnabled(level),
  });
}

// Backwards-compatible singleton. New service entrypoints should prefer createLogger(role).
export const log = createLogger(process.env.SHADE_TREE_ROLE || "");
export default log;
