// Self-test for the dependency-free operator logger.
//
//   node packages/node/lib/log.selftest.mjs

import {
  createLogger,
  isLogLevelEnabled,
  log,
  resolveLogFormat,
  resolveLogLevel,
} from "./log.mjs";

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else {
    console.log(`  FAIL ${message}`);
    failures++;
  }
};

function capture(fn) {
  const logs = [];
  const warns = [];
  const errors = [];
  const original = { log: console.log, warn: console.warn, error: console.error };
  console.log = (...args) => logs.push(args.join(" "));
  console.warn = (...args) => warns.push(args.join(" "));
  console.error = (...args) => errors.push(args.join(" "));
  try { fn(); }
  finally { Object.assign(console, original); }
  return { logs, warns, errors };
}

function withEnv(env, fn) {
  const previous = Object.keys(env).map((key) => [
    key,
    Object.hasOwn(process.env, key),
    process.env[key],
  ]);
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try { return fn(); }
  finally {
    for (const [key, hadValue, value] of previous) {
      if (hadValue) process.env[key] = value;
      else delete process.env[key];
    }
  }
}

function withStdoutTTY(isTTY, fn) {
  const descriptor = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
  Object.defineProperty(process.stdout, "isTTY", { configurable: true, value: isTTY });
  try { return fn(); }
  finally {
    if (descriptor) Object.defineProperty(process.stdout, "isTTY", descriptor);
    else delete process.stdout.isTTY;
  }
}

function parse(line) {
  try { return JSON.parse(line); }
  catch { return null; }
}

function main() {
  console.log("format resolution:");
  {
    const base = { TERM: "xterm-256color" };
    ok(resolveLogFormat(base, { isTTY: true }) === "pretty", "auto selects pretty on a TTY");
    ok(resolveLogFormat(base, { isTTY: false }) === "json", "auto selects JSON off a TTY");
    ok(resolveLogFormat({ ...base, CI: "1" }, { isTTY: true }) === "json", "auto selects JSON in CI");
    ok(resolveLogFormat({ ...base, SHADE_TREE_LOG_FORMAT: "text" }, { isTTY: true }) === "text", "explicit text format wins");
    ok(resolveLogFormat({ SHADE_TREE_LOG_FORMAT: "bogus" }, { isTTY: true }) === "json", "invalid format fails closed to JSON");
  }
  {
    const { logs } = withStdoutTTY(false, () => withEnv({
      SHADE_TREE_LOG_FORMAT: undefined,
      SHADE_TREE_LOG_LEVEL: undefined,
      CI: undefined,
      TERM: "xterm-256color",
    }, () => capture(() => log.info("canopy ready", { peers: 3 }))));
    const record = parse(logs[0]);
    ok(logs.length === 1 && record?.msg === "canopy ready" && record?.peers === 3,
      "default auto format emits one JSON record off a TTY");
  }
  {
    const { logs } = withEnv({ SHADE_TREE_LOG_FORMAT: "text" }, () =>
      capture(() => log.info("gateway ready", { bind: "127.0.0.1:8443", note: "two words" })));
    ok(logs[0] === 'gateway ready bind=127.0.0.1:8443 note="two words"',
      "text stays concise and quotes whitespace");
  }
  {
    const { logs } = withStdoutTTY(false, () => withEnv({ SHADE_TREE_LOG_FORMAT: "pretty" }, () =>
      capture(() => createLogger("node").info("cover ready", { port: 8443 }))));
    ok(/^\d{2}:\d{2}:\d{2} INF node\s+cover ready port=8443$/.test(logs[0]),
      "pretty includes time, level, component, message, and fields");
  }

  console.log("\nlevels and sinks:");
  {
    ok(resolveLogLevel({ SHADE_TREE_LOG_LEVEL: "DEBUG" }) === "debug", "level parsing is case-insensitive");
    ok(resolveLogLevel({ SHADE_TREE_LOG_LEVEL: "bogus" }) === "info", "invalid level falls back to info");
    ok(!isLogLevelEnabled("debug", { SHADE_TREE_LOG_LEVEL: "info" })
      && isLogLevelEnabled("warn", { SHADE_TREE_LOG_LEVEL: "info" }), "level threshold comparison is correct");
  }
  {
    const output = withEnv({ SHADE_TREE_LOG_FORMAT: "text", SHADE_TREE_LOG_LEVEL: "debug" }, () =>
      capture(() => { log.debug("d"); log.info("i"); log.warn("w"); log.error("e"); }));
    ok(output.logs.join(",") === "d,i", "debug and info use console.log");
    ok(output.warns[0] === "w", "warn uses console.warn");
    ok(output.errors[0] === "e", "error uses console.error");
  }
  {
    const output = withEnv({ SHADE_TREE_LOG_LEVEL: "error" }, () =>
      capture(() => { log.debug("d"); log.info("i"); log.warn("w"); log.error("e"); }));
    ok(output.logs.length === 0 && output.warns.length === 0 && output.errors.length === 1,
      "error threshold suppresses lower levels");
  }
  {
    const output = withEnv({ SHADE_TREE_LOG_LEVEL: "off" }, () =>
      capture(() => { log.debug("d"); log.info("i"); log.warn("w"); log.error("e"); }));
    ok(output.logs.length + output.warns.length + output.errors.length === 0, "off suppresses every level");
  }

  console.log("\nstructured context:");
  {
    const logger = createLogger("node", { network: "mainnet", component: "spoofed" })
      .child({ peerClass: "invited" });
    const { logs } = withEnv({ SHADE_TREE_LOG_FORMAT: "json" }, () => capture(() =>
      logger.info("ready", {
        network: "testnet",
        ts: "forged",
        level: "error",
        msg: "forged",
        component: "forged",
      })));
    const record = parse(logs[0]);
    ok(record?.component === "node" && record?.msg === "ready" && record?.level === "info",
      "caller fields cannot replace reserved JSON fields");
    ok(record?.network === "testnet" && record?.peerClass === "invited",
      "child and call fields compose with call fields taking precedence");
    ok(Number.isFinite(Date.parse(record?.ts)), "structured record has a valid timestamp");
    ok(logger.isEnabled("info"), "component logger exposes the active threshold");
  }

  console.log("\nredaction:");
  {
    const { logs } = withEnv({ SHADE_TREE_LOG_FORMAT: "json" }, () => capture(() =>
      createLogger("proxy").info(
        "dial https://alice:hunter2@example.test/?token=message-token",
        {
          SHADE_TREE_SECRET: "tree-secret",
          api_key: "api-secret",
          "x-api-key": "header-api-secret",
          nested: {
            private_key: "private-secret",
            Authorization: "Bearer bearer-secret",
            url: "https://bob:password@example.test/path?api-key=query-secret",
          },
        },
      )));
    const raw = logs[0];
    const record = parse(raw);
    ok(record?.SHADE_TREE_SECRET === "[redacted]" && record?.api_key === "[redacted]" && record?.["x-api-key"] === "[redacted]"
      && record?.nested?.private_key === "[redacted]", "environment, snake-case, and nested secret fields are redacted");
    ok(record?.nested?.Authorization === "[redacted]", "authorization fields are redacted before bearer text is considered");
    ok(record?.msg.includes("https://[redacted]@example.test/[redacted]")
      && !record?.msg.includes("token="), "credentials and complete URL paths or queries are scrubbed from messages");
    ok(record?.nested?.url.includes("https://[redacted]@example.test/[redacted]")
      && !record?.nested?.url.includes("api-key="), "credentials are scrubbed recursively in field strings");
    ok(!raw.includes("hunter2") && !raw.includes("tree-secret") && !raw.includes("api-secret") && !raw.includes("header-api-secret")
      && !raw.includes("private-secret") && !raw.includes("bearer-secret")
      && !raw.includes("query-secret") && !raw.includes("message-token"), "serialized output contains none of the supplied secrets");
  }
  {
    const pathKey = "RPC_PATH_KEY_SENTINEL_7f31c9";
    const { errors } = withEnv({ SHADE_TREE_LOG_FORMAT: "json" }, () => capture(() =>
      createLogger("node").error("root refresh failed", {
        err: new Error(`request to https://rpc.example/v3/${pathKey} failed`),
      })));
    const raw = errors[0];
    const record = parse(raw);
    ok(record?.err === "request to https://rpc.example/[redacted] failed",
      "opaque RPC URL paths are removed from Error fields while the origin remains useful");
    ok(!raw.includes(pathKey) && !raw.includes("/v3/"),
      "an RPC path-key sentinel cannot reach serialized operator logs");
  }

  console.log("\nserialization safety:");
  {
    const circular = { value: 1 };
    circular.self = circular;
    let threw = false;
    let record;
    withEnv({ SHADE_TREE_LOG_FORMAT: "json" }, () => {
      const { logs } = capture(() => {
        try { log.info("safe", { circular, epoch: 7n, error: new Error("Bearer error-token") }); }
        catch { threw = true; }
      });
      record = parse(logs[0]);
    });
    ok(!threw && record?.circular?.self === "[Circular]", "circular input is replaced without throwing");
    ok(record?.epoch === "7", "bigint is serialized as a string");
    ok(record?.error === "Bearer [redacted]", "Error values are reduced to a scrubbed message");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: log selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
