// Self-test for the interactive operator banner.
//
//   node packages/node/lib/operator-ui.selftest.mjs

import {
  printOperatorBanner,
  renderOperatorBanner,
  resolveBannerMode,
  SHADE_TREE_ART,
  shouldShowBanner,
} from "./operator-ui.mjs";

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else {
    console.log(`  FAIL ${message}`);
    failures++;
  }
};

const terminalEnv = Object.freeze({
  SHADE_TREE_BANNER: "auto",
  SHADE_TREE_LOG_FORMAT: "auto",
  SHADE_TREE_LOG_LEVEL: "info",
  TERM: "xterm-256color",
});

function main() {
  console.log("banner policy:");
  ok(resolveBannerMode({ SHADE_TREE_BANNER: "TRUE" }) === "always", "truthy alias resolves to always");
  ok(resolveBannerMode({ SHADE_TREE_BANNER: "off" }) === "never", "falsey alias resolves to never");
  ok(resolveBannerMode({ SHADE_TREE_BANNER: "unexpected" }) === "auto", "unknown mode resolves to auto");
  ok(shouldShowBanner({ env: terminalEnv, stream: { isTTY: true } }), "auto shows on an interactive pretty terminal");
  ok(!shouldShowBanner({ env: terminalEnv, stream: { isTTY: false } }), "auto stays quiet off a TTY");
  ok(!shouldShowBanner({ env: { ...terminalEnv, CI: "1" }, stream: { isTTY: true } }), "auto stays quiet in CI");
  ok(!shouldShowBanner({ env: { ...terminalEnv, TERM: "dumb" }, stream: { isTTY: true } }), "auto stays quiet on a dumb terminal");
  ok(shouldShowBanner({
    env: { ...terminalEnv, SHADE_TREE_BANNER: "always", SHADE_TREE_LOG_FORMAT: "text" },
    stream: { isTTY: false },
  }), "always forces art in a non-JSON stream");
  ok(!shouldShowBanner({
    env: { ...terminalEnv, SHADE_TREE_BANNER: "always", SHADE_TREE_LOG_FORMAT: "json" },
    stream: { isTTY: true },
  }), "JSON mode never mixes in banner art");
  ok(!shouldShowBanner({
    env: { ...terminalEnv, SHADE_TREE_BANNER: "never", SHADE_TREE_LOG_FORMAT: "pretty" },
    stream: { isTTY: true },
  }), "never suppresses banner art");
  ok(!shouldShowBanner({
    env: { ...terminalEnv, SHADE_TREE_BANNER: "always", SHADE_TREE_LOG_FORMAT: "text", SHADE_TREE_LOG_LEVEL: "warn" },
    stream: { isTTY: true },
  }), "banner is suppressed when info output is disabled");

  console.log("\nrendering:");
  {
    const banner = renderOperatorBanner({
      role: "node",
      rows: [
        ["metrics", "127.0.0.1:9101"],
        ["bad\nlabel", "value\twith\x1bescape"],
      ],
    });
    ok(SHADE_TREE_ART.every((line) => banner.includes(line)), "render contains the complete shade tree");
    ok(banner.includes("NODE | cover ready"), "known role gets its themed ready state");
    ok(banner.includes("metrics    127.0.0.1:9101"), "operator rows render as compact label/value pairs");
    ok(!banner.includes("bad\nlabel") && !banner.includes("\t") && !banner.includes("\x1b"),
      "row cells cannot inject lines, tabs, or terminal escapes");
    ok(banner.endsWith("\n"), "banner ends at a clean line boundary");
  }
  {
    const longValue = "x".repeat(140);
    const banner = renderOperatorBanner({ role: "custom\nrole", state: "green\x1b", rows: [["field", longValue]] });
    ok(banner.includes("CUSTOM ROLE | green "), "role and state controls are sanitized");
    ok(!banner.includes(longValue), "operator cells are bounded in length");
  }

  console.log("\nprinting:");
  {
    let output = "";
    const stream = { isTTY: false, write: (chunk) => { output += chunk; } };
    const shown = printOperatorBanner({
      role: "proxy",
      env: { ...terminalEnv, SHADE_TREE_BANNER: "always", SHADE_TREE_LOG_FORMAT: "text" },
      stream,
    });
    ok(shown && output.includes("PROXY | shade ready"), "print writes the rendered role banner and reports success");
  }
  {
    let writes = 0;
    const stream = { isTTY: false, write: () => { writes++; } };
    const shown = printOperatorBanner({ role: "elder", env: terminalEnv, stream });
    ok(!shown && writes === 0, "hidden banner performs no stream write");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: operator UI selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
