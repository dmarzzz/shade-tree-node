import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const workflow = readFileSync(join(root, ".github", "workflows", "hermes-e2e.yml"), "utf8");
const harness = readFileSync(join(root, "test", "hermes-e2e.sh"), "utf8");
const guide = readFileSync(join(root, "test", "HERMES-E2E.md"), "utf8");

assert.match(workflow, /^name: hermes-e2e$/m);
assert.match(workflow, /^\s+schedule:\n\s+- cron: "23 7 \* \* 1"$/m, "weekly schedule remains explicit");
assert.match(workflow, /^\s+workflow_dispatch:$/m, "manual dispatch remains available");
assert.match(workflow, /^\s+runs-on: ubuntu-latest$/m, "uses a disposable GitHub-hosted VM");
assert.match(workflow, /^\s+timeout-minutes: 30$/m, "live integration is bounded");
assert.match(workflow, /actions\/checkout@[0-9a-f]{40}/, "checkout action is commit-pinned");
assert.match(workflow, /actions\/setup-node@[0-9a-f]{40}/, "Node action is commit-pinned");
assert.match(workflow, /actions\/setup-python@[0-9a-f]{40}/, "Python action is commit-pinned");
assert.match(workflow, /HERMES_COMMIT: [0-9a-f]{40}/, "Hermes source is commit-pinned");
assert.match(workflow, /git\+https:\/\/github\.com\/NousResearch\/hermes-agent\.git@\$HERMES_COMMIT/);
assert.match(workflow, /cargo build --locked --manifest-path Cargo\.toml -p shadenet-cli --features live/, "builds the embedded-Arti Rust Proxy");
assert.match(workflow, /HERMES_E2E_RUST_BIN: \$\{\{ github\.workspace \}\}\/target\/debug\/shade-tree/, "passes the exact live binary to the harness");
assert.match(workflow, /node test\/hermes-openai-stub\.mjs/, "starts the deterministic model stub");
assert.match(workflow, /CUSTOM_BASE_URL: http:\/\/127\.0\.0\.1:18080\/v1/, "model stays on loopback");
assert.match(workflow, /npm run test:hermes/, "runs the real live harness");
assert.match(workflow, /for attempt in 1 2/, "Tor publication gets one bounded retry");
assert.doesNotMatch(workflow, /secrets\./, "recurring Hermes E2E requires no repository secrets");

assert.match(harness, /"\$RUST_SHADE_TREE" proxy/, "Hermes uses the Rust CONNECT Proxy");
assert.match(harness, /--onion "\$\{ONION\}:80"/, "the Rust Proxy dials the ephemeral onion");
assert.match(harness, /--identity "\$IDENTITY"/, "the Rust Proxy receives the ephemeral identity file");
assert.match(harness, /--SocksPort 0/, "system Tor publishes only the server-side onion");
assert.match(harness, /HERMES_E2E_RUN_ATTEMPTS:-3/, "ephemeral onion requests get bounded retries");
assert.match(harness, /gateway_pass_count/, "each successful child request is corroborated immediately by the node metric");
assert.doesNotMatch(harness, /client\/shim\.mjs/, "the recurring path does not fall back to the JS/SOCKS Proxy");
assert.doesNotMatch(harness, /SHADE_TREE_TOR_PORT/, "the client side has no system Tor or SOCKS dependency");
assert.match(guide, /embedded Arti/, "the operator guide names the tested client transport");

console.log("PASS: recurring Hermes workflow uses the hosted Rust Proxy, embedded Arti, and no credentials");
