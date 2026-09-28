// NAME-7 wire-string freeze (fast lane, no Tor, no chain): every string below is signed, hashed,
// proved or compiled into a deployed contract, so it keeps its "Shade Tree"/"grove" spelling through
// the ShadeNet rename. A find-and-replace that touches one of them breaks signatures, proofs or the
// live StakedReputationSet without any other test noticing on the renamed side alone.
//
// Each entry pins the exact literal in every source file that DEFINES or EMITS it (tests and golden
// vectors are pinned too, so both halves of a round-trip can't drift together). The only legitimate
// way to change an entry is a versioned protocol bump (v5) or a fresh contract deploy: edit this list
// in the same PR, keep the old value as a PRE_V5_* observer constant, and say so in CHANGELOG.
//
//   node test/wire-freeze.selftest.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CAPS_DOMAIN, PRE_V4_CAPS_DOMAIN, ADMIT_PATHS } from "../lib/directory.mjs";
import { RECEIPT_DOMAIN } from "../lib/receipt.mjs";
import { GROVE_SCHEMA, GROVE_ATTESTATION_KEY_ID } from "../lib/public-grove.mjs";
import {
  GROVE_RELAY_SCHEMA, RELAY_COUNTER_SCHEMA, RELAY_REPORT_STATE_SCHEMA, RELAY_REPORT_SCHEMA,
  RELAY_AGGREGATE_SCHEMA, RELAY_ELDER_STATE_SCHEMA,
} from "../lib/relay-telemetry.mjs";
import { GROVE_SETTLEMENT_SCHEMA } from "../lib/grove-onchain.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// [frozen literal as it appears in source, [files that must contain it byte for byte]]
const FROZEN = [
  // Exit / withdraw proof-context tags. The v4 tags "SHADE_TREE_EXIT" / "SHADE_TREE_WITHDRAW" were
  // compiled into the retired v4 set 0xEB67…4275; the ShadeNet contracts (M1, audit 2.2.1) bind
  // chain id, set address and leaf index under these tags, which are now compiled into every
  // ShadeNet deployment and bound into withdraw proofs. No code verifies the v4 tags any more.
  ['"SHADENET_EXIT"', [
    "contracts/StakedReputationSet.sol", "crates/shadenet-cli/src/member.rs",
    "testdata/gen-withdraw-proof.mjs", "test/StakedReputationSet.tiers.t.sol", "test/WithdrawVerifier.t.sol",
  ]],
  ['"SHADENET_WITHDRAW"', [
    "contracts/StakedReputationSet.sol", "crates/shadenet-cli/src/member.rs",
    "testdata/gen-withdraw-proof.mjs", "test/WithdrawVerifier.t.sol",
  ]],
  // RLN request signal: its hash is the circuit's public x.
  ["shade-tree:v4\\n", [
    "lib/rln.mjs", "crates/shadenet-proto/src/lib.rs", "crates/shadenet-proto/tests/conformance.rs",
    "testdata/vectors.json",
  ]],
  // Onion-signed and personal_sign domains.
  ["Shade Tree gateway capabilities v1\\n", [
    "lib/directory.mjs", "crates/shadenet-proto/src/lib.rs", "crates/shadenet-proto/tests/conformance.rs",
    "testdata/vectors.json",
  ]],
  ["Shade Tree gateway operator authorization\\nonion=", [
    "bootnode/announce.mjs", "crates/shadenet-proto/src/lib.rs", "testdata/vectors.json",
  ]],
  ["Shade Tree egress success receipt v1\\n", [
    "lib/receipt.mjs", "crates/shadenet-proto/src/lib.rs", "testdata/vectors.json",
  ]],
  ["RGOE gateway capabilities v1\\n", ["lib/directory.mjs"]],
  // HKDF info for member subkeys: changing it changes every derived secret and leaf.
  ['"shade-tree-subkey:v1"', ["lib/subkeys.mjs"]],
  // Rate-policy scope inside onion-signed caps and the bundled network record.
  ['"grove-v4"', [
    "lib/directory.mjs", "lib/network-record.mjs", "bootnode/heartbeat.mjs", "client/shade-tree-client.mjs",
    "deploy/v4/preflight.mjs", "crates/shadenet-cli/src/dircache.rs",
  ]],
  ['"scope": "grove-v4"', ["network/sepolia/deployment.json"]],
  // Signed caps `admits` values, in anonymity order.
  ['["invited", "staked", "paid"]', [
    "lib/directory.mjs", "lib/admission.mjs", "deploy/v4/preflight.mjs", "crates/shadenet-proto/src/lib.rs",
  ]],
  // Ed25519-signed public snapshot schemas and the pinned attestation key id.
  ['"shade-tree-public-grove-v1"', [
    "lib/public-grove.mjs", "docs/post/api/_grove-contract.mjs", "docs/post/grove/network.js",
    "docs/post/grove/network.fallback.json", "scripts/site-smoke.mjs",
  ]],
  ['"shade-tree-public-grove-v2"', [
    "lib/relay-telemetry.mjs", "docs/post/api/_grove-v2-contract.mjs", "docs/post/grove/network.js",
    "docs/post/openapi-v2.json", "scripts/site-smoke.mjs",
  ]],
  ["const: shade-tree-public-grove-v1", ["specs/data-api.openapi.yaml"]],
  ["const: shade-tree-public-grove-v2", ["specs/data-api.openapi.yaml"]],
  ['"grove-2026-08"', [
    "lib/public-grove.mjs", "docs/post/api/_grove-contract.mjs", "docs/post/api/_grove-v2-contract.mjs",
    "docs/post/grove/network.js", "docs/post/grove/network.fallback.json", "docs/post/openapi-v2.json",
  ]],
  ["const: grove-2026-08", ["specs/data-api.openapi.yaml"]],
  // Onion-signed relay telemetry and published settlement schemas.
  ['"shade-tree-relay-counter-v1"', ["lib/relay-telemetry.mjs"]],
  ['"shade-tree-relay-report-state-v1"', ["lib/relay-telemetry.mjs"]],
  ['"shade-tree-relay-report-v1"', ["lib/relay-telemetry.mjs"]],
  ['"shade-tree-relay-aggregate-v1"', ["lib/relay-telemetry.mjs"]],
  ['"shade-tree-relay-elder-state-v1"', ["lib/relay-telemetry.mjs"]],
  ['"shade-tree-registrar-settlements-v1"', ["lib/grove-onchain.mjs"]],
  ['"signed-registrar-chain-verified-v1"', [
    "lib/grove-onchain.mjs", "docs/post/api/_grove-onchain-contract.mjs", "docs/post/grove/onchain.js",
    "docs/post/openapi-v2.json",
  ]],
];

console.log("=== wire-string freeze: source pins ===");
const cache = new Map();
const read = (f) => {
  if (!cache.has(f)) cache.set(f, readFileSync(join(ROOT, f), "utf8"));
  return cache.get(f);
};
for (const [literal, files] of FROZEN) {
  for (const f of files) ok(read(f).includes(literal), `${f} keeps ${literal}`);
}

console.log("=== wire-string freeze: runtime values ===");
ok(CAPS_DOMAIN === "Shade Tree gateway capabilities v1\n", "CAPS_DOMAIN");
ok(PRE_V4_CAPS_DOMAIN === "RGOE gateway capabilities v1\n", "PRE_V4_CAPS_DOMAIN");
ok(RECEIPT_DOMAIN === "Shade Tree egress success receipt v1\n", "RECEIPT_DOMAIN");
ok(JSON.stringify(ADMIT_PATHS) === '["invited","staked","paid"]', "ADMIT_PATHS order");
ok(GROVE_SCHEMA === "shade-tree-public-grove-v1", "GROVE_SCHEMA");
ok(GROVE_RELAY_SCHEMA === "shade-tree-public-grove-v2", "GROVE_RELAY_SCHEMA");
ok(GROVE_ATTESTATION_KEY_ID === "grove-2026-08", "GROVE_ATTESTATION_KEY_ID");
ok(GROVE_SETTLEMENT_SCHEMA === "shade-tree-registrar-settlements-v1", "GROVE_SETTLEMENT_SCHEMA");
ok(RELAY_COUNTER_SCHEMA === "shade-tree-relay-counter-v1"
  && RELAY_REPORT_STATE_SCHEMA === "shade-tree-relay-report-state-v1"
  && RELAY_REPORT_SCHEMA === "shade-tree-relay-report-v1"
  && RELAY_AGGREGATE_SCHEMA === "shade-tree-relay-aggregate-v1"
  && RELAY_ELDER_STATE_SCHEMA === "shade-tree-relay-elder-state-v1", "relay telemetry schemas");

// Golden vectors: the signed messages must still start with the frozen domains.
const V = JSON.parse(read("testdata/vectors.json"));
ok(V.operatorAuthMessage?.startsWith("Shade Tree gateway operator authorization\nonion="), "vectors.operatorAuthMessage");

if (failures) {
  console.log(`\nFAIL: ${failures} frozen wire string(s) changed. These are signed, hashed or on chain; see the header.`);
  process.exit(1);
}
console.log("\nPASS: wire-string freeze");
