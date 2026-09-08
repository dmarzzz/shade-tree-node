import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import {
  BOND,
  CHAIN_ID,
  CONTRACT,
  LIMIT,
  deriveIdentity,
  identityBytes,
  parseCommitment,
  parseIdentityFile,
} from "../site-src/stake.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const deployment = JSON.parse(readFileSync(join(ROOT, "network/sepolia/deployment.json"), "utf8"));
const html = readFileSync(join(ROOT, "docs/post/stake/index.html"), "utf8");
const source = readFileSync(join(ROOT, "site-src/stake.mjs"), "utf8");
const bundle = readFileSync(join(ROOT, "docs/post/stake/stake.js"));
const checks = [];
const check = (name, condition) => {
  assert.ok(condition, name);
  checks.push(name);
  console.log(`  ok   ${name}`);
};

const staked = deployment.admission.roots.staked;
check("browser profile is pinned to the live deployment record", CHAIN_ID === BigInt(staked.chainId)
  && CONTRACT.toLowerCase() === staked.contract.toLowerCase()
  && LIMIT === BigInt(staked.defaultLimit)
  && BOND === BigInt(staked.tiers.find((tier) => tier.limit === Number(LIMIT)).bondWei));

const vector = await deriveIdentity(Uint8Array.from({ length: 32 }, () => 0x5a));
check("browser identity derivation matches the Rust and Semaphore-v3 vector", vector.identitySecret === "619880168657502627082950702222527535803368023538932999730878823680368560389"
  && vector.leaf === "15422591461559048085568001683323977812416390282127809084852072421595506429792"
  && vector.limit === 1);
check("downloaded identity round-trips without changing its public leaf", parseIdentityFile(identityBytes(vector)).leaf === vector.leaf);
for (const [name, malformed] of [
  ["wrong tier", { ...vector, limit: 8 }],
  ["mismatched leaf", { ...vector, leaf: "1" }],
  ["extra secret field", { ...vector, appSecret: "1" }],
]) {
  assert.throws(() => parseIdentityFile(JSON.stringify(malformed)), undefined, name);
}
check("identity import rejects mismatched tiers, leaves, and extra fields", true);
assert.throws(() => parseCommitment("0"));
assert.throws(() => parseCommitment("01"));
assert.throws(() => parseCommitment("not-a-field"));
check("sponsor commitments are canonical non-zero field elements", parseCommitment(vector.leaf) === vector.leaf);

check("the static page promises only the privacy boundary it implements", /No identity API exists/.test(html)
  && /Loading any website can expose your IP/.test(html)
  && /wallet, amount, commitment, and timing are public/.test(html)
  && /Misuse can slash your sponsored bond/.test(html));
check("the page exposes member, sponsor, recovery, and agent handoff paths", /data-mode="member"/.test(html)
  && /data-mode="sponsor"/.test(html)
  && /data-download-identity/.test(html)
  && /data-recovery-check/.test(html)
  && /shade-tree enroll --out identity\.json/.test(html)
  && /register-member --identity identity\.json/.test(html)
  && /member-status --identity identity\.json --json/.test(html)
  && /private, proof-authorized exit/.test(html));
check("identity state is never persisted or sent through a site API", !/localStorage|sessionStorage|indexedDB|fetch\s*\(|XMLHttpRequest|sendBeacon|analytics/i.test(source));
check("wallet preflight pins chain, code, bond, active state, simulation, gas, and balance", [
  "wallet_switchEthereumChain",
  "eth_chainId",
  "eth_getCode",
  "bondFor",
  "isActive",
  "limitOf",
  "eth_estimateGas",
  "eth_getBalance",
  "eth_call",
  "eth_sendTransaction",
].every((needle) => source.includes(needle)) && /bond !== BOND/.test(source));

const rebuilt = await build({
  entryPoints: [join(ROOT, "site-src/stake.mjs")],
  bundle: true,
  format: "esm",
  minify: true,
  legalComments: "eof",
  sourcemap: false,
  target: ["chrome109", "firefox115", "safari16.4"],
  write: false,
});
check("committed browser bundle is reproducible from reviewed source", Buffer.compare(bundle, Buffer.from(rebuilt.outputFiles[0].contents)) === 0);

console.log(`PASS: private staking site selftest (${checks.length} checks)`);
