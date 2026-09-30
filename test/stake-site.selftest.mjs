import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CHAIN_ID,
  CONTRACT,
  DEFAULT_LIMIT,
  TIERS,
  deriveIdentity,
  describeMember,
  finalityEstimate,
  identityBytes,
  parseCommitment,
  parseIdentityFile,
  registerCommitment,
  describeBalance,
} from "../site-src/stake.mjs";
import { CLIENT_RELEASE, SITE_NETWORK, formatEth, formatDuration } from "../site-src/profile.mjs";
import { explainError, formatExplanation } from "../site-src/stake-errors.mjs";
import { describeSetSize } from "../site-src/stake-live.mjs";
import { PROVER_MB, renderStakePage } from "../site-src/stake-page.mjs";
import { GET as stakeHead, readStakeHead, STAKE_HEAD_SCHEMA } from "../docs/post/api/stake-head.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const deployment = JSON.parse(readFileSync(join(ROOT, `network/${SITE_NETWORK}/deployment.json`), "utf8"));
const html = readFileSync(join(ROOT, "docs/post/stake/index.html"), "utf8");
const source = readFileSync(join(ROOT, "site-src/stake.mjs"), "utf8");
const sdkStaking = readFileSync(join(ROOT, "packages/sdk/src/staking.mjs"), "utf8");
const liveSource = readFileSync(join(ROOT, "site-src/stake-live.mjs"), "utf8");
const pageSource = readFileSync(join(ROOT, "site-src/stake-page.mjs"), "utf8");
const bundle = readFileSync(join(ROOT, "docs/post/stake/stake.js"));
const checks = [];
const check = (name, condition) => {
  assert.ok(condition, name);
  checks.push(name);
  console.log(`  ok   ${name}`);
};

const staked = deployment.admission.roots.staked;
check(`browser profile is pinned to the ${SITE_NETWORK} deployment record`, CHAIN_ID === BigInt(staked.chainId)
  && CONTRACT.toLowerCase() === staked.contract.toLowerCase()
  && DEFAULT_LIMIT === BigInt(staked.defaultLimit)
  && TIERS.length === staked.tiers.length
  && TIERS.every((tier, i) => tier.limit === BigInt(staked.tiers[i].limit) && tier.bondWei === BigInt(staked.tiers[i].bondWei)));

check("formatting is exact for wei and whole durations", formatEth(100000000000000000n) === "0.1" && formatEth(800000000000000000n) === "0.8"
  && formatEth(1250000000000000000n) === "1.25" && formatEth(10n ** 18n) === "1" && formatDuration(86400) === "24 hours" && formatDuration(60) === "1 minute");

const vector = await deriveIdentity(Uint8Array.from({ length: 32 }, () => 0x5a));
check("browser identity derivation matches the Rust and Semaphore-v3 vector", vector.identitySecret === "619880168657502627082950702222527535803368023538932999730878823680368560389"
  && vector.leaf === "15422591461559048085568001683323977812416390282127809084852072421595506429792"
  && vector.limit === 1);
check("downloaded identity round-trips without changing its public leaf", parseIdentityFile(identityBytes(vector)).leaf === vector.leaf);
const tier8 = await deriveIdentity(Uint8Array.from({ length: 32 }, () => 0x5a), 8n);
check("every offered tier derives its own leaf from the same secret", tier8.limit === 8 && tier8.identitySecret === vector.identitySecret && tier8.leaf !== vector.leaf
  && parseIdentityFile(identityBytes(tier8)).limit === 8);
await assert.rejects(() => deriveIdentity(new Uint8Array(32), 3n));
for (const [name, malformed] of [
  ["tier not offered", { ...vector, limit: 3 }],
  ["mismatched leaf", { ...vector, leaf: "1" }],
  ["tier swapped without leaf", { ...vector, limit: 8 }],
  ["extra secret field", { ...vector, appSecret: "1" }],
]) {
  assert.throws(() => parseIdentityFile(JSON.stringify(malformed)), undefined, name);
}
check("identity import rejects unoffered tiers, mismatched leaves, and extra fields", true);
const idcAbi = staked.registerInput === "identityCommitment";
check(`register takes the ${idcAbi ? "identity commitment" : "leaf"} under the current record's ABI`, idcAbi
  ? (registerCommitment(vector) !== vector.leaf && /^\d+$/.test(registerCommitment(vector)))
  : registerCommitment(vector) === vector.leaf);
assert.throws(() => parseCommitment("0"));
assert.throws(() => parseCommitment("01"));
assert.throws(() => parseCommitment("not-a-field"));
check("sponsor commitments are canonical non-zero field elements", parseCommitment(vector.leaf) === vector.leaf);

check("member status covers pending, active, exiting, withdrawable and unregistered (SDK states)", describeMember({ state: "active", limit: 1, finalized: false, now: 0 }).state === "pending"
  && describeMember({ state: "active", limit: 1, finalized: true, now: 0 }).state === "active"
  && describeMember({ state: "exiting", limit: 1, withdrawableAt: "1970-01-01T02:00:00Z", now: 0 }).state === "exiting"
  && describeMember({ state: "withdrawable", limit: 1, withdrawableAt: "1970-01-01T00:00:10Z", now: 20 }).state === "withdrawable"
  && describeMember({ state: "none", limit: 0, withdrawableAt: null, now: 0 }).state === "unregistered");
check("finality countdown counts remaining slots", finalityEstimate(110, 100).seconds === 120 && finalityEstimate(100, 105).final);
check("anonymity-set disclosure is honest at zero and small sizes", /0 staked members today/.test(describeSetSize(0)) && /among 3/.test(describeSetSize(3)) && describeSetSize(-1) === null);

// The page is generated from the record: every tier's bond appears, and no bond or address is typed by hand.
check("Get access page shows every tier from the record, twice (member and sponsor)", TIERS.every((tier) => (html.match(new RegExp(`<span class="tier-name">tier ${tier.limit}</span>`, "g")) || []).length === 2 && html.includes(`${formatEth(tier.bondWei)} ETH`)));
check("page template hard-codes no bond, contract, rate or unbonding value", !/0\.1 |0\.8 |0\.001 |0x[0-9a-fA-F]{40}|40 MiB|60-second|24 hours|86400|41943040/.test(pageSource));
check("the static page promises only the privacy boundary it implements", /No identity API exists/.test(html)
  && /Loading any website can expose your IP/.test(html)
  && /wallet, amount, commitment, and timing are public/.test(html)
  && /Misuse can slash your sponsored bond/.test(html)
  && /data-live-set/.test(html));
check("the page covers tiers, funding, member, sponsor, recovery, hand-off, leave and FAQ", /Choose a tier/.test(html)
  && new RegExp(`No ${deployment.admission.roots.staked.chainId === 11155111 ? "Sepolia" : "chain"} ETH\\? Two ways in`).test(html)
  && /data-mode="member"/.test(html)
  && /data-mode="sponsor"/.test(html)
  && /data-sponsor-tier/.test(html)
  && /data-download-identity/.test(html)
  && /data-recovery-check/.test(html)
  && /data-rail-step="handoff"/.test(html)
  && /chmod 600 ~\/.config\/shadenet\/identity\.json/.test(html)
  && /shadenet status --wait/.test(html)
  && /shadenet run --no-proxy/.test(html)
  && /hermes mcp add shadenet --command shadenet --args mcp/.test(html)
  && /claude mcp add shadenet -- shadenet mcp/.test(html)
  && /docker compose up -d/.test(html)
  && /@shadenet\/sdk/.test(html)
  && /shadenet exit-member/.test(html)
  && /shadenet withdraw-member/.test(html)
  && /<details>/.test(html)
  && /research preview/i.test(html));
check("install lines pin the newest release that ships the shadenet binary", new RegExp(`SHADENET_VERSION=${CLIENT_RELEASE.replace(/\./g, "\\.")} sh`).test(html) && /^v\d+\.\d+\.\d+/.test(CLIENT_RELEASE));
check("hand-off commands carry the identity file name and the prover states its size", (html.match(/data-file-name/g) || []).length >= 3
  && new RegExp(`<span data-prover-mb>${PROVER_MB}</span> MB`).test(html) && Number(PROVER_MB) > 0 && Number(PROVER_MB) < 5);
check("hand-off tabs are a keyboard-operable tablist with one panel per client", (html.match(/role="tab"/g) || []).length === 5 && (html.match(/role="tabpanel"/g) || []).length === 5 && /role="tablist"/.test(html));
check("the page says once, plainly, that ShadeNet is not Shade Network or Shade Protocol", /ShadeNet is not affiliated with Shade Network, Shade Protocol/.test(html) && !/Shade Net\b/.test(html));
check("every step has a rail entry and a panel", ["tier", "identity", "save", "stake"].every((step) => html.includes(`data-step-panel="${step}"`) && html.includes(`data-rail-step="${step}"`)));
check("errors use an assertive alert region and progress a polite status", /data-alert role="alert"/.test(html) && /data-status role="status" aria-live="polite"/.test(html));
check("the recovery confirmation is a deliberate click, never auto-ticked", !/recoveryCheck\.checked = true/.test(source));
const balanceOk = describeBalance({ balanceWei: 10n ** 18n, tier: TIERS[0], gasPriceWei: 10n ** 9n });
const balanceShort = describeBalance({ balanceWei: 1n, tier: TIERS[0], gasPriceWei: 10n ** 9n });
check("the wallet's balance is judged against bond plus gas before any stake is attempted", balanceOk.enough && /enough for tier/.test(balanceOk.message)
  && !balanceShort.enough && /more/.test(balanceShort.message) && /sponsor/.test(balanceShort.message) && /readBalance\(\)/.test(source));
const explained = [
  [{ code: 4001, message: "User rejected the request." }, /cancelled in the wallet/],
  [{ code: -32002, message: "Request of type 'wallet_requestPermissions' already pending" }, /already has a request open/],
  [new Error("Wallet is on chain 1; Sepolia (11155111) is required."), /not on Sepolia/],
  [{ message: "insufficient funds for gas * price + value" }, /Not enough Sepolia ETH/],
  [{ message: "transaction 0xab reverted" }, /rejected the transaction/],
  [{ message: "contract bond for tier 1 is 5 wei, the record says 6; refusing to send" }, /differs from the number this page shows/],
  [{ message: "this commitment is exiting and cannot be registered again yet" }, /still unbonding/],
  [new Error("No compatible Ethereum wallet was found in this browser."), /No Ethereum wallet/],
  [{ message: "RPC eth_call failed: Failed to fetch" }, /Could not reach Sepolia/],
  [{ message: "failed to load /stake/zk/withdraw.wasm" }, /prover/],
  [{ message: "This canopy offers tiers 1 and 8; limit 3 is not one of them." }, /offers tiers/],
];
check("every wallet and SDK failure gets a plain sentence and a next step", explained.every(([error, expected]) => {
  const view = explainError(error, { chainName: "Sepolia", need: "0.001 ETH" });
  return expected.test(formatExplanation(view)) && typeof view.text === "string" && view.text.length > 0;
}) && /fail\(error/.test(source) && !/announce\(error\.message/.test(source));
check("only identities created in this tab can stake", /state\.imported/.test(source) && /memberBlocked = state\.mode === "member" && \(!saved \|\| state\.imported\)/.test(source));
check("identity state is never persisted or sent through a site API", !/localStorage|sessionStorage|indexedDB|fetch\s*\(|XMLHttpRequest|sendBeacon|analytics/i.test(source));
check("the live module fetches only fixed aggregate URLs and never touches identity or wallet state",
  !/identity|leaf|commitment|ethereum|account|localStorage|sessionStorage/i.test(liveSource.replace(/^\/\/.*$/gm, ""))
  && (liveSource.match(/fetch\(/g) || []).length === 1
  && /"\/api\/v1\/data\/stake\/sepolia\/head"/.test(liveSource)
  && /"\/api\/v1\/data\/grove\/sepolia\/head"/.test(liveSource)
  && /credentials: "omit"/.test(liveSource));
check("wallet preflight (SDK) pins chain, code, bond, active state, simulation, gas, and balance", [
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
].every((needle) => sdkStaking.includes(needle)) && /bond !== tier\.bondWei/.test(sdkStaking) && /createStaking\(/.test(source));
check("the stake entry stays small", bundle.length < 150_000);
check("rendering is deterministic", renderStakePage() === renderStakePage());

const build = spawnSync(process.execPath, [join(ROOT, "scripts/build-stake-site.mjs"), "--check"], { encoding: "utf8" });
check("committed page, bundle, API profile and shared nav are reproducible from reviewed source", build.status === 0);

const vercel = JSON.parse(readFileSync(join(ROOT, "docs/post/vercel.json"), "utf8"));
const cspFor = (source) => vercel.headers.find((h) => h.source === source)?.headers.find((x) => x.key === "Content-Security-Policy")?.value || "";
check("only /stake/ may compile WASM for the prover; the rest of the site keeps the strict CSP",
  /'wasm-unsafe-eval'/.test(cspFor("/stake/(.*)")) && /'wasm-unsafe-eval'/.test(cspFor("/stake"))
  && !/wasm-unsafe-eval|unsafe-eval'/.test(cspFor("/(.*)")) && !/'unsafe-eval'/.test(cspFor("/stake/(.*)")) && /connect-src 'self'/.test(cspFor("/stake/(.*)")));
const lock = JSON.parse(readFileSync(join(ROOT, "testdata/zk-artifacts.lock.json"), "utf8"));
const { createHash } = await import("node:crypto");
check("the served withdraw circuit is byte-identical to the locked artifacts", [
  ["docs/post/stake/zk/withdraw.wasm", "circuits/rln/withdraw.wasm"],
  ["docs/post/stake/zk/withdraw_final.zkey", "circuits/rln/withdraw_final.zkey"],
].every(([served, locked]) => createHash("sha256").update(readFileSync(join(ROOT, served))).digest("hex") === lock.artifacts[locked].sha256));
check("snarkjs stays out of the entry bundle; it loads only for exit or withdraw", /await import\("\.\/chunks\/browser\.esm-[A-Z0-9]+\.js"\)/.test(bundle.toString()) && !/Groth16 verification|bn128/.test(bundle.toString()) && bundle.length < 150_000);

// Same-origin status API: no parameters accepted, aggregate reads only, fails closed.
const calls = [];
const fakeRpc = async (method, params) => {
  calls.push([method, params]);
  if (method === "eth_blockNumber") return "0x100";
  if (method === "eth_getBlockByNumber") return { number: "0xf0" };
  if (method === "eth_call") {
    const data = params[0].data;
    if (data === "0xfc7e9c6f") return `0x${(5n).toString(16).padStart(64, "0")}`;
    if (data === "0x4331ed1f") return `0x${(4n).toString(16).padStart(64, "0")}`;
    const limit = BigInt(`0x${data.slice(10)}`);
    return `0x${TIERS.find((t) => t.limit === limit).bondWei.toString(16).padStart(64, "0")}`;
  }
  throw new Error("unexpected");
};
const head = await readStakeHead(fakeRpc, new Date("2026-09-28T00:00:00Z"));
check("stake head reports finalized set size, blocks and on-chain bonds", head.schema === STAKE_HEAD_SCHEMA && head.activeCount === 4 && head.nextIndex === 5
  && head.headBlock === 256 && head.finalizedBlock === 240 && head.tiers.every((t) => t.onChainBondWei === t.bondWei));
check("set size is read at the finalized block", calls.filter(([m, p]) => m === "eth_call" && ["0xfc7e9c6f", "0x4331ed1f"].includes(p[0].data)).every(([, p]) => p[1] === "finalized"));
const rejected = await stakeHead(new Request("https://example.test/api/stake-head?commitment=1"), { rpc: fakeRpc });
check("stake head refuses any query string, so it never receives a commitment", rejected.status === 400);
const failing = await stakeHead(new Request("https://example.test/api/stake-head"), { rpc: async () => { throw new Error("down"); } });
check("stake head fails closed with 503 and no-store", failing.status === 503 && failing.headers.get("cache-control") === "no-store");

console.log(`PASS: Get access page selftest (${checks.length} checks)`);
