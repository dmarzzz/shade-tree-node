import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CHAIN_ID,
  CONTRACT,
  DEFAULT_LIMIT,
  STORAGE_KEY,
  TIERS,
  approxEth,
  describeBalance,
  describeMember,
  finalityEstimate,
  memberLeaf,
  parseCommitment,
  readCommitmentInput,
  stakeLink,
} from "../site-src/stake.mjs";
import { CLIENT_RELEASE, SITE_NETWORK, formatEth, formatDuration } from "../site-src/profile.mjs";
import { explainError, formatExplanation } from "../site-src/stake-errors.mjs";
import { describeSetSize } from "../site-src/stake-live.mjs";
import { COMMITMENT_PRINTED_FROM, PREVIEW_STATEMENT, PRIVACY_NOTE_HTML, agentBriefHtml, describeSlot, releaseAtLeast, renderStakePage } from "../site-src/stake-page.mjs";
import { deriveIdentity, identityCommitmentOf } from "../packages/node/lib/identity-core.mjs";
import { GET as stakeHead, readStakeHead, STAKE_HEAD_SCHEMA } from "../docs/post/api/stake-head.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const deployment = JSON.parse(readFileSync(join(ROOT, `network/${SITE_NETWORK}/deployment.json`), "utf8"));
const html = readFileSync(join(ROOT, "docs/post/stake/index.html"), "utf8");
const css = readFileSync(join(ROOT, "docs/post/stake/stake.css"), "utf8");
const landing = readFileSync(join(ROOT, "docs/post/index.html"), "utf8");
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
const count = (text, pattern) => (text.match(pattern) || []).length;
const throwsWith = (fn, pattern) => {
  try { fn(); } catch (error) { return pattern.test(error.message); }
  return false;
};

const staked = deployment.admission.roots.staked;
check(`browser profile is pinned to the ${SITE_NETWORK} deployment record`, CHAIN_ID === BigInt(staked.chainId)
  && CONTRACT.toLowerCase() === staked.contract.toLowerCase()
  && DEFAULT_LIMIT === BigInt(staked.defaultLimit)
  && TIERS.length === staked.tiers.length
  && TIERS.every((tier, i) => tier.limit === BigInt(staked.tiers[i].limit) && tier.bondWei === BigInt(staked.tiers[i].bondWei)));

check("formatting is exact for wei and whole durations", formatEth(100000000000000000n) === "0.1" && formatEth(800000000000000000n) === "0.8"
  && formatEth(1250000000000000000n) === "1.25" && formatEth(10n ** 18n) === "1" && formatDuration(86400) === "24 hours" && formatDuration(60) === "1 minute");

// The page takes one public value: the identity commitment, Poseidon1(identitySecret). The contract
// derives the member leaf from it. The shared Rust and Semaphore-v3 vector ties the two together.
const vector = await deriveIdentity(Uint8Array.from({ length: 32 }, () => 0x5a), 1);
const IDC = identityCommitmentOf(vector.identitySecret).toString();
const LEAF_1 = vector.leaf;
check("the leaf the page expects on chain is the one the Rust and Semaphore-v3 vector derives", vector.leaf === "15422591461559048085568001683323977812416390282127809084852072421595506429792"
  && IDC === "14692468883281903598588342006319433011389983428096670545506672469914954128114"
  && IDC !== LEAF_1);
const idcAbi = staked.registerInput === "identityCommitment";
check(`register takes the ${idcAbi ? "identity commitment" : "leaf"} under the current record's ABI`, idcAbi
  ? memberLeaf(IDC, 1) === LEAF_1
  : memberLeaf(LEAF_1, 1) === LEAF_1);
assert.throws(() => parseCommitment("0"));
assert.throws(() => parseCommitment("01"));
assert.throws(() => parseCommitment("not-a-field"));
check("identity commitments are canonical non-zero field elements", parseCommitment(IDC) === IDC);

const firstLimit = Number(TIERS[0].limit);
const firstLeaf = memberLeaf(IDC, firstLimit);
const bare = readCommitmentInput(`  ${IDC.slice(0, 40)}\n${IDC.slice(40)} `);
check("a pasted identity commitment is read through spaces and line breaks", bare.commitment === IDC && bare.leaf === null && bare.limit === null);
check("the lines shadenet init prints are read by their labels, and a leaf beside the commitment is checked", (() => {
  const parsed = readCommitmentInput(`  identity commitment ${IDC}\n  leaf ${firstLeaf} (tier ${firstLimit})`);
  return parsed.commitment === IDC && parsed.leaf === firstLeaf && parsed.limit === firstLimit;
})());
check("a leaf pasted alone is refused: staking it would lock the bond on a member nobody holds", throwsWith(() => readCommitmentInput(`leaf ${LEAF_1}`), /That is the leaf/)
  && throwsWith(() => readCommitmentInput(`  leaf ${LEAF_1}\n\nNext, stake this leaf: tier 1`), /That is the leaf/));
check("each malformed paste gets its own plain reason", throwsWith(() => readCommitmentInput(""), /Paste the identity commitment/)
  && throwsWith(() => readCommitmentInput(IDC.slice(0, 30)), /That is 30 digits\. The identity commitment has about 77/)
  && throwsWith(() => readCommitmentInput(`0x${BigInt(IDC).toString(16)}`), /decimal number shadenet init prints, without 0x/)
  && throwsWith(() => readCommitmentInput(`${IDC}x`), /other characters/)
  && throwsWith(() => readCommitmentInput(`0${IDC.slice(1)}`), /does not start with 0/)
  && throwsWith(() => readCommitmentInput(`${IDC}${IDC}`), /too large/)
  && throwsWith(() => readCommitmentInput("9".repeat(77)), /too large/));
const link = stakeLink({ commitment: IDC, limit: firstLimit, leaf: firstLeaf }, "https://example.test/stake/");
check("a link carries the commitment, tier and leaf in the fragment, and reads back to the same values", link === `https://example.test/stake/#c=${IDC}&limit=${firstLimit}&leaf=${firstLeaf}`
  && JSON.stringify(readCommitmentInput(link)) === JSON.stringify({ commitment: IDC, limit: firstLimit, leaf: firstLeaf })
  && readCommitmentInput(`c=${IDC}`).commitment === IDC
  && readCommitmentInput(`c=${IDC}&leaf=${firstLeaf}`).limit === firstLimit
  && stakeLink({ commitment: IDC }) === `/stake/#c=${IDC}`);
check("a link whose leaf does not belong to its commitment, or whose tier is not offered, is refused", throwsWith(() => readCommitmentInput(`c=${IDC}&leaf=${IDC}`), /leaf does not match this identity commitment/)
  && throwsWith(() => readCommitmentInput(`c=${firstLeaf}&leaf=${IDC}`), /leaf does not match/)
  && throwsWith(() => readCommitmentInput(`c=${IDC}&limit=3`), /Tier 3 is not one of them/)
  && throwsWith(() => readCommitmentInput(`c=123`), /That is 3 digits/));

check("member status covers pending, active, exiting, withdrawable and unregistered (SDK states)", describeMember({ state: "active", limit: 1, finalized: false, now: 0 }).state === "pending"
  && describeMember({ state: "active", limit: 1, finalized: true, now: 0 }).state === "active"
  && /^Admitted at tier 1/.test(describeMember({ state: "active", limit: 1, finalized: true, now: 0 }).message)
  && describeMember({ state: "exiting", limit: 1, withdrawableAt: "1970-01-01T02:00:00Z", now: 0 }).state === "exiting"
  && describeMember({ state: "withdrawable", limit: 1, withdrawableAt: "1970-01-01T00:00:10Z", now: 20 }).state === "withdrawable"
  && describeMember({ state: "none", limit: 0, withdrawableAt: null, now: 0 }).state === "unregistered");
check("finality countdown counts remaining slots", finalityEstimate(110, 100).seconds === 120 && finalityEstimate(100, 105).final);
check("the set-size sentence is honest at zero and small sizes, and names the tier only when there is more than one", /0 staked members today/.test(describeSetSize(0)) && /among 3, so timing can still/.test(describeSetSize(3))
  && /among 3, so timing and tier can still/.test(describeSetSize(3, 2)) && /^1 staked member today/.test(describeSetSize(1)) && describeSetSize(-1) === null);

// The page is generated from the record: a first-screen chooser, three steps and a details screen.
const panels = [...html.matchAll(/<section class="panel[^"]*" id="([a-z]+)" data-panel="\1"/g)].map((m) => m[1]);
check("the page is the chooser, three steps and the details screen, in order", panels.join(",") === "choose,setup,stake,start,details"
  && count(html, /data-step-link="/g) === 3
  && /<nav class="stepper" aria-label="Steps" data-stepper>\s*<ol>/.test(html)
  && /data-step-link="setup" aria-current="step"/.test(html) && count(html, /aria-current="step"/g) === 1
  && count(html, /<h2 [^>]*tabindex="-1"/g) === 5);
check("only the first step is marked current, and no panel is hidden in the markup, so the page reads in order without scripting", count(html, /data-current/g) === 1
  && !/<section[^>]*hidden/.test(html) && /@media \(scripting: enabled\)\s*{\s*\.panel:not\(\[data-current\]\)/.test(css) && /@media \(scripting: none\)/.test(css));
check("the page never creates, reads, downloads or stores an identity", !/type="file"|download|create identity|import an identity|identitySecret|recovery/i.test(html)
  && !/createIdentity|importIdentity|identitySecret|serializeIdentity|new Blob|createObjectURL|type === "file"/.test(source)
  && !/identity\.mjs|exit-proof|proveAction|\.exit\(|\.withdraw\(/.test(source));
check("step 1 walks through the CLI: pinned install line, shadenet init, one field for the identity commitment", new RegExp(`SHADENET_VERSION=${CLIENT_RELEASE.replace(/\./g, "\\.")} sh`).test(html) && /^v\d+\.\d+\.\d+/.test(CLIENT_RELEASE)
  && /<code>shadenet init<\/code><\/pre>/.test(html) && count(html, /<textarea/g) === 1 && count(html, /<input(?![^>]*type="radio")/g) === 0
  && /Run these on the machine where your agent runs\./.test(html) && /for="commitment">Paste the identity commitment</.test(html));
const printsIt = releaseAtLeast(CLIENT_RELEASE, COMMITMENT_PRINTED_FROM);
check(`step 1 is true for the pinned client: ${CLIENT_RELEASE} ${printsIt ? "prints the identity commitment" : "prints only a leaf, and the page says so"}`, printsIt
  ? (/<code>shadenet init<\/code> prints it\./.test(html) && !/data-leaf-caution/.test(html))
  : (/data-leaf-caution/.test(html) && html.includes(`<code>shadenet ${CLIENT_RELEASE}</code> prints a leaf`) && !/<code>shadenet init<\/code> prints it\./.test(html)));
check("the leaf caution leaves with the first release that prints the identity commitment", releaseAtLeast("v0.7.2", "v0.7.2") && releaseAtLeast("v0.10.0", "v0.7.2") && releaseAtLeast("v1.0.0", "v0.7.2") && !releaseAtLeast("v0.7.1", "v0.7.2")
  && /data-leaf-caution/.test(renderStakePage({ clientRelease: "v0.7.1" })) && !/data-leaf-caution/.test(renderStakePage({ clientRelease: COMMITMENT_PRINTED_FROM }))
  && /SHADENET_VERSION=v9\.9\.9 sh/.test(renderStakePage({ clientRelease: "v9.9.9" })));
check("the page uses one name for the value it takes", !/public commitment|decimal field element/i.test(html) && count(html, /identity commitment/gi) >= 5);
check("step 2 carries the approved privacy note with both links", html.includes(PRIVACY_NOTE_HTML)
  && /Staking links your wallet to this membership on chain, permanently\./.test(html)
  && /<a href="https:\/\/www\.railgun\.org\/" rel="noreferrer">Railgun<\/a>/.test(html)
  && /<a href="https:\/\/github\.com\/dmarzzz\/agent-boost" rel="noreferrer">agent-boost<\/a>/.test(html));
check("the research preview statement is one constant, shown once, before the stake button", count(html, /data-preview-statement/g) === 1
  && html.includes(`data-preview-statement>${PREVIEW_STATEMENT}</p>`) && count(pageSource, /research preview on Sepolia\. The code is unaudited/g) === 1
  && html.indexOf("data-preview-statement") < html.indexOf("data-primary")
  && /research preview/.test(PREVIEW_STATEMENT) && /trusted setup/.test(PREVIEW_STATEMENT) && /motivated actor/.test(PREVIEW_STATEMENT));
// The agent brief is shown in two places now (the chooser and step 1's For-agents tab), so its
// own "sponsor" wording and register line are stripped from every occurrence before the chrome is
// checked, and the register line is counted across both briefs plus the one terminal command.
check("staking for someone else is the same step, and the terminal path is one quiet command", !/sponsor/i.test(html.split(agentBriefHtml()).join(""))
  && /To stake for someone else, paste theirs\./.test(html)
  && /shadenet register-member --identity ~\/\.config\/shadenet\/identity\.json --key-file funded\.key/.test(html) && count(html, /register-member --identity/g) === 3);
check(TIERS.length === 1 ? "one tier in the record: the page offers no tier choice" : "several tiers in the record: one compact choice, every tier in it",
  count(html, /data-tier /g) === (TIERS.length === 1 ? 0 : TIERS.length)
  && TIERS.every((tier) => TIERS.length === 1 || html.includes(`value="${tier.limit}" data-tier data-bond-text="${formatEth(tier.bondWei)} Sepolia ETH"`)));
check("page template hard-codes no bond, contract, rate or unbonding value", !/0\.1 |0\.8 |0\.01 |0\.001 |0x[0-9a-fA-F]{40}|40 MiB|60-second|24 hours|86400|41943040/.test(pageSource));
check("step 3 has a Human and an Agent tab with commands the released client has", /id="start-tab-human"[^>]*aria-controls="start-panel-human"/.test(html) && /id="start-tab-agent"[^>]*aria-controls="start-panel-agent"/.test(html)
  && /<code>shadenet status --wait<\/code>/.test(html) && /<code>shadenet proxy<\/code>/.test(html)
  && /<code>shadenet run --no-proxy api\.openai\.com -- your-agent<\/code>/.test(html) && /<code>shadenet mcp<\/code><\/pre>/.test(html)
  && /claude mcp add shadenet -- shadenet mcp/.test(html) && !/shadenet plan|shadenet_plan|shadenet_search/.test(html));
// The agent vs human split stays visible at every step: step 1 carries it as a For-humans (CLI) /
// For-agents (copy brief) tab pair, and every step can return to the chooser.
check("step 1 keeps the agent and human split, and every step can go back to start", /id="setup-tab-human"[^>]*aria-controls="setup-panel-human"/.test(html) && /id="setup-tab-agent"[^>]*aria-controls="setup-panel-agent"/.test(html)
  && /id="setup-panel-agent"[\s\S]*?data-copy-brief[\s\S]*?data-brief>/.test(html)
  && /id="setup-panel-human"[\s\S]*?data-commitment/.test(html)
  && count(html, /data-go="choose"/g) === 3 && count(html, />Back to start</g) === 3
  && count(html, /role="tab"/g) === 4 && count(html, /role="tabpanel"/g) === 4);
const brief = landing.match(/<code id="agent-setup-task"[^>]*>([\s\S]*?)<\/code>/)?.[1].trim();
check("the agent brief is the landing page's, word for word", Boolean(brief) && agentBriefHtml() === brief && html.includes(`data-brief hidden>${brief}</p>`)
  && html.includes(`<p class="path-lead">${brief.split(/(?<=\.)\s/)[0]}</p>`));
check("leaving is a CLI matter on the extra screen: exit, wait, withdraw to a fresh address", /shadenet exit-member --identity ~\/\.config\/shadenet\/identity\.json --key-file gas\.key/.test(html)
  && /shadenet withdraw-member --identity ~\/\.config\/shadenet\/identity\.json --recipient 0xFRESH --key-file gas\.key/.test(html)
  && html.includes(`The bond unlocks ${formatDuration(staked.unbondingSeconds)} later.`)
  && !/data-exit|data-withdraw|prover/i.test(html) && /docs\/PUBLIC-STAKING\.md/.test(html) && /docs\/THREAT-MODEL\.md/.test(html));
check("the extra screen keeps what is still true: the bond, what each party learns, funding, the name", count(html, /<details name="access-details"/g) === 5
  && /lets anyone slash the bond/.test(html) && /lose it and the bond stays locked for good/.test(html)
  && /<dt>Shade Tree nodes<\/dt>/.test(html) && /data-live-set/.test(html) && /sepolia-faucet\.pk910\.de/.test(html));
check("the page says once, plainly, that ShadeNet is not Shade Network or Shade Protocol", count(html, /ShadeNet is not affiliated with Shade Network, Shade Protocol/g) === 1 && !/Shade Net\b/.test(html));
check("copy rules: no em dash, no arrow, no question, the protocol is ShadeNet and a node is a Shade Tree node", (() => {
  const text = html.replace(/<script[\s\S]*?<\/script>|<[^>]+>/g, " ").replace(agentBriefHtml().replace(/&lt;/g, "<").replace(/&gt;/g, ">"), " ");
  return !/\u2014|\u2192|\?/.test(text.replace(agentBriefHtml(), "")) && !/Shade Tree protocol|ShadeNet node\b/.test(text);
})());
check("errors use an assertive alert region and progress a polite status", /data-alert role="alert"/.test(html) && /data-status role="status" aria-live="polite"/.test(html)
  && /data-commitment-message role="status" aria-live="polite"/.test(html) && /aria-describedby="commitment-hint commitment-message"/.test(html));
check("the stylesheet leaves the shared nav and the site's type tokens alone", !/\.site-nav|\.wordmark|\.nav-links|\.site-footer/.test(css)
  && !/--(display|sans|serif|mono|page)\s*:/.test(css) && !/^\.stake-page\s*{[^}]*font/m.test(css)
  && !/border-radius:\s*(999|50%|[2-9]\dpx)/.test(css));
// Phase 2 brings a material language: gradients are allowed, but only on the four sanctioned
// surfaces (the command plate's edge mask, the glass panels, the canopy field veil, and the
// commit-button fill), and none may be a neon or a full-strength wash.
check("gradients stay restrained: only the sanctioned surfaces, no neon, no opaque wash", (() => {
  const gradients = css.match(/(?:linear|radial)-gradient\([^;]*\)/g) || [];
  const sanctioned = gradients.every((g) =>
    /to right, #000/.test(g)                                    // .cmd pre edge mask
    || /rgba\(227, 233, 221,/.test(g)                           // glass panels (site ink, tinted)
    || /rgba\(12, 36, 25,|rgba\(4, 10, 7,/.test(g)              // canopy field veil
    || /rgba\(255, 244, 214,/.test(g));                         // commit fill (the amber signal, warm)
  const neon = /#(0f0|f0f|0ff|ff0|00f|f00)\b|\b(lime|magenta|fuchsia|cyan)\b|saturate\(1\.[5-9]/i.test(css);
  const opaqueWash = gradients.some((g) => /rgba\([^)]*,\s*(0\.[6-9]\d*|1)\s*\)/.test(g) && !/to right, #000/.test(g));
  return gradients.length && sanctioned && !neon && !opaqueWash;
})());
check("juice is event-only: motion lives under no-preference, nothing loops, and reduced motion stops every animation", /@media \(prefers-reduced-motion: no-preference\)/.test(css)
  && !/animation:[^;]*\binfinite\b/.test(css)
  && /@media \(prefers-reduced-motion: reduce\)\s*{[\s\S]*?animation: none !important;[\s\S]*?}/.test(css)
  && /\.finality-bar i\s*{[^}]*background: var\(--signal\)/.test(css)
  && /\.stepper a\[aria-current="step"\]::after\s*{[^}]*transform: scaleX\(1\)/.test(css));
// Phase 2: the canopy is the page's one identity object, and the four real-state events animate
// your leaf in it. The leaf appears on a valid commitment, the commit sweeps the button, finality
// reads real blocks from the RPC, and admission lights the leaf.
check("the canopy grove loads once, below the content, as the page's one identity object",
  /<script src="\.\/canopy\.js" defer><\/script>/.test(html)
  && count(html, /canopy\.js/g) === 1
  && /<div class="canopy glyph-grove" aria-hidden="true">\s*<canvas class="glyph-canvas"><\/canvas>\s*<\/div>/.test(html)
  && /\.canopy\s*{[^}]*flex: 1 1 0;[^}]*min-height: 0;[^}]*}/.test(css));
check("event 1, your leaf appears on a valid commitment, and event 4 lights it on admission",
  /function seatFrac\(\)/.test(source) && /function syncCanopy\(\)/.test(source)
  && /c\.addSeat\(seatFrac\(\)\)/.test(source) && /state\.stage === "final"\) c\.lightSeat\(\)/.test(source)
  && /else if \(state\.seated\) {\s*c\.clearSeat\(\)/.test(source)
  && /syncCanopy\(\);/.test(source));
check("event 2, the physical commit sweeps a fill across the Stake button and clears, off under reduced motion",
  /function commit\(\)/.test(source) && /state\.stage === "ready" \? commit\(\) : connectWallet\(\)/.test(source)
  && /prefers-reduced-motion: reduce.*matches/.test(source.replace(/\n/g, " "))
  && /\[data-primary\]\[data-committing\]::after\s*{[^}]*animation: commit-fill/.test(css)
  && /@keyframes commit-fill/.test(css));
check("event 3, finality shows real blocks-to-finality from the RPC, never a fabricated timer",
  (() => { const e = finalityEstimate(120, 100); return e.blocks === 20 && !e.final && finalityEstimate(100, 100).final; })()
  && /\$\{blocks\} to \$\{CHAIN_NAME\} finality/.test(source) && /estimate\.blocks/.test(source)
  && /eth_getBlockByNumber", \["finalized"/.test(source));
check("touch targets are 44 px: steps, buttons, copy, tabs and the tier choice", /--tap: 2\.75rem/.test(css) && count(css, /min-height: var\(--tap\)/g) >= 8);
check("commands never wrap inside a flag: they are preformatted and scroll sideways in place", /\.cmd pre\s*{[^}]*overflow-x: auto;[^}]*white-space: pre;/.test(css) && /mask-image/.test(css));
const balanceOk = describeBalance({ balanceWei: 10n ** 18n, tier: TIERS[0], gasPriceWei: 10n ** 9n });
const balanceShort = describeBalance({ balanceWei: 1n, tier: TIERS[0], gasPriceWei: 10n ** 9n });
check("the wallet's balance is judged against bond plus gas before any stake is attempted", balanceOk.enough && /^1 Sepolia ETH, enough for the bond and gas\.$/.test(balanceOk.message)
  && !balanceShort.enough && /^under 0\.000001 Sepolia ETH\. The bond and gas come to about [\d.]+ ETH, so this wallet needs about [\d.]+ ETH more\.$/.test(balanceShort.message)
  && /readBalance\(\)/.test(source) && approxEth(0n) === "0" && approxEth(10n ** 16n) === "0.01" && approxEth(10n ** 16n + 1n) === "0.010001");
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
  [{ message: "tier 3 is not offered on sepolia" }, /not offered/],
];
check("every wallet and SDK failure gets a plain sentence and a next step", explained.every(([error, expected]) => {
  const view = explainError(error, { chainName: "Sepolia", need: "0.001 ETH" });
  return expected.test(formatExplanation(view)) && typeof view.text === "string" && view.text.length > 0;
}) && /fail\(error/.test(source) && !/announce\(error\.message/.test(source));
check("only the step, the public commitment and the stake transaction survive a reload, in sessionStorage, guarded", STORAGE_KEY === "shadenet.access.v1"
  && count(source, /sessionStorage\.(get|set)Item\(STORAGE_KEY/g) === 2 && count(source, /sessionStorage/g) === 2
  && /panel: state\.panel, input: el\.input\.value\.slice\(0, 600\), tx: state\.tx, limit: state\.limit,/.test(source)
  && !/localStorage|indexedDB|document\.cookie|fetch\s*\(|XMLHttpRequest|sendBeacon|analytics/i.test(source));
check("the live module fetches one fixed aggregate URL and never touches what the visitor typed or connected",
  !/identity|leaf|commitment|ethereum|account|localStorage|sessionStorage/i.test(liveSource.replace(/^\/\/.*$/gm, ""))
  && count(liveSource, /fetch\(/g) === 1
  && /"\/api\/v1\/data\/stake\/sepolia\/head"/.test(liveSource)
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
check("the bundle is one small file: no prover, no code chunks, no circuit to download", bundle.length < 130_000
  && !existsSync(join(ROOT, "docs/post/stake/chunks")) && !existsSync(join(ROOT, "docs/post/stake/zk"))
  && !/snarkjs|groth16|fullProve|\.wasm|zkey|import\(/i.test(bundle.toString()));
check("rendering is deterministic", renderStakePage() === renderStakePage() && renderStakePage() === html);
const tunnelWords = describeSlot({ sessionTickets: false });
const sessionWords = describeSlot({ sessionTickets: true });
check("what a slot buys reads right with session tickets off and on (H2's switch)", tunnelWords.unit(1) === "1 new tunnel per minute"
  && sessionWords.unit(8) === "8 sessions per minute" && /up to 6 connections and/.test(sessionWords.each)
  && html.includes(`It buys <span data-buys>${describeSlot().unit(Number(DEFAULT_LIMIT))}</span>.`));

const build = spawnSync(process.execPath, [join(ROOT, "scripts/build-stake-site.mjs"), "--check"], { encoding: "utf8" });
check("committed page, bundle, API profile and shared nav are reproducible from reviewed source", build.status === 0);

// The same sources must make a right page for a one-tier record and for a two-tier one, whichever
// the committed record is: build both into a scratch tree from records derived from the real one.
const scratch = mkdtempSync(join(tmpdir(), "shadenet-stake-"));
try {
  const variants = {};
  for (const [name, tiers, defaultLimit] of [
    ["one", [{ limit: 8, bondWei: "10000000000000000" }], 8],
    ["two", [{ limit: 1, bondWei: "10000000000000000" }, { limit: 8, bondWei: "80000000000000000" }], 1],
  ]) {
    const record = structuredClone(deployment);
    Object.assign(record.admission.roots.staked, { tiers, defaultLimit });
    mkdirSync(join(scratch, name, "record"), { recursive: true });
    writeFileSync(join(scratch, name, "record", "deployment.json"), JSON.stringify(record));
    const out = join(scratch, name, "site");
    const made = spawnSync(process.execPath, [join(ROOT, "scripts/build-stake-site.mjs")], {
      encoding: "utf8",
      env: { ...process.env, SHADENET_SITE_NETWORK: relative(join(ROOT, "network"), join(scratch, name, "record")), SHADENET_SITE_OUT: out, SHADENET_SITE_CLIENT: COMMITMENT_PRINTED_FROM },
    });
    assert.equal(made.status, 0, made.stderr);
    variants[name] = readFileSync(join(out, "docs/post/stake/index.html"), "utf8");
  }
  check("a one-tier record builds a page with no tier choice and that tier's bond and budget", count(variants.one, /type="radio"/g) === 0 && !/data-tier-row/.test(variants.one)
    && /<span data-bond>0\.01 Sepolia ETH<\/span>/.test(variants.one) && /<summary>Leave<\/summary>/.test(variants.one) && !/To change tier/.test(variants.one)
    && variants.one.includes(`It buys <span data-buys>${describeSlot().unit(8)}</span>.`));
  check("a two-tier record builds one compact choice with the default tier checked", count(variants.two, /type="radio"/g) === 2 && /value="1" data-tier [^>]*checked/.test(variants.two)
    && !/value="8" data-tier [^>]*checked/.test(variants.two) && /data-bond-text="0\.08 Sepolia ETH"/.test(variants.two)
    && /<summary>Leave or change tier<\/summary>/.test(variants.two) && /To change tier/.test(variants.two));
  check("a preview for a release that prints the identity commitment drops the leaf caution", !/data-leaf-caution/.test(variants.one) && /<code>shadenet init<\/code> prints it\./.test(variants.one)
    && new RegExp(`SHADENET_VERSION=${COMMITMENT_PRINTED_FROM.replace(/\./g, "\\.")} sh`).test(variants.one));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

const vercel = JSON.parse(readFileSync(join(ROOT, "docs/post/vercel.json"), "utf8"));
const cspFor = (source) => vercel.headers.find((h) => h.source === source)?.headers.find((x) => x.key === "Content-Security-Policy")?.value || "";
check("the site-wide CSP stays strict: same-origin scripts and connections only, no eval",
  /script-src 'self'/.test(cspFor("/(.*)")) && /connect-src 'self'/.test(cspFor("/(.*)")) && !/unsafe-eval/.test(cspFor("/(.*)"))
  && !/'unsafe-eval'/.test(cspFor("/stake/(.*)")) && !/<script(?![^>]*src="\.\/stake\.js")(?![^>]*src="\.\/canopy\.js")(?![^>]*application\/ld\+json)/.test(html) && !/https?:\/\/[^"]+\.(js|css|woff2?)"/.test(html));

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
