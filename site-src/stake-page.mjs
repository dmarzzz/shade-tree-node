// Renders docs/post/stake/index.html ("Get access") from the network record via profile.mjs.
// Three steps, one on screen at a time: set up with the CLI, stake, start. A fourth screen holds
// leaving and the details. The page never creates, reads or stores a member secret: the CLI does
// that on the member's machine and the page takes only the public identity commitment.
// No price, tier, rate or address is written by hand here; `npm run site:build:stake` regenerates
// the page and test/stake-site.selftest.mjs fails if the committed HTML drifts from this template.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CHAIN_NAME,
  CLIENT_RELEASE,
  CONTRACT,
  DEFAULT_LIMIT,
  EXPLORER_URL,
  RATE,
  SESSION_CLASS,
  SESSION_TICKETS,
  SLASH_REWARD_DIVISOR,
  TIERS,
  UNBONDING_SECONDS,
  formatDuration,
  formatEth,
  shortAddress,
} from "./profile.mjs";
import { siteNav } from "./site-nav.mjs";

const esc = (value) => String(value).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = "https://github.com/dmarzzz/shade-tree-node";

// The research preview statement, short form, shown before the stake button. The wording is
// waiting on final approval (launch task 25): change it here and nowhere else.
export const PREVIEW_STATEMENT = "ShadeNet is a research preview on Sepolia. The code is unaudited, the proof keys come from a trusted setup, and it should not be considered secure against a motivated actor: do not use it for real funds or sensitive traffic.";

// The privacy note of the stake step (approved direction, launch task 36). The two names are links.
export const PRIVACY_NOTE_HTML = `Staking links your wallet to this membership on chain, permanently. To keep a wallet you care about out of it, shield ETH with <a href="https://www.railgun.org/" rel="noreferrer">Railgun</a>, send it to a fresh wallet, and stake from that one. An agent can do the same through <a href="https://github.com/dmarzzz/agent-boost" rel="noreferrer">agent-boost</a>.`;

// The staking contract takes the identity commitment, Poseidon1(identitySecret), and derives the
// member leaf itself. `shadenet init` up to v0.7.1 prints only the leaf, a different number: a
// bond staked on a leaf admits a member nobody holds the secret for, and it cannot be exited.
// This is the first release whose `init` prints the identity commitment; while the pinned
// release is older, step 1 says so and sends the reader to the terminal.
export const COMMITMENT_PRINTED_FROM = "v0.7.2";

export function releaseAtLeast(release, wanted) {
  const parts = (v) => String(v).replace(/^v/, "").split(/[.-]/).slice(0, 3).map((n) => Number.parseInt(n, 10) || 0);
  const [a, b] = [parts(release), parts(wanted)];
  for (let i = 0; i < 3; i++) if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  return true;
}

// The landing page's agent brief, reused word for word so the site carries one version of it.
export function agentBriefHtml() {
  const landing = readFileSync(join(ROOT, "docs/post/index.html"), "utf8");
  const match = landing.match(/<code id="agent-setup-task"[^>]*>([\s\S]*?)<\/code>/);
  if (!match) throw new Error("docs/post/index.html has no agent brief (code#agent-setup-task); the Get access page reuses it.");
  return match[1].trim();
}

const epoch = formatDuration(RATE.epochSeconds);
const perEpoch = RATE.epochSeconds === 60 ? "per minute" : `per ${epoch}`;
const epochNoun = epoch === "1 minute" ? "minute" : "epoch";
const mib = Number.isInteger(RATE.payloadMiB) ? `${RATE.payloadMiB} MiB` : `${RATE.payloadMiB.toFixed(1)} MiB`;
const unbonding = formatDuration(UNBONDING_SECONDS);
const baseTier = TIERS.find((tier) => tier.limit === DEFAULT_LIMIT) || TIERS[0];
const oneTier = TIERS.length === 1;
const contractLink = EXPLORER_URL ? `${EXPLORER_URL}/address/${CONTRACT}` : null;
const slashLine = SLASH_REWARD_DIVISOR
  ? `A valid slash pays 1/${SLASH_REWARD_DIVISOR} of the bond to whoever reports it and burns the rest.`
  : "A valid slash forfeits the bond.";
const IDENTITY_PATH = "~/.config/shadenet/identity.json";

// What one slot buys, in the words a first-time reader needs, for either setting of the switch.
export function describeSlot({ sessionTickets = SESSION_TICKETS, epochWords = perEpoch, payload = mib, klass = SESSION_CLASS } = {}) {
  if (sessionTickets) {
    return {
      unit: (n) => `${n} ${n === 1 ? "session" : "sessions"} ${epochWords}`,
      each: `up to ${klass.tickets} connections and ${payload} each`,
    };
  }
  return {
    unit: (n) => `${n} new ${n === 1 ? "tunnel" : "tunnels"} ${epochWords}`,
    each: `${payload} each`,
  };
}
const slot = describeSlot();

// A command on a plate with a copy button. The text is preformatted, so a flag never breaks at a
// hyphen; a line wider than the plate scrolls sideways inside it.
function command(label, code) {
  return `<div class="cmd">
            <pre tabindex="0" aria-label="${esc(label)}"><code>${code}</code></pre>
            <button class="needs-script" type="button" data-copy-block aria-label="Copy: ${esc(label)}">copy</button>
          </div>`;
}

// One command, shown on three lines where there is room and on one scrolling line on a phone.
// Copied either way it is the same valid command.
const CONTINUE = `<span class="cont"> \\\n </span> `;
const installLine = (release) => [
  "curl -fsSL --proto '=https' --proto-redir '=https'",
  "https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh",
  `| SHADENET_VERSION=${esc(release)} sh`,
].join(CONTINUE);
const REGISTER_LINE = `shadenet register-member --identity ${IDENTITY_PATH} --key-file funded.key`;

// With one tier there is nothing to choose. With more, the tier is a property of the identity
// the CLI made, so the choice sits with the commitment, as one row.
function tierChoice() {
  if (oneTier) return "";
  const options = TIERS.map((tier) => {
    const n = Number(tier.limit);
    return `<label><input type="radio" name="tier" value="${n}" data-tier data-bond-text="${formatEth(tier.bondWei)} ${CHAIN_NAME} ETH" data-buys-text="${esc(slot.unit(n))}"${tier.limit === DEFAULT_LIMIT ? " checked" : ""}> tier ${n}</label>`;
  }).join("\n                    ");
  return `
              <div data-tier-row>
                <dt id="tier-label">tier</dt>
                <dd>
                  <div class="tier-pick" role="radiogroup" aria-labelledby="tier-label" aria-describedby="tier-hint">
                    ${options}
                  </div>
                  <p class="hint" id="tier-hint" data-tier-hint>Stake the tier the identity was made for. <code>shadenet init</code> makes tier ${Number(DEFAULT_LIMIT)} unless you pass <code>--limit</code>.</p>
                </dd>
              </div>`;
}

function setupNotes(initPrintsCommitment, release) {
  const hint = `<p class="note" id="commitment-hint">${initPrintsCommitment ? "<code>shadenet init</code> prints it. " : ""}The identity commitment is public. The secret stays in <code>identity.json</code> on that machine, and this page never asks for it. To stake for someone else, paste theirs.</p>`;
  if (initPrintsCommitment) return hint;
  return `${hint}
            <p class="caution" data-leaf-caution><code>shadenet ${esc(release)}</code> prints a leaf, which is a different number. A bond staked on a leaf is lost. Until a release prints the identity commitment, stake from the terminal (step 2).</p>`;
}

const detailsLink = `<a class="more-link" href="#details" data-go="details">Leave and details</a>`;

export function renderStakePage({ clientRelease = CLIENT_RELEASE } = {}) {
  const initPrintsCommitment = releaseAtLeast(clientRelease, COMMITMENT_PRINTED_FROM);
  const baseBond = `${formatEth(baseTier.bondWei)} ${CHAIN_NAME} ETH`;
  const description = `Get proof-gated Tor egress for an AI agent: set up the shadenet CLI, stake ${baseBond} for its public identity commitment, and start.`;
  const buys = slot.unit(Number(baseTier.limit));
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${esc(description)}">
  <meta name="theme-color" content="#07100c">
  <meta property="og:title" content="Get Access · ShadeNet">
  <meta property="og:description" content="Three steps: set up the shadenet CLI, stake the bond on ${CHAIN_NAME} for its public identity commitment, and start. The member secret never reaches this page.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://shadenet.xyz/stake/">
  <meta property="og:site_name" content="ShadeNet">
  <meta property="og:image" content="https://shadenet.xyz/fig/shade-tree-og.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="A low-poly grove crossed by a private data path">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="canonical" href="https://shadenet.xyz/stake/">
  <link rel="icon" href="../favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="../site.css">
  <link rel="stylesheet" href="./stake.css">
  <script type="module" src="./stake.js"></script>
  <script type="application/ld+json">
    {"@context":"https://schema.org","@type":"WebApplication","name":"ShadeNet Get Access","url":"https://shadenet.xyz/stake/","applicationCategory":"FinanceApplication","operatingSystem":"Web browser"}
  </script>
  <title>Get Access · ShadeNet</title>
</head>
<body class="stake-page">
  <a class="skip-link" href="#access">Skip to the steps</a>
${siteNav("stake", { indent: "  " })}

  <main id="access" class="access">
    <header class="access-head">
      <h1>Get access</h1>
      <p class="access-net">Research preview on ${CHAIN_NAME}</p>
    </header>

    <nav class="stepper" aria-label="Steps" data-stepper>
      <ol>
        <li><a href="#setup" data-step-link="setup" aria-current="step"><span class="step-n">1</span> Set up</a></li>
        <li><a href="#stake" data-step-link="stake"><span class="step-n">2</span> Stake</a></li>
        <li><a href="#start" data-step-link="start"><span class="step-n">3</span> Start</a></li>
      </ol>
    </nav>

    <div class="panels">
      <section class="panel" id="setup" data-panel="setup" data-current aria-labelledby="setup-title">
        <h2 class="sr-only" id="setup-title" tabindex="-1">Step 1: set up with the CLI</h2>
        <div class="panel-split">
          <div class="split-main">
            <p class="lead">Run these on the machine where your agent runs.</p>
            <p class="cmd-label">Install the client</p>
            ${command("Install the ShadeNet client", installLine(clientRelease))}
            <p class="cmd-label">Create the identity</p>
            ${command("Create the identity", "shadenet init")}
            <label class="cmd-label needs-script" for="commitment">Paste the identity commitment</label>
            <textarea class="needs-script" id="commitment" data-commitment rows="2" inputmode="numeric" autocomplete="off" autocapitalize="off" spellcheck="false" aria-describedby="commitment-hint commitment-message"></textarea>
            <p class="field-message needs-script" id="commitment-message" data-commitment-message role="status" aria-live="polite"></p>
          </div>
          <div class="split-notes">
            ${setupNotes(initPrintsCommitment, clientRelease)}
          </div>
        </div>
        <div class="panel-nav">
          <a class="solid-action" href="#stake" data-go="stake">Next</a>
          ${detailsLink}
        </div>
      </section>

      <section class="panel" id="stake" data-panel="stake" data-stage="idle" aria-labelledby="stake-title">
        <h2 class="sr-only" id="stake-title" tabindex="-1">Step 2: stake the bond</h2>
        <div class="panel-split">
          <div class="split-main split-facts">
            <dl class="facts">
              <div class="needs-script">
                <dt>identity commitment</dt>
                <dd><output data-commitment-shown>None yet. Enter it in step 1.</output> <button class="text-action" type="button" data-copy-link hidden>copy link</button></dd>
              </div>${tierChoice()}
              <div>
                <dt>bond</dt>
                <dd><span data-bond>${baseBond}</span>, returned ${unbonding} after you leave. It buys <span data-buys>${buys}</span>.</dd>
              </div>
              <div data-wallet-row hidden>
                <dt>wallet</dt>
                <dd><span data-wallet></span> <button class="text-action" type="button" data-change-wallet>change</button><br><span data-balance></span></dd>
              </div>
            </dl>
          </div>
          <div class="split-notes" data-before-stake>
            <p class="note" data-privacy-note>${PRIVACY_NOTE_HTML}</p>
            <p class="note" data-preview-statement>${esc(PREVIEW_STATEMENT)}</p>
          </div>
          <div class="split-main split-act">
            <noscript><p class="caution">Staking from a browser wallet needs JavaScript. The terminal command below does not.</p></noscript>
            <div class="button-row needs-script">
              <button class="solid-action" type="button" data-primary>Connect wallet</button>
            </div>
            <p class="status" data-status role="status" aria-live="polite"></p>
            <p class="alert" data-alert role="alert"></p>
            <p class="status" data-receipt hidden>Transaction <a data-receipt-link href="${EXPLORER_URL || "#"}" target="_blank" rel="noreferrer">view</a></p>
            <div class="finality" data-finality-panel hidden>
              <div class="finality-bar" aria-hidden="true"><i data-finality-bar></i></div>
              <p data-finality role="status" aria-live="polite"></p>
            </div>
            <p class="admitted" data-member-state hidden></p>
            <div class="quiet" data-terminal>
              <p data-terminal-text>Without a browser wallet, stake from the terminal with a funded key.</p>
              ${command("Stake from the terminal", REGISTER_LINE)}
            </div>
          </div>
        </div>
        <div class="panel-nav">
          <a class="line-action" href="#setup" data-go="setup">Back</a>
          <a class="line-action" href="#start" data-go="start" data-next-start>Next</a>
          ${detailsLink}
        </div>
      </section>

      <section class="panel" id="start" data-panel="start" aria-labelledby="start-title">
        <h2 class="sr-only" id="start-title" tabindex="-1">Step 3: start</h2>
        <div class="panel-split">
          <div class="split-notes">
            <p class="note" data-start-state>Nodes admit the identity once its stake is final, usually 13 to 16 minutes after it confirms.</p>
          </div>
          <div class="split-main tabs" data-tabs>
            <div role="tablist" aria-label="Who starts it">
              <button type="button" role="tab" id="start-tab-human" aria-controls="start-panel-human" aria-selected="true">Human</button>
              <button type="button" role="tab" id="start-tab-agent" aria-controls="start-panel-agent" aria-selected="false">Agent</button>
            </div>
            <div role="tabpanel" id="start-panel-human" aria-labelledby="start-tab-human">
              <h3 class="tab-title">Human</h3>
              <ol class="runs">
                <li>
                  ${command("Wait until the identity is admitted", "shadenet status --wait")}
                  <p>Returns once the stake is final and nodes admit the identity.</p>
                </li>
                <li>
                  ${command("Start the proxy", "shadenet proxy")}
                  <p>Starts the local proxy. Leave it running.</p>
                </li>
                <li>
                  ${command("Run your agent through the proxy", "shadenet run --no-proxy api.openai.com -- your-agent")}
                  <p>Runs your agent with its web traffic on ShadeNet. Keep your model API host on <code>--no-proxy</code>.</p>
                </li>
              </ol>
            </div>
            <div role="tabpanel" id="start-panel-agent" aria-labelledby="start-tab-agent">
              <h3 class="tab-title">Agent</h3>
              <div class="brief">
                <p class="brief-text" id="agent-brief" data-brief tabindex="0">${agentBriefHtml()}</p>
                <button class="line-action needs-script" type="button" data-copy-brief>copy agent brief</button>
              </div>
              ${command("Serve the ShadeNet MCP tools", "shadenet mcp")}
              <p>Serves <code>shadenet_fetch</code> and <code>shadenet_status</code> to any MCP client over stdio. In Claude Code: <code>claude mcp add shadenet -- shadenet mcp</code>.</p>
            </div>
          </div>
        </div>
        <div class="panel-nav">
          <a class="line-action" href="#stake" data-go="stake">Back</a>
          ${detailsLink}
        </div>
      </section>

      <section class="panel" id="details" data-panel="details" aria-labelledby="details-title">
        <div class="panel-split">
          <div class="split-main more">
            <h2 id="details-title" tabindex="-1">Leave and details</h2>
            <details name="access-details" open>
              <summary>${oneTier ? "Leave" : "Leave or change tier"}</summary>
              <p>Leave from the machine that holds <code>identity.json</code>. The key only pays gas.</p>
              ${command("Start the exit", `shadenet exit-member --identity ${IDENTITY_PATH} --key-file gas.key`)}
              <p>The bond unlocks ${unbonding} later. Withdraw it to a fresh address, so the refund does not point back at the funder.</p>
              ${command("Withdraw the bond", `shadenet withdraw-member --identity ${IDENTITY_PATH} --recipient 0xFRESH --key-file gas.key`)}${oneTier ? "" : `
              <p>To change tier, make a new identity with <code>shadenet init --dir NEW_FOLDER --limit N</code>, stake it, then exit the old one.</p>`}
            </details>
            <details name="access-details">
              <summary>The bond</summary>
              <p>The bond is refundable collateral. Tier ${Number(baseTier.limit)} buys ${slot.unit(Number(baseTier.limit))}, ${slot.each}. Sending two different requests from the same slot in one ${epochNoun} reveals the secret and lets anyone slash the bond. ${slashLine}</p>
              <p>Exit and withdraw need <code>identity.json</code>. Nobody can recover it for you: lose it and the bond stays locked for good.</p>
              <p>The contract is ${contractLink ? `<a href="${contractLink}" rel="noreferrer">${shortAddress(CONTRACT)}</a>` : shortAddress(CONTRACT)} on ${CHAIN_NAME}. It, the bond and the unbonding time can change at the next deployment. <a href="${REPO}/blob/main/docs/PUBLIC-STAKING.md" rel="noreferrer">Protocol parameters</a></p>
            </details>
            <details name="access-details">
              <summary>What each party learns</summary>
              <dl class="ledger">
                <div><dt>This page</dt> <dd>The identity commitment you paste, which it hands only to your wallet.</dd></div>
                <div><dt>Your wallet and its RPC</dt> <dd>Your address, the identity commitment, the bond and the time.</dd></div>
                <div><dt>Shade Tree nodes</dt> <dd>A valid proof, the destination host, timing and byte counts. They cannot tell which member sent it.</dd></div>
                <div><dt>The destination</dt> <dd>A Shade Tree node's address, never yours.</dd></div>
              </dl>
              <p data-live-set>A proof hides you among the staked members, so your privacy is only as large as that set.</p>
            </details>
            <details name="access-details">
              <summary>No ${CHAIN_NAME} ETH</summary>
              <p>Faucet drips are often smaller than the bond, so funding can take a few tries. Someone else can also stake for you: copy the link in step 2 and send it to them. They never see the secret.</p>
              <ul>
                <li><a href="https://sepolia-faucet.pk910.de/" rel="noreferrer">pk910 proof-of-work faucet</a>, no account.</li>
                <li><a href="https://cloud.google.com/application/web3/faucet/ethereum/sepolia" rel="noreferrer">Google Cloud Web3 faucet</a>, needs a Google account.</li>
                <li><a href="https://www.alchemy.com/faucets/ethereum-sepolia" rel="noreferrer">Alchemy faucet</a>, may ask for a small mainnet balance.</li>
              </ul>
            </details>
            <details name="access-details">
              <summary>The name</summary>
              <p>ShadeNet is not affiliated with Shade Network, Shade Protocol or any other project with Shade in its name.</p>
            </details>
          </div>
        </div>
        <div class="panel-nav">
          <a class="line-action" href="#setup" data-go="back">Back to the steps</a>
          <a class="more-link" href="${REPO}/blob/main/docs/THREAT-MODEL.md" rel="noreferrer">Threat model</a>
        </div>
      </section>
    </div>
  </main>
</body>
</html>
`;
}
