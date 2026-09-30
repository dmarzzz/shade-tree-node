// Renders docs/post/stake/index.html ("Get access") from the network record via profile.mjs.
// No price, tier, rate or address is written by hand here; `npm run site:build:stake` regenerates
// the page and test/stake-site.selftest.mjs fails if the committed HTML drifts from this template.
import { statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CHAIN_NAME,
  CLIENT_RELEASE,
  CONTRACT,
  DEFAULT_LIMIT,
  EXPLORER_URL,
  RATE,
  REGISTER_INPUT,
  SECURITY,
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
// The withdraw circuit the in-browser prover downloads, once, when someone exits or withdraws.
// Its size is stated on the page before the download starts.
const PROVER_FILES = ["circuits/rln/withdraw.wasm", "circuits/rln/withdraw_final.zkey"];
export const PROVER_BYTES = PROVER_FILES.reduce((sum, file) => sum + statSync(join(ROOT, file)).size, 0);
export const PROVER_MB = (PROVER_BYTES / 1e6).toFixed(1);

const epoch = formatDuration(RATE.epochSeconds);
const perEpoch = RATE.epochSeconds === 60 ? "per minute" : `per ${epoch}`;
const epochNoun = epoch === "1 minute" ? "minute" : "epoch";
const mib = Number.isInteger(RATE.payloadMiB) ? `${RATE.payloadMiB} MiB` : `${RATE.payloadMiB.toFixed(1)} MiB`;
const unbonding = formatDuration(UNBONDING_SECONDS);
const baseTier = TIERS.find((tier) => tier.limit === DEFAULT_LIMIT) || TIERS[0];
const baseBond = `${formatEth(baseTier.bondWei)} ${CHAIN_NAME} ETH`;
const contractLink = EXPLORER_URL ? `${EXPLORER_URL}/address/${CONTRACT}` : null;
const commitmentNoun = REGISTER_INPUT === "identityCommitment" ? "identity commitment" : "public commitment";
const slashLine = SLASH_REWARD_DIVISOR
  ? `A valid slash pays 1/${SLASH_REWARD_DIVISOR} of the bond to whoever reports it and burns the rest.`
  : "A valid slash forfeits the bond.";
const artifactsLine = SECURITY.proofArtifacts === "untrusted-testnet"
  ? "The proof setup is untrusted testnet material until the trusted-setup ceremony runs."
  : "The proof keys come from the published trusted-setup ceremony.";
const FILE_PLACEHOLDER = "shadenet-identity-XXXXXXXX.json";
const fileName = () => `<span data-file-name>${FILE_PLACEHOLDER}</span>`;

const tunnels = (n) => `${n} new ${n === 1 ? "tunnel" : "tunnels"} ${perEpoch}`;

function tierRows(name, attr) {
  return TIERS.map((tier) => {
    const n = Number(tier.limit);
    const checked = tier.limit === DEFAULT_LIMIT ? " checked" : "";
    return `          <label class="tier-row">
            <input type="radio" name="${name}" value="${n}" ${attr}${checked}>
            <span class="tier-name">tier ${n}</span>
            <span class="tier-bond">${formatEth(tier.bondWei)} ETH</span>
            <span class="tier-buys">${tunnels(n)}, ${mib} each</span>
          </label>`;
  }).join("\n");
}

function codeBlock(label, code) {
  return `<div class="code-block">
          <pre tabindex="0" aria-label="${esc(label)}"><code>${code}</code></pre>
          <button class="copy-block" type="button" data-copy-block aria-label="Copy: ${esc(label)}">copy</button>
        </div>`;
}

const INSTALL_LINE = `curl -fsSL --proto '=https' --proto-redir '=https' \\
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh \\
  | SHADENET_VERSION=${CLIENT_RELEASE} sh`;

function handoffTabs() {
  const tabs = [
    ["cli", "CLI", `<p>Install the <code>shadenet</code> binary (it embeds Tor), put the file where it looks, and run the proxy. Every command after <code>init</code> reads the identity from that folder.</p>
        ${codeBlock("Install the ShadeNet client", INSTALL_LINE)}
        ${codeBlock("Move the identity file into place and start the proxy", `mkdir -p ~/.config/shadenet &amp;&amp; chmod 700 ~/.config/shadenet
mv ~/Downloads/${fileName()} ~/.config/shadenet/identity.json
chmod 600 ~/.config/shadenet/identity.json
shadenet init            # keeps that identity, writes the proxy token and config
shadenet status --wait   # returns once the stake is final
shadenet proxy           # leave this running
shadenet run --no-proxy api.openai.com -- your-agent`)}
        <p><code>run</code> gives only the child process the proxy settings. Keep your model API host on <code>--no-proxy</code>: it has its own network path and would waste tunnels.</p>`],
    ["hermes", "Hermes", `<p>Hermes calls ShadeNet as an MCP tool. After the CLI steps, register the server and drop the skill file in so the model knows when to use it.</p>
        ${codeBlock("Register the ShadeNet MCP server in Hermes", `hermes mcp add shadenet --command shadenet --args mcp
cp -r examples/hermes ~/.hermes/skills/shadenet   # from a checkout of the repo`)}
        <p>The model then has <code>shadenet_fetch</code> and <code>shadenet_status</code>. Add <code>--env SHADENET_SEARXNG_URL=http://127.0.0.1:8080</code> to the first line for <code>shadenet_search</code> as well.</p>`],
    ["mcp", "Claude Code / Codex", `<p>Any MCP client works the same way: the server is <code>shadenet mcp</code> on stdio.</p>
        ${codeBlock("Register the server in Claude Code", `claude mcp add shadenet -- shadenet mcp`)}
        ${codeBlock("Register the server in Codex (config.toml)", `[mcp_servers.shadenet]
command = "shadenet"
args = ["mcp"]`)}`],
    ["searxng", "SearXNG", `<p>A private SearXNG whose blocked engines reach the web through ShadeNet. The identity lives next to the compose file.</p>
        ${codeBlock("Run SearXNG through ShadeNet", `git clone https://github.com/dmarzzz/shade-tree-node.git &amp;&amp; cd shade-tree-node/examples/searxng
mkdir -p shadenet &amp;&amp; mv ~/Downloads/${fileName()} shadenet/identity.json
chmod 600 shadenet/identity.json
shadenet init --dir ./shadenet --offline
shadenet status --identity ./shadenet/identity.json --wait
mkdir -m 0755 state
SHADENET_UID=$(id -u) SHADENET_GID=$(id -g) docker compose up -d
open http://127.0.0.1:8080`)}
        <p>Keep <code>./state</code>: it holds the slot state that stops a nullifier being reused inside an epoch.</p>`],
    ["js", "JavaScript", `<p>The same SDK this page runs. In Node it reads the identity file and talks to a local <code>shadenet proxy</code>; in a browser it can check status and prove exit and withdraw.</p>
        ${codeBlock("Check the membership from Node with @shadenet/sdk", `import { readFileSync } from "node:fs";
import { createStaking, importIdentity, jsonRpcProvider } from "@shadenet/sdk";

const identity = importIdentity(readFileSync("${fileName()}", "utf8"));
const staking = createStaking({ provider: jsonRpcProvider(process.env.SHADENET_RPC_URL) });
console.log(await staking.memberStatus(identity.leaf));   // { state, limit, withdrawableAt, finalized }`)}`],
  ];
  const buttons = tabs.map(([id, label], i) => `<button type="button" role="tab" id="handoff-tab-${id}" aria-controls="handoff-panel-${id}" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}">${label}</button>`).join("\n        ");
  const panels = tabs.map(([id, , body], i) => `<div role="tabpanel" id="handoff-panel-${id}" aria-labelledby="handoff-tab-${id}"${i === 0 ? "" : " hidden"}>
        ${body}
      </div>`).join("\n      ");
  return `<div class="handoff-tabs" data-tabs>
        <div role="tablist" aria-label="Where the identity goes">
        ${buttons}
        </div>
      ${panels}
      </div>`;
}

export function renderStakePage() {
  const description = `Get anonymous Tor egress for an AI agent: create a ShadeNet identity locally and stake ${baseBond}, or sponsor someone else's.`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="${esc(description)}">
  <meta name="theme-color" content="#07100c">
  <meta property="og:title" content="Get Access · ShadeNet">
  <meta property="og:description" content="Create the member secret locally, save its recovery file, and send only the public commitment to ${CHAIN_NAME}.">
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://shade-tree-node.vercel.app/stake/">
  <meta property="og:site_name" content="ShadeNet">
  <meta property="og:image" content="https://shade-tree-node.vercel.app/fig/shade-tree-og.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="A low-poly grove crossed by a private data path">
  <meta name="twitter:card" content="summary_large_image">
  <link rel="canonical" href="https://shade-tree-node.vercel.app/stake/">
  <link rel="icon" href="../favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="../site.css">
  <link rel="stylesheet" href="./stake.css">
  <script type="module" src="./stake.js"></script>
  <script type="application/ld+json">
    {"@context":"https://schema.org","@type":"WebApplication","name":"ShadeNet Get Access","url":"https://shade-tree-node.vercel.app/stake/","applicationCategory":"FinanceApplication","operatingSystem":"Web browser"}
  </script>
  <title>Get Access · ShadeNet</title>
</head>
<body class="stake-page">
  <a class="skip-link" href="#staking">Skip to staking</a>
${siteNav("stake", { indent: "  " })}

  <main id="staking" class="stake-main">
    <header class="stake-hero">
      <div class="shade-light" aria-hidden="true"></div>
      <div class="stake-hero-copy">
        <p class="instrument">get access <span aria-hidden="true">//</span> ${CHAIN_NAME.toLowerCase()} research preview</p>
        <h1>Stake without giving us an identity.</h1>
        <p class="lede">A refundable bond on ${CHAIN_NAME} buys your agent a budget of anonymous HTTPS tunnels through the canopy. The identity is made in this tab and stays with you. Only its public commitment goes on chain, and nodes only ever see a proof of membership.</p>
        <dl class="live-row" aria-label="Live network">
          <div><dt>network</dt><dd>${CHAIN_NAME} testnet</dd></div>
          <div><dt>nodes announced</dt><dd data-live-nodes>…</dd></div>
          <div><dt>staked members</dt><dd class="signal" data-live-members>…</dd></div>
        </dl>
        <p class="set-note" data-live-set>Your privacy is only as large as the staked set. The live count loads from this site's aggregate API.</p>
      </div>
    </header>

    <section class="who-learns" aria-labelledby="privacy-title">
      <h2 id="privacy-title">What each party learns</h2>
      <dl class="ledger">
        <div><dt>This page</dt><dd>Generates and validates locally. No identity API exists.</dd></div>
        <div><dt>Your wallet and its RPC</dt><dd>Sees your address, public commitment, bond, and timing.</dd></div>
        <div><dt>The canopy</dt><dd>Later sees a valid anonymous membership proof, not which leaf made it.</dd></div>
        <div><dt>The destination</dt><dd>Sees a Shade Tree node's IP, never yours.</dd></div>
      </dl>
      <p class="fine">Loading any website can expose your IP to its host. This static page never sends the commitment or recovery file to the ShadeNet server.</p>
    </section>

    <div class="role-switch" aria-label="Choose a staking role">
      <button type="button" data-mode="member" aria-pressed="true">I’m joining</button>
      <button type="button" data-mode="sponsor" aria-pressed="false">I’m sponsoring someone</button>
    </div>

    <div class="flow">
      <ol class="rail" data-rail aria-label="Progress">
        <li data-rail-step="tier" data-state="current"><span>01</span> tier</li>
        <li data-rail-step="identity" data-state="todo"><span>02</span> identity</li>
        <li data-rail-step="save" data-state="todo"><span>03</span> save</li>
        <li data-rail-step="stake" data-state="todo"><span>04</span> stake</li>
        <li data-rail-step="finality" data-state="todo"><span>05</span> finality</li>
        <li data-rail-step="handoff" data-state="todo"><span>06</span> hand off</li>
      </ol>

      <div class="flow-body">
    <section class="stake-trail" data-member-steps aria-label="Member staking steps">
      <article class="step" data-step-panel="tier">
        <p class="step-index" aria-hidden="true">01</p>
        <h2>Choose a tier</h2>
        <p>A tunnel is one HTTPS connection to one site. Each tier gets that many new tunnels ${perEpoch}, canopy-wide, and each tunnel carries up to ${mib} in both directions combined. A search plus five result pages is about six tunnels. The tier is part of the identity, so pick it first.</p>
        <fieldset class="tier-pick">
          <legend class="sr-only">Tier</legend>
${tierRows("tier", "data-tier")}
        </fieldset>
        <p class="fine">The bond is refundable collateral, not a fee: exit whenever you like and withdraw it after ${unbonding}. Sending two different requests from the same slot in one ${epochNoun} reveals your secret and lets anyone slash the bond. ${slashLine} To change tier later, stake a new identity and exit the old one.</p>
      </article>

      <article class="step" data-step-panel="identity">
        <p class="step-index" aria-hidden="true">02</p>
        <h2>Create the identity</h2>
        <p>The secret comes from your operating system's randomness and never leaves this tab. Already have an identity file? Import it to check its status, exit, or withdraw; each new stake needs a new identity.</p>
        <div class="button-row">
          <button class="solid-action" type="button" data-create-identity>create identity</button>
          <button class="line-action" type="button" data-import-identity>import an identity file</button>
          <input type="file" accept="application/json,.json" data-identity-file hidden>
        </div>
        <div class="leaf-tag" data-leaf-tag data-ready="false">
          <span class="label">public commitment</span>
          <output data-leaf>Create or import an identity to reveal its public commitment.</output>
          <button class="line-action small" type="button" data-copy-leaf disabled>copy</button>
        </div>
      </article>

      <article class="step" data-step-panel="save">
        <p class="step-index" aria-hidden="true">03</p>
        <h2>Save the file</h2>
        <p>The ShadeNet client reads this file directly. Whoever holds it can use the membership and authorise its exit, and nobody can recover it for you.</p>
        <div class="button-row">
          <button class="solid-action" type="button" data-download-identity disabled>download identity file</button>
        </div>
        <ul class="checklist">
          <li>Keep it on an encrypted disk or in a secrets vault.</li>
          <li>Never paste it into chat, email, or a ticket. The public commitment is the only thing to share.</li>
          <li>Lose it and the bond stays locked for good.</li>
        </ul>
        <label class="recovery-check"><input type="checkbox" data-recovery-check disabled> I saved the file somewhere private and recoverable.</label>
      </article>

      <article class="step transaction-step" data-step-panel="stake">
        <p class="step-index" aria-hidden="true">04</p>
        <h2>Fund and stake</h2>
        <p>The wallet sends exactly the tier's bond to the pinned contract, plus gas. Its address is linked to the commitment forever, so use a wallet you don't mind linking, or let a sponsor stake for you.</p>
        <p class="contract-line"><span class="label">contract</span> ${contractLink ? `<a href="${contractLink}">${shortAddress(CONTRACT)}</a>` : shortAddress(CONTRACT)}</p>
        <div class="button-row">
          <button class="line-action" type="button" data-connect-wallet>connect wallet</button>
          <button class="solid-action" type="button" data-stake disabled>stake ${baseBond}</button>
        </div>
        <p class="wallet-state" data-wallet>No wallet connected</p>
        <p class="wallet-state" data-balance hidden></p>
        <details class="funding">
          <summary>No ${CHAIN_NAME} ETH? Two ways in</summary>
          <p>Faucet drips are usually smaller than a bond, so funding can take a few tries. No ETH at all: copy your public commitment above and send it to a sponsor. The sponsor never sees the secret.</p>
          <ul>
            <li><a href="https://sepolia-faucet.pk910.de/">pk910 proof-of-work faucet</a>: mine in the browser, no account.</li>
            <li><a href="https://cloud.google.com/application/web3/faucet/ethereum/sepolia">Google Cloud Web3 faucet</a>: needs a Google account.</li>
            <li><a href="https://www.alchemy.com/faucets/ethereum-sepolia">Alchemy faucet</a> and <a href="https://faucet.quicknode.com/ethereum/sepolia">QuickNode faucet</a>: may ask for a small mainnet balance.</li>
          </ul>
        </details>
      </article>
    </section>

    <section class="sponsor-panel" data-sponsor-step hidden aria-labelledby="sponsor-title">
      <p class="step-index" aria-hidden="true">01</p>
      <h2 id="sponsor-title">Stake someone else’s public commitment</h2>
      <p>Ask the member or agent for its decimal ${commitmentNoun} and tier only. Any wallet may fund it; only the secret holder can prove as that member or authorise the withdrawal.</p>
      <label class="label" for="sponsor-leaf">public commitment</label>
      <textarea id="sponsor-leaf" data-sponsor-leaf rows="3" inputmode="numeric" autocomplete="off" spellcheck="false" placeholder="decimal field element"></textarea>
      <fieldset class="tier-pick">
        <legend class="label">their tier</legend>
${tierRows("sponsor-tier", "data-sponsor-tier")}
      </fieldset>
      <p class="fine"><strong>Know the tradeoff:</strong> your wallet, amount, commitment, and timing are public. The member controls the bearer credential and chooses the eventual refund recipient. Misuse can slash your sponsored bond.</p>
      <div class="button-row">
        <button class="line-action" type="button" data-connect-wallet>connect wallet</button>
        <button class="solid-action" type="button" data-stake disabled>stake this commitment</button>
      </div>
    </section>

    <section class="stake-feedback" aria-label="Progress and status">
      <p data-status role="status" aria-live="polite">Member mode: the identity stays in this tab until you download it.</p>
      <p data-alert role="alert"></p>
      <p data-receipt hidden>Transaction: <a data-receipt-link href="${EXPLORER_URL || "#"}" target="_blank" rel="noreferrer">view</a></p>
      <div class="finality" data-finality-panel hidden>
        <p class="label">05 finality</p>
        <p data-finality role="status" aria-live="polite"></p>
        <div class="finality-bar" aria-hidden="true"><i data-finality-bar></i></div>
        <p class="fine">Nodes read the finalized member set, so a reorg can never admit or drop a member. ${CHAIN_NAME} finality is usually 13 to 16 minutes after the stake confirms; the bar follows the chain's own finalized block.</p>
      </div>
      <p data-member-state hidden></p>
      <div class="button-row">
        <button class="line-action" type="button" data-check-status disabled>check status through my wallet</button>
      </div>
    </section>

    <section class="handoff-section" data-handoff aria-labelledby="handoff-title">
      <p class="step-index" aria-hidden="true">06</p>
      <h2 id="handoff-title">Hand it to your agent</h2>
      <p data-handoff-note>The commands below fill in your identity file's name once you create one. They work the same for a file made by <code>shadenet init</code>.</p>
      ${handoffTabs()}
      <p class="fine">Nodes admit the identity once its stake is final: <code>shadenet status --wait</code> returns then, and one request through the proxy returns a Tor exit address, not yours (<code>shadenet run -- curl -s https://api.ipify.org</code>).</p>
    </section>

    <section class="stake-lifecycle" aria-labelledby="leave-title">
      <h2 id="leave-title">Change tier or leave</h2>
      <p>Exit and withdraw are zero-knowledge proofs of the identity secret. Made here, they take a few seconds in this tab after a one-time <span data-prover-mb>${PROVER_MB}</span> MB prover download; the secret never leaves the page. The connected wallet only pays gas, so it can be one unrelated to the funder.</p>
      <ol class="leave-steps">
        <li>Import the identity file above and connect a wallet that only pays gas.</li>
        <li>Start the exit. The bond unlocks ${unbonding} later.</li>
        <li>Withdraw to a fresh address so the refund doesn't link back to the funder.</li>
      </ol>
      <div class="leave-actions">
        <button class="line-action" type="button" data-exit disabled>start exit</button>
        <label class="label" for="withdraw-to">fresh recipient address</label>
        <input id="withdraw-to" data-withdraw-to type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="0x…">
        <button class="line-action" type="button" data-withdraw disabled>withdraw bond</button>
      </div>
      <p class="fine">From a terminal instead: <code>shadenet exit-member --identity identity.json --key-file gas.key</code>, then after ${unbonding} <code>shadenet withdraw-member --identity identity.json --recipient 0xFRESH --key-file gas.key</code>. To change tier, stake a new identity at the new tier, then exit the old one; both bonds are locked for ${unbonding}.</p>
    </section>

    <section class="stake-faq" aria-labelledby="faq-title">
      <h2 id="faq-title">Questions</h2>
      <details>
        <summary>What do Shade Tree nodes see?</summary>
        <p>The destination hostname, timing, and how many bytes flow, as any proxy would. They see a valid membership proof, not which member made it. Destinations see the node's IP, not yours.</p>
      </details>
      <details>
        <summary>Why wait for finality?</summary>
        <p>Nodes and the proxy both read the finalized member set, so a reorg can't admit or drop a member. On ${CHAIN_NAME} that is usually 13 to 16 minutes after the stake confirms.</p>
      </details>
      <details>
        <summary>What if I lose the identity file?</summary>
        <p>Nobody can recover it for you. Without it you can't use the membership, exit, or withdraw, so the bond stays locked for good.</p>
      </details>
      <details>
        <summary>Can nodes limit me across the whole canopy?</summary>
        <p>The per-${epochNoun} budget is canopy-wide, but nodes share spent proofs on a best-effort basis today. Double use across two nodes at the same moment may not be caught immediately; it is still slashable once seen.</p>
      </details>
      <details>
        <summary>Is there a free or paid path?</summary>
        <p>Operators can admit invited members from a private members file; ask one for their <a href="../agent/index.html">setup details</a>. A paid path exists in the code but is not offered on this canopy.</p>
      </details>
      <details>
        <summary>Will these addresses and prices change?</summary>
        <p>Yes. This is a research preview. The contract, bonds, tiers and unbonding time can change at the next deployment, and this page is rebuilt from that deployment's record.</p>
      </details>
      <details>
        <summary>Is ShadeNet related to Shade Network or Shade Protocol?</summary>
        <p>No. ShadeNet is not affiliated with Shade Network, Shade Protocol or any other project with Shade in its name. It is one word, and it is this: proof-gated Tor egress for AI agents.</p>
      </details>
    </section>

    <section class="stake-boundary" aria-labelledby="boundary-title">
      <h2 id="boundary-title">Honest boundary</h2>
      <p>Tier ${Number(baseTier.limit)} buys ${Number(baseTier.limit) === 1 ? "one new HTTPS tunnel" : `${Number(baseTier.limit)} new HTTPS tunnels`} per fixed ${RATE.epochSeconds}-second epoch, capped at ${mib} combined traffic each. Registration becomes usable after ${CHAIN_NAME} finality. The wallet-to-commitment link is permanent; use a separately funded wallet or a sponsor if address-graph separation matters. Exit and withdraw are proof-authorised and return the testnet bond to a fresh recipient after ${unbonding}. ${artifactsLine} Never use mainnet ETH or sensitive traffic.</p>
    </section>
      </div>
    </div>
  </main>

  <footer class="site-footer">
    <span>Research preview</span>
    <nav aria-label="Project links">
      <a href="../index.html">Home</a>
      <a href="../agent/index.html">Agent guide</a>
      <a href="https://github.com/dmarzzz/shade-tree-node/blob/main/docs/PUBLIC-STAKING.md">Protocol parameters</a>
      <a href="https://github.com/dmarzzz/shade-tree-node/blob/main/docs/THREAT-MODEL.md">Threat model</a>
    </nav>
  </footer>
</body>
</html>
`;
}
