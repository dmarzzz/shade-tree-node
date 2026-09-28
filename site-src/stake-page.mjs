// Renders docs/post/stake/index.html ("Get access") from the network record via profile.mjs.
// No price, tier, rate or address is written by hand here; `npm run build:stake` regenerates the
// page and test/stake-site.selftest.mjs fails if the committed HTML drifts from this template.
import {
  CHAIN_NAME,
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

const epoch = formatDuration(RATE.epochSeconds);
const perEpoch = RATE.epochSeconds === 60 ? "per minute" : `per ${epoch}`;
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

function tierRows() {
  return TIERS.map((tier) => {
    const n = Number(tier.limit);
    return `          <tr>
            <th scope="row">${n}</th>
            <td>${formatEth(tier.bondWei)} ETH</td>
            <td>${n} ${n === 1 ? "tunnel" : "tunnels"} ${perEpoch}</td>
            <td>${mib} each</td>
            <td>${unbonding}</td>
          </tr>`;
  }).join("\n");
}

function tierRadios(name, attr) {
  return TIERS.map((tier) => {
    const n = Number(tier.limit);
    const checked = tier.limit === DEFAULT_LIMIT ? " checked" : "";
    return `<label><input type="radio" name="${name}" value="${n}" ${attr}${checked}> tier ${n} · ${formatEth(tier.bondWei)} ETH</label>`;
  }).join("\n            ");
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
    <header class="stake-intro">
      <p class="stake-eyebrow">Get access · ${CHAIN_NAME} research preview</p>
      <h1>Stake without giving us an identity.</h1>
      <p>Create a bearer credential in this tab, keep its recovery file, and put only its public commitment on chain. The canopy never receives the secret.</p>
      <dl class="live-chips" aria-label="Live network">
        <div><dt>Network</dt><dd>${CHAIN_NAME} testnet</dd></div>
        <div><dt>Nodes announced</dt><dd data-live-nodes>…</dd></div>
        <div><dt>Staked members</dt><dd data-live-members>…</dd></div>
      </dl>
      <div class="mode-switch" aria-label="Choose a staking role">
        <button type="button" data-mode="member" aria-pressed="true">I’m joining</button>
        <button type="button" data-mode="sponsor" aria-pressed="false">I’m sponsoring</button>
      </div>
    </header>

    <aside class="privacy-ledger" aria-labelledby="privacy-title">
      <h2 id="privacy-title">What each party learns</h2>
      <dl>
        <div><dt>This page</dt><dd>Generates and validates locally. No identity API exists.</dd></div>
        <div><dt>Your wallet / RPC</dt><dd>Sees your address, public commitment, bond, and timing.</dd></div>
        <div><dt>The canopy</dt><dd>Later sees a valid anonymous membership proof, not which leaf made it.</dd></div>
      </dl>
      <p data-live-set>Your privacy is only as large as the staked set. The live count loads from this site's aggregate API.</p>
      <p>Loading any website can expose your IP to its host. This static page never sends the commitment or recovery file to the ShadeNet server.</p>
    </aside>

    <section class="tier-table" aria-labelledby="tiers-title">
      <h2 id="tiers-title">What a stake buys</h2>
      <p>A tunnel is one HTTPS connection to one site. Each tier gets that many new tunnels ${perEpoch}, canopy-wide, and each tunnel carries up to ${mib} in both directions combined. A search plus five result pages is about six tunnels.</p>
      <div class="table-wrap" tabindex="0" role="region" aria-labelledby="tiers-title">
        <table>
          <thead>
            <tr><th scope="col">Tier</th><th scope="col">Bond</th><th scope="col">New tunnels</th><th scope="col">Per tunnel</th><th scope="col">Unbonding</th></tr>
          </thead>
          <tbody>
${tierRows()}
          </tbody>
        </table>
      </div>
      <p>The bond is refundable collateral, not a fee. Sending two different requests from the same slot in one ${epoch === "1 minute" ? "minute" : "epoch"} reveals your secret and lets anyone slash the bond. ${slashLine} A tier is fixed to the identity: to change tier, stake a new identity and exit the old one.</p>
    </section>

    <section class="funding" aria-labelledby="funding-title">
      <h2 id="funding-title">Get ${CHAIN_NAME} ETH</h2>
      <p>You need the bond plus a little gas, from a wallet you don't mind linking to your commitment forever. Faucet drips are usually smaller than a bond, so it can take a few days, or a sponsor can stake for you.</p>
      <ul>
        <li><a href="https://sepolia-faucet.pk910.de/">pk910 proof-of-work faucet</a>: mine in the browser, no account.</li>
        <li><a href="https://cloud.google.com/application/web3/faucet/ethereum/sepolia">Google Cloud Web3 faucet</a>: needs a Google account.</li>
        <li><a href="https://www.alchemy.com/faucets/ethereum-sepolia">Alchemy faucet</a> and <a href="https://faucet.quicknode.com/ethereum/sepolia">QuickNode faucet</a>: may ask for a small mainnet balance.</li>
        <li>No ETH at all: choose <em>I’m joining</em>, copy your public commitment, and send it to a sponsor. The sponsor never sees the secret.</li>
      </ul>
    </section>

    <section class="stake-trail" data-member-steps aria-label="Member staking steps">
      <article class="stake-step">
        <span class="trail-number" aria-hidden="true">1</span>
        <h2>Create locally</h2>
        <p>Pick a tier, then generate an identity from fresh operating-system randomness. The tier is part of the identity.</p>
        <fieldset class="tier-pick">
          <legend>Tier</legend>
            ${tierRadios("tier", "data-tier")}
        </fieldset>
        <div class="button-row">
          <button class="solid-action" type="button" data-create-identity>create identity</button>
          <button class="line-action" type="button" data-import-identity>import to check status</button>
          <input type="file" accept="application/json,.json" data-identity-file hidden>
        </div>
        <div class="leaf-tag" data-leaf-tag data-ready="false">
          <span>Public commitment</span>
          <output data-leaf>Create or import an identity to reveal its public commitment.</output>
        </div>
      </article>

      <article class="stake-step">
        <span class="trail-number" aria-hidden="true">2</span>
        <h2>Save the bearer file</h2>
        <p>The ShadeNet CLI reads this file directly. Whoever has it can use the membership and authorize its eventual exit.</p>
        <div class="button-row">
          <button class="solid-action" type="button" data-download-identity disabled>download identity.json</button>
          <button class="line-action" type="button" data-copy-leaf disabled>copy public commitment</button>
        </div>
        <label class="recovery-check"><input type="checkbox" data-recovery-check disabled> I saved the file somewhere private and recoverable.</label>
        <p class="plain-warning">The download is plaintext. Keep it on an encrypted device or in a secret vault; do not email or paste it into chat.</p>
      </article>

      <article class="stake-step transaction-step">
        <span class="trail-number" aria-hidden="true">3</span>
        <h2>Stake on ${CHAIN_NAME}</h2>
        <p>The wallet sends exactly the tier's bond to the pinned contract. Gas is additional. Each stake needs a new identity created here.</p>
        <p class="contract-line"><span>Contract</span>${contractLink ? `<a href="${contractLink}">${shortAddress(CONTRACT)}</a>` : shortAddress(CONTRACT)}</p>
        <div class="button-row">
          <button class="line-action" type="button" data-connect-wallet>connect wallet</button>
          <button class="solid-action" type="button" data-stake disabled>stake ${baseBond}</button>
        </div>
        <p class="wallet-state" data-wallet>No wallet connected</p>
      </article>
    </section>

    <section class="sponsor-panel" data-sponsor-step hidden aria-labelledby="sponsor-title">
      <div>
        <p class="stake-eyebrow">Secret-free handoff</p>
        <h2 id="sponsor-title">Stake someone else’s public commitment.</h2>
        <p>Ask the member or agent for its decimal ${commitmentNoun} and tier only. The contract permits any wallet to fund it, while only the secret holder can prove as that member or authorize withdrawal.</p>
        <label for="sponsor-leaf">Public commitment</label>
        <textarea id="sponsor-leaf" data-sponsor-leaf rows="3" inputmode="numeric" autocomplete="off" spellcheck="false" placeholder="Decimal field element"></textarea>
        <fieldset class="tier-pick">
          <legend>Their tier</legend>
            ${tierRadios("sponsor-tier", "data-sponsor-tier")}
        </fieldset>
      </div>
      <div class="sponsor-action">
        <p><strong>Know the tradeoff:</strong> your wallet, amount, commitment, and timing are public. The member controls the bearer credential and can choose the eventual refund recipient. Misuse can slash your sponsored bond.</p>
        <div class="button-row">
          <button class="line-action" type="button" data-connect-wallet>connect wallet</button>
          <button class="solid-action" type="button" data-stake disabled>stake this commitment</button>
        </div>
      </div>
    </section>

    <div class="stake-feedback">
      <p data-status role="status" aria-live="polite">Member mode: the identity stays in this tab until you download it.</p>
      <p data-alert role="alert"></p>
      <p data-receipt hidden>Transaction: <a data-receipt-link href="${EXPLORER_URL || "#"}" target="_blank" rel="noreferrer">view</a></p>
      <p data-finality role="status" aria-live="polite" hidden></p>
      <p data-member-state hidden></p>
      <div class="button-row">
        <button class="line-action" type="button" data-check-status disabled>check status through my wallet</button>
      </div>
    </div>

    <section class="agent-handoff" aria-labelledby="agent-handoff-title">
      <div>
        <p class="stake-eyebrow">Hand it to your agent</p>
        <h2 id="agent-handoff-title">Staked in this tab</h2>
        <p>Move the downloaded file next to the agent, lock it to your user, start the Proxy, and launch the agent through it. <a href="../agent/index.html">Install the binary first.</a></p>
      </div>
      <pre tabindex="0" aria-label="Commands after staking in the browser"><code>mv ~/Downloads/shadenet-identity-*.json identity.json
chmod 600 identity.json
(umask 077; set -C; shade-tree proxy-token &gt; proxy-token.txt)
IFS= read -r SHADE_TREE_PROXY_TOKEN &lt; proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree proxy --identity identity.json --listen 127.0.0.1:8118
shade-tree run -- your-agent</code></pre>
    </section>

    <section class="agent-handoff" aria-labelledby="terminal-title">
      <div>
        <p class="stake-eyebrow">For agents and terminals</p>
        <h2 id="terminal-title">The same boundary, without a browser.</h2>
        <p>The CLI creates an owner-only identity file, prints only the public leaf, and signs locally from an owner-only key file. Contract, RPC, tier, and bond come from the same bundled ${CHAIN_NAME} record.</p>
      </div>
      <pre tabindex="0" aria-label="Agent staking commands"><code>shade-tree enroll --out identity.json
shade-tree register-member --identity identity.json \\
  --key-file funded-sepolia.key
shade-tree member-status --identity identity.json --json
shade-tree proxy --identity identity.json</code></pre>
      <a class="line-action" href="../agent/index.html">complete agent setup</a>
    </section>

    <section class="stake-lifecycle" aria-labelledby="verify-title">
      <div>
        <h2 id="verify-title">Verify it works</h2>
        <p>After finality, <code>member-status</code> reports the identity as active, and one request through the Proxy should return a Tor exit address, not yours.</p>
        <pre tabindex="0" aria-label="Verification commands"><code>shade-tree member-status --identity identity.json --json
shade-tree run -- curl -s https://api.ipify.org</code></pre>
      </div>
      <div>
        <h2 id="leave-title">Change tier or leave</h2>
        <p>Exit and withdraw are zero-knowledge proofs made on your machine. After exit the bond unlocks in ${unbonding}; withdraw it to a fresh address so it doesn't link back to the funder. A gas wallet for these calls can be unrelated to both.</p>
        <pre tabindex="0" aria-label="Exit and withdraw commands"><code>shade-tree exit-member --identity identity.json --key-file gas.key
shade-tree member-status --identity identity.json --json
shade-tree withdraw-member --identity identity.json \\
  --recipient 0xFRESH_ADDRESS --key-file gas.key</code></pre>
        <p>Or leave from this tab: import the identity above, connect a wallet that only pays gas, then exit. The proof is made here and the secret never leaves the page.</p>
        <div class="leave-actions">
          <button class="line-action" type="button" data-exit disabled>start exit</button>
          <label for="withdraw-to">Fresh recipient address</label>
          <input id="withdraw-to" data-withdraw-to type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="0x…">
          <button class="line-action" type="button" data-withdraw disabled>withdraw bond</button>
        </div>
        <p>To change tier, create a new identity at the new tier here, stake it, then exit the old one. For ${unbonding} both bonds are locked.</p>
      </div>
    </section>

    <section class="stake-faq" aria-labelledby="faq-title">
      <h2 id="faq-title">Questions</h2>
      <details>
        <summary>What do Shade Tree nodes see?</summary>
        <p>The destination hostname, timing, and how many bytes flow, as any proxy would. They see a valid membership proof, not which member made it. Destinations see the node's IP, not yours.</p>
      </details>
      <details>
        <summary>Why wait for finality?</summary>
        <p>Nodes and the Proxy both read the finalized member set, so a reorg can't admit or drop a member. On ${CHAIN_NAME} that is usually 13 to 16 minutes after the stake confirms.</p>
      </details>
      <details>
        <summary>What if I lose identity.json?</summary>
        <p>Nobody can recover it for you. Without it you can't use the membership, exit, or withdraw, so the bond stays locked for good.</p>
      </details>
      <details>
        <summary>Can nodes limit me across the whole canopy?</summary>
        <p>The per-${epoch === "1 minute" ? "minute" : "epoch"} budget is canopy-wide, but nodes share spent proofs on a best-effort basis today. Double use across two nodes at the same moment may not be caught immediately; it is still slashable once seen.</p>
      </details>
      <details>
        <summary>Is there a free or paid path?</summary>
        <p>Operators can admit invited members from a private members file; ask one for their <a href="../agent/index.html">setup details</a>. A paid path exists in the code but is not offered on this canopy.</p>
      </details>
      <details>
        <summary>Will these addresses and prices change?</summary>
        <p>Yes. This is a research preview. The contract, bonds, tiers and unbonding time can change at the next deployment, and this page is rebuilt from that deployment's record.</p>
      </details>
    </section>

    <section class="stake-boundary" aria-labelledby="boundary-title">
      <h2 id="boundary-title">Honest boundary</h2>
      <p>Tier ${Number(baseTier.limit)} buys ${Number(baseTier.limit) === 1 ? "one new HTTPS tunnel" : `${Number(baseTier.limit)} new HTTPS tunnels`} per fixed ${RATE.epochSeconds}-second epoch, capped at ${mib} combined traffic each. Registration becomes usable after ${CHAIN_NAME} finality. The wallet-to-commitment link is permanent; use a separately funded wallet or a sponsor if address-graph separation matters. The CLI can later initiate a private, proof-authorized exit and return the testnet bond to a fresh recipient after ${unbonding}. ${artifactsLine} Never use mainnet ETH or sensitive traffic.</p>
    </section>
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
