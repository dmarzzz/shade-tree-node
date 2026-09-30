import { getAddress } from "ethers";
import { createIdentity, createStaking, importIdentity, serializeIdentity, identityCommitmentOf, identityFileName } from "../packages/sdk/src/index.mjs";
import { deriveIdentity as deriveCore, leafFromIdentityCommitment, parseCommitment as parseCore } from "../packages/node/lib/identity-core.mjs";
import {
  CHAIN_ID,
  CHAIN_NAME,
  CONTRACT as RECORD_CONTRACT,
  DEFAULT_LIMIT,
  EXPLORER_URL,
  REGISTER_INPUT,
  RPC_URL,
  TIERS,
  formatDuration,
  formatEth,
  tierFor,
  NETWORK_RECORD,
} from "./profile.mjs";
import { explainError, formatExplanation } from "./stake-errors.mjs";

export { CHAIN_ID, DEFAULT_LIMIT, EXPLORER_URL, REGISTER_INPUT, RPC_URL, TIERS };
export const CONTRACT = getAddress(RECORD_CONTRACT);
// Sepolia targets 12 s slots; finality is two epochs behind head in the normal case.
const SLOT_SECONDS = 12;
// Gas a register call needs, with room; only used to tell the visitor whether the wallet can pay.
const REGISTER_GAS = 200_000n;
// The withdraw circuit the in-browser prover runs, served same-origin by the site build.
export const PROVER_ARTIFACTS = Object.freeze({ wasm: "/stake/zk/withdraw.wasm", zkey: "/stake/zk/withdraw_final.zkey" });
const STEPS = ["tier", "identity", "save", "stake", "finality", "handoff"];

// Stake, sponsor, status, exit and withdraw all go through the SDK. snarkjs inside it loads
// lazily, only when someone exits or withdraws.
function staking() {
  if (!window.ethereum?.request) throw new Error("No compatible Ethereum wallet was found in this browser.");
  return createStaking({ network: NETWORK_RECORD, provider: window.ethereum });
}

export function parseRecipient(text) {
  const value = String(text || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) throw new Error("Enter the fresh recipient as a 0x address.");
  const address = getAddress(value);
  if (/^0x0{40}$/i.test(address)) throw new Error("The recipient cannot be the zero address.");
  return address;
}

function offeredTier(limit) {
  const tier = tierFor(limit);
  if (!tier) {
    throw new Error(`This canopy offers tiers ${TIERS.map((t) => t.limit).join(" and ")}; limit ${limit} is not one of them.`);
  }
  return tier;
}

// Seeded derivation, for the shared Rust/Semaphore test vector. The page itself calls the SDK's
// createIdentity, which draws the seed from WebCrypto.
export async function deriveIdentity(seed, limit = DEFAULT_LIMIT) {
  const tier = offeredTier(limit);
  return deriveCore(seed, Number(tier.limit));
}

export function parseIdentityFile(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("That is not a valid ShadeNet identity JSON file.");
  }
  if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("The identity file must contain one JSON object.");
  if (Object.keys(value).sort().join(",") !== "identitySecret,leaf,limit") {
    throw new Error("The identity file must contain only identitySecret, leaf, and limit.");
  }
  offeredTier(value.limit);
  return importIdentity(value, { network: NETWORK_RECORD });
}

// The value `register` takes for this identity, per the deployment record's ABI.
export function registerCommitment(identity) {
  if (REGISTER_INPUT === "identityCommitment") return identityCommitmentOf(BigInt(identity.identitySecret)).toString();
  return identity.leaf;
}

// The member leaf the contract stores for a registration value at `limit`. ShadeNet sets take the
// identity commitment and derive Poseidon2(idc, limit) themselves (launch audit 2.1.4).
export function memberLeaf(commitment, limit) {
  if (REGISTER_INPUT !== "identityCommitment") return String(commitment);
  return leafFromIdentityCommitment(BigInt(commitment), BigInt(limit)).toString();
}

export function parseCommitment(text) {
  try {
    return parseCore(String(text || "").trim()).toString();
  } catch {
    throw new Error("Commitment must be a canonical, non-zero decimal field element.");
  }
}

export const identityBytes = serializeIdentity;

// Pure status model for a commitment read from the contract: what the page tells the member.
export function describeMember({ state, limit, withdrawableAt, finalized, now }) {
  if (state === "active" && finalized === false) return { state: "pending", message: `Registered at tier ${limit}. Nodes accept it once its block is finalized.` };
  if (state === "active") return { state: "active", message: `Active at tier ${limit} and finalized. Nodes accept it.` };
  if (state === "exiting" || state === "withdrawable") {
    const at = withdrawableAt ? Date.parse(withdrawableAt) / 1000 : 0;
    if (state === "exiting" && at > now) return { state: "exiting", message: `Exiting. The bond is withdrawable in about ${formatDuration(Math.max(60, Math.ceil((at - now) / 60) * 60))}.` };
    return { state: "withdrawable", message: "Exit complete. Withdraw the bond to a fresh address, here or with the CLI." };
  }
  return { state: "unregistered", message: "Not registered on this contract." };
}

export function finalityEstimate(targetBlock, finalizedBlock) {
  const remaining = BigInt(targetBlock) - BigInt(finalizedBlock);
  if (remaining <= 0n) return { final: true, seconds: 0 };
  return { final: false, seconds: Number(remaining) * SLOT_SECONDS };
}

// Whether a wallet can pay a tier's bond plus gas, as one sentence. Pure; balance and gas price in wei.
export function describeBalance({ balanceWei, tier, gasPriceWei }) {
  const balance = BigInt(balanceWei);
  const gas = BigInt(gasPriceWei ?? 0n) * REGISTER_GAS;
  const need = tier.bondWei + gas;
  const have = `${formatEth(balance)} ${CHAIN_NAME} ETH`;
  if (balance >= need) return { enough: true, message: `Balance ${have}: enough for tier ${tier.limit} (${formatEth(tier.bondWei)} ETH plus gas).` };
  const short = need - balance;
  return { enough: false, message: `Balance ${have}. Tier ${tier.limit} needs ${formatEth(tier.bondWei)} ETH plus about ${formatEth(gas)} ETH gas, so about ${formatEth(short)} ETH more. Get ${CHAIN_NAME} ETH below, or send your commitment to a sponsor.` };
}

function short(value, left = 8, right = 7) {
  if (!value) return "";
  return `${value.slice(0, left)}…${value.slice(-right)}`;
}

function hexQuantity(value) {
  return `0x${BigInt(value).toString(16)}`;
}

function elements() {
  return {
    modeButtons: [...document.querySelectorAll("[data-mode]")],
    memberSteps: document.querySelector("[data-member-steps]"),
    sponsorStep: document.querySelector("[data-sponsor-step]"),
    rail: [...document.querySelectorAll("[data-rail-step]")],
    tierInputs: [...document.querySelectorAll("[data-tier]")],
    sponsorTierInputs: [...document.querySelectorAll("[data-sponsor-tier]")],
    createButton: document.querySelector("[data-create-identity]"),
    importButton: document.querySelector("[data-import-identity]"),
    fileInput: document.querySelector("[data-identity-file]"),
    downloadButton: document.querySelector("[data-download-identity]"),
    copyButton: document.querySelector("[data-copy-leaf]"),
    recoveryCheck: document.querySelector("[data-recovery-check]"),
    leaf: document.querySelector("[data-leaf]"),
    leafTag: document.querySelector("[data-leaf-tag]"),
    sponsorInput: document.querySelector("[data-sponsor-leaf]"),
    connectButtons: [...document.querySelectorAll("[data-connect-wallet]")],
    stakeButtons: [...document.querySelectorAll("[data-stake]")],
    statusButton: document.querySelector("[data-check-status]"),
    wallet: document.querySelector("[data-wallet]"),
    balance: document.querySelector("[data-balance]"),
    status: document.querySelector("[data-status]"),
    alert: document.querySelector("[data-alert]"),
    receipt: document.querySelector("[data-receipt]"),
    receiptLink: document.querySelector("[data-receipt-link]"),
    memberState: document.querySelector("[data-member-state]"),
    exitButton: document.querySelector("[data-exit]"),
    withdrawButton: document.querySelector("[data-withdraw]"),
    withdrawTo: document.querySelector("[data-withdraw-to]"),
    finalityPanel: document.querySelector("[data-finality-panel]"),
    finality: document.querySelector("[data-finality]"),
    finalityBar: document.querySelector("[data-finality-bar]"),
    fileNames: [...document.querySelectorAll("[data-file-name]")],
    handoff: document.querySelector("[data-handoff]"),
    handoffNote: document.querySelector("[data-handoff-note]"),
    copyBlocks: [...document.querySelectorAll("[data-copy-block]")],
    tabs: document.querySelector("[data-tabs]"),
  };
}

function mount() {
  const el = elements();
  const state = {
    mode: "member", identity: null, imported: false, account: null, busy: false, tier: DEFAULT_LIMIT,
    finalityTimer: null, stakeStep: "idle", admitted: false, balanceOk: null, balanceHave: null, finalityStart: null,
  };

  function announce(message, kind = "plain") {
    // Errors go to an assertive alert region; progress goes to the polite status region.
    if (kind === "bad") {
      el.alert.textContent = message;
      el.status.textContent = "";
    } else {
      el.alert.textContent = "";
      el.status.textContent = message;
    }
    el.status.dataset.kind = kind;
  }

  function fail(error, context = {}) {
    const explained = explainError(error, { chainName: CHAIN_NAME, ...context });
    announce(formatExplanation(explained), "bad");
    if (explained.detail && explained.detail !== explained.text) el.alert.title = explained.detail;
    else el.alert.removeAttribute("title");
  }

  function sponsorTier() {
    const checked = el.sponsorTierInputs.find((input) => input.checked);
    return checked ? BigInt(checked.value) : DEFAULT_LIMIT;
  }

  function stakeTier() {
    return state.mode === "member" ? BigInt(state.identity?.limit ?? state.tier) : sponsorTier();
  }

  function selectedCommitment() {
    if (state.mode === "member") return state.identity ? registerCommitment(state.identity) : null;
    try {
      return parseCommitment(el.sponsorInput.value);
    } catch {
      return null;
    }
  }

  // Where the member is on the rail: every step before the current one is done.
  function railState() {
    const hasIdentity = Boolean(state.identity);
    const saved = hasIdentity && (el.recoveryCheck.checked || state.imported);
    let current = "tier";
    if (hasIdentity) current = "save";
    if (saved) current = "stake";
    if (state.stakeStep === "confirmed") current = "finality";
    if (state.stakeStep === "final") current = "handoff";
    if (state.admitted) current = "done";
    return current;
  }

  function paintRail() {
    const current = railState();
    const index = current === "done" ? STEPS.length : STEPS.indexOf(current);
    for (const item of el.rail) {
      const i = STEPS.indexOf(item.dataset.railStep);
      item.dataset.state = i < index ? "done" : i === index ? "current" : "todo";
      if (i === index) item.setAttribute("aria-current", "step");
      else item.removeAttribute("aria-current");
    }
  }

  function update() {
    const hasIdentity = Boolean(state.identity);
    const saved = hasIdentity && el.recoveryCheck.checked;
    const commitment = selectedCommitment();
    const tier = tierFor(stakeTier());
    el.memberSteps.hidden = state.mode !== "member";
    el.sponsorStep.hidden = state.mode !== "sponsor";
    for (const button of el.modeButtons) button.setAttribute("aria-pressed", String(button.dataset.mode === state.mode));
    for (const input of el.tierInputs) input.disabled = hasIdentity || state.busy;
    el.downloadButton.disabled = !hasIdentity || state.imported || state.busy;
    el.copyButton.disabled = !hasIdentity || state.busy;
    el.recoveryCheck.disabled = !hasIdentity || state.imported || state.busy;
    for (const button of el.connectButtons) {
      button.disabled = state.busy;
      button.textContent = state.account ? "change wallet" : "connect wallet";
    }
    for (const button of el.stakeButtons) {
      const memberBlocked = state.mode === "member" && (!saved || state.imported);
      button.disabled = state.busy || !state.account || !commitment || !tier || memberBlocked;
      button.textContent = state.mode === "sponsor"
        ? `stake ${tier ? formatEth(tier.bondWei) : "?"} ${CHAIN_NAME} ETH for this commitment`
        : `stake ${tier ? formatEth(tier.bondWei) : "?"} ${CHAIN_NAME} ETH`;
    }
    if (el.statusButton) el.statusButton.disabled = state.busy || !state.account || !commitment;
    const canProve = hasIdentity && Boolean(state.account) && !state.busy && state.mode === "member";
    if (el.exitButton) el.exitButton.disabled = !canProve;
    if (el.withdrawButton) {
      let recipientOk = false;
      try { parseRecipient(el.withdrawTo.value); recipientOk = true; } catch {}
      el.withdrawButton.disabled = !canProve || !recipientOk;
    }
    el.leaf.textContent = hasIdentity ? registerCommitment(state.identity) : "Create or import an identity to reveal its public commitment.";
    el.leafTag.dataset.ready = String(hasIdentity);
    el.wallet.textContent = state.account ? `Connected: ${short(state.account, 8, 6)}` : "No wallet connected";
    const name = hasIdentity ? identityFileName(state.identity) : "shadenet-identity-XXXXXXXX.json";
    for (const node of el.fileNames) node.textContent = name;
    if (el.handoffNote) {
      el.handoffNote.textContent = hasIdentity
        ? `The commands below name your file, ${name}. They work the same for a file made by shadenet init.`
        : "The commands below fill in your identity file's name once you create one. They work the same for a file made by shadenet init.";
    }
    if (el.handoff) el.handoff.dataset.ready = String(state.stakeStep === "final" || state.admitted);
    paintRail();
  }

  async function onCreateIdentity() {
    state.busy = true;
    update();
    try {
      state.identity = await createIdentity({ network: NETWORK_RECORD, limit: Number(state.tier) });
      state.imported = false;
      state.stakeStep = "idle";
      state.admitted = false;
      el.recoveryCheck.checked = false;
      announce(`Tier ${state.identity.limit} identity created in this tab. Download it and confirm you saved it before staking.`, "good");
    } catch (error) {
      fail(error, { action: "creating the identity" });
    } finally {
      state.busy = false;
      update();
    }
  }

  async function importIdentityFile(file) {
    try {
      if (!file || file.size > 16 * 1024) throw new Error("Choose a ShadeNet identity file under 16 KiB.");
      state.identity = parseIdentityFile(await file.text());
      state.imported = true;
      state.stakeStep = "idle";
      state.admitted = false;
      el.recoveryCheck.checked = false;
      announce("Identity validated locally and not uploaded. Imported identities can check status, exit and withdraw; stake a new identity for a new bond.", "good");
    } catch (error) {
      state.identity = null;
      state.imported = false;
      el.recoveryCheck.checked = false;
      fail(error, { action: "importing the identity" });
    } finally {
      el.fileInput.value = "";
      update();
    }
  }

  function downloadIdentity() {
    if (!state.identity) return;
    const blob = new Blob([identityBytes(state.identity)], { type: "application/json" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.href = url;
    link.download = identityFileName(state.identity);
    link.click();
    URL.revokeObjectURL(url);
    announce(`Download started: ${link.download}. Check the file is saved, then tick the box. It is a bearer credential.`, "good");
    update();
  }

  async function copyText(text, okMessage) {
    try {
      await navigator.clipboard.writeText(text);
      announce(okMessage, "good");
      return true;
    } catch (error) {
      fail(error, { action: "copying" });
      return false;
    }
  }

  async function copyLeaf() {
    if (!state.identity) return;
    const ok = await copyText(registerCommitment(state.identity), "Public commitment copied. It is safe to give to a sponsor.");
    if (!ok) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el.leaf);
      selection.removeAllRanges();
      selection.addRange(range);
    }
  }

  async function request(method, params = []) {
    if (!window.ethereum?.request) throw new Error("No compatible Ethereum wallet was found in this browser.");
    return window.ethereum.request({ method, params });
  }

  async function selectChain() {
    try {
      await request("wallet_switchEthereumChain", [{ chainId: hexQuantity(CHAIN_ID) }]);
    } catch (error) {
      if (error?.code !== 4902) throw error;
      await request("wallet_addEthereumChain", [{
        chainId: hexQuantity(CHAIN_ID),
        chainName: CHAIN_NAME,
        nativeCurrency: { name: `${CHAIN_NAME} Ether`, symbol: "ETH", decimals: 18 },
        rpcUrls: [RPC_URL],
        blockExplorerUrls: EXPLORER_URL ? [EXPLORER_URL] : [],
      }]);
    }
    const chain = BigInt(await request("eth_chainId"));
    if (chain !== CHAIN_ID) throw new Error(`Wallet is on chain ${chain}; ${CHAIN_NAME} (${CHAIN_ID}) is required.`);
  }

  // Say up front whether the wallet can pay, instead of letting the stake fail later.
  async function readBalance() {
    if (!state.account || !el.balance) return;
    const tier = tierFor(stakeTier());
    if (!tier) return;
    try {
      const [balanceWei, gasPriceWei] = await Promise.all([request("eth_getBalance", [state.account, "latest"]), request("eth_gasPrice").catch(() => "0x0")]);
      const verdict = describeBalance({ balanceWei, tier, gasPriceWei });
      state.balanceOk = verdict.enough;
      state.balanceHave = `${formatEth(BigInt(balanceWei))} ${CHAIN_NAME} ETH`;
      el.balance.textContent = verdict.message;
      el.balance.dataset.kind = verdict.enough ? "good" : "warn";
      el.balance.hidden = false;
    } catch {
      el.balance.hidden = true;
      state.balanceOk = null;
    }
  }

  async function connectWallet() {
    state.busy = true;
    update();
    try {
      const accounts = await request("eth_requestAccounts");
      if (!Array.isArray(accounts) || !accounts[0]) throw new Error("The wallet did not provide an account.");
      await selectChain();
      state.account = getAddress(accounts[0]);
      const code = await request("eth_getCode", [CONTRACT, "latest"]);
      if (!code || code === "0x") throw new Error(`The pinned staking contract is not deployed on this wallet's ${CHAIN_NAME} network.`);
      announce(`Wallet connected on ${CHAIN_NAME}. Its address and the staking transaction will be public.`, "good");
      await readBalance();
    } catch (error) {
      state.account = null;
      el.balance.hidden = true;
      fail(error, { action: "connecting the wallet" });
    } finally {
      state.busy = false;
      update();
    }
  }

  function paintFinality(estimate, finalizedBlock, targetBlock) {
    if (!el.finalityBar) return;
    if (estimate.final) {
      el.finalityBar.style.width = "100%";
      return;
    }
    if (state.finalityStart == null) state.finalityStart = Number(finalizedBlock);
    const total = Math.max(1, Number(targetBlock) - state.finalityStart);
    const done = Math.max(0, Number(finalizedBlock) - state.finalityStart);
    el.finalityBar.style.width = `${Math.min(97, Math.round((done / total) * 100))}%`;
  }

  async function confirmAdmitted(commitment, limit) {
    try {
      const status = await staking().memberStatus(memberLeaf(commitment, limit));
      if (status.state === "active" && status.finalized) {
        state.admitted = true;
        state.stakeStep = "final";
        el.memberState.textContent = describeMember({ ...status, now: Math.floor(Date.now() / 1000) }).message;
        el.memberState.dataset.state = "active";
        el.memberState.hidden = false;
        announce("Admitted. Nodes accept this identity; hand the file to your agent below.", "good");
        el.handoff?.scrollIntoView?.({ behavior: "smooth", block: "start" });
      }
    } catch {
      // The finality text already says what to do; a failed read here is not an error worth an alert.
    }
    update();
  }

  function watchFinality(blockNumber, commitment, limit) {
    window.clearInterval(state.finalityTimer);
    state.finalityStart = null;
    const tick = async () => {
      try {
        const finalized = await request("eth_getBlockByNumber", ["finalized", false]);
        const finalizedBlock = finalized?.number ?? 0;
        const estimate = finalityEstimate(blockNumber, finalizedBlock);
        paintFinality(estimate, finalizedBlock, blockNumber);
        if (estimate.final) {
          window.clearInterval(state.finalityTimer);
          state.stakeStep = "final";
          el.finality.textContent = "Finalized. Nodes accept this membership once their next root refresh lands, usually within a minute.";
          el.finality.dataset.kind = "good";
          update();
          await confirmAdmitted(commitment, limit);
        } else {
          const minutes = Math.max(1, Math.round(estimate.seconds / 60));
          el.finality.textContent = `Waiting for ${CHAIN_NAME} finality: about ${minutes} min left (finalized block ${Number(finalizedBlock)}, yours is ${Number(blockNumber)}). Keep this tab open, or come back and check status.`;
          el.finality.dataset.kind = "plain";
        }
      } catch {
        el.finality.textContent = "Could not read finality from the wallet. It usually takes 13 to 16 minutes after the stake confirms; check status below afterwards.";
      }
    };
    el.finalityPanel.hidden = false;
    tick();
    state.finalityTimer = window.setInterval(tick, SLOT_SECONDS * 1000);
  }

  async function checkStatus() {
    let commitment;
    try {
      commitment = parseCommitment(selectedCommitment());
    } catch (error) {
      fail(error, { action: "checking status" });
      return;
    }
    state.busy = true;
    update();
    try {
      await selectChain();
      const status = await staking().memberStatus(memberLeaf(commitment, stakeTier()));
      const view = describeMember({ ...status, now: Math.floor(Date.now() / 1000) });
      el.memberState.textContent = view.message;
      el.memberState.dataset.state = view.state;
      el.memberState.hidden = false;
      if (view.state === "active") {
        state.admitted = true;
        state.stakeStep = "final";
      }
      announce("Status read through your wallet's RPC. This page sent it nowhere else.", "good");
    } catch (error) {
      fail(error, { action: "checking status" });
    } finally {
      state.busy = false;
      update();
    }
  }

  // Exit and withdraw prove knowledge of the identity secret in this tab (Groth16 over the
  // withdraw circuit). The wallet only pays gas; use one unrelated to the funder.
  async function leave(action) {
    if (!state.identity || !state.account) return;
    let recipient;
    if (action === "withdraw") {
      try {
        recipient = parseRecipient(el.withdrawTo.value);
      } catch (error) {
        fail(error, { action });
        return;
      }
    }
    state.busy = true;
    update();
    try {
      announce(`Checking the membership, then loading the prover (${PROVER_MB_TEXT} MB, once)…`);
      const sdk = staking();
      const status = await sdk.memberStatus(state.identity.leaf);
      if (action === "exit" && status.state !== "active") throw new Error("Only an active membership can start an exit.");
      if (action === "withdraw" && status.state !== "withdrawable") {
        throw new Error(status.state === "exiting" ? "Still unbonding. Withdraw after the deadline passes." : "There is no finished exit to withdraw.");
      }
      announce("Proving in this tab. This can take a few seconds; the secret never leaves the page.");
      const onSent = (hash) => {
        if (EXPLORER_URL) el.receiptLink.href = `${EXPLORER_URL}/tx/${hash}`;
        el.receiptLink.textContent = short(hash, 12, 10);
        el.receipt.hidden = false;
        announce("Transaction sent. Waiting for one confirmation…");
      };
      const sent = action === "exit"
        ? await sdk.exit({ identity: state.identity, from: state.account, artifacts: PROVER_ARTIFACTS, onSent })
        : await sdk.withdraw({ identity: state.identity, recipient, from: state.account, artifacts: PROVER_ARTIFACTS, onSent });
      const receipt = await sent.wait();
      if (!receipt) announce("Still pending after three minutes. Follow the transaction link; do not send again blindly.");
      else announce(action === "exit"
        ? "Exit started. The bond unlocks after the unbonding period; withdraw it here to a fresh address."
        : "Withdrawn. The bond went to the recipient address.", "good");
    } catch (error) {
      fail(error, { action, proverMb: PROVER_MB_TEXT });
    } finally {
      state.busy = false;
      update();
    }
  }

  async function stake() {
    let commitment;
    try {
      commitment = parseCommitment(selectedCommitment());
    } catch (error) {
      fail(error, { action: "stake" });
      return;
    }
    const tier = tierFor(stakeTier());
    if (!tier) {
      announce("Choose a tier this canopy offers.", "bad");
      return;
    }
    state.busy = true;
    el.receipt.hidden = true;
    update();
    try {
      await selectChain();
      announce(`Confirm the exact ${formatEth(tier.bondWei)} ${CHAIN_NAME} ETH transaction in your wallet.`);
      const sent = await staking().stake({
        commitment,
        limit: Number(tier.limit),
        from: state.account,
        onSent: (hash) => {
          if (EXPLORER_URL) el.receiptLink.href = `${EXPLORER_URL}/tx/${hash}`;
          el.receiptLink.textContent = short(hash, 12, 10);
          el.receipt.hidden = false;
          state.stakeStep = "sent";
          announce("Transaction sent. Waiting for one confirmation…");
        },
      });
      if (sent.alreadyActive) {
        announce("This commitment is already active. Nothing was sent.", "good");
        state.stakeStep = "confirmed";
        return;
      }
      const receipt = await sent.wait();
      if (!receipt) {
        announce("Still pending after three minutes. Use the transaction link to follow it; do not send again blindly.", "plain");
      } else {
        state.stakeStep = "confirmed";
        announce("Stake confirmed. Finality comes next; the hand-off commands below are ready meanwhile.", "good");
        watchFinality(receipt.blockNumber, commitment, tier.limit);
      }
    } catch (error) {
      fail(error, { action: "stake", need: `${formatEth(tier.bondWei)} ${CHAIN_NAME} ETH`, balance: state.balanceHave });
    } finally {
      state.busy = false;
      update();
    }
  }

  function mountTabs() {
    if (!el.tabs) return;
    const tabs = [...el.tabs.querySelectorAll('[role="tab"]')];
    const panels = [...el.tabs.querySelectorAll('[role="tabpanel"]')];
    const select = (index, focus = false) => {
      tabs.forEach((tab, i) => {
        tab.setAttribute("aria-selected", String(i === index));
        tab.tabIndex = i === index ? 0 : -1;
        panels[i].hidden = i !== index;
      });
      if (focus) tabs[index].focus();
    };
    tabs.forEach((tab, i) => {
      tab.addEventListener("click", () => select(i));
      tab.addEventListener("keydown", (event) => {
        const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
        if (event.key === "Home") { event.preventDefault(); select(0, true); }
        else if (event.key === "End") { event.preventDefault(); select(tabs.length - 1, true); }
        else if (step) { event.preventDefault(); select((i + step + tabs.length) % tabs.length, true); }
      });
    });
  }

  for (const button of el.modeButtons) button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    announce(state.mode === "member"
      ? "Member mode: the identity stays in this tab until you download it."
      : "Sponsor mode: paste only the member’s public commitment and tier. The member keeps the secret.");
    update();
    readBalance();
  });
  for (const input of el.tierInputs) input.addEventListener("change", () => {
    if (input.checked) state.tier = BigInt(input.value);
    update();
    readBalance();
  });
  for (const input of el.sponsorTierInputs) input.addEventListener("change", () => { update(); readBalance(); });
  el.createButton.addEventListener("click", onCreateIdentity);
  el.importButton.addEventListener("click", () => el.fileInput.click());
  el.fileInput.addEventListener("change", () => importIdentityFile(el.fileInput.files?.[0]));
  el.downloadButton.addEventListener("click", downloadIdentity);
  el.copyButton.addEventListener("click", copyLeaf);
  el.recoveryCheck.addEventListener("change", update);
  el.sponsorInput.addEventListener("input", update);
  el.statusButton?.addEventListener("click", checkStatus);
  el.exitButton?.addEventListener("click", () => leave("exit"));
  el.withdrawButton?.addEventListener("click", () => leave("withdraw"));
  el.withdrawTo?.addEventListener("input", update);
  for (const button of el.connectButtons) button.addEventListener("click", connectWallet);
  for (const button of el.stakeButtons) button.addEventListener("click", stake);
  for (const button of el.copyBlocks) button.addEventListener("click", async () => {
    const code = button.parentElement.querySelector("code");
    const ok = await copyText(code.textContent, "Copied.");
    button.textContent = ok ? "copied" : "copy";
    window.setTimeout(() => { button.textContent = "copy"; }, 1600);
  });
  mountTabs();
  window.ethereum?.on?.("accountsChanged", (accounts) => {
    state.account = accounts?.[0] ? getAddress(accounts[0]) : null;
    announce(state.account ? "Wallet account changed." : "Wallet disconnected.");
    update();
    readBalance();
  });
  window.ethereum?.on?.("chainChanged", () => {
    state.account = null;
    el.balance.hidden = true;
    announce("Wallet network changed. Reconnect to verify the chain.");
    update();
  });
  update();
}

// Stated on the page before any download; the build writes the same number into the HTML.
const PROVER_MB_TEXT = typeof document !== "undefined"
  ? (document.querySelector("[data-prover-mb]")?.textContent || "1.8")
  : "1.8";

if (typeof document !== "undefined" && document.querySelector("[data-member-steps]")) mount();
