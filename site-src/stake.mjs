// The Get access flow: three steps, one on screen. The page takes one public value, the identity
// commitment that `shadenet init` prints, and stakes the bond for it from a browser wallet.
// It never creates, reads, stores or sends a member secret; exit and withdraw run in the CLI.
import { getAddress } from "ethers";
import { createStaking } from "../packages/sdk/src/staking.mjs";
import { FIELD, leafFromIdentityCommitment, parseCommitment as parseCore } from "../packages/node/lib/identity-core.mjs";
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
const STEPS = ["setup", "stake", "start"];
const PANELS = [...STEPS, "details"];
// Step, public commitment and the stake transaction survive a reload. Nothing here is secret.
export const STORAGE_KEY = "shadenet.access.v1";
// A field element drawn at random has 76 or 77 digits; one under 60 digits is a cut-off paste.
const MIN_DIGITS = 60;

function staking() {
  if (!window.ethereum?.request) throw new Error("No compatible Ethereum wallet was found in this browser.");
  return createStaking({ network: NETWORK_RECORD, provider: window.ethereum });
}

const tierWords = () => (TIERS.length === 1 ? `tier ${TIERS[0].limit}` : `tiers ${TIERS.map((t) => t.limit).join(" and ")}`);

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
    throw new Error("The identity commitment must be a canonical, non-zero decimal field element.");
  }
}

// One decimal number out of pasted text, with a plain reason when it cannot be one.
function decimalOf(text, name) {
  const value = String(text).replace(/[\s,_]/g, "");
  if (!value) throw new Error(`Paste the ${name} that shadenet init prints.`);
  if (/^0x[0-9a-f]*$/i.test(value)) throw new Error(`Paste the ${name} as the decimal number shadenet init prints, without 0x.`);
  if (!/^[0-9]+$/.test(value)) throw new Error(`The ${name} is one decimal number. This has other characters in it.`);
  if (/^0/.test(value)) throw new Error(`The ${name} does not start with 0. Check that the first digits were copied.`);
  if (value.length < MIN_DIGITS) throw new Error(`That is ${value.length} ${value.length === 1 ? "digit" : "digits"}. The ${name} has about 77. Check that all of it was copied.`);
  if (value.length > 77 || BigInt(value) >= FIELD) throw new Error(`That number is too large to be the ${name}. Check that it was pasted once and nothing was added.`);
  return value;
}

function offeredLimit(text) {
  const value = String(text).trim();
  const tier = /^[0-9]{1,5}$/.test(value) ? tierFor(value) : null;
  if (!tier) throw new Error(`This canopy offers ${tierWords()}. Tier ${value || "?"} is not one of them.`);
  return Number(tier.limit);
}

// What the visitor pasted, or what a link's fragment carried: the identity commitment, and when
// the text also has them, the tier and the leaf. Accepts the bare number, the lines `shadenet
// init` prints, or a link to this page. A leaf makes the value checkable: the contract derives
// leaf = Poseidon2(identityCommitment, tier), so a link or paste that carries both proves the
// commitment is the right number for an identity made at a tier this canopy offers.
export function readCommitmentInput(text) {
  const raw = String(text ?? "").trim();
  if (!raw) throw new Error("Paste the identity commitment that shadenet init prints.");
  let commitmentText = null;
  let leafText = null;
  let limitText = null;
  const fragment = raw.match(/(?:^|[#?&])c=([^&#\s]*)/);
  if (fragment) {
    const params = new URLSearchParams(raw.slice(raw.indexOf("#") + 1).replace(/^.*\?/, ""));
    commitmentText = params.get("c") ?? fragment[1];
    leafText = params.get("leaf");
    limitText = params.get("limit");
  } else {
    const labelled = raw.match(/identity[ _-]?commitment["']?\s*[:=]?\s*["']?([0-9][0-9\s,_]*)/i);
    const leaf = raw.match(/\bleaf["']?\s*[:=]?\s*["']?([0-9][0-9\s,_]*)/i);
    const tier = raw.match(/\b(?:tier|limit)["']?\s*[:=]?\s*["']?([0-9]{1,5})\b/i);
    if (leaf && !labelled) {
      throw new Error("That is the leaf. Paste the identity commitment, which is a different number.");
    }
    commitmentText = labelled ? labelled[1] : raw;
    leafText = leaf ? leaf[1] : null;
    limitText = tier && (labelled || leaf) ? tier[1] : null;
  }
  const commitment = parseCommitment(decimalOf(commitmentText ?? "", "identity commitment"));
  let limit = limitText == null || limitText === "" ? null : offeredLimit(limitText);
  let leaf = null;
  if (leafText != null && leafText !== "") {
    leaf = decimalOf(leafText, "leaf");
    const matches = TIERS.map((tier) => Number(tier.limit)).filter((n) => memberLeaf(commitment, n) === leaf);
    if (!matches.length) {
      throw new Error(`The leaf does not match this identity commitment at ${tierWords()}, so the two numbers are swapped or the identity was made for another tier or network. Run shadenet init with the current release and paste what it prints.`);
    }
    if (limit != null && !matches.includes(limit)) {
      throw new Error(`The leaf belongs to tier ${matches[0]}, and the link says tier ${limit}. Run shadenet init again and use the link it prints.`);
    }
    limit = matches[0];
  }
  return { commitment, limit, leaf };
}

// A link that opens the stake step with the commitment filled in. The fragment is never sent to a
// server; it carries public values only.
export function stakeLink({ commitment, limit = null, leaf = null }, base = "/stake/") {
  const params = [`c=${commitment}`];
  if (limit != null) params.push(`limit=${limit}`);
  if (leaf) params.push(`leaf=${leaf}`);
  return `${base}#${params.join("&")}`;
}

// Pure status model for a commitment read from the contract: what the page tells the member.
export function describeMember({ state, limit, withdrawableAt, finalized, now }) {
  if (state === "active" && finalized === false) return { state: "pending", message: `Staked at tier ${limit}. Nodes admit it once its block is final.` };
  if (state === "active") return { state: "active", message: `Admitted at tier ${limit}. The stake is final and nodes accept this identity.` };
  if (state === "exiting" || state === "withdrawable") {
    const at = withdrawableAt ? Date.parse(withdrawableAt) / 1000 : 0;
    if (state === "exiting" && at > now) return { state: "exiting", message: `This identity is leaving the set. Its bond can be withdrawn in about ${formatDuration(Math.max(60, Math.ceil((at - now) / 60) * 60))}, with shadenet withdraw-member.` };
    return { state: "withdrawable", message: "This identity has left the set. Withdraw its bond with shadenet withdraw-member." };
  }
  return { state: "unregistered", message: "Not staked on this contract yet." };
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
  const have = `${approxEth(balance)} ${CHAIN_NAME} ETH`;
  if (balance >= need) return { enough: true, message: `${have}, enough for the bond and gas.` };
  const short = need - balance;
  return { enough: false, message: `${have}. The bond and gas come to about ${approxEth(need)} ETH, so this wallet needs about ${approxEth(short)} ETH more.` };
}

// Wei as ether to six places, rounded up, for sentences where the exact figure does not help.
export function approxEth(wei) {
  const value = BigInt(wei);
  if (value === 0n) return "0";
  const unit = 10n ** 12n;
  if (value < unit) return "under 0.000001";
  return formatEth(((value + unit - 1n) / unit) * unit);
}

function short(value, left = 8, right = 7) {
  if (!value) return "";
  return `${value.slice(0, left)}…${value.slice(-right)}`;
}

function hexQuantity(value) {
  return `0x${BigInt(value).toString(16)}`;
}

function loadSaved() {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) || "null");
    return value && typeof value === "object" ? value : {};
  } catch {
    return {};
  }
}

function mount() {
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const el = {
    panels: $$("[data-panel]"),
    stepper: $("[data-stepper]"),
    stepLinks: $$("[data-step-link]"),
    goLinks: $$("[data-go]"),
    input: $("[data-commitment]"),
    inputMessage: $("[data-commitment-message]"),
    shown: $("[data-commitment-shown]"),
    copyLink: $("[data-copy-link]"),
    bond: $("[data-bond]"),
    buys: $("[data-buys]"),
    tierInputs: $$("[data-tier]"),
    tierHint: $("[data-tier-hint]"),
    beforeStake: $("[data-before-stake]"),
    primary: $("[data-primary]"),
    changeWallet: $("[data-change-wallet]"),
    stakePanel: $('[data-panel="stake"]'),
    walletRow: $("[data-wallet-row]"),
    wallet: $("[data-wallet]"),
    tierRow: $("[data-tier-row]"),
    tierPick: $(".tier-pick"),
    terminal: $("[data-terminal]"),
    terminalText: $("[data-terminal-text]"),
    balance: $("[data-balance]"),
    status: $("[data-status]"),
    alert: $("[data-alert]"),
    receipt: $("[data-receipt]"),
    receiptLink: $("[data-receipt-link]"),
    finalityPanel: $("[data-finality-panel]"),
    finality: $("[data-finality]"),
    finalityBar: $("[data-finality-bar]"),
    memberState: $("[data-member-state]"),
    nextStart: $("[data-next-start]"),
    startState: $("[data-start-state]"),
    copyBlocks: $$("[data-copy-block]"),
    brief: $("[data-brief]"),
    copyBrief: $("[data-copy-brief]"),
    tabs: $("[data-tabs]"),
    scrollers: $$(".cmd pre"),
    details: $$("details[name]"),
  };
  const tierHintDefault = el.tierHint?.innerHTML;
  const buysText = new Map(el.tierInputs.map((input) => [input.value, input.dataset.buysText]));
  const saved = loadSaved();
  const state = {
    panel: PANELS.includes(saved.panel) ? saved.panel : "setup",
    lastStep: "setup",
    commitment: null, limit: null, leaf: null,
    // The last value that arrived with its leaf (a link or a full paste), so the check and the
    // tier it proved survive the field being read again as a bare number.
    checked: null,
    account: null, busy: false,
    // idle: no wallet yet. ready: may stake. sent: transaction in flight. confirmed: mined, waiting
    // for finality. final: admitted. left: the identity is exiting or has exited. resume: a stake
    // was sent before a reload and the wallet is not connected yet.
    stage: "idle",
    tx: null, finalityTimer: null, finalityStart: null,
  };

  function save() {
    try {
      window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify({
        panel: state.panel, input: el.input.value.slice(0, 600), tx: state.tx, limit: state.limit,
      }));
    } catch {
      // Private windows and blocked storage: the page works, a reload starts over.
    }
  }

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

  const stakeLimit = () => BigInt(state.limit ?? DEFAULT_LIMIT);
  const hasWallet = () => Boolean(window.ethereum?.request);

  // Read the field. Returns true when it holds a usable identity commitment.
  function readInput({ origin = "" } = {}) {
    const previous = state.commitment;
    try {
      const parsed = readCommitmentInput(el.input.value);
      if (parsed.leaf) state.checked = parsed;
      const checked = state.checked?.commitment === parsed.commitment ? state.checked : null;
      state.commitment = parsed.commitment;
      state.leaf = checked?.leaf ?? null;
      const limit = checked?.limit ?? parsed.limit;
      if (limit != null) state.limit = limit;
      else if (state.limit == null || !tierFor(state.limit)) state.limit = Number(DEFAULT_LIMIT);
      // A link or a full paste leaves only the number in the field.
      if (el.input.value.trim() !== parsed.commitment) el.input.value = parsed.commitment;
      el.input.removeAttribute("aria-invalid");
      el.inputMessage.dataset.kind = "good";
      el.inputMessage.textContent = state.leaf
        ? `${origin}Checked against its leaf: a tier ${state.limit} identity.`
        : `${origin}${parsed.commitment.length} digits, ending ${parsed.commitment.slice(-6)}.`;
    } catch (error) {
      state.commitment = null;
      state.leaf = null;
      if (!el.input.value.trim()) {
        el.input.removeAttribute("aria-invalid");
        el.inputMessage.textContent = "";
      } else {
        el.input.setAttribute("aria-invalid", "true");
        el.inputMessage.dataset.kind = "bad";
        el.inputMessage.textContent = origin ? `The link is not usable. ${error.message}` : error.message;
      }
    }
    if (previous !== state.commitment && previous !== null) resetStake();
    return Boolean(state.commitment);
  }

  function resetStake() {
    window.clearInterval(state.finalityTimer);
    state.tx = null;
    state.finalityStart = null;
    state.stage = state.account ? "ready" : "idle";
    el.receipt.hidden = true;
    el.finalityPanel.hidden = true;
    el.memberState.hidden = true;
    announce("");
  }

  function update() {
    const tier = tierFor(stakeLimit());
    const bond = tier ? `${formatEth(tier.bondWei)} ${CHAIN_NAME} ETH` : "";
    const staked = ["sent", "confirmed", "final", "left"].includes(state.stage);
    const resume = state.stage === "resume";
    el.shown.textContent = state.commitment ? short(state.commitment, 10, 8) : "None yet. Enter it in step 1.";
    el.shown.title = state.commitment || "";
    el.copyLink.hidden = !state.commitment;
    if (tier) el.bond.textContent = bond;
    if (tier && buysText.size) el.buys.textContent = `${buysText.get(String(tier.limit))}`;
    for (const input of el.tierInputs) {
      input.checked = BigInt(input.value) === stakeLimit();
      input.disabled = state.busy || staked || resume || Boolean(state.leaf);
    }
    // A leaf settles the tier: no choice to make, so none is shown.
    if (el.tierPick) el.tierPick.hidden = Boolean(state.leaf);
    if (el.tierHint) {
      if (state.leaf) el.tierHint.textContent = `Tier ${state.limit}, checked against the identity's leaf.`;
      else el.tierHint.innerHTML = tierHintDefault;
    }
    el.stakePanel.dataset.stage = state.stage;
    el.beforeStake.hidden = staked || resume;
    el.primary.hidden = staked;
    el.primary.disabled = state.busy;
    el.primary.textContent = state.stage === "ready" ? `Stake ${bond}` : "Connect wallet";
    el.walletRow.hidden = !state.account;
    el.wallet.textContent = state.account ? short(state.account, 8, 6) : "";
    el.wallet.title = state.account || "";
    el.changeWallet.hidden = staked;
    el.balance.hidden = staked;
    el.changeWallet.disabled = state.busy;
    if (el.tierRow) el.tierRow.hidden = staked || resume;
    el.terminal.hidden = staked || resume;
    el.terminalText.textContent = hasWallet()
      ? "Without a browser wallet, stake from the terminal with a funded key."
      : "No wallet in this browser. On a phone, open this page inside your wallet app. Or stake from the terminal with a funded key.";
    // One primary action per screen: once the stake is in, going on is the action.
    const onward = state.stage === "confirmed" || state.stage === "final";
    el.nextStart.className = onward ? "solid-action" : "line-action";
    el.startState.textContent = state.stage === "final"
      ? "Admitted. Nodes accept this identity."
      : state.stage === "confirmed" || state.stage === "sent" || resume
        ? "The stake is in. Nodes admit the identity once it is final, usually 13 to 16 minutes after it confirms."
        : "Nodes admit the identity once its stake is final, usually 13 to 16 minutes after it confirms.";
    el.startState.dataset.kind = state.stage === "final" ? "good" : "plain";
    // A step is done when its work is: the commitment is in, the stake is mined.
    const done = { setup: Boolean(state.commitment), stake: state.stage === "confirmed" || state.stage === "final", start: false };
    for (const link of el.stepLinks) {
      const step = link.dataset.stepLink;
      if (step === state.panel) link.setAttribute("aria-current", "step");
      else link.removeAttribute("aria-current");
      link.toggleAttribute("data-done", done[step] && step !== state.panel);
    }
  }

  function show(panel, { focus = true, push = true } = {}) {
    if (!PANELS.includes(panel)) return;
    state.panel = panel;
    if (STEPS.includes(panel)) state.lastStep = panel;
    for (const section of el.panels) {
      const current = section.dataset.panel === panel;
      section.hidden = !current;
      section.toggleAttribute("data-current", current);
    }
    // Leave and details is a screen of its own, outside the three steps.
    el.stepper.hidden = panel === "details";
    update();
    save();
    if (push) {
      try { window.history.pushState({ panel }, ""); } catch {}
    }
    window.scrollTo(0, 0);
    if (focus) document.querySelector(`[data-panel="${panel}"] h2`)?.focus({ preventScroll: true });
    markScrollers();
    if (panel === "stake" && state.stage === "ready" && !state.busy) refreshMember();
  }

  function go(target) {
    if (target === "back") target = state.lastStep;
    if (target === "stake" && state.panel === "setup" && !readInput()) {
      if (!el.input.value.trim()) {
        el.input.setAttribute("aria-invalid", "true");
        el.inputMessage.dataset.kind = "bad";
        el.inputMessage.textContent = "Paste the identity commitment that shadenet init prints.";
      }
      el.input.focus();
      return;
    }
    show(target);
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }

  // "copied" on the button itself; if the clipboard is closed, select the text to copy by hand.
  async function copyFrom(button, source, text) {
    const label = button.dataset.label || (button.dataset.label = button.textContent);
    const ok = await copyText(text);
    if (!ok && source) {
      const range = document.createRange();
      range.selectNodeContents(source);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
    button.textContent = ok ? "copied" : "select and copy";
    window.setTimeout(() => { button.textContent = label; }, 1600);
  }

  async function request(method, params = []) {
    if (!hasWallet()) throw new Error("No compatible Ethereum wallet was found in this browser.");
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
    const tier = tierFor(stakeLimit());
    if (!state.account || !tier) return;
    try {
      const [balanceWei, gasPriceWei] = await Promise.all([request("eth_getBalance", [state.account, "latest"]), request("eth_gasPrice").catch(() => "0x0")]);
      const verdict = describeBalance({ balanceWei, tier, gasPriceWei });
      el.balance.textContent = verdict.message;
      el.balance.dataset.kind = verdict.enough ? "plain" : "warn";
    } catch {
      el.balance.textContent = "";
    }
  }

  function showReceipt(hash) {
    if (EXPLORER_URL) el.receiptLink.href = `${EXPLORER_URL}/tx/${hash}`;
    el.receiptLink.textContent = short(hash, 10, 8);
    el.receipt.hidden = false;
  }

  function admitted(view) {
    window.clearInterval(state.finalityTimer);
    state.stage = "final";
    el.finalityPanel.hidden = true;
    el.memberState.textContent = view.message;
    el.memberState.dataset.state = "active";
    el.memberState.hidden = false;
    announce("");
    update();
  }

  // What the contract says about this commitment at this tier, read through the wallet's RPC.
  async function readMember() {
    const status = await staking().memberStatus(memberLeaf(state.commitment, stakeLimit()));
    return describeMember({ ...status, now: Math.floor(Date.now() / 1000) });
  }

  function paintFinality(estimate, finalizedBlock, targetBlock) {
    if (estimate.final) {
      el.finalityBar.style.width = "100%";
      return;
    }
    if (state.finalityStart == null) state.finalityStart = Number(finalizedBlock);
    const total = Math.max(1, Number(targetBlock) - state.finalityStart);
    const done = Math.max(0, Number(finalizedBlock) - state.finalityStart);
    el.finalityBar.style.width = `${Math.min(97, Math.max(3, Math.round((done / total) * 100)))}%`;
  }

  // Follow the chain's own finalized block until it passes the stake's block, then confirm with
  // the contract that the member is active. Without a known block, poll the contract alone.
  function watchFinality(blockNumber) {
    window.clearInterval(state.finalityTimer);
    state.finalityStart = null;
    const commitment = state.commitment;
    const tick = async () => {
      if (commitment !== state.commitment) return;
      try {
        let final = blockNumber == null;
        if (blockNumber != null) {
          const finalized = await request("eth_getBlockByNumber", ["finalized", false]);
          const finalizedBlock = finalized?.number ?? 0;
          const estimate = finalityEstimate(blockNumber, finalizedBlock);
          paintFinality(estimate, finalizedBlock, blockNumber);
          final = estimate.final;
          if (!final) {
            const minutes = Math.max(1, Math.round(estimate.seconds / 60));
            el.finality.textContent = `Waiting for ${CHAIN_NAME} finality, about ${minutes} min left. You can go on to step 3 meanwhile.`;
          }
        }
        if (final) {
          const view = await readMember();
          if (view.state === "active") admitted(view);
          else el.finality.textContent = `Waiting for ${CHAIN_NAME} finality, usually 13 to 16 minutes after the stake confirms. You can go on to step 3 meanwhile.`;
        }
      } catch {
        el.finality.textContent = `Could not read finality through the wallet. It usually takes 13 to 16 minutes; shadenet status --wait returns when it is done.`;
      }
    };
    el.finalityPanel.hidden = false;
    el.finalityBar.style.width = blockNumber == null ? "0" : "3%";
    tick();
    state.finalityTimer = window.setInterval(tick, SLOT_SECONDS * 1000);
  }

  // A commitment that is already staked (from the terminal, by someone else, or before a reload)
  // goes straight to its real state, so nothing is sent twice.
  async function refreshMember() {
    if (!state.account || !state.commitment) return;
    const commitment = state.commitment;
    const view = await readMember().catch(() => null);
    if (!view || commitment !== state.commitment) return;
    if (view.state === "active") admitted(view);
    else if (view.state === "pending") {
      state.stage = "confirmed";
      if (state.tx?.hash) showReceipt(state.tx.hash);
      watchFinality(state.tx?.block ?? null);
    } else if (view.state === "exiting" || view.state === "withdrawable") {
      state.stage = "left";
      el.memberState.textContent = view.message;
      el.memberState.dataset.state = view.state;
      el.memberState.hidden = false;
    } else if (state.tx?.hash) {
      announce("That transaction has not confirmed. Follow its link before staking again.");
    }
    update();
  }

  async function connectWallet() {
    if (!hasWallet()) {
      // The line above the terminal command already says what to do.
      announce("No wallet was found in this browser.", "bad");
      return;
    }
    state.busy = true;
    update();
    try {
      const accounts = await request("eth_requestAccounts");
      if (!Array.isArray(accounts) || !accounts[0]) throw new Error("The wallet did not provide an account.");
      await selectChain();
      state.account = getAddress(accounts[0]);
      const code = await request("eth_getCode", [CONTRACT, "latest"]);
      if (!code || code === "0x") throw new Error(`The pinned staking contract is not deployed on this wallet's ${CHAIN_NAME} network.`);
      announce("");
      await readBalance();
      state.stage = "ready";
      if (state.commitment) await refreshMember();
      else announce("Enter the identity commitment in step 1 before staking.");
    } catch (error) {
      state.account = null;
      state.stage = "idle";
      fail(error, { action: "connecting the wallet" });
    } finally {
      state.busy = false;
      update();
    }
  }

  async function stake() {
    if (!state.commitment) {
      announce("Enter the identity commitment in step 1 before staking.", "bad");
      return;
    }
    const tier = tierFor(stakeLimit());
    if (!tier) {
      announce("Choose a tier this canopy offers.", "bad");
      return;
    }
    const commitment = state.commitment;
    state.busy = true;
    el.receipt.hidden = true;
    update();
    try {
      await selectChain();
      announce(`Confirm the ${formatEth(tier.bondWei)} ${CHAIN_NAME} ETH transaction in your wallet.`);
      const sent = await staking().stake({
        commitment,
        limit: Number(tier.limit),
        from: state.account,
        onSent: (hash) => {
          showReceipt(hash);
          state.stage = "sent";
          state.tx = { hash, block: null };
          save();
          announce("Transaction sent. Waiting for one confirmation.");
          update();
        },
      });
      if (sent.alreadyActive) {
        state.stage = "confirmed";
        announce("This identity commitment is already staked. Nothing was sent.");
        watchFinality(null);
        return;
      }
      const receipt = await sent.wait();
      if (!receipt) {
        announce("Still pending after three minutes. Follow the transaction link; do not send again.");
      } else {
        state.stage = "confirmed";
        state.tx = { hash: sent.hash, block: Number(BigInt(receipt.blockNumber)) };
        save();
        announce("Stake confirmed.", "good");
        watchFinality(state.tx.block);
      }
    } catch (error) {
      if (state.stage === "sent") state.stage = "ready";
      // The wallet row already shows the balance and the shortfall; the alert stays short.
      fail(error, { action: "stake" });
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
      markScrollers();
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
    select(0);
  }

  // A command wider than its plate fades at the right edge until it is scrolled to its end.
  function markScrollers() {
    for (const pre of el.scrollers) {
      const more = pre.scrollWidth - pre.clientWidth - pre.scrollLeft > 2;
      pre.toggleAttribute("data-more", more);
    }
  }

  for (const link of [...el.stepLinks, ...el.goLinks]) {
    link.addEventListener("click", (event) => {
      event.preventDefault();
      go(link.dataset.stepLink || link.dataset.go);
    });
  }
  window.addEventListener("popstate", (event) => {
    if (event.state?.panel) show(event.state.panel, { push: false });
  });
  el.input.addEventListener("input", () => { readInput(); update(); save(); });
  el.input.addEventListener("keydown", (event) => {
    if (event.key === "Enter") { event.preventDefault(); go("stake"); }
  });
  for (const input of el.tierInputs) input.addEventListener("change", () => {
    if (input.checked) state.limit = Number(input.value);
    update();
    save();
    readBalance();
    if (state.stage === "ready") refreshMember();
  });
  el.primary.addEventListener("click", () => (state.stage === "ready" ? stake() : connectWallet()));
  el.changeWallet.addEventListener("click", connectWallet);
  el.copyLink.addEventListener("click", () => {
    if (!state.commitment) return;
    const base = `${window.location.origin}${window.location.pathname}`;
    copyFrom(el.copyLink, null, stakeLink({ commitment: state.commitment, limit: Number(stakeLimit()), leaf: state.leaf }, base));
  });
  for (const button of el.copyBlocks) button.addEventListener("click", () => {
    const code = button.parentElement.querySelector("code");
    copyFrom(button, code, code.textContent);
  });
  el.copyBrief?.addEventListener("click", () => copyFrom(el.copyBrief, el.brief, el.brief.textContent.trim()));
  for (const pre of el.scrollers) pre.addEventListener("scroll", markScrollers, { passive: true });
  window.addEventListener("resize", markScrollers);
  // One details section open at a time, also where the name attribute is not supported.
  for (const item of el.details) item.addEventListener("toggle", () => {
    if (item.open) for (const other of el.details) if (other !== item) other.open = false;
  });
  mountTabs();
  window.ethereum?.on?.("accountsChanged", (accounts) => {
    state.account = accounts?.[0] ? getAddress(accounts[0]) : null;
    if (!state.account && !["sent", "confirmed", "final"].includes(state.stage)) state.stage = "idle";
    update();
    readBalance();
  });
  window.ethereum?.on?.("chainChanged", () => {
    if (["sent", "confirmed", "final"].includes(state.stage)) return;
    state.account = null;
    state.stage = "idle";
    announce("The wallet changed network. Connect it again.");
    update();
  });

  // Where to start: a link's fragment wins, then what this tab had before a reload.
  let start = state.panel;
  const fragment = window.location.hash.slice(1);
  if (/(^|&)c=/.test(fragment)) {
    el.input.value = fragment;
    start = readInput({ origin: "From your link. " }) ? "stake" : "setup";
  } else {
    if (PANELS.includes(fragment)) start = fragment;
    if (typeof saved.input === "string" && saved.input) {
      el.input.value = saved.input;
      if (saved.limit != null && tierFor(saved.limit)) state.limit = Number(saved.limit);
      readInput();
    }
    if (start === "stake" && !state.commitment) start = "setup";
  }
  if (state.commitment && state.commitment === saved.input && saved.tx?.hash) {
    // A stake sent before the reload: show it, and follow it again once the wallet is back.
    state.tx = { hash: String(saved.tx.hash), block: saved.tx.block ?? null };
    state.stage = "resume";
    showReceipt(state.tx.hash);
    announce("Connect the wallet again to follow finality here, or run shadenet status --wait.");
  }
  document.documentElement.dataset.access = "ready";
  try { window.history.replaceState({ panel: start }, ""); } catch {}
  show(start, { focus: false, push: false });
}

if (typeof document !== "undefined" && document.querySelector("[data-panel]")) mount();
