import { Interface, getAddress } from "ethers";
import { poseidon1 } from "poseidon-lite/poseidon1";
import { poseidon2 } from "poseidon-lite/poseidon2";
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
} from "./profile.mjs";

export { CHAIN_ID, DEFAULT_LIMIT, EXPLORER_URL, REGISTER_INPUT, RPC_URL, TIERS };
export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const CONTRACT = getAddress(RECORD_CONTRACT);
// Sepolia targets 12 s slots; finality is two epochs behind head in the normal case.
const SLOT_SECONDS = 12;

const ABI = [
  "function register(uint256 commitment, uint256 limit) payable",
  "function registerIdentity(uint256 identityCommitment, uint256 limit) payable returns (uint256)",
  "function bondFor(uint256 limit) view returns (uint256)",
  "function isActive(uint256 commitment) view returns (bool)",
  "function limitOf(uint256 commitment) view returns (uint256)",
  "function withdrawableAt(uint256 commitment) view returns (uint256)",
];
const iface = new Interface(ABI);

const encoder = new TextEncoder();

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function canonicalField(value, label, { nonzero = true } = {}) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical decimal field element.`);
  }
  const parsed = BigInt(value);
  if (parsed >= FIELD || (nonzero && parsed === 0n)) {
    throw new Error(`${label} is outside the supported identity field.`);
  }
  return parsed;
}

function offeredTier(limit) {
  const tier = tierFor(limit);
  if (!tier) {
    throw new Error(`This canopy offers tiers ${TIERS.map((t) => t.limit).join(" and ")}; limit ${limit} is not one of them.`);
  }
  return tier;
}

export async function deriveIdentity(seed, limit = DEFAULT_LIMIT) {
  if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) {
    throw new Error("Identity seed must be exactly 32 random bytes.");
  }
  const tier = offeredTier(limit);
  const appSecret = bytesToBigInt(seed) % FIELD;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", encoder.encode(appSecret.toString())));
  const nullifier = bytesToBigInt(digest.slice(0, 32)) >> 3n;
  const trapdoor = bytesToBigInt(digest.slice(32)) >> 3n;
  digest.fill(0);
  const identitySecret = poseidon2([nullifier, trapdoor]);
  const leaf = poseidon2([poseidon1([identitySecret]), tier.limit]);
  return {
    identitySecret: identitySecret.toString(),
    leaf: leaf.toString(),
    limit: Number(tier.limit),
  };
}

export function parseIdentityFile(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("That is not a valid ShadeNet identity JSON file.");
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error("The identity file must contain one JSON object.");
  }
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "identitySecret,leaf,limit") {
    throw new Error("The identity file must contain only identitySecret, leaf, and limit.");
  }
  if (!Number.isSafeInteger(value.limit)) throw new Error("The identity file's limit must be an integer tier.");
  const tier = offeredTier(value.limit);
  const identitySecret = canonicalField(value.identitySecret, "identitySecret");
  const leaf = canonicalField(value.leaf, "leaf");
  const expected = poseidon2([poseidon1([identitySecret]), tier.limit]);
  if (leaf !== expected) {
    throw new Error("The public leaf does not match this identity secret and tier.");
  }
  return { identitySecret: identitySecret.toString(), leaf: leaf.toString(), limit: Number(tier.limit) };
}

// The value `register` takes for this identity, per the deployment record's ABI.
export function registerCommitment(identity) {
  if (REGISTER_INPUT === "identityCommitment") return poseidon1([BigInt(identity.identitySecret)]).toString();
  return identity.leaf;
}

// The member leaf the contract stores for a registration value at `limit`. The ShadeNet sets take
// the identity commitment and derive Poseidon2(idc, limit) themselves (launch audit 2.1.4).
export function memberLeaf(commitment, limit) {
  if (REGISTER_INPUT !== "identityCommitment") return String(commitment);
  return poseidon2([BigInt(commitment), BigInt(limit)]).toString();
}

export function parseCommitment(text) {
  return canonicalField(String(text || "").trim(), "Commitment").toString();
}

export function identityBytes(identity) {
  return `${JSON.stringify(identity, null, 2)}\n`;
}

// Pure status model for a commitment read from the contract: what the page tells the member.
export function describeMember({ active, limit, withdrawableAt, now }) {
  if (active) return { state: "active", message: `Active at tier ${limit}. Nodes accept it once its block is finalized.` };
  if (limit !== 0n) {
    const at = Number(withdrawableAt);
    if (at > now) return { state: "exiting", message: `Exiting. The bond is withdrawable in about ${formatDuration(Math.max(60, Math.ceil((at - now) / 60) * 60))}.` };
    return { state: "withdrawable", message: "Exit complete. Withdraw the bond to a fresh address with the CLI." };
  }
  return { state: "unregistered", message: "Not registered on this contract." };
}

export function finalityEstimate(targetBlock, finalizedBlock) {
  const remaining = BigInt(targetBlock) - BigInt(finalizedBlock);
  if (remaining <= 0n) return { final: true, seconds: 0 };
  return { final: false, seconds: Number(remaining) * SLOT_SECONDS };
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
    status: document.querySelector("[data-status]"),
    alert: document.querySelector("[data-alert]"),
    receipt: document.querySelector("[data-receipt]"),
    receiptLink: document.querySelector("[data-receipt-link]"),
    memberState: document.querySelector("[data-member-state]"),
    finality: document.querySelector("[data-finality]"),
  };
}

function mount() {
  const el = elements();
  const state = { mode: "member", identity: null, imported: false, account: null, busy: false, tier: DEFAULT_LIMIT, finalityTimer: null };

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
    el.leaf.textContent = hasIdentity ? registerCommitment(state.identity) : "Create or import an identity to reveal its public commitment.";
    el.leafTag.dataset.ready = String(hasIdentity);
    el.wallet.textContent = state.account ? `Connected: ${short(state.account, 8, 6)}` : "No wallet connected";
  }

  async function createIdentity() {
    state.busy = true;
    update();
    try {
      const seed = crypto.getRandomValues(new Uint8Array(32));
      state.identity = await deriveIdentity(seed, state.tier);
      state.imported = false;
      seed.fill(0);
      el.recoveryCheck.checked = false;
      announce(`Tier ${state.identity.limit} identity created in this tab. Download it and confirm you saved it before staking.`, "good");
    } catch (error) {
      announce(error.message, "bad");
    } finally {
      state.busy = false;
      update();
    }
  }

  async function importIdentity(file) {
    try {
      if (!file || file.size > 16 * 1024) throw new Error("Choose a ShadeNet identity file under 16 KiB.");
      state.identity = parseIdentityFile(await file.text());
      state.imported = true;
      el.recoveryCheck.checked = false;
      announce("Identity validated locally and not uploaded. Imported identities can check status; stake a new identity for a new bond.", "good");
    } catch (error) {
      state.identity = null;
      state.imported = false;
      el.recoveryCheck.checked = false;
      announce(error.message, "bad");
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
    link.download = `shadenet-identity-${state.identity.leaf.slice(0, 8)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    announce("Download started. Check the file is saved, then tick the box. It is a bearer credential.", "good");
    update();
  }

  async function copyLeaf() {
    if (!state.identity) return;
    try {
      await navigator.clipboard.writeText(registerCommitment(state.identity));
      announce("Public commitment copied. It is safe to give to a sponsor.", "good");
    } catch {
      announce("Could not use the clipboard. Select and copy the visible commitment.", "bad");
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
    } catch (error) {
      state.account = null;
      announce(error.shortMessage || error.message || "Wallet connection failed.", "bad");
    } finally {
      state.busy = false;
      update();
    }
  }

  async function readContract(name, args, block = "latest") {
    const data = iface.encodeFunctionData(name, args);
    const result = await request("eth_call", [{ to: CONTRACT, data }, block]);
    return iface.decodeFunctionResult(name, result)[0];
  }

  async function waitForReceipt(hash) {
    const deadline = Date.now() + 180_000;
    while (Date.now() < deadline) {
      const receipt = await request("eth_getTransactionReceipt", [hash]);
      if (receipt) return receipt;
      await new Promise((resolve) => window.setTimeout(resolve, 1_500));
    }
    return null;
  }

  function watchFinality(blockNumber) {
    window.clearInterval(state.finalityTimer);
    const tick = async () => {
      try {
        const finalized = await request("eth_getBlockByNumber", ["finalized", false]);
        const estimate = finalityEstimate(blockNumber, finalized?.number ?? 0);
        if (estimate.final) {
          window.clearInterval(state.finalityTimer);
          el.finality.textContent = "Finalized. Nodes accept this membership once their next root refresh lands, usually within a minute.";
          el.finality.dataset.kind = "good";
        } else {
          el.finality.textContent = `Waiting for ${CHAIN_NAME} finality: about ${Math.max(1, Math.round(estimate.seconds / 60))} min left.`;
          el.finality.dataset.kind = "plain";
        }
      } catch {
        el.finality.textContent = "Could not read finality from the wallet. It usually takes 13 to 16 minutes after the stake confirms.";
      }
    };
    el.finality.hidden = false;
    tick();
    state.finalityTimer = window.setInterval(tick, SLOT_SECONDS * 1000);
  }

  async function checkStatus() {
    let commitment;
    try {
      commitment = parseCommitment(selectedCommitment());
    } catch (error) {
      announce(error.message, "bad");
      return;
    }
    state.busy = true;
    update();
    try {
      await selectChain();
      const leaf = memberLeaf(commitment, (tierFor(stakeTier()) ?? tierFor(DEFAULT_LIMIT)).limit);
      const [active, limit, withdrawableAt] = await Promise.all([
        readContract("isActive", [leaf]),
        readContract("limitOf", [leaf]),
        readContract("withdrawableAt", [leaf]).catch(() => 0n),
      ]);
      const view = describeMember({ active, limit, withdrawableAt, now: Math.floor(Date.now() / 1000) });
      el.memberState.textContent = view.message;
      el.memberState.dataset.state = view.state;
      el.memberState.hidden = false;
      announce("Status read through your wallet's RPC. This page sent it nowhere else.", "good");
    } catch (error) {
      announce(error.shortMessage || error.message || "Status check failed.", "bad");
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
      announce(error.message, "bad");
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
      const [bond, active, existingLimit] = await Promise.all([
        readContract("bondFor", [tier.limit]),
        readContract("isActive", [memberLeaf(commitment, tier.limit)]),
        readContract("limitOf", [memberLeaf(commitment, tier.limit)]),
      ]);
      if (bond !== tier.bondWei) {
        throw new Error(`The contract's tier-${tier.limit} bond differs from the published ${formatEth(tier.bondWei)} ETH; refusing to send.`);
      }
      if (active) {
        announce("This commitment is already active. Nothing was sent.", "good");
        return;
      }
      if (existingLimit !== 0n) {
        throw new Error("This commitment is exiting and cannot be registered again. Create a new identity instead.");
      }
      const data = REGISTER_INPUT === "identityCommitment"
        ? iface.encodeFunctionData("registerIdentity", [commitment, tier.limit])
        : iface.encodeFunctionData("register", [commitment, tier.limit]);
      const transaction = { from: state.account, to: CONTRACT, value: hexQuantity(bond), data };
      const balance = BigInt(await request("eth_getBalance", [state.account, "latest"]));
      const gas = BigInt(await request("eth_estimateGas", [transaction]));
      const gasPrice = BigInt(await request("eth_gasPrice"));
      if (balance < bond + gas * gasPrice) {
        throw new Error(`This wallet needs at least ${formatEth(bond)} ${CHAIN_NAME} ETH plus about ${formatEth(gas * gasPrice)} ETH gas.`);
      }
      await request("eth_call", [transaction, "latest"]);
      announce(`Confirm the exact ${formatEth(bond)} ${CHAIN_NAME} ETH transaction in your wallet.`);
      const hash = await request("eth_sendTransaction", [transaction]);
      if (EXPLORER_URL) el.receiptLink.href = `${EXPLORER_URL}/tx/${hash}`;
      el.receiptLink.textContent = short(hash, 12, 10);
      el.receipt.hidden = false;
      announce("Transaction sent. Waiting for one confirmation…");
      const receipt = await waitForReceipt(hash);
      if (!receipt) {
        announce("Still pending after three minutes. Use the transaction link to follow it; do not send again blindly.", "plain");
      } else if (BigInt(receipt.status) !== 1n) {
        throw new Error("The registration transaction reverted. No stake was admitted.");
      } else {
        announce("Stake confirmed. Hand the identity file to your agent while finality lands.", "good");
        watchFinality(receipt.blockNumber);
      }
    } catch (error) {
      announce(error.shortMessage || error.message || "Staking failed.", "bad");
    } finally {
      state.busy = false;
      update();
    }
  }

  for (const button of el.modeButtons) button.addEventListener("click", () => {
    state.mode = button.dataset.mode;
    announce(state.mode === "member"
      ? "Member mode: the identity stays in this tab until you download it."
      : "Sponsor mode: paste only the member’s public commitment and tier. The member keeps the secret.");
    update();
  });
  for (const input of el.tierInputs) input.addEventListener("change", () => {
    if (input.checked) state.tier = BigInt(input.value);
    update();
  });
  for (const input of el.sponsorTierInputs) input.addEventListener("change", update);
  el.createButton.addEventListener("click", createIdentity);
  el.importButton.addEventListener("click", () => el.fileInput.click());
  el.fileInput.addEventListener("change", () => importIdentity(el.fileInput.files?.[0]));
  el.downloadButton.addEventListener("click", downloadIdentity);
  el.copyButton.addEventListener("click", copyLeaf);
  el.recoveryCheck.addEventListener("change", update);
  el.sponsorInput.addEventListener("input", update);
  el.statusButton?.addEventListener("click", checkStatus);
  for (const button of el.connectButtons) button.addEventListener("click", connectWallet);
  for (const button of el.stakeButtons) button.addEventListener("click", stake);
  window.ethereum?.on?.("accountsChanged", (accounts) => {
    state.account = accounts?.[0] ? getAddress(accounts[0]) : null;
    announce(state.account ? "Wallet account changed." : "Wallet disconnected.");
    update();
  });
  window.ethereum?.on?.("chainChanged", () => {
    state.account = null;
    announce("Wallet network changed. Reconnect to verify the chain.");
    update();
  });
  update();
}

if (typeof document !== "undefined" && document.querySelector("[data-member-steps]")) mount();
