import { getAddress } from "ethers";
import {
  resolveNetwork, tierFor, createStaking, importIdentity, serializeIdentity, parseCommitment as sdkParseCommitment,
  identityFileName,
} from "@shadenet/sdk";
import { deriveIdentity as deriveCore } from "../lib/identity-core.mjs";

// Everything below comes from the bundled deployment record through @shadenet/sdk.
const NETWORK = resolveNetwork("sepolia");
export const CHAIN_ID = BigInt(NETWORK.staked.chainId);
export const CONTRACT = getAddress(NETWORK.staked.contract);
export const LIMIT = BigInt(NETWORK.staked.defaultLimit);
export const BOND = tierFor(NETWORK, LIMIT).bondWei;
export const EXPLORER_URL = "https://sepolia.etherscan.io";

// The page admits the base tier only.
export function deriveIdentity(seed) {
  return deriveCore(seed, LIMIT);
}

export function parseIdentityFile(text) {
  const identity = importIdentity(text, { network: NETWORK });
  if (identity.limit !== Number(LIMIT)) throw new Error(`This canopy currently admits the base tier only (limit ${LIMIT}).`);
  return identity;
}

export const parseCommitment = sdkParseCommitment;
export const identityBytes = serializeIdentity;

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
    wallet: document.querySelector("[data-wallet]"),
    status: document.querySelector("[data-status]"),
    receipt: document.querySelector("[data-receipt]"),
    receiptLink: document.querySelector("[data-receipt-link]"),
  };
}

function mount() {
  const el = elements();
  const state = { mode: "member", identity: null, account: null, busy: false };

  function announce(message, kind = "plain") {
    el.status.textContent = message;
    el.status.dataset.kind = kind;
  }

  function selectedCommitment() {
    if (state.mode === "member") return state.identity?.leaf || null;
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
    el.memberSteps.hidden = state.mode !== "member";
    el.sponsorStep.hidden = state.mode !== "sponsor";
    for (const button of el.modeButtons) {
      const active = button.dataset.mode === state.mode;
      button.setAttribute("aria-pressed", String(active));
    }
    el.downloadButton.disabled = !hasIdentity || state.busy;
    el.copyButton.disabled = !hasIdentity || state.busy;
    el.recoveryCheck.disabled = !hasIdentity || state.busy;
    for (const button of el.connectButtons) {
      button.disabled = state.busy;
      button.textContent = state.account ? "change wallet" : "connect wallet";
    }
    for (const button of el.stakeButtons) {
      button.disabled = state.busy || !state.account || !commitment || (state.mode === "member" && !saved);
      button.textContent = state.mode === "sponsor" ? "stake this commitment" : "stake 0.1 Sepolia ETH";
    }
    el.leaf.textContent = hasIdentity ? state.identity.leaf : "Generate or import an identity to reveal its public leaf.";
    el.leafTag.dataset.ready = String(hasIdentity);
    el.wallet.textContent = state.account ? `Connected: ${short(state.account, 8, 6)}` : "No wallet connected";
  }

  async function createIdentity() {
    state.busy = true;
    update();
    try {
      const seed = crypto.getRandomValues(new Uint8Array(32));
      state.identity = await deriveIdentity(seed);
      seed.fill(0);
      el.recoveryCheck.checked = false;
      announce("Identity created in this tab. Download it before connecting a wallet.", "good");
    } catch (error) {
      announce(error.message, "bad");
    } finally {
      state.busy = false;
      update();
    }
  }

  async function importIdentity(file) {
    try {
      if (!file || file.size > 16 * 1024) throw new Error("Choose an identity file under 16 KiB.");
      state.identity = parseIdentityFile(await file.text());
      el.recoveryCheck.checked = true;
      announce("Identity validated locally. The file was not uploaded.", "good");
    } catch (error) {
      state.identity = null;
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
    link.download = identityFileName(state.identity);
    link.click();
    URL.revokeObjectURL(url);
    el.recoveryCheck.checked = true;
    announce("Recovery file downloaded. Keep it private; it is a bearer credential.", "good");
    update();
  }

  async function copyLeaf() {
    if (!state.identity) return;
    try {
      await navigator.clipboard.writeText(state.identity.leaf);
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

  // The SDK does the preflight: chain, deployed code, record-pinned bond, simulation, gas and balance.
  const staking = () => createStaking({ network: NETWORK, provider: window.ethereum });

  async function connectWallet() {
    state.busy = true;
    update();
    try {
      const accounts = await request("eth_requestAccounts");
      if (!Array.isArray(accounts) || !accounts[0]) throw new Error("The wallet did not provide an account.");
      const chain = BigInt(await request("eth_chainId"));
      if (chain !== CHAIN_ID) {
        await request("wallet_switchEthereumChain", [{ chainId: hexQuantity(CHAIN_ID) }]);
      }
      state.account = getAddress(accounts[0]);
      announce("Wallet connected. Its address and the staking transaction will be public.", "good");
    } catch (error) {
      state.account = null;
      announce(error.shortMessage || error.message || "Wallet connection failed.", "bad");
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
    state.busy = true;
    el.receipt.hidden = true;
    update();
    try {
      announce(`Confirm the exact ${Number(BOND) / 1e18} ETH transaction in your wallet.`);
      const sent = await staking().stake({
        commitment,
        limit: Number(LIMIT),
        from: state.account,
        onSent(hash) {
          el.receiptLink.href = `${EXPLORER_URL}/tx/${hash}`;
          el.receiptLink.textContent = short(hash, 12, 10);
          el.receipt.hidden = false;
          announce("Transaction sent. Waiting for one confirmation…");
        },
      });
      if (sent.alreadyActive) {
        announce("This commitment is already active. Nothing was sent.", "good");
        return;
      }
      const receipt = await sent.wait();
      if (!receipt) {
        announce("Still pending after three minutes. Use the transaction link to follow it; do not send again blindly.", "plain");
      } else {
        announce("Stake confirmed. The identity becomes usable after finality.", "good");
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
      : "Sponsor mode: paste only the member’s public commitment. The member keeps the secret.");
    update();
  });
  el.createButton.addEventListener("click", createIdentity);
  el.importButton.addEventListener("click", () => el.fileInput.click());
  el.fileInput.addEventListener("change", () => importIdentity(el.fileInput.files?.[0]));
  el.downloadButton.addEventListener("click", downloadIdentity);
  el.copyButton.addEventListener("click", copyLeaf);
  el.recoveryCheck.addEventListener("change", update);
  el.sponsorInput.addEventListener("input", update);
  for (const button of el.connectButtons) button.addEventListener("click", connectWallet);
  for (const button of el.stakeButtons) button.addEventListener("click", stake);
  window.ethereum?.on?.("accountsChanged", (accounts) => {
    state.account = accounts?.[0] ? getAddress(accounts[0]) : null;
    announce(state.account ? "Wallet account changed." : "Wallet disconnected.");
    update();
  });
  window.ethereum?.on?.("chainChanged", () => {
    state.account = null;
    announce("Wallet network changed. Reconnect to verify Sepolia.");
    update();
  });
  update();
}

if (typeof document !== "undefined") mount();
