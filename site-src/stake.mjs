import { Interface, getAddress } from "ethers";
import { poseidon1, poseidon2 } from "poseidon-lite";

export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const CHAIN_ID = 11155111n;
export const CONTRACT = getAddress("0xEB67Abf066c11D78856BccC63476ed14d51e4275");
export const LIMIT = 1n;
export const BOND = 100000000000000000n;
export const RPC_URL = "https://rpc.sepolia.ethpandaops.io";
export const EXPLORER_URL = "https://sepolia.etherscan.io";

const ABI = [
  "function register(uint256 commitment, uint256 limit) payable",
  "function bondFor(uint256 limit) view returns (uint256)",
  "function isActive(uint256 commitment) view returns (bool)",
  "function limitOf(uint256 commitment) view returns (uint256)",
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

export async function deriveIdentity(seed) {
  if (!(seed instanceof Uint8Array) || seed.byteLength !== 32) {
    throw new Error("Identity seed must be exactly 32 random bytes.");
  }
  const appSecret = bytesToBigInt(seed) % FIELD;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-512", encoder.encode(appSecret.toString())));
  const nullifier = bytesToBigInt(digest.slice(0, 32)) >> 3n;
  const trapdoor = bytesToBigInt(digest.slice(32)) >> 3n;
  digest.fill(0);
  const identitySecret = poseidon2([nullifier, trapdoor]);
  const leaf = poseidon2([poseidon1([identitySecret]), LIMIT]);
  return {
    identitySecret: identitySecret.toString(),
    leaf: leaf.toString(),
    limit: Number(LIMIT),
  };
}

export function parseIdentityFile(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("That is not a valid Shade Tree identity JSON file.");
  }
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error("The identity file must contain one JSON object.");
  }
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "identitySecret,leaf,limit") {
    throw new Error("The identity file must contain only identitySecret, leaf, and limit.");
  }
  if (value.limit !== Number(LIMIT)) {
    throw new Error(`This Grove currently admits the base tier only (limit ${LIMIT}).`);
  }
  const identitySecret = canonicalField(value.identitySecret, "identitySecret");
  const leaf = canonicalField(value.leaf, "leaf");
  const expected = poseidon2([poseidon1([identitySecret]), LIMIT]);
  if (leaf !== expected) {
    throw new Error("The public leaf does not match this identity secret and tier.");
  }
  return { identitySecret: identitySecret.toString(), leaf: leaf.toString(), limit: Number(LIMIT) };
}

export function parseCommitment(text) {
  return canonicalField(String(text || "").trim(), "Commitment").toString();
}

export function identityBytes(identity) {
  return `${JSON.stringify(identity, null, 2)}\n`;
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
      if (!file || file.size > 16 * 1024) throw new Error("Choose a Shade Tree identity file under 16 KiB.");
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
    link.download = `shade-tree-identity-${state.identity.leaf.slice(0, 8)}.json`;
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

  async function selectSepolia() {
    try {
      await request("wallet_switchEthereumChain", [{ chainId: hexQuantity(CHAIN_ID) }]);
    } catch (error) {
      if (error?.code !== 4902) throw error;
      await request("wallet_addEthereumChain", [{
        chainId: hexQuantity(CHAIN_ID),
        chainName: "Sepolia",
        nativeCurrency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
        rpcUrls: [RPC_URL],
        blockExplorerUrls: [EXPLORER_URL],
      }]);
    }
    const chain = BigInt(await request("eth_chainId"));
    if (chain !== CHAIN_ID) throw new Error(`Wallet is on chain ${chain}; Sepolia (${CHAIN_ID}) is required.`);
  }

  async function connectWallet() {
    state.busy = true;
    update();
    try {
      const accounts = await request("eth_requestAccounts");
      if (!Array.isArray(accounts) || !accounts[0]) throw new Error("The wallet did not provide an account.");
      await selectSepolia();
      state.account = getAddress(accounts[0]);
      const code = await request("eth_getCode", [CONTRACT, "latest"]);
      if (!code || code === "0x") throw new Error("The pinned staking contract is not deployed on this wallet network.");
      announce("Wallet connected on Sepolia. Its address and the staking transaction will be public.", "good");
    } catch (error) {
      state.account = null;
      announce(error.shortMessage || error.message || "Wallet connection failed.", "bad");
    } finally {
      state.busy = false;
      update();
    }
  }

  async function readContract(name, args) {
    const data = iface.encodeFunctionData(name, args);
    const result = await request("eth_call", [{ to: CONTRACT, data }, "latest"]);
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
      await selectSepolia();
      const [bond, active, existingLimit] = await Promise.all([
        readContract("bondFor", [LIMIT]),
        readContract("isActive", [commitment]),
        readContract("limitOf", [commitment]),
      ]);
      if (bond !== BOND) throw new Error(`Contract bond changed from the pinned 0.1 ETH profile; refusing to send.`);
      if (active) {
        announce("This commitment is already active. Nothing was sent.", "good");
        return;
      }
      if (existingLimit !== 0n) {
        throw new Error("This commitment is already exiting and cannot be registered again yet.");
      }
      const data = iface.encodeFunctionData("register", [commitment, LIMIT]);
      const transaction = { from: state.account, to: CONTRACT, value: hexQuantity(bond), data };
      const balance = BigInt(await request("eth_getBalance", [state.account, "latest"]));
      const gas = BigInt(await request("eth_estimateGas", [transaction]));
      const gasPrice = BigInt(await request("eth_gasPrice"));
      if (balance < bond + gas * gasPrice) throw new Error("This wallet needs at least 0.1 Sepolia ETH plus estimated gas.");
      await request("eth_call", [transaction, "latest"]);
      announce("Confirm the exact 0.1 Sepolia ETH transaction in your wallet.");
      const hash = await request("eth_sendTransaction", [transaction]);
      el.receiptLink.href = `${EXPLORER_URL}/tx/${hash}`;
      el.receiptLink.textContent = short(hash, 12, 10);
      el.receipt.hidden = false;
      announce("Transaction sent. Waiting for one confirmation…");
      const receipt = await waitForReceipt(hash);
      if (!receipt) {
        announce("Still pending after three minutes. Use the transaction link to follow it; do not send again blindly.", "plain");
      } else if (BigInt(receipt.status) !== 1n) {
        throw new Error("The registration transaction reverted. No stake was admitted.");
      } else {
        announce("Stake confirmed. The identity becomes usable after Sepolia finality.", "good");
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
