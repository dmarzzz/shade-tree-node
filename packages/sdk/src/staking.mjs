// Stake, sponsor, exit and withdraw against the network's StakedReputationSet, through any
// EIP-1193 provider (a browser wallet, or `jsonRpcProvider(url)` for reads). Every address, tier
// and bond comes from the network record; the client refuses to send if the chain disagrees.

import { Interface, getAddress, id as topicOf } from "ethers";
import { identityCommitmentOf, leafFromIdentityCommitment, parseCommitment, rateCommitment, tierLimit } from "../../../lib/identity-core.mjs";
import { resolveNetwork, tierFor } from "./network.mjs";
import { exitContext, withdrawContext } from "./contexts.mjs";
import { proveAction } from "./exit-proof.mjs";
import { ShadeNetError } from "./errors.mjs";

const ABI = [
  "function register(uint256 commitment, uint256 limit) payable",
  "function registerIdentity(uint256 identityCommitment, uint256 limit) payable returns (uint256)",
  "function members(uint256 commitment) view returns (uint256 bond, uint64 index, uint64 exitInitiatedAt, uint32 limit)",
  "function exitContext(uint256 commitment) view returns (bytes32)",
  "function withdrawContext(uint256 commitment, address recipient) view returns (bytes32)",
  "function initiateExit(uint256 commitment, bytes proof)",
  "function withdraw(uint256 commitment, address recipient, bytes proof)",
  "function bondFor(uint256 limit) view returns (uint256)",
  "function allowedLimits() view returns (uint256[])",
  "function isActive(uint256 commitment) view returns (bool)",
  "function limitOf(uint256 commitment) view returns (uint256)",
  "function withdrawableAt(uint256 commitment) view returns (uint256)",
];
export const stakingInterface = new Interface(ABI);
const REGISTERED_TOPIC = topicOf("MemberRegistered(uint256,uint64,uint256)");

const hexQuantity = (v) => `0x${BigInt(v).toString(16)}`;
const word = (v) => `0x${BigInt(v).toString(16).padStart(64, "0")}`;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A minimal read-only EIP-1193 provider over HTTP JSON-RPC (for status checks without a wallet).
export function jsonRpcProvider(url, { fetchImpl = globalThis.fetch } = {}) {
  let nextId = 1;
  return {
    async request({ method, params = [] }) {
      let body;
      try {
        const res = await fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: nextId++, method, params }),
        });
        body = await res.json();
      } catch (cause) {
        throw new ShadeNetError("Rpc", `RPC ${method} failed: ${cause?.message ?? cause}`, { cause });
      }
      if (body.error) throw new ShadeNetError("Rpc", `RPC ${method}: ${body.error.message}`, { rpcError: body.error });
      return body.result;
    },
  };
}

export function createStaking({ network = "sepolia", provider, readProvider } = {}) {
  const net = typeof network === "object" && network.record ? network : resolveNetwork(network);
  const profile = net.staked;
  if (!profile) throw new ShadeNetError("InvalidInput", `${net.name} has no staked admission profile`);
  const contract = getAddress(profile.contract);
  const reader = readProvider ?? provider ?? jsonRpcProvider(profile.rpcUrl);
  const shadenet = profile.registerInput === "identityCommitment";

  async function rpc(p, method, params) {
    if (!p?.request) throw new ShadeNetError("Wallet", "no EIP-1193 provider (wallet) was given");
    try {
      return await p.request({ method, params });
    } catch (cause) {
      if (cause instanceof ShadeNetError) throw cause;
      const code = cause?.code === 4001 || cause?.code === "ACTION_REJECTED" ? "Wallet" : "Rpc";
      throw new ShadeNetError(code, cause?.shortMessage || cause?.message || `${method} failed`, { cause });
    }
  }

  async function call(name, args) {
    const data = stakingInterface.encodeFunctionData(name, args);
    const result = await rpc(reader, "eth_call", [{ to: contract, data }, "latest"]);
    return stakingInterface.decodeFunctionResult(name, result)[0];
  }

  async function ensureChain(p) {
    const chain = BigInt(await rpc(p, "eth_chainId", []));
    if (chain === BigInt(profile.chainId)) return;
    try {
      await rpc(p, "wallet_switchEthereumChain", [{ chainId: hexQuantity(profile.chainId) }]);
    } catch (error) {
      if (error?.cause?.code !== 4902) throw error;
      await rpc(p, "wallet_addEthereumChain", [{
        chainId: hexQuantity(profile.chainId),
        chainName: net.name,
        nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
        rpcUrls: [profile.rpcUrl],
      }]);
    }
    const now = BigInt(await rpc(p, "eth_chainId", []));
    if (now !== BigInt(profile.chainId)) {
      throw new ShadeNetError("Wallet", `wallet is on chain ${now}; ${net.name} (${profile.chainId}) is required`);
    }
  }

  // Preflight before any signature: right chain, contract deployed there, the call simulates,
  // and the wallet holds value + estimated gas.
  async function sendAndWait(from, data, value = 0n, { onSent } = {}) {
    await ensureChain(provider);
    const code = await rpc(provider, "eth_getCode", [contract, "latest"]);
    if (!code || code === "0x") throw new ShadeNetError("Wallet", `the staking contract is not deployed on the wallet's network`);
    const tx = { from: getAddress(from), to: contract, data, value: hexQuantity(value) };
    await rpc(provider, "eth_call", [tx, "latest"]); // simulate: a revert fails here
    const [balance, gas, gasPrice] = await Promise.all([
      rpc(provider, "eth_getBalance", [tx.from, "latest"]),
      rpc(provider, "eth_estimateGas", [tx]),
      rpc(provider, "eth_gasPrice", []),
    ]);
    const need = BigInt(value) + BigInt(gas) * BigInt(gasPrice);
    if (BigInt(balance) < need) {
      throw new ShadeNetError("Wallet", `this wallet needs at least ${need} wei (value plus estimated gas)`, { needWei: need });
    }
    const hash = await rpc(provider, "eth_sendTransaction", [tx]);
    onSent?.(hash);
    return { hash, wait: (opts) => waitForReceipt(hash, opts) };
  }

  async function waitForReceipt(hash, { timeoutMs = 180_000, pollMs = 1_500 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const receipt = await rpc(reader, "eth_getTransactionReceipt", [hash]);
      if (receipt) {
        if (BigInt(receipt.status) !== 1n) throw new ShadeNetError("Rpc", `transaction ${hash} reverted`, { receipt });
        return receipt;
      }
      await sleep(pollMs);
    }
    return null; // still pending; the caller shows the hash and must not resend blindly
  }

  // ShadeNet sets: compute the bound context locally and require the set's own view to agree, so a
  // proof is never built for a context the contract will not check.
  async function boundContext(kind, leaf, recipient) {
    const raw = await rpc(reader, "eth_call", [{ to: contract, data: stakingInterface.encodeFunctionData("members", [leaf]) }, "latest"]);
    const [, index] = stakingInterface.decodeFunctionResult("members", raw);
    const binding = { chainId: profile.chainId, contract, index };
    const local = kind === "exit" ? exitContext(leaf, binding) : withdrawContext(leaf, recipient, binding);
    const onchain = kind === "exit" ? await call("exitContext", [leaf]) : await call("withdrawContext", [leaf, recipient]);
    if (onchain !== local) throw new ShadeNetError("Rpc", "the staking set's proof context differs from the local one; refusing to prove");
    return local;
  }

  // What `stake` sends for an identity: its identity commitment on a ShadeNet set, its leaf on v4.
  function registrationValue(identity, limit) {
    return shadenet ? identityCommitmentOf(identity.identitySecret).toString() : rateCommitment(identity.identitySecret, limit).toString();
  }

  return {
    network: net,
    contract,
    registerInput: profile.registerInput,
    registrationValue,

    async bondFor(limit) {
      return call("bondFor", [tierLimit(limit)]);
    },

    // { state: "none" | "active" | "exiting" | "withdrawable", limit, withdrawableAt, finalized }
    // `finalized` is true once the registration is in a finalized block, which is when a node's
    // root (and so admission) includes it. Before that, egress fails with NotFinalized.
    async memberStatus(commitment) {
      const c = BigInt(parseCommitment(commitment));
      const [active, limit, withdrawableAt] = await Promise.all([
        call("isActive", [c]), call("limitOf", [c]), call("withdrawableAt", [c]),
      ]);
      let state = "none";
      if (active) state = "active";
      else if (limit !== 0n) state = BigInt(Math.floor(Date.now() / 1000)) >= withdrawableAt ? "withdrawable" : "exiting";
      let finalized = null;
      if (state !== "none") {
        const logs = await rpc(reader, "eth_getLogs", [{
          address: contract,
          topics: [REGISTERED_TOPIC, word(c)],
          fromBlock: profile.deployBlock == null ? "earliest" : hexQuantity(profile.deployBlock),
          toBlock: "finalized",
        }]);
        finalized = Array.isArray(logs) && logs.length > 0;
      }
      return {
        state,
        limit: Number(limit),
        withdrawableAt: withdrawableAt === 0n ? null : new Date(Number(withdrawableAt) * 1000).toISOString(),
        finalized,
      };
    },

    // Stake the tier's bond for a commitment: on a ShadeNet set the identity commitment (the set
    // derives the leaf at the tier), on the v4 set the leaf. Works for a member or, as a sponsor, for
    // someone else's public value: the secret is never needed.
    async stake({ commitment, limit = profile.defaultLimit, from, onSent } = {}) {
      const c = BigInt(parseCommitment(commitment));
      const tier = tierFor(net, limit);
      const leaf = shadenet ? leafFromIdentityCommitment(c, tier.limit) : c;
      const [bond, active, existing] = await Promise.all([call("bondFor", [tier.limit]), call("isActive", [leaf]), call("limitOf", [leaf])]);
      if (bond !== tier.bondWei) {
        throw new ShadeNetError("Rpc", `contract bond for tier ${tier.limit} is ${bond} wei, the record says ${tier.bondWei}; refusing to send`);
      }
      if (active) return { alreadyActive: true };
      if (existing !== 0n) throw new ShadeNetError("InvalidInput", "this commitment is exiting and cannot be registered again yet");
      const data = shadenet
        ? stakingInterface.encodeFunctionData("registerIdentity", [c, tier.limit])
        : stakingInterface.encodeFunctionData("register", [c, tier.limit]);
      return sendAndWait(from, data, bond, { onSent });
    },

    // A sponsor stakes a member's public commitment from the sponsor's own wallet.
    async sponsor(opts) {
      return this.stake(opts);
    },

    // Start unbonding. Proves knowledge of the identity secret (in-browser Groth16 if in a tab).
    async exit({ identity, from, artifacts, onSent } = {}) {
      const c = BigInt(parseCommitment(identity?.leaf));
      const context = shadenet ? await boundContext("exit", c) : exitContext(c);
      const proof = await proveAction({ identitySecret: identity.identitySecret, context, artifacts });
      return sendAndWait(from, stakingInterface.encodeFunctionData("initiateExit", [c, proof]), 0n, { onSent });
    },

    // After unbonding, pay the bond to `recipient` (bound into the proof, so it can't be redirected).
    async withdraw({ identity, recipient, from, artifacts, onSent } = {}) {
      const c = BigInt(parseCommitment(identity?.leaf));
      const to = getAddress(recipient);
      const context = shadenet ? await boundContext("withdraw", c, to) : withdrawContext(c, to);
      const proof = await proveAction({ identitySecret: identity.identitySecret, context, artifacts });
      return sendAndWait(from, stakingInterface.encodeFunctionData("withdraw", [c, to, proof]), 0n, { onSent });
    },

    waitForReceipt,
  };
}
