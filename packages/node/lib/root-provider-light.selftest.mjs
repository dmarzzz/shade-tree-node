// T-DEV-9: unit test for LightClientRootProvider + its Merkle-Patricia proof verifier in
// packages/node/lib/root-provider.mjs. The provider reads the on-chain committed membership root from a
// known storage slot and proves it via eth_getProof against a block's state root, so a
// light client no longer trusts an RPC's event-reconstruction (see the trust note in the
// module). This test builds REAL, cryptographically valid single-entry account + storage
// tries by hand (keccak/RLP from ethers, already a dep), feeds them through a stubbed
// JSON-RPC, and asserts:
//   * the provider surfaces the exact on-chain root the slot holds (== the T-DEV-9 golden);
//   * a TAMPERED slot value, a tampered proof node, and a lying reported value are REJECTED;
//   * the MPT verifier proves absence (empty slot) and rejects an incomplete proof;
//   * the eth_getStorageAt fallback mode surfaces the value (documented weaker path).
//
//   node packages/node/lib/root-provider-light.selftest.mjs

import { keccak256, encodeRlp, getBytes } from "ethers";
import { LightClientRootProvider, _internals } from "./root-provider.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
async function throws(fn, msg) {
  try { await fn(); ok(false, msg + " (expected throw)"); }
  catch { ok(true, msg); }
}

// ---- tiny trie builders (single-entry secure trie) --------------------------

// nibbles of a 0x-hex byte string.
const nibbles = (hex) => [...getBytes(hex)].flatMap((b) => [b >> 4, b & 0x0f]);

// hex-prefix (compact) encoding of a nibble path.
function hpEncode(nibs, isLeaf) {
  const flag = isLeaf ? 2 : 0;
  const odd = nibs.length % 2 === 1;
  const bytes = [];
  if (odd) bytes.push(((flag | 1) << 4) | nibs[0]);
  else bytes.push(flag << 4);
  for (let i = odd ? 1 : 0; i < nibs.length; i += 2) bytes.push((nibs[i] << 4) | nibs[i + 1]);
  return "0x" + bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// minimal big-endian hex of a uint (RLP scalar form; 0 -> empty string 0x).
function minimalHex(v) {
  if (v === 0n) return "0x";
  let h = v.toString(16);
  if (h.length % 2) h = "0" + h;
  return "0x" + h;
}

// A single-entry secure trie holding rawKey->value: the whole trie is one leaf node whose
// keccak is the root. Returns { root, proof:[leafHex], valueField }.
function singleEntryTrie(rawKeyHex, valueFieldHex) {
  const key = nibbles(keccak256(rawKeyHex)); // 64 nibbles
  const leaf = encodeRlp([hpEncode(key, true), valueFieldHex]);
  return { root: keccak256(leaf), proof: [leaf], valueField: valueFieldHex };
}

// ---- fixtures ---------------------------------------------------------------

const CONTRACT = "0xdae242ae3ecd18e5f74d5e96332fcd4682eb20fc"; // deployed.local.json (lowercased)
const SLOT = 3;
const SLOT_HEX = "0x" + BigInt(SLOT).toString(16).padStart(64, "0");
const EMPTY_CODE_HASH = "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
// The T-DEV-9 golden root (register-3 / slash-middle) — the SAME value the contract commits
// (test/StakedReputationSet.t.sol) and the off-chain reconstructRoot produces.
const GOLDEN_ROOT =
  14367190620832145537223890636337926502210861635134078778082353204233456513838n;

// Build the storage trie: slot 3 -> GOLDEN_ROOT. Storage value field = RLP(minimal bytes).
function buildProofResponse(rootValue) {
  const storage = singleEntryTrie(SLOT_HEX, encodeRlp(minimalHex(rootValue)));
  // Account = [nonce=0, balance=0, storageHash, codeHash]; its leaf hashes to the stateRoot.
  const accountRlp = encodeRlp(["0x", "0x", storage.root, EMPTY_CODE_HASH]);
  const account = singleEntryTrie(CONTRACT, accountRlp);
  return {
    stateRoot: account.root,
    accountProof: account.proof,
    storageHash: storage.root,
    storageProof: [{ key: SLOT_HEX, value: minimalHex(rootValue), proof: storage.proof }],
    _storage: storage,
    _accountRlp: accountRlp,
  };
}

// A stubbed JSON-RPC over global.fetch. `overrides` mutate the proof/block before serving.
function installFetchStub({ rootValue = GOLDEN_ROOT, mutate = null, storageAtValue = null } = {}) {
  const built = buildProofResponse(rootValue);
  if (mutate) mutate(built);
  const prev = global.fetch;
  global.fetch = async (_url, opts) => {
    const req = JSON.parse(opts.body);
    let result;
    if (req.method === "eth_getBlockByNumber") {
      result = { number: "0x64", stateRoot: built.stateRoot };
    } else if (req.method === "eth_getProof") {
      result = {
        accountProof: built.accountProof,
        storageHash: built.storageHash,
        storageProof: built.storageProof,
      };
    } else if (req.method === "eth_getStorageAt") {
      result = storageAtValue != null ? storageAtValue : minimalHex(rootValue);
    } else {
      result = null;
    }
    return { json: async () => ({ jsonrpc: "2.0", id: req.id, result }) };
  };
  return { restore: () => { global.fetch = prev; }, built };
}

async function main() {
  // ---- 1. MPT verifier directly: valid storage proof yields the value field -------------
  {
    const st = singleEntryTrie(SLOT_HEX, encodeRlp(minimalHex(GOLDEN_ROOT)));
    const vf = await _internals.verifyMptProof(st.root, SLOT_HEX, st.proof);
    ok(vf != null && BigInt((await import("ethers")).decodeRlp(vf)) === GOLDEN_ROOT, "verifyMptProof returns the exact slot value");
    // tamper a proof node byte -> its keccak no longer matches the root -> reject.
    const bad = st.proof.slice();
    bad[0] = bad[0].slice(0, -2) + (bad[0].endsWith("00") ? "01" : "00");
    await throws(() => _internals.verifyMptProof(st.root, SLOT_HEX, bad), "tampered storage proof node rejected");
    // empty proof list -> referenced hash missing -> reject.
    await throws(() => _internals.verifyMptProof(st.root, SLOT_HEX, []), "incomplete proof rejected");
    // proving a DIFFERENT slot against this trie -> absence (null), not a throw.
    const other = "0x" + (4).toString(16).padStart(64, "0");
    const abs = await _internals.verifyMptProof(st.root, other, st.proof);
    ok(abs === null, "wrong-key proof proves absence (null)");
  }

  // ---- 2. Provider end-to-end: surfaces the on-chain golden root -------------------------
  {
    const { restore } = installFetchStub({ rootValue: GOLDEN_ROOT });
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: "http://stub" });
    const res = await p.currentRoots();
    ok(res.roots.length === 1 && res.roots[0] === GOLDEN_ROOT.toString(), "provider surfaces the golden on-chain root");
    ok(res.verified === true, "proof mode reports verified:true");
    ok(res.observedAtBlock === 100, "observedAtBlock from the confirmed block");
    restore();
  }

  // ---- 3. Provider rejects a tampered slot value (root altered in the leaf) --------------
  {
    // Rebuild the storage leaf with a DIFFERENT value but leave the account committing the
    // ORIGINAL storageHash -> the tampered storage leaf won't hash to the committed root.
    const { restore } = installFetchStub({
      rootValue: GOLDEN_ROOT,
      mutate: (b) => {
        const evil = singleEntryTrie(SLOT_HEX, encodeRlp(minimalHex(GOLDEN_ROOT + 1n)));
        b.storageProof[0].proof = evil.proof; // account still commits the old storageHash
      },
    });
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: "http://stub" });
    await throws(() => p.currentRoots(), "tampered storage leaf (root swap) rejected");
    restore();
  }

  // ---- 4. Provider rejects a lying REPORTED value that disagrees with the proof ----------
  {
    const { restore } = installFetchStub({
      rootValue: GOLDEN_ROOT,
      mutate: (b) => { b.storageProof[0].value = minimalHex(GOLDEN_ROOT + 123n); },
    });
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: "http://stub" });
    await throws(() => p.currentRoots(), "reported value != proven value rejected");
    restore();
  }

  // ---- 5. Provider rejects a tampered account proof (bad storageHash chain) ---------------
  {
    const { restore } = installFetchStub({
      rootValue: GOLDEN_ROOT,
      mutate: (b) => {
        // corrupt the account leaf so it no longer hashes to the state root.
        b.accountProof[0] = b.accountProof[0].slice(0, -2) + (b.accountProof[0].endsWith("00") ? "01" : "00");
      },
    });
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: "http://stub" });
    await throws(() => p.currentRoots(), "tampered account proof rejected");
    restore();
  }

  // ---- 6. storageat fallback mode surfaces the value (weaker, unverified) -----------------
  {
    const { restore } = installFetchStub({ rootValue: GOLDEN_ROOT });
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: "http://stub", mode: "storageat" });
    const res = await p.currentRoots();
    ok(res.roots[0] === GOLDEN_ROOT.toString(), "storageat mode surfaces the slot value");
    ok(res.verified === false, "storageat mode reports verified:false (trusts the RPC)");
    restore();
  }

  // ---- 7. empty slot (value 0) maps to no-members (roots:[]) ------------------------------
  {
    const { restore } = installFetchStub({ rootValue: 0n, mode: "storageat", storageAtValue: "0x0" });
    const p = LightClientRootProvider({ contract: CONTRACT, rpcUrl: "http://stub", mode: "storageat" });
    const res = await p.currentRoots();
    ok(res.roots.length === 0, "zero slot -> empty root set (no members)");
    restore();
  }

  // ---- 8. trustedStateRoot injection hook is honored (Helios sidecar seam, T-DEV-9b) ------
  // The hook's stateRoot is the anchor; the RPC's header for the SAME block is only cross-
  // checked: agree -> proof verified against the anchor; disagree -> rejected with the precise
  // "stateRoot mismatch" reason (the lying-RPC attack). packages/node/lib/helios-root.selftest.mjs drives the
  // real Helios implementation of this hook end to end.
  {
    const built = buildProofResponse(GOLDEN_ROOT);
    const prev = global.fetch;
    const rpcPathKey = "RPC_PATH_KEY_SENTINEL_7f31c9";
    const keyedRpcUrl = `https://rpc.example/v3/${rpcPathKey}`;
    let rpcStateRoot = built.stateRoot; // honest RPC header
    let hookCalls = 0;
    global.fetch = async (_url, opts) => {
      const req = JSON.parse(opts.body);
      let result = null;
      if (req.method === "eth_getProof") {
        result = { accountProof: built.accountProof, storageHash: built.storageHash, storageProof: built.storageProof };
      } else if (req.method === "eth_getBlockByNumber") {
        result = { number: "0x64", stateRoot: rpcStateRoot };
      }
      return { json: async () => ({ jsonrpc: "2.0", id: req.id, result }) };
    };
    const p = LightClientRootProvider({
      contract: CONTRACT,
      rpcUrl: keyedRpcUrl,
      heliosRpcUrl: "", // the injected hook, not the env-installed Helios one
      trustedStateRoot: async (tag) => { hookCalls++; ok(tag === "finalized", "hook receives the confirmed block tag (finalized)"); return { stateRoot: built.stateRoot, number: 100 }; },
    });
    const res = await p.currentRoots();
    ok(res.roots[0] === GOLDEN_ROOT.toString() && hookCalls === 1, "trustedStateRoot hook anchors the proof (honest RPC header agrees)");
    ok(res.stateRootVerified === true, "result flags stateRootVerified:true when a hook anchors it");
    ok(/injected trustedStateRoot hook/.test(p.describe().stateRootSource), "describe() names the injected hook as the stateRoot source");
    // the attack: RPC lies about the header's stateRoot -> rejected precisely, proof not trusted
    // (After a good read the shared last-known-good cache turns the rejection into a STALE
    // result carrying the reason -- the lying value is never surfaced; a fresh provider throws.)
    rpcStateRoot = "0x" + "de".repeat(32);
    const stale = await p.currentRoots();
    ok(stale.stale === true && stale.roots[0] === GOLDEN_ROOT.toString() && /stateRoot mismatch at block 100: RPC \(https:\/\/rpc\.example\) claims 0xdede/.test(stale.error) && stale.error.includes(built.stateRoot),
      "RPC header stateRoot != anchor after a good read -> last-known-good root, stale:true, precise mismatch reason");
    ok(!stale.error.includes(rpcPathKey) && !stale.error.includes("/v3/"),
      "root-provider mismatch errors retain the RPC origin but omit an API key in its URL path");
    const fresh = LightClientRootProvider({ contract: CONTRACT, rpcUrl: keyedRpcUrl, heliosRpcUrl: "", trustedStateRoot: async () => ({ stateRoot: built.stateRoot, number: 100 }) });
    await throws(() => fresh.currentRoots(), "fresh provider with a lying RPC header rejects outright (no LKG to fall back on)");
    global.fetch = prev;
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: light-client root-provider selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
