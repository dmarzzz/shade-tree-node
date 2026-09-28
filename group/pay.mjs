// pay — buy a membership leaf from an operator's registrar over HTTP 402 (T-FEAT-7, Layer 1 of
// docs/PAYMENTS.md as shipped). Two rails, one signature: the buyer signs an EIP-3009
// TransferWithAuthorization for the stablecoin (needs the coin, NO gas); the operator submits it,
// then inserts the buyer's commitment into the on-chain PaidAccessSet. Egress afterwards is the
// ordinary `shade-tree-node client` with the same secret (the gateway trusts the paid root).
//
//   shade-tree-node pay --bootnode <onion> --limit 8 [--protocol x402|mpp] [--key-file <path>] [--dry-run]
//   shade-tree-node pay --bootnode <v4-operator-onion> --limit 32 --protocol mpp
//   shade-tree-node pay --registrar-url http://127.0.0.1:8878 ...      (no Tor: tests / a local registrar)
//
// Flow (x402):  GET  /pay/quote?limit=N          -> 402 + PAYMENT-REQUIRED (accepts[])
//               POST /pay {commitment,limit}     + PAYMENT-SIGNATURE (signed authorization)
//               200 + PAYMENT-RESPONSE           -> {settleTx, insertTx, leafIndex, root}
// Flow (mpp):   POST /pay {commitment,limit}     -> 402 + WWW-Authenticate: Payment (digest-bound)
//               POST /pay (same body)            + Authorization: Payment <credential>
//               200 + Payment-Receipt
//
// Inputs, first match wins:
//   registrar:  --registrar-url <http://host:port> | --bootnode <onion> [--registrar-port 8878]
//               | SHADE_TREE_BOOTNODE_ONION (SHADE_TREE_NETWORK fills it from network/<name>/bootnode.json)
//   buyer key:  --key-file <path> (0x hex) | --account <keystore.json> (SHADE_TREE_PAY_PASSPHRASE) | SHADE_TREE_PAY_KEY
//   member:     --commitment <dec>  |  the member secret exactly like `shade-tree identity`
//               (--secret-file <path> | SHADE_TREE_SECRET/--secret | ./.secret) -> leaf at --limit
//   Tor SOCKS:  SHADE_TREE_TOR_HOST / SHADE_TREE_TOR_PORT (default 127.0.0.1:9250)
//
// --dry-run prints the 402 challenge(s) and the exact authorization it WOULD sign, signs nothing,
// sends nothing further. Nothing secret is ever printed: not the buyer key, not the member secret,
// not the signature.
//
// Layer 0 (docs/PAYMENTS.md): the transfer is PUBLIC on chain — buyer address -> operator, amount
// = the tier's price. Pay from a FRESH address funded through a shared pool if you don't want your
// main wallet linked to "customer of this operator". Which leaf you got is not on the wire (the
// operator learns commitment <-> payer; the gateway never does — it sees an RLN proof, not a leaf).

import { readFileSync, existsSync } from "node:fs";
import { ethers } from "ethers";
import { request } from "../payments/http-client.mjs";
import { tokenDomain, randomNonce, signAuthorization, checkAuthorizationShape } from "../payments/eip3009.mjs";
import {
  decodeX402Header, x402PaymentPayload, encodeX402Header, chainIdOfCaip2,
  parseWwwAuthenticate, mppCredential, mppNonce, decodeMppReceipt, b64decode, jsonParseSafe,
} from "../payments/wire.mjs";
import { resolveSecret } from "./identity.mjs";
import { identityFileFor } from "../lib/identity-file.mjs";
import { K_SLOTS, normLimit } from "../lib/rln.mjs";

const USAGE = `usage: shade-tree-node pay (--bootnode <onion> | --registrar-url <url>) --limit <tier> [--protocol x402|mpp] [--key-file <path> | --account <keystore.json>] [--commitment <dec> | --secret-file <path>] [--dry-run]`;

export function parseArgs(argv, env = process.env) {
  const o = { bootnode: env.SHADE_TREE_BOOTNODE_ONION || null, registrarUrl: env.SHADE_TREE_REGISTRAR_URL || null, registrarPort: Number(env.SHADE_TREE_REGISTRAR_PORT || 8878),
    limit: env.SHADE_TREE_LIMIT || null, protocol: (env.SHADE_TREE_PAY_PROTOCOL || "x402").toLowerCase(), keyFile: null, account: null, commitment: null, secretFile: null, dryRun: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { console.log(USAGE); process.exit(0); }
    if (a === "--dry-run") { o.dryRun = true; continue; }
    if (a === "--json") { o.json = true; continue; }
    if (!a.startsWith("--")) throw new Error(`unexpected argument ${a}`);
    const eq = a.indexOf("=");
    const key = eq === -1 ? a.slice(2) : a.slice(2, eq);
    const val = eq === -1 ? argv[++i] : a.slice(eq + 1);
    if (val === undefined || val === "" || (typeof val === "string" && val.startsWith("--"))) throw new Error(`--${key} needs a value`);
    switch (key) {
      case "bootnode": o.bootnode = val; break;
      case "registrar-url": o.registrarUrl = val; break;
      case "registrar-port": o.registrarPort = Number(val); break;
      case "limit": o.limit = val; break;
      case "protocol": o.protocol = val.toLowerCase(); break;
      case "key-file": o.keyFile = val; break;
      case "account": o.account = val; break;
      case "commitment": o.commitment = val; break;
      case "secret-file": o.secretFile = val; break;
      default: throw new Error(`unknown flag --${key}`);
    }
  }
  if (!["x402", "mpp"].includes(o.protocol)) throw new Error(`--protocol must be x402 or mpp (got ${o.protocol})`);
  if (!o.registrarUrl && !o.bootnode) throw new Error("no registrar: pass --bootnode <onion> (or --network <name>) or --registrar-url <url>");
  o.limit = Number(normLimit(o.limit == null ? K_SLOTS : o.limit));
  return o;
}

// The buyer wallet, never echoed. Returns an ethers.Wallet (no provider: it only signs typed data).
export async function resolveBuyerWallet(o, env = process.env) {
  if (o.keyFile) {
    if (!existsSync(o.keyFile)) throw new Error(`key file not found: ${o.keyFile}`);
    return { wallet: new ethers.Wallet(readFileSync(o.keyFile, "utf8").trim()), source: `--key-file ${o.keyFile}` };
  }
  if (o.account) {
    if (!existsSync(o.account)) throw new Error(`keystore not found: ${o.account}`);
    const pw = env.SHADE_TREE_PAY_PASSPHRASE;
    if (!pw) throw new Error("--account <keystore.json> needs SHADE_TREE_PAY_PASSPHRASE");
    return { wallet: await ethers.Wallet.fromEncryptedJson(readFileSync(o.account, "utf8"), pw), source: `--account ${o.account}` };
  }
  if (env.SHADE_TREE_PAY_KEY && env.SHADE_TREE_PAY_KEY.trim()) return { wallet: new ethers.Wallet(env.SHADE_TREE_PAY_KEY.trim()), source: "SHADE_TREE_PAY_KEY" };
  throw new Error("no buyer key: pass --key-file <path>, --account <keystore.json>, or set SHADE_TREE_PAY_KEY (a wallet holding the stablecoin; it needs no ETH)");
}

// The commitment to insert: --commitment, else the member secret's leaf at --limit (same
// derivation as `shade-tree identity` / `shade-tree enroll --limit`).
export function resolveCommitment(o, env = process.env) {
  if (o.commitment) {
    if (!/^(0|[1-9][0-9]*)$/.test(o.commitment)) throw new Error("--commitment must be a decimal field element (the leaf `shade-tree enroll` printed)");
    return { commitment: o.commitment, source: "--commitment" };
  }
  const { secret, source } = resolveSecret({ secretFile: o.secretFile, env });
  return { commitment: identityFileFor(secret, o.limit).leaf, source: `leaf of ${source} at limit ${o.limit}` };
}

// T-FEAT-9: a registrar serves only the rails its provider enabled (SHADE_TREE_PAY_PROTOCOLS); the 402
// body's `pay.protocols` says which. Turn "no header" into a precise "this rail is not sold here".
function railHint(q, rail) {
  try {
    const protos = JSON.parse(q.body || "{}")?.pay?.protocols;
    if (Array.isArray(protos) && !protos.includes(rail)) return ` -- this registrar does not serve ${rail} (it sells via: ${protos.join(", ")}); retry with --protocol ${protos[0]}`;
  } catch { /* not a JSON problem body */ }
  return "";
}
const target = (o) => (o.registrarUrl ? { url: o.registrarUrl } : { onion: o.bootnode, port: o.registrarPort });
// The paying POST waits for settle + insert to be mined (2 confirmations on a 12 s chain) over Tor.
const PAY_TIMEOUT_MS = Number(process.env.SHADE_TREE_PAY_HTTP_TIMEOUT_MS || 240000);

// ---- x402 ---------------------------------------------------------------------------------
export async function payX402({ o, wallet, commitment, out, nowMs = Date.now() }) {
  const q = await request({ ...target(o), method: "GET", path: `/pay/quote?limit=${o.limit}` });
  if (q.status !== 402) throw new Error(`expected 402 from /pay/quote, got ${q.status}: ${q.body.slice(0, 200)}`);
  const pr = decodeX402Header(q.headers["payment-required"]);
  if (!pr || pr.x402Version !== 2 || !Array.isArray(pr.accepts)) throw new Error("registrar sent no usable PAYMENT-REQUIRED (x402 v2) header" + railHint(q, "x402"));
  const accepted = pr.accepts.find((a) => a && a.scheme === "exact" && a.extra && Number(a.extra.limit) === o.limit && chainIdOfCaip2(a.network));
  if (!accepted) throw new Error(`no x402 'exact' requirement for tier ${o.limit} in the quote (accepts: ${pr.accepts.map((a) => `${a.scheme}/${a.network}/${a.amount}`).join(", ")})`);
  const chainId = chainIdOfCaip2(accepted.network);
  const domain = tokenDomain({ name: accepted.extra.name, version: accepted.extra.version, chainId, asset: accepted.asset });
  const auth = {
    from: wallet.address, to: ethers.getAddress(accepted.payTo), value: String(accepted.amount),
    validAfter: "0", validBefore: String(Math.floor(nowMs / 1000) + Number(accepted.maxTimeoutSeconds)), nonce: randomNonce(),
  };
  const shapeErr = checkAuthorizationShape(auth); if (shapeErr) throw new Error("bad quote: " + shapeErr);
  out.log(`quote: tier ${o.limit} = ${accepted.amount} atomic units of ${accepted.extra.name} (${accepted.asset}) on ${accepted.network}, payTo ${accepted.payTo}, valid ${accepted.maxTimeoutSeconds}s`);
  if (o.dryRun) {
    out.log("dry-run: would sign EIP-712 TransferWithAuthorization (x402 exact/eip3009):");
    out.log(JSON.stringify({ domain, authorization: auth, resource: pr.resource }, null, 2));
    return { dryRun: true, protocol: "x402", quote: pr, authorization: auth, domain };
  }
  const signature = await signAuthorization(wallet, domain, auth);
  const payload = x402PaymentPayload(pr, accepted, auth, signature);
  // The paying POST spans settle + insert (two confirmations) plus Tor latency: give it minutes,
  // and one retry — an identical retry is idempotent on the registrar (stored receipt).
  const r = await request({ ...target(o), method: "POST", path: "/pay", headers: { "PAYMENT-SIGNATURE": encodeX402Header(payload) }, body: { commitment, limit: o.limit }, timeoutMs: PAY_TIMEOUT_MS, attempts: 2 });
  const settlement = decodeX402Header(r.headers["payment-response"]);
  if (r.status !== 200) throw new Error(`payment refused (HTTP ${r.status}): ${settlement?.errorReason || ""} ${r.body.slice(0, 300)}`);
  return { protocol: "x402", settlement, result: r.json, nonce: auth.nonce };
}

// ---- MPP ----------------------------------------------------------------------------------
export async function payMpp({ o, wallet, commitment, out, nowMs = Date.now() }) {
  const body = JSON.stringify({ commitment, limit: o.limit }); // byte-identical on both POSTs (digest binding)
  const q = await request({ ...target(o), method: "POST", path: "/pay", body });
  if (q.status !== 402) throw new Error(`expected 402 challenge from POST /pay, got ${q.status}: ${q.body.slice(0, 200)}`);
  const raw = q.headers["www-authenticate"];
  const lines = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const challenges = lines.flatMap((l) => parseWwwAuthenticate(l)).map((c) => c.params);
  const decodeReq = (c) => { const s = b64decode(c.request || "", { url: true }); return s == null ? null : jsonParseSafe(s); };
  const pick = challenges.map((c) => ({ c, req: decodeReq(c) })).find(({ c, req }) => c.method === "evm" && c.intent === "charge" && req && req.externalId === `limit=${o.limit}`);
  if (!pick) throw new Error(`no MPP evm/charge challenge for tier ${o.limit} (got ${challenges.length} challenge(s))` + railHint(q, "mpp"));
  const { c, req } = pick;
  const md = req.methodDetails || {};
  if (!Array.isArray(md.credentialTypes) || !md.credentialTypes.includes("authorization")) throw new Error("registrar's MPP challenge does not accept type=authorization (EIP-3009); this client implements no other credential type");
  const chainId = Number(md.chainId);
  // draft-evm-charge-00 has no field for the token's EIP-712 domain (name/version), which a
  // type=authorization signer needs. The registrar puts it in methodDetails.eip712Domain (a
  // labelled extension) and in the 402 body's `pay` block; take either.
  const pay = q.json && q.json.pay ? q.json.pay : {};
  const name = md.eip712Domain?.name || pay.assetName; const version = md.eip712Domain?.version || pay.assetVersion;
  if (!name || !version) throw new Error("registrar's challenge lacks the token's EIP-712 domain (methodDetails.eip712Domain / pay.assetName+assetVersion)");
  const domain = tokenDomain({ name, version, chainId, asset: req.currency });
  const expiresSec = Math.floor(Date.parse(c.expires) / 1000);
  const auth = { from: wallet.address, to: ethers.getAddress(req.recipient), value: String(req.amount), validAfter: "0", validBefore: String(expiresSec), nonce: mppNonce(c.id, c.realm) };
  const shapeErr = checkAuthorizationShape(auth); if (shapeErr) throw new Error("bad challenge: " + shapeErr);
  out.log(`challenge ${c.id}: tier ${o.limit} = ${req.amount} atomic units of ${name} (${req.currency}) on eip155:${chainId}, recipient ${req.recipient}, expires ${c.expires}`);
  if (o.dryRun) {
    out.log("dry-run: would sign EIP-712 TransferWithAuthorization (MPP evm/charge type=authorization, nonce = keccak256(id ‖ realm)):");
    out.log(JSON.stringify({ challenge: c, domain, authorization: auth }, null, 2));
    return { dryRun: true, protocol: "mpp", challenge: c, authorization: auth, domain };
  }
  const signature = await signAuthorization(wallet, domain, auth);
  const cred = mppCredential(c, { type: "authorization", ...auth, signature }, { source: `did:pkh:eip155:${chainId}:${wallet.address}` });
  const r = await request({ ...target(o), method: "POST", path: "/pay", headers: { Authorization: `Payment ${cred}` }, body, timeoutMs: PAY_TIMEOUT_MS, attempts: 2 });
  if (r.status !== 200) throw new Error(`payment refused (HTTP ${r.status}): ${r.json?.type || ""} ${r.json?.detail || r.body.slice(0, 300)}`);
  return { protocol: "mpp", receipt: decodeMppReceipt(r.headers["payment-receipt"]), result: r.json, nonce: auth.nonce };
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  let o;
  try { o = parseArgs(argv, env); } catch (e) { console.error(`pay: ${e.message}\n${USAGE}`); process.exit(2); }
  const out = { log: (s) => console.error(s) };
  let wallet, walletSource, commitment, commitmentSource;
  try {
    ({ wallet, source: walletSource } = await resolveBuyerWallet(o, env));
    ({ commitment, source: commitmentSource } = resolveCommitment(o, env));
  } catch (e) { console.error(`pay: ${e.message}`); process.exit(1); }
  out.log(`pay: ${o.protocol} via ${o.registrarUrl ? o.registrarUrl : `${o.bootnode}:${o.registrarPort} over Tor`}`);
  out.log(`  buyer:      ${wallet.address}   (${walletSource})`);
  out.log(`  commitment: ${commitment}   (${commitmentSource})`);
  out.log(`  tier:       ${o.limit}`);
  out.log(`  Layer 0: the transfer is public on chain (buyer address -> operator, tier price). Pay from a FRESH address if that link matters to you.`);
  let res;
  try { res = await (o.protocol === "mpp" ? payMpp : payX402)({ o, wallet, commitment, out }); }
  catch (e) { console.error(`pay: ${e.message}`); process.exit(1); }
  if (res.dryRun) { out.log("dry-run: nothing signed, nothing sent."); return; }
  const r = res.result || {};
  if (o.json) { console.log(JSON.stringify({ protocol: res.protocol, ...r, settlement: res.settlement || null, receipt: res.receipt || null }, null, 2)); return; }
  console.log(`paid (${res.protocol}${r.replayed ? ", replayed order" : ""}):`);
  console.log(`  settleTx:  ${r.settleTx}`);
  console.log(`  insertTx:  ${r.insertTx}`);
  console.log(`  leafIndex: ${r.leafIndex}`);
  console.log(`  root:      ${r.root}`);
  console.log(`  status:    /pay/status/${res.nonce}`);
  console.log("now:  load your member secret into SHADE_TREE_SECRET (do not pass it on argv), then:");
  console.log(`      ${o.limit !== K_SLOTS ? `SHADE_TREE_LIMIT=${o.limit} ` : ""}shade-tree proxy --bootnode ${o.bootnode || "<onion>"}   (proves membership in the paid set; the node trusts its root)`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error("pay failed:", e.message); process.exit(1); });
}
