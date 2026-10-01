#!/usr/bin/env node
// One operator secret, three role keys (day-two ops; docs/OPERATOR.md "One operator key").
//
// A new operator manages ONE 32-byte seed. The three role keys the node needs (slasher,
// gateway-operator, registrar) derive from it with HKDF-SHA256 and distinct info strings, so
// rotating the seed rotates all three and backing up one file backs up everything. Deriving is
// one-way: a leaked role key does not expose the seed or the other roles.
//
//   node scripts/operator-keys.mjs generate --out <seed file>          mint a seed (0600, refuses overwrite)
//   node scripts/operator-keys.mjs show --seed <seed file>             print the three addresses
//   node scripts/operator-keys.mjs derive --seed <seed file> --out-dir <dir>
//        write SHADE_TREE_SLASH_KEY, SHADE_TREE_GW_OPERATOR_KEY, SHADE_TREE_REGISTRAR_KEY (0600)
//        in the credential-file layout bootstrap.sh installs from (SHADE_TREE_CREDENTIALS_FROM)
//   --json on show/derive prints machine-readable output; private keys never go to stdout.
//
// Opt-in: an operator with three independently managed keys changes nothing.
import { randomBytes, hkdfSync } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { Wallet } from "ethers";

export const ROLES = Object.freeze({
  SHADE_TREE_SLASH_KEY: "shadenet/operator/v1/slasher",
  SHADE_TREE_GW_OPERATOR_KEY: "shadenet/operator/v1/gateway-operator",
  SHADE_TREE_REGISTRAR_KEY: "shadenet/operator/v1/registrar",
});
const SALT = Buffer.from("shadenet-operator-keys-v1", "utf8");
const SECP256K1_N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

export function parseSeed(text) {
  const hex = String(text).trim().replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("seed must be 32 bytes of hex (64 hex chars)");
  return Buffer.from(hex, "hex");
}

// HKDF-SHA256(seed, salt, info) -> 32 bytes, reduced into the secp256k1 scalar range (the
// probability of hitting >= n is ~2^-128; reduce anyway so the output is always a valid key).
export function deriveRoleKey(seed, role) {
  const info = ROLES[role];
  if (!info) throw new Error(`unknown role ${role}; one of ${Object.keys(ROLES).join(", ")}`);
  const okm = Buffer.from(hkdfSync("sha256", seed, SALT, Buffer.from(info, "utf8"), 32));
  let k = BigInt("0x" + okm.toString("hex")) % SECP256K1_N;
  if (k === 0n) k = 1n;
  return "0x" + k.toString(16).padStart(64, "0");
}

export function deriveAll(seed) {
  const out = {};
  for (const role of Object.keys(ROLES)) {
    const priv = deriveRoleKey(seed, role);
    out[role] = { address: new Wallet(priv).address, privateKey: priv };
  }
  return out;
}

function arg(flags, name, required = true) {
  const v = flags[name];
  if (required && (v === undefined || v === "true")) throw new Error(`--${name} is required`);
  return v;
}

function parse(argv) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) flags[a.slice(2, eq)] = a.slice(eq + 1);
      else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) flags[a.slice(2)] = argv[++i];
      else flags[a.slice(2)] = "true";
    } else positionals.push(a);
  }
  return { flags, positionals };
}

export function main(argv = process.argv.slice(2), io = { log: console.log, error: console.error }) {
  const { flags, positionals } = parse(argv);
  const cmd = positionals[0];
  if (!cmd || flags.help) {
    io.log("usage: operator-keys.mjs generate --out <seed file> | show --seed <seed file> [--json] | derive --seed <seed file> --out-dir <dir> [--json]");
    return cmd ? 0 : 1;
  }
  if (cmd === "generate") {
    const out = arg(flags, "out");
    if (existsSync(out)) throw new Error(`${out} exists; refusing to overwrite an operator seed`);
    writeFileSync(out, randomBytes(32).toString("hex") + "\n", { mode: 0o600 });
    io.log(`seed written to ${out} (0600). Back it up off-box; it derives every role key.`);
    return 0;
  }
  const seed = parseSeed(readFileSync(arg(flags, "seed"), "utf8"));
  const keys = deriveAll(seed);
  if (cmd === "show") {
    if (flags.json) io.log(JSON.stringify(Object.fromEntries(Object.entries(keys).map(([r, k]) => [r, k.address])), null, 2));
    else for (const [role, k] of Object.entries(keys)) io.log(`${role.padEnd(28)} ${k.address}`);
    return 0;
  }
  if (cmd === "derive") {
    const dir = arg(flags, "out-dir");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    for (const [role, k] of Object.entries(keys)) {
      const path = join(dir, role);
      if (existsSync(path) && !flags.force) throw new Error(`${path} exists; pass --force to overwrite`);
      writeFileSync(path, k.privateKey.slice(2) + "\n", { mode: 0o600 });
    }
    const summary = Object.fromEntries(Object.entries(keys).map(([r, k]) => [r, k.address]));
    if (flags.json) io.log(JSON.stringify({ dir, addresses: summary }, null, 2));
    else {
      io.log(`three role keys written under ${dir} (0600):`);
      for (const [role, address] of Object.entries(summary)) io.log(`  ${role.padEnd(28)} ${address}`);
      io.log(`install them with: SHADE_TREE_CREDENTIALS_FROM=${dir} bootstrap.sh ... (they land in /etc/credstore)`);
    }
    return 0;
  }
  throw new Error(`unknown command ${cmd}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { process.exit(main()); } catch (e) { console.error(`operator-keys: ${e.message}`); process.exit(2); }
}
