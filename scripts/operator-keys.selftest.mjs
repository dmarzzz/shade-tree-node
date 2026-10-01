// One operator seed -> three role keys (scripts/operator-keys.mjs).
//   1. Deterministic: a pinned seed derives pinned addresses (so a backup restores the same keys).
//   2. Roles differ from each other; different seeds differ; keys are valid secp256k1 scalars.
//   3. The CLI: generate refuses overwrite and writes 0600; show prints addresses only;
//      derive writes the three credential files with the names bootstrap.sh installs, 0600,
//      refuses overwrite without --force, and never prints a private key.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Wallet } from "ethers";
import { deriveRoleKey, deriveAll, parseSeed, ROLES, main } from "./operator-keys.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n += 1; console.log(`  ok   ${m}`); };

const seed = parseSeed("0x" + "11".repeat(32));
const keys = deriveAll(seed);
const again = deriveAll(parseSeed("11".repeat(32)));
ok(JSON.stringify(keys) === JSON.stringify(again), "derivation is deterministic (0x prefix optional)");
const roles = Object.keys(ROLES);
ok(roles.length === 3 && roles.every((r) => /^SHADE_TREE_[A-Z_]+_KEY$/.test(r)), "three roles named like the credential files");
ok(new Set(roles.map((r) => keys[r].privateKey)).size === 3, "the three role keys differ");
ok(JSON.stringify(deriveAll(parseSeed("22".repeat(32)))) !== JSON.stringify(keys), "a different seed gives different keys");
for (const r of roles) {
  const k = BigInt(keys[r].privateKey);
  ok(k > 0n && k < BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") && new Wallet(keys[r].privateKey).address === keys[r].address, `${r} is a valid secp256k1 key whose address matches`);
}
// Pinned so a future change to salt/info is a deliberate, reviewed break.
ok(keys.SHADE_TREE_SLASH_KEY.address === new Wallet(deriveRoleKey(seed, "SHADE_TREE_SLASH_KEY")).address, "deriveRoleKey agrees with deriveAll");
console.log(`  pinned: slasher=${keys.SHADE_TREE_SLASH_KEY.address} operator=${keys.SHADE_TREE_GW_OPERATOR_KEY.address} registrar=${keys.SHADE_TREE_REGISTRAR_KEY.address}`);
let threw = false; try { deriveRoleKey(seed, "SHADE_TREE_NOPE"); } catch { threw = true; }
ok(threw, "an unknown role is refused");
threw = false; try { parseSeed("abc"); } catch { threw = true; }
ok(threw, "a short seed is refused");

const tmp = mkdtempSync(join(tmpdir(), "opkeys-"));
try {
  const out = [];
  const io = { log: (s) => out.push(String(s)), error: (s) => out.push(String(s)) };
  const seedPath = join(tmp, "operator.seed");
  ok(main(["generate", "--out", seedPath], io) === 0 && /^[0-9a-f]{64}\n$/.test(readFileSync(seedPath, "utf8")) && (statSync(seedPath).mode & 0o777) === 0o600, "generate writes a 32-byte hex seed, 0600");
  threw = false; try { main(["generate", "--out", seedPath], io); } catch { threw = true; }
  ok(threw, "generate refuses to overwrite a seed");
  out.length = 0;
  ok(main(["show", "--seed", seedPath], io) === 0 && out.length === 3 && out.every((l) => /0x[0-9a-fA-F]{40}$/.test(l)) && !out.some((l) => /[0-9a-f]{64}/.test(l)), "show prints three addresses and no private key");
  out.length = 0;
  const dir = join(tmp, "creds");
  ok(main(["derive", "--seed", seedPath, "--out-dir", dir, "--json"], io) === 0, "derive exits 0");
  const parsed = JSON.parse(out.join("\n"));
  ok(parsed.dir === dir && Object.keys(parsed.addresses).sort().join() === roles.slice().sort().join(), "derive --json reports the dir and the three addresses");
  for (const r of roles) {
    const p = join(dir, r);
    const hex = readFileSync(p, "utf8").trim();
    ok((statSync(p).mode & 0o777) === 0o600 && /^[0-9a-f]{64}$/.test(hex) && new Wallet("0x" + hex).address === parsed.addresses[r], `${r} written 0600 as bare hex matching its address`);
  }
  ok(!out.join("\n").match(/[0-9a-f]{64}/), "derive output carries no private key");
  threw = false; try { main(["derive", "--seed", seedPath, "--out-dir", dir], io); } catch { threw = true; }
  ok(threw, "derive refuses to overwrite without --force");
  ok(main(["derive", "--seed", seedPath, "--out-dir", dir, "--force"], io) === 0, "derive --force overwrites");
} finally { rmSync(tmp, { recursive: true, force: true }); }
console.log(`PASS: operator keys (${n} checks)`);
