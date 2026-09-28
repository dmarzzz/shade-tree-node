// Selftest for `shade-tree identity` (group/identity.mjs + lib/identity-file.mjs): the Rust client's
// `--identity` file exported from a member's secret. Proves, spawning the real CLI as a child:
//   - the file's `leaf` == rateCommitmentOf(identityFor(secret)) from lib/rln.mjs — the SAME
//     leaf `shade-tree enroll` publishes / the on-chain slash names — and `identitySecret` ==
//     identitySecretOf(...), so the Rust client is the same member as the JS client;
//   - the bytes are IDENTICAL to what the interop harness helper
//     crates/shadenet-rln/interop/egress-derive.mjs writes (byte-for-byte), so the harness and the
//     command cannot drift;
//   - secret sourcing: --secret-file > SHADE_TREE_SECRET (router --secret) > ./.secret; no secret => exit 1;
//   - --out writes mode 0600 (even over a pre-existing 0644 file), stdout stays EMPTY;
//     without --out the JSON is on stdout alone;
//   - the secret and identitySecret NEVER appear on stderr (no-leak), only the public leaf;
//   - argument validation (unknown flag / missing value => exit 2).
//
//   node group/identity.selftest.mjs

import { spawnSync } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile, stat, chmod, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { identityFor, identitySecretOf, rateCommitmentOf } from "../lib/rln.mjs";
import { identityFileFor, serializeIdentityFile } from "../lib/identity-file.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "bin", "shade-tree.mjs");
const DERIVE = join(ROOT, "crates", "shadenet-rln", "interop", "egress-derive.mjs");

// A fixed test secret (0x-hex, as `shade-tree enroll` mints). Never a real member.
const SECRET = "0x" + "5a".repeat(32);

function cleanEnv(extra = {}) {
  const base = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("SHADE_TREE_")) base[k] = v;
  return { ...base, ...extra };
}
function run(args, { env = {}, cwd } = {}) {
  // This interoperability fixture predates the public tier-1 default and intentionally
  // exercises the legacy limit-8 identity encoding used by egress-derive.mjs.
  const r = spawnSync(process.execPath, [CLI, "identity", ...args], {
    encoding: "utf8",
    env: cleanEnv({ SHADE_TREE_LIMIT: "8", ...env }),
    cwd,
    timeout: 60_000,
  });
  if (r.error) throw r.error;
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-identity-"));
  try {
    // ---- reference values from lib/rln.mjs ------------------------------------------------
    const identity = identityFor(SECRET);
    const refLeaf = rateCommitmentOf(identity).toString();
    const refIdSecret = identitySecretOf(identity).toString();

    console.log("lib/identity-file.mjs derivation:");
    const file = identityFileFor(SECRET);
    ok(file.leaf === refLeaf, "identityFileFor(secret).leaf == rateCommitmentOf(identityFor(secret)) (lib/rln.mjs)");
    ok(file.identitySecret === refIdSecret, "identityFileFor(secret).identitySecret == identitySecretOf(identityFor(secret))");
    ok(Object.keys(JSON.parse(serializeIdentityFile(file))).join(",") === "identitySecret,leaf", "serialized key order is identitySecret,leaf");
    let threw = false; try { identityFileFor(""); } catch { threw = true; }
    ok(threw, "identityFileFor('') throws");

    // ---- stdout mode: JSON alone on stdout, secret sourced from SHADE_TREE_SECRET -----------------
    console.log("\nshade-tree identity (SHADE_TREE_SECRET, stdout):");
    const so = run([], { env: { SHADE_TREE_SECRET: SECRET } });
    ok(so.code === 0, "exits 0");
    let parsed = null; try { parsed = JSON.parse(so.stdout); } catch { /* not json */ }
    ok(parsed && parsed.leaf === refLeaf && parsed.identitySecret === refIdSecret, "stdout is exactly the {identitySecret, leaf} JSON with the reference values");
    ok(so.stdout === serializeIdentityFile(file), "stdout bytes == serializeIdentityFile()");
    ok(/SHADE_TREE_SECRET/.test(so.stderr) && so.stderr.includes(refLeaf), "stderr names the source and the PUBLIC leaf");
    ok(!so.stderr.includes(SECRET) && !so.stderr.includes(SECRET.slice(2)) && !so.stderr.includes(refIdSecret), "stderr never contains the secret or the identitySecret (no-leak)");

    // ---- router flag: --secret sets SHADE_TREE_SECRET ---------------------------------------------
    console.log("\nshade-tree identity --secret (router flag -> SHADE_TREE_SECRET):");
    const sf = run(["--secret", SECRET]);
    ok(sf.code === 0 && sf.stdout === so.stdout, "--secret yields the same file as SHADE_TREE_SECRET");

    // ---- --out: file mode 0600, stdout empty, byte-equal to the harness helper ---------------
    console.log("\nshade-tree identity --out (file, 0600, byte-equal to egress-derive.mjs):");
    const outPath = join(work, "identity.json");
    const wo = run(["--out", outPath], { env: { SHADE_TREE_SECRET: SECRET } });
    ok(wo.code === 0, "--out exits 0");
    ok(wo.stdout === "", "--out: stdout is empty (no secret on stdout)");
    const st = await stat(outPath);
    ok((st.mode & 0o777) === 0o600, `--out file mode is 0600 (got ${(st.mode & 0o777).toString(8)})`);
    ok(!wo.stderr.includes(SECRET.slice(2)) && !wo.stderr.includes(refIdSecret), "--out: stderr has no secret material");
    ok(wo.stderr.includes(outPath) && wo.stderr.includes(refLeaf), "--out: stderr names the path and the public leaf");

    const harnessDir = join(work, "harness");
    await mkdir(harnessDir);
    const h = spawnSync(process.execPath, [DERIVE, harnessDir, SECRET], { encoding: "utf8", env: cleanEnv(), timeout: 60_000 });
    ok(h.status === 0, "harness egress-derive.mjs runs (still works after the refactor)");
    const ours = await readFile(outPath);
    const theirs = await readFile(join(harnessDir, "identity.json"));
    ok(Buffer.compare(ours, theirs) === 0, "shade-tree identity --out == egress-derive.mjs identity.json BYTE-FOR-BYTE");
    const members = JSON.parse(await readFile(join(harnessDir, "members.json"), "utf8"));
    ok(members.version === 2 && members.members.length === 1 && members.members[0] === refLeaf, "harness members.json still {version:2, members:[leaf]}");

    // ---- --out over a pre-existing loose file re-tightens to 0600 ---------------------------
    console.log("\n--out over an existing 0644 file:");
    const loose = join(work, "loose.json");
    await writeFile(loose, "stale\n"); await chmod(loose, 0o644);
    const lo = run(["--out", loose], { env: { SHADE_TREE_SECRET: SECRET } });
    const lst = await stat(loose);
    ok(lo.code === 0 && (lst.mode & 0o777) === 0o600, "existing file is overwritten and chmod'ed to 0600");
    ok((await readFile(loose)).equals(ours), "overwritten content is the identity file");

    // ---- secret sources: --secret-file wins; ./.secret fallback; none => exit 1 --------------
    console.log("\nsecret sources:");
    const secretFile = join(work, "member.secret");
    await writeFile(secretFile, SECRET + "\n", { mode: 0o600 });
    const OTHER = "0x" + "77".repeat(32);
    const fs1 = run(["--secret-file", secretFile], { env: { SHADE_TREE_SECRET: OTHER } });
    ok(fs1.code === 0 && fs1.stdout === so.stdout, "--secret-file wins over SHADE_TREE_SECRET (trailing newline trimmed)");
    ok(/--secret-file/.test(fs1.stderr), "stderr says the secret came from --secret-file");
    const cwdDir = join(work, "cwd"); await mkdir(cwdDir);
    await writeFile(join(cwdDir, ".secret"), SECRET, { mode: 0o600 });
    const dot = run([], { cwd: cwdDir });
    ok(dot.code === 0 && dot.stdout === so.stdout && /\.secret/.test(dot.stderr), "./.secret in cwd is the fallback source");
    const none = run([], { cwd: work });
    ok(none.code === 1 && /no secret/.test(none.stderr) && none.stdout === "", "no source at all => exit 1, explains, nothing on stdout");
    const missing = run(["--secret-file", join(work, "nope")]);
    ok(missing.code === 1 && /not found/.test(missing.stderr), "--secret-file to a missing path => exit 1");
    const emptyFile = join(work, "empty.secret"); await writeFile(emptyFile, "\n");
    const em = run(["--secret-file", emptyFile]);
    ok(em.code === 1 && em.stdout === "", "empty secret file => exit 1, nothing on stdout");
    const badSecret = run([], { env: { SHADE_TREE_SECRET: "not-a-number" } });
    ok(badSecret.code === 1 && badSecret.stdout === "" && !/not-a-number/.test(badSecret.stderr), "non-numeric secret => exit 1 and the value is not echoed");

    // ---- arg validation ---------------------------------------------------------------------
    console.log("\nargument validation:");
    ok(run(["--bogus", "x"], { env: { SHADE_TREE_SECRET: SECRET } }).code === 2, "unknown flag => exit 2");
    ok(run(["--out"], { env: { SHADE_TREE_SECRET: SECRET } }).code === 2, "--out without a value => exit 2");
    ok(run(["stray"], { env: { SHADE_TREE_SECRET: SECRET } }).code === 2, "stray positional => exit 2");
    const help = run(["--help"]);
    ok(help.code === 0 && /identity/.test(help.stdout), "--help exits 0");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: shade-tree identity selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
