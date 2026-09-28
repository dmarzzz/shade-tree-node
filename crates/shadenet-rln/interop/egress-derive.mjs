// T-RUST-2d harness helper: derive a member identity + the group member set from a fixed
// app secret using the JS reference (lib/rln.mjs), and write the two input files the Rust
// `shade-tree egress --features live` build consumes:
//
//   <outdir>/identity.json  = { identitySecret, leaf }   (the member's derived secret + leaf)
//   <outdir>/members.json   = { members: [leaf, ...] }   (the ordered group)
//
// The SAME members.json is copied over group/members.json by egress-run.sh so the JS
// gateway's PoC root source (loadGroup) computes the identical depth-20 root the Rust
// native tree does. The identity derivation itself (Semaphore-v3 identitySecret +
// rateCommitment leaf) lives in lib/identity-file.mjs, shared with the member-facing
// `shade-tree identity` command (group/identity.mjs), so the harness and the CLI can never drift.
// The Rust side takes them as inputs and computes the root + path natively.
//
// This is a HARNESS helper (fixed dev secret, single-leaf members.json). Members exporting
// their real identity for the Rust client should use `shade-tree identity` instead.
//
// Usage: node egress-derive.mjs <outdir> [secret]
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { identityFileFor, serializeIdentityFile } from "../../../lib/identity-file.mjs";
import { cleanUp } from "../../../lib/rln.mjs";

const outdir = process.argv[2];
if (!outdir) {
  console.error("usage: node egress-derive.mjs <outdir> [secret]");
  process.exit(2);
}
const SECRET = process.argv[3] || "12345678901234567890";

const { identitySecret, leaf } = identityFileFor(SECRET);

writeFileSync(join(outdir, "identity.json"), serializeIdentityFile({ identitySecret, leaf }));
writeFileSync(join(outdir, "members.json"), JSON.stringify({ version: 2, members: [leaf] }, null, 2) + "\n");

console.error("[derive] secret          =", SECRET);
console.error("[derive] identitySecret  =", identitySecret);
console.error("[derive] leaf (commit)   =", leaf);
console.error("[derive] wrote", join(outdir, "identity.json"), "+", join(outdir, "members.json"));
cleanUp();
