// Cross-impl over-spend: two RUST-generated shares for the SAME (identity, epoch,
// slot) but DIFFERENT x (different nonce) lie on the same degree-1 line and share a
// nullifier. lib/rln.mjs reconstructSecret must recover the identitySecret from the
// two Rust shares — the slash primitive working across the JS/Rust boundary.
//
// Usage: node overspend.mjs <rust-envelope-A.json> <rust-envelope-B.json> <fixture-A.json>
import { readFileSync } from "node:fs";
import { reconstructSecret, cleanUp } from "../../../lib/rln.mjs";

const a = JSON.parse(readFileSync(process.argv[2], "utf8"));
const b = JSON.parse(readFileSync(process.argv[3], "utf8"));
const fixture = JSON.parse(readFileSync(process.argv[4], "utf8"));

console.log("nullifier A == B (same slot/epoch breach key):", a.nullifier === b.nullifier);
if (a.share.x === b.share.x) {
  console.error("shares share x; not a breach");
  process.exit(1);
}

const recovered = reconstructSecret(a.share, b.share);
console.log("recovered identitySecret:", recovered);
console.log("expected  identitySecret:", fixture.identitySecret);
const ok = a.nullifier === b.nullifier && recovered === fixture.identitySecret;
console.log(ok
  ? "PASS: over-spend cross-impl reconstruction recovers the identity secret."
  : "FAIL: reconstruction mismatch.");
cleanUp();
process.exit(ok ? 0 : 1);
