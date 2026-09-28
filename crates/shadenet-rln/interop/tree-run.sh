#!/usr/bin/env bash
# Native Rust RLN merkle-tree parity harness (T-RUST-2c).
#
# Proves two things end-to-end, against the SAME rlnjs libraries the gateway uses:
#
#   [A] ROOT PARITY: the native Rust depth-20 Poseidon tree root EQUALS the rlnjs
#       Semaphore-v3 group root over several identical member lists.
#   [B] SINGLE-MEMBER ENVELOPE: a RUST-computed root+path (index 0, all-zero
#       siblings) drives the circom-rln prover and lib/rln.mjs verifyEnvelope ACCEPTS it.
#   [C] MULTI-MEMBER ENVELOPE: a RUST-computed root+path for a member at a NON-zero
#       index (real leaf + real internal-node siblings) drives the prover and
#       verifyEnvelope ACCEPTS it.
#
# The JS side here is only the rlnjs reference (imported from lib/rln.mjs) and small
# inline readers/mergers; no existing .mjs is modified. run.sh (T-RUST-2b) still
# covers the JS-fixture path; this script is the Rust-owned-tree counterpart.
#
# Prereqs: `npm install` at the repo root (rlnjs) and a Rust toolchain.
# Run from anywhere: bash crates/shadenet-rln/interop/tree-run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CIRCUITS="$REPO/circuits/rln"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building rust probe + tree =="
cargo build -p shadenet-rln --bin shadenet-rln-probe --bin shadenet-rln-tree --manifest-path "$REPO/Cargo.toml"
PROBE="$REPO/target/debug/shadenet-rln-probe"
TREE="$REPO/target/debug/shadenet-rln-tree"

# --- [A] root parity over several member lists --------------------------------
echo "== [A] root parity: Rust tree root == rlnjs group root =="
js_root() { # args: leaves...  -> rlnjs newGroup([...]).root
  node --input-type=module -e '
    import { newGroup } from "'"$REPO"'/lib/rln.mjs";
    console.log(newGroup(process.argv.slice(1).map(BigInt)).root.toString());
  ' "$@"
}
for SET in "111 222 333" "7 8 9 10 11" "42" "1000000 2000000 3000000 4000000"; do
  # shellcheck disable=SC2086
  JS=$(js_root $SET)
  # shellcheck disable=SC2086
  RS=$("$TREE" root $SET)
  if [ "$JS" != "$RS" ]; then
    echo "  FAIL members=[$SET]: js=$JS rust=$RS"; exit 1
  fi
  echo "  OK members=[$SET] root=$RS"
done

# --- [B] single-member envelope with a RUST-computed root+path ----------------
echo "== [B] single-member envelope: RUST root+path -> prover -> verifyEnvelope =="
node "$HERE/fixture-gen.mjs" 0123456789abcdef0123456789abcdef > "$WORK/fixtureB.json"
LEAF=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).leaf)' "$WORK/fixtureB.json")
JSROOT=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root)' "$WORK/fixtureB.json")
"$TREE" proof 0 "$LEAF" > "$WORK/rustB.json"
RUSTROOT=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root)' "$WORK/rustB.json")
[ "$JSROOT" = "$RUSTROOT" ] || { echo "  FAIL: rust root ($RUSTROOT) != js root ($JSROOT)"; exit 1; }
echo "  rust root == js root: $RUSTROOT"
node -e '
  const fs=require("fs");
  const fx=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  const rt=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
  fx.root=rt.root; fx.pathElements=rt.pathElements; fx.identityPathIndex=rt.identityPathIndex;
  fx.ref_publicSignals.root=rt.root;
  fs.writeFileSync(process.argv[3], JSON.stringify(fx,null,2));
' "$WORK/fixtureB.json" "$WORK/rustB.json" "$WORK/fixtureB_rust.json"
"$PROBE" "$WORK/fixtureB_rust.json" "$WORK/envB.json" "$CIRCUITS"
node "$HERE/verify-envelope.mjs" "$WORK/envB.json"

# --- [C] multi-member envelope: member at a NON-zero index --------------------
echo "== [C] multi-member envelope: RUST root+path (real siblings) -> prover -> verifyEnvelope =="
# Build a 3-member group with our real member at index 1 (decoys either side), emit
# the circuit fields + rlnjs reference public signals, WITHOUT any JS merkle path.
node --input-type=module -e '
  import {
    identityFor, identitySecretOf, rateCommitmentOf, newGroup,
    externalNullifierFor, requestSignal, proveForSlot, K_SLOTS, RLN_IDENTIFIER,
    calculateSignalHash, cleanUp,
  } from "'"$REPO"'/lib/rln.mjs";
  import { writeFileSync } from "node:fs";

  const SECRET = "12345678901234567890";
  const EPOCH = 42n, MESSAGE_ID = 3, TARGET = "example.com:443";
  const NONCE = "0123456789abcdef0123456789abcdef";
  const DECOY_A = 987654321n, DECOY_B = 55555555n;

  const identity = identityFor(SECRET);
  const identitySecret = identitySecretOf(identity);
  const leaf = rateCommitmentOf(identity);
  const members = [DECOY_A, leaf, DECOY_B]; // real member at index 1
  const group = newGroup(members);
  const signal = requestSignal(TARGET, NONCE);
  const x = calculateSignalHash(signal);
  const extNull = externalNullifierFor(EPOCH);
  const ref = await proveForSlot(SECRET, EPOCH, MESSAGE_ID, signal, { group });

  const out = {
    secret: SECRET, epoch: String(EPOCH), rlnIdentifier: String(RLN_IDENTIFIER),
    userMessageLimit: String(K_SLOTS), messageId: String(MESSAGE_ID),
    target: TARGET, nonce: NONCE, signal,
    identitySecret: String(identitySecret), leaf: String(leaf),
    members: members.map(String), memberIndex: 1,
    root: String(group.root), // rlnjs multi-member root (Rust will reproduce it)
    x: String(x), externalNullifier: String(extNull),
    ref_publicSignals: {
      y: String(ref.share.y), root: String(group.root),
      nullifier: String(ref.nullifier), x: String(ref.share.x),
      externalNullifier: String(ref.externalNullifier),
    },
  };
  writeFileSync(process.argv[1], JSON.stringify(out, null, 2));
  cleanUp();
' "$WORK/fixtureC.json"

# Rust computes the root + path for member index 1 over the SAME ordered members.
INDEX=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).memberIndex)' "$WORK/fixtureC.json")
# members are plain decimal integers (no embedded spaces) -> safe to word-split.
MEMBERS=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).members.join(" "))' "$WORK/fixtureC.json")
# shellcheck disable=SC2086
"$TREE" proof "$INDEX" $MEMBERS > "$WORK/rustC.json"
JSROOTC=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root)' "$WORK/fixtureC.json")
RUSTROOTC=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).root)' "$WORK/rustC.json")
[ "$JSROOTC" = "$RUSTROOTC" ] || { echo "  FAIL: rust root ($RUSTROOTC) != js root ($JSROOTC)"; exit 1; }
echo "  rust root == js root (member idx $INDEX): $RUSTROOTC"
node -e '
  const fs=require("fs");
  const fx=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  const rt=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
  fx.root=rt.root; fx.pathElements=rt.pathElements; fx.identityPathIndex=rt.identityPathIndex;
  fx.ref_publicSignals.root=rt.root;
  fs.writeFileSync(process.argv[3], JSON.stringify(fx,null,2));
' "$WORK/fixtureC.json" "$WORK/rustC.json" "$WORK/fixtureC_rust.json"
"$PROBE" "$WORK/fixtureC_rust.json" "$WORK/envC.json" "$CIRCUITS"
node "$HERE/verify-envelope.mjs" "$WORK/envC.json"

# --- [D] leaf-removal parity (T-DEV-2b): Rust remove-middle == JS reconstructRoot -
echo "== [D] removal parity: Rust remove-middle root == JS reconstructRoot / contract golden =="
# The loop-26 register-3 / slash-middle scenario. Leaves are the RLN rate commitments
# for secrets 111/222/333 (deriveCommitment), the SAME leaves as the on-chain contract
# test + lib/rln-removal-parity.selftest.mjs. The JS side computes the zero-in-place
# root two independent ways (root-provider.mjs reconstructRoot over the Member* event
# log, AND a direct Group.removeMember oracle); the Rust side reproduces it via the
# native tree. All must equal the pinned GOLDEN root.
GOLDEN="14367190620832145537223890636337926502210861635134078778082353204233456513838"
# JS: reconstructRoot(register c0@0,c1@1,c2@2; slash c1) and a removeMember oracle,
# plus the leaves + the tree zero value, emitted together so Rust reuses them.
node --input-type=module -e '
  import { newGroup, deriveCommitment } from "'"$REPO"'/lib/rln.mjs";
  import { reconstructRoot } from "'"$REPO"'/lib/root-provider.mjs";
  import { writeFileSync } from "node:fs";
  const TOPIC = {
    registered: "0x0dbb6a3ed41d8f3d21e481b86d0e8bbf65a630b7dc4c5ee6c2c1a74561841e6d",
    slashed:    "0x707cd9719d0c14265b9e456f7add99095401f907e570e5cdd65a92920947c450",
  };
  const mklog = (t,c,b,i=0) => ({
    topics:[t,"0x"+BigInt(c).toString(16)],
    blockNumber:"0x"+BigInt(b).toString(16), logIndex:"0x"+BigInt(i).toString(16),
  });
  const c0=deriveCommitment(111n), c1=deriveCommitment(222n), c2=deriveCommitment(333n);
  const reconstructed = reconstructRoot([
    mklog(TOPIC.registered,c0,1), mklog(TOPIC.registered,c1,2),
    mklog(TOPIC.registered,c2,3), mklog(TOPIC.slashed,c1,4),
  ]);
  const g=newGroup(); g.addMember(BigInt(c0)); g.addMember(BigInt(c1)); g.addMember(BigInt(c2));
  g.removeMember(1);
  writeFileSync(process.argv[1], JSON.stringify({
    c0:String(c0), c1:String(c1), c2:String(c2),
    zeroValue:String(newGroup().zeroValue),
    reconstructRoot:String(reconstructed), oracleRemoveRoot:String(g.root),
  }, null, 2));
' "$WORK/removeD.json"
read -r C0 C1 C2 ZERO JS_RECON JS_ORACLE < <(node -e '
  const d=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
  console.log(d.c0,d.c1,d.c2,d.zeroValue,d.reconstructRoot,d.oracleRemoveRoot);
' "$WORK/removeD.json")
# The JS side must agree with itself and the pinned golden first.
[ "$JS_RECON" = "$JS_ORACLE" ] || { echo "  FAIL: JS reconstructRoot ($JS_RECON) != removeMember oracle ($JS_ORACLE)"; exit 1; }
[ "$JS_RECON" = "$GOLDEN" ]    || { echo "  FAIL: JS reconstructRoot ($JS_RECON) != pinned GOLDEN ($GOLDEN)"; exit 1; }
# Rust reproduces the zero-in-place remove-middle tree. remove(index) is byte-identical
# to a fresh build with leaf[index] = the tree zero value (proven in tests/tree_parity.rs
# `remove_middle_matches_zero_in_place_reconstruction`), so the `root` mode over
# [c0, ZERO, c2] computes exactly the Rust remove(1) root.
RUST_REMOVE=$("$TREE" root "$C0" "$ZERO" "$C2")
[ "$RUST_REMOVE" = "$JS_RECON" ] || { echo "  FAIL: Rust remove-middle root ($RUST_REMOVE) != JS reconstructRoot ($JS_RECON)"; exit 1; }
echo "  JS reconstructRoot == removeMember oracle == GOLDEN == Rust remove-middle: $RUST_REMOVE"
# Sanity: the pre-removal 3-member root differs (proves the removal actually changed the root).
RUST_FULL=$("$TREE" root "$C0" "$C1" "$C2")
[ "$RUST_FULL" != "$RUST_REMOVE" ] || { echo "  FAIL: remove-middle root unchanged from full 3-member root"; exit 1; }
echo "  (pre-removal 3-member root $RUST_FULL differs, as expected)"

echo "== RLN MERKLE-TREE PARITY OK (root parity + single/multi-member envelopes + removal parity) =="
