// Groth16 proofs of knowledge of an identity secret, bound to an exit or withdraw context.
// Runs snarkjs over circuits/rln/withdraw.{wasm,zkey}; in a browser it proves in WASM, so the
// identity secret never leaves the tab. snarkjs is imported lazily: a page that only stakes
// never loads it.
//
// Proof bytes are what WithdrawVerifier.verify decodes:
//   abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256 identityCommitment)

import { AbiCoder } from "ethers";
import { identityCommitmentOf, canonicalField } from "../../node/lib/identity-core.mjs";
import { contextToField } from "./contexts.mjs";
import { ShadeNetError } from "./errors.mjs";

// Where the withdraw circuit lives when the caller passes no artifacts. The Node entry
// (./node.mjs) points this at the repo's committed circuits; a browser must pass URLs or bytes.
let defaultArtifacts = null;
export function setDefaultArtifacts(artifacts) {
  defaultArtifacts = artifacts;
}

const asSource = (x) => (x instanceof Uint8Array ? { type: "mem", data: x } : x);

export async function proveAction({ identitySecret, context, artifacts } = {}) {
  let secret;
  try {
    secret = canonicalField(String(identitySecret ?? ""), "identitySecret");
  } catch (cause) {
    throw new ShadeNetError("InvalidInput", cause.message, { cause });
  }
  const source = artifacts ?? defaultArtifacts;
  if (!source) throw new ShadeNetError("InvalidInput", "pass artifacts: { wasm, zkey } (URLs or bytes) to prove in a browser");
  const { wasm, zkey } = source;
  const { groth16 } = await import("snarkjs");
  let proof, publicSignals;
  try {
    ({ proof, publicSignals } = await groth16.fullProve(
      { identitySecret: secret.toString(), address: contextToField(context).toString() },
      asSource(wasm),
      asSource(zkey),
      undefined,
      undefined,
      // Browsers prove on the main thread: no worker (and no worker-src CSP) needed.
      { singleThread: typeof window !== "undefined" },
    ));
  } catch (cause) {
    throw new ShadeNetError("InvalidInput", `exit proof failed: ${cause?.message ?? cause}`, { cause });
  }
  const idc = identityCommitmentOf(secret).toString();
  if (publicSignals[0] !== idc || publicSignals[1] !== contextToField(context).toString()) {
    throw new ShadeNetError("InvalidInput", "exit proof public signals do not match the identity and context");
  }
  const calldata = await groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c] = JSON.parse(`[${calldata}]`);
  return AbiCoder.defaultAbiCoder().encode(["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256"], [a, b, c, idc]);
}
