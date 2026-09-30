// Adversary probe: connect straight to the gateway onion over Tor and try to
// egress with a bad/forged/missing proof. Confirms the gate drops non-members.
//
//   node scripts/probe.mjs noproof      -> envelope with no proof
//   node scripts/probe.mjs garbage      -> structurally bogus proof
//   node scripts/probe.mjs wronggroup   -> a VALID Semaphore proof, but for an
//                                          attacker-controlled group (the real
//                                          attack: prove membership in a set you
//                                          made up). Gateway must reject on root.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { SocksClient } from "socks";
import { Identity } from "@semaphore-protocol/identity";
import { Group } from "@semaphore-protocol/group";
import { generateProof } from "@semaphore-protocol/proof";
import { currentEpoch } from "../packages/node/lib/semaphore.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const mode = process.argv[2] || "noproof";
const onion = (await readFile(join(HERE, "..", "tor", "hs", "hostname"), "utf8")).trim();

let proof = null;
if (mode === "garbage") {
  proof = { merkleTreeRoot: "123", nullifier: "1", scope: String(currentEpoch()), message: "1", merkleTreeDepth: 1, points: Array(8).fill("1") };
} else if (mode === "wronggroup") {
  // Attacker forges a perfectly valid proof against a group they invented.
  const attacker = new Identity("attacker-not-enrolled");
  const fakeGroup = new Group([attacker.commitment]);
  proof = await generateProof(attacker, fakeGroup, 1n, currentEpoch());
  console.log("attacker built a VALID proof, root", String(proof.merkleTreeRoot).slice(0, 18) + "..");
}

const { socket } = await SocksClient.createConnection({
  proxy: { host: "127.0.0.1", port: 9250, type: 5 },
  command: "connect",
  destination: { host: onion, port: 80 },
  timeout: 60000,
});

socket.write(JSON.stringify({ v: 4, target: "api.ipify.org:443", nonce: `probe-${mode}`, proof }) + "\n");
let buf = "";
socket.on("data", (d) => {
  buf += d.toString();
  if (buf.includes("\n")) {
    console.log(`mode=${mode}  gateway replied: ${buf.trim()}`);
    socket.destroy();
    process.exit(0);
  }
});
socket.on("error", (e) => { console.log("socket error", e.message); process.exit(1); });
setTimeout(() => { console.log("timeout, no reply"); process.exit(1); }, 30000);
