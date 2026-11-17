// Announce a freshly minted onion to an Elder over plain HTTP with the JavaScript reference
// implementation (`keygen.mjs` + `announce.mjs`), and print the Elder's reply. The harness uses
// it to put a JavaScript-built announce in front of the Rust Elder, and a second one in front
// of the JavaScript Elder for the Rust Elder to pull through federation.
//
// Usage: node elder-announce.mjs <elder-port> <hs-dir> [label]   -> prints {"onion":..,"reply":..}
import { generateOnionIdentity } from "../../../packages/node/bootnode/keygen.mjs";
import { buildAnnounce } from "../../../packages/node/bootnode/announce.mjs";

const port = Number(process.argv[2]);
const hsDir = process.argv[3];
const label = process.argv[4] || "interop";
if (!port || !hsDir) {
  console.error("usage: node elder-announce.mjs <elder-port> <hs-dir> [label]");
  process.exit(2);
}
const id = await generateOnionIdentity(hsDir, { label });
const rec = buildAnnounce({ onion: id.onion, weight: 100, onionSeedHex: id.seed, caps: { ports: [443], region: "eu" } });
const res = await fetch(`http://127.0.0.1:${port}/announce`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(rec),
});
const reply = await res.json();
console.log(JSON.stringify({ onion: id.onion, status: res.status, reply }));
process.exit(res.status === 200 && reply.ok === true ? 0 : 1);
