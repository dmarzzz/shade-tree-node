// Build the aggregate JSON consumed by the public /grove/ page.
//
// The collector reaches the bootnode over Tor through observeFleet(), verifies /directory against
// the pinned signer, and only then passes it to buildPublicGroveSnapshot(). The raw directory is
// never written. Output contains only the allowlisted aggregate, its privacy contract, and a
// dedicated publication signature.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createPublicKey } from "node:crypto";
import { dirname, resolve } from "node:path";
import { observeFleet } from "./uptime-probe.mjs";
import { attestPublicGroveSnapshot, buildPublicGroveSnapshot } from "../packages/node/lib/public-grove.mjs";
import { fetchOverTor } from "../packages/node/bootnode/fetch.mjs";
import { publicRelayFromAggregate } from "../packages/node/lib/relay-telemetry.mjs";

function option(argv, name, fallback = null) {
  const exact = argv.indexOf(name);
  if (exact !== -1) return argv[exact + 1] || fallback;
  const inline = argv.find((arg) => arg.startsWith(name + "="));
  return inline ? inline.slice(name.length + 1) : fallback;
}

async function readPrevious(path) {
  if (!path) return null;
  try { return JSON.parse(await readFile(resolve(path), "utf8")); } catch { return null; }
}

export async function observeRelayAggregate({
  onion = process.env.SHADE_TREE_BOOTNODE_ONION,
  torHost = process.env.SHADE_TREE_TOR_HOST || "127.0.0.1",
  torPort = Number(process.env.SHADE_TREE_TOR_PORT || 9250),
  fetchRelay = fetchOverTor,
} = {}) {
  if (!onion) throw new Error("relay aggregate observer requires bootnode onion");
  return fetchRelay(onion, "/telemetry/aggregate", { torHost, torPort, maxBytes: 64 * 1024 });
}

export async function collectPublicGrove({
  previous = null,
  network = process.env.SHADE_TREE_NETWORK || "unknown",
  observedAt = new Date(),
  observe = observeFleet,
  signingKey = process.env.SHADE_TREE_GROVE_SIGNING_KEY,
  relayAggregate = null,
  onchainActivity = null,
} = {}) {
  if (!signingKey) throw new Error("public Grove signing key required");
  const { result, directory } = await observe();
  if (!result.ok || !result.signerOk || !result.directoryFresh || !directory) {
    throw new Error("no verified bootnode directory available for public snapshot");
  }
  const previousPublicKey = createPublicKey(signingKey).export({ type: "spki", format: "pem" });
  const relay = relayAggregate === null ? null : publicRelayFromAggregate(relayAggregate, directory.signer);
  const snapshot = buildPublicGroveSnapshot({ directory, previous, previousPublicKey, observedAt, network, relay, onchain: onchainActivity });
  return attestPublicGroveSnapshot(snapshot, signingKey);
}

async function main() {
  const argv = process.argv.slice(2);
  const outPath = resolve(option(argv, "--out", "grove.json"));
  const previous = await readPrevious(option(argv, "--previous"));
  const network = option(argv, "--network", process.env.SHADE_TREE_NETWORK || "unknown");
  const includeRelay = option(argv, "--relay", process.env.SHADE_TREE_GROVE_RELAY || "0") === "1";
  const relayAggregate = includeRelay ? await observeRelayAggregate() : null;
  const onchainActivity = await readPrevious(option(argv, "--onchain"));
  if (onchainActivity !== null && !includeRelay) throw new Error("--onchain requires --relay 1");
  const snapshot = await collectPublicGrove({ previous, network, relayAggregate, onchainActivity });
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
  console.log("public Grove snapshot: signed aggregate written");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(() => {
    // Never echo a transport target or raw response here. The collector's public failure is a
    // fixed message; detailed uptime diagnostics remain in the separately scrubbed probe step.
    console.error("public grove snapshot unavailable: no verified directory");
    process.exit(1);
  });
}
