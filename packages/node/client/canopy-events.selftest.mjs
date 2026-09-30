// Local discovery event selftest. Canopy events describe only a live Elder refresh and never
// become telemetry. Static files and in-memory refresh-window hits stay silent.

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { pubkeyToOnion, signDirectory } from "../lib/directory.mjs";
import { ShadeTreeClient } from "./shade-tree-client.mjs";

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else { console.log(`  FAIL ${message}`); failures++;
  }
};

const HERE = dirname(fileURLToPath(import.meta.url));
const SELECTION = join(HERE, "selection.mjs");

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" });
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  return {
    pub: pub.subarray(pub.length - 32).toString("hex"),
    priv: priv.subarray(priv.length - 32).toString("hex"),
  };
}

function signedCanopy(issued, count = 2) {
  const signer = keypair();
  const gateways = Array.from({ length: count }, () => {
    const key = keypair();
    return { onion: pubkeyToOnion(key.pub), pubkey: key.pub, weight: 1, health: "up" };
  });
  return {
    signer,
    directory: signDirectory({ version: 1, issued, gateways, signer: signer.pub }, signer.priv),
  };
}

async function loadSelection(tag, work, signer, { live = true, cache = null, directory = null } = {}) {
  delete process.env.SHADE_TREE_NETWORK;
  process.env.SHADE_TREE_DIR_SIGNER = signer;
  process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "600000";
  process.env.SHADE_TREE_DIRECTORY_CACHE = cache || join(work, `${tag}.lkg.json`);
  process.env.SHADE_TREE_HEALTH_CACHE = join(work, `${tag}.health.json`);
  process.env.SHADE_TREE_RECEIPT_SCORING = "0";
  if (live) {
    process.env.SHADE_TREE_BOOTNODE_ONION = "private-elder-address";
    delete process.env.SHADE_TREE_DIRECTORY;
  } else {
    delete process.env.SHADE_TREE_BOOTNODE_ONION;
    process.env.SHADE_TREE_DIRECTORY = directory;
  }
  return import(pathToFileURL(SELECTION).href + `?canopy-selftest=${tag}-${Date.now()}`);
}

function safeEventShape(events) {
  const forbidden = new Set(["onion", "target", "secret", "url", "raw", "response", "requestId", "queryCount"]);
  return events.every((event) =>
    Object.keys(event).every((key) => !forbidden.has(key)) &&
    !JSON.stringify(event).includes("private-elder-address")
  );
}

async function main() {
  const work = mkdtempSync(join(tmpdir(), "shade-tree-canopy-events-"));
  try {
    const { signer, directory } = signedCanopy(1_700_000_001, 2);

    console.log("live refresh:");
    const live = await loadSelection("verified", work, signer.pub);
    live._setCanopyFetch(async () => directory);
    const liveEvents = [];
    const candidates = await live.selectCandidates(null, null, { onEvent: (event) => liveEvents.push(event) });
    ok(candidates.length === 2, "verified canopy supplies both candidates");
    ok(liveEvents.length === 2 && liveEvents[0].status === "query" && liveEvents[1].status === "verified", "live refresh emits query then verified");
    ok(liveEvents[1].issued === directory.issued && liveEvents[1].count === 2, "verified event carries only signed issue time and node count");
    ok(safeEventShape(liveEvents), "events carry no address, target, secret, raw response, URL, request id, or query counter");

    const warmEvents = [];
    await live.selectCandidates(null, null, { onEvent: (event) => warmEvents.push(event) });
    ok(warmEvents.length === 0, "selection inside the refresh window emits no canopy event");

    console.log("background refresh:");
    let scheduled = null;
    live._setDirectoryPollScheduler({
      setTimeoutFn: (fn, delay) => {
        scheduled = { fn, delay };
        return { unref() {} };
      },
      clearTimeoutFn: () => {},
      rng: () => 0.5,
    });
    const replacementGateway = keypair();
    const replacement = signDirectory({
      version: 1,
      issued: directory.issued + 1,
      gateways: [{ onion: pubkeyToOnion(replacementGateway.pub), pubkey: replacementGateway.pub, weight: 1, health: "up" }],
      signer: signer.pub,
    }, signer.priv);
    live._setCanopyFetch(async () => replacement);
    live.startDirectoryPolling();
    ok(scheduled?.delay === 600000, "poll loop schedules the default refresh interval with deterministic midpoint jitter");
    await scheduled.fn();
    const refreshed = await live.selectCandidates();
    ok(refreshed.length === 1 && refreshed[0].onion === replacement.gateways[0].onion.replace(/\.onion$/, ""),
      "idle poll swaps in a newer verified Canopy before the next CONNECT");
    live.stopDirectoryPolling();

    console.log("last-known-good cache:");
    const cachePath = join(work, "cache.lkg.json");
    writeFileSync(cachePath, JSON.stringify(directory) + "\n");
    const cached = await loadSelection("cache", work, signer.pub, { cache: cachePath });
    cached._setCanopyFetch(async () => { throw new Error("private transport detail"); });
    const cacheEvents = [];
    const cachedCandidates = await cached.selectCandidates(null, null, { onEvent: (event) => cacheEvents.push(event) });
    ok(cachedCandidates.length === 2, "verified last-known-good canopy remains usable");
    ok(cacheEvents.length === 2 && cacheEvents[0].status === "query" && cacheEvents[1].status === "cache", "failed refresh emits query then cache");
    ok(cacheEvents[1].issued === directory.issued && cacheEvents[1].count === 2, "cache event carries signed issue time and node count");
    ok(safeEventShape(cacheEvents), "cache event does not expose the transport error");

    console.log("fail closed:");
    const failed = await loadSelection("error", work, signer.pub);
    failed._setCanopyFetch(async () => { throw new Error("http://private-elder-address/directory"); });
    const errorEvents = [];
    let threw = false;
    try {
      await failed.selectCandidates(null, null, { onEvent: (event) => errorEvents.push(event) });
    } catch { threw = true; }
    ok(threw, "no live canopy and no valid cache fails closed");
    ok(errorEvents.length === 2 && errorEvents[0].status === "query" && errorEvents[1].status === "error", "hard failure emits query then error");
    ok(errorEvents[1].reason === "unavailable-or-invalid" && safeEventShape(errorEvents), "error event uses a stable non-identifying reason");

    console.log("static source:");
    const staticPath = join(work, "static.json");
    writeFileSync(staticPath, JSON.stringify(directory) + "\n");
    const staticSelection = await loadSelection("static", work, signer.pub, { live: false, directory: staticPath });
    const staticEvents = [];
    await staticSelection.selectCandidates(null, null, { onEvent: (event) => staticEvents.push(event) });
    ok(staticEvents.length === 0, "static signed directory emits no canopy event");

    console.log("client threading:");
    const client = Object.create(ShadeTreeClient.prototype);
    client.onion = null;
    client.maxAnon = false;
    client._admission = async () => ({ leafSource: "invited", maxAnon: false });
    let forwarded = false;
    const localEvents = [];
    const localCallback = (event) => localEvents.push(event);
    client._selection = {
      directoryEnabled: () => true,
      selectCandidates: async (_req, _adm, opts) => {
        forwarded = opts?.onEvent === localCallback;
        opts?.onEvent?.({ phase: "canopy", status: "verified", issued: directory.issued, count: 2 });
        return [{ onion: directory.gateways[0].onion }];
      },
    };
    const threaded = await client._candidates(localCallback);
    ok(forwarded && threaded.length === 1 && localEvents[0]?.phase === "canopy", "_candidates forwards the local progress callback to selection");

    const connectProbe = Object.create(ShadeTreeClient.prototype);
    connectProbe.gatewayArtifacts = null;
    connectProbe._candidates = async (onEvent) => {
      onEvent({ phase: "canopy", status: "query" });
      throw new Error("stop after callback probe");
    };
    const connectEvents = [];
    try { await connectProbe.connect("example.com:443", { onEvent: (event) => connectEvents.push(event) }); } catch {}
    ok(connectEvents.some((event) => event.phase === "canopy" && event.status === "query"), "connect passes its best-effort emitter into _candidates");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: canopy events selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => { console.error(error); process.exit(1); });
