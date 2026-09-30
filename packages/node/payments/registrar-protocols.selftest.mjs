// T-FEAT-9 registrar payment-rail subset (fast lane: no chain, no Tor -- a fake settlement engine +
// a fake PaidAccessSet behind the REAL HTTP transport, packages/node/payments/registrar.mjs makeServer):
//   - SHADE_TREE_PAY_PROTOCOLS parses into offer.protocols (default both; subset; unknown -> error);
//   - a 402 (GET /pay/quote and the bodied POST /pay challenge) carries ONLY the enabled rails'
//     challenges: x402-only => PAYMENT-REQUIRED and NO WWW-Authenticate; mpp-only => the reverse;
//     both => both (unchanged);
//   - the offer summary (402 body `pay.protocols`, /health `pay.protocols`) lists only the enabled rails;
//   - a POST /pay carrying the DISABLED rail's header is refused 400 `protocol-disabled` naming the
//     enabled rails, before any parsing/settlement (the fake engine is never called);
//   - the enabled rail still reaches the engine (the request shape is unchanged).
// The real-chain twin (anvil, both rails end to end) is packages/node/payments/registrar.selftest.mjs (slow lane).
//
//   node packages/node/payments/registrar-protocols.selftest.mjs

import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { makeStore, makeServer, makeOffer, offerSummary, offerProtocols, paymentMetricLabels } from "./registrar.mjs";
import { parsePayProtocols } from "../lib/admission.mjs";
import { makeRegistry } from "../lib/metrics.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const ASSET = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const BASE_ENV = { SHADE_TREE_PAY_ASSET: ASSET, SHADE_TREE_PAY_PRICES: "8=100000,32=400000", SHADE_TREE_REGISTRAR_PORT: "0" };
const COMMITMENT = "12345678901234567890";
const PAYMENT_METRIC = "shade_tree_registrar_payments_total";
let registrarSeq = 0;

function metricValue(registry, labels) {
  const suffix = "{" + Object.entries(labels).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}="${v}"`).join(",") + "}";
  const line = registry.render().split("\n").find((row) => row.startsWith(PAYMENT_METRIC + suffix + " "));
  return line ? Number(line.slice(line.lastIndexOf(" ") + 1)) : 0;
}
function paymentTotal(registry) {
  return registry.render().split("\n").filter((row) => row.startsWith(PAYMENT_METRIC + "{")).reduce((sum, row) => sum + Number(row.slice(row.lastIndexOf(" ") + 1)), 0);
}

function request(port, { method = "GET", path = "/", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

// One registrar over fakes for a given SHADE_TREE_PAY_PROTOCOLS. The fake engine records every call.
async function startRegistrar(work, protocolsSpec) {
  const env = { ...BASE_ENV };
  if (protocolsSpec !== undefined) env.SHADE_TREE_PAY_PROTOCOLS = protocolsSpec;
  const offer = makeOffer(env);
  Object.assign(offer, { chainId: 11155111, assetName: "Test USD", assetVersion: "1", decimals: 6, payTo: "0x000000000000000000000000000000000000dEaD" });
  const store = makeStore(join(work, `store-${registrarSeq++}-${String(protocolsSpec).replace(/[^a-z0-9]/gi, "_")}.json`));
  const calls = [];
  const engine = { verifyAndSettle: async (args) => { calls.push(args); return { ok: false, status: 402, reason: "bad-signature", detail: "fake engine" }; }, inflight: () => 0 };
  const set = { target: "0x1111111111111111111111111111111111111111", leafCount: async () => 3n, currentRoot: async () => 42n };
  const metricRegistry = makeRegistry();
  const server = makeServer(engine, { offer, store, set, limits: { headersTimeout: 1500, requestTimeout: 3000, maxHeaderSize: 32768, connectionsCheckingInterval: 200 }, metricRegistry });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { offer, calls, metricRegistry, server, port: server.address().port, stop: () => new Promise((r) => server.close(r)) };
}

async function main() {
  console.log("registrar startup errors use the structured logger:");
  {
    const run = spawnSync(process.execPath, [fileURLToPath(new URL("./registrar.mjs", import.meta.url))], {
      encoding: "utf8",
      timeout: 10_000,
      env: {
        ...process.env,
        SHADE_TREE_LOG_LEVEL: "info",
        SHADE_TREE_LOG_FORMAT: "json",
        SHADE_TREE_REGISTRAR_KEY: "",
      },
    });
    let record = null;
    try { record = JSON.parse(run.stderr.trim().split("\n").filter(Boolean).at(-1)); } catch {}
    ok(run.status === 1, "missing operator key still fails fast with exit status 1");
    ok(record?.level === "error" && record?.component === "registrar"
      && /SHADE_TREE_REGISTRAR_KEY/.test(record?.msg || ""),
      "the startup failure is a structured registrar error instead of raw console output");
  }

  console.log("\nSHADE_TREE_PAY_PROTOCOLS -> offer.protocols:");
  {
    ok(JSON.stringify(makeOffer(BASE_ENV).protocols) === '["x402","mpp"]', "unset -> both (default when the registrar is enabled)");
    ok(JSON.stringify(makeOffer({ ...BASE_ENV, SHADE_TREE_PAY_PROTOCOLS: "mpp" }).protocols) === '["mpp"]' && JSON.stringify(makeOffer({ ...BASE_ENV, SHADE_TREE_PAY_PROTOCOLS: " X402 " }).protocols) === '["x402"]' && JSON.stringify(makeOffer({ ...BASE_ENV, SHADE_TREE_PAY_PROTOCOLS: "mpp,x402" }).protocols) === '["x402","mpp"]', "subsets, case/space tolerant, canonical order x402,mpp");
    let threw = null; try { makeOffer({ ...BASE_ENV, SHADE_TREE_PAY_PROTOCOLS: "x402,lightning" }); } catch (e) { threw = e.message; }
    ok(/SHADE_TREE_PAY_PROTOCOLS: unknown payment protocol "lightning"/.test(threw || ""), "an unknown rail is a startup error (fail fast)");
    ok(JSON.stringify(offerProtocols({})) === '["x402","mpp"]' && JSON.stringify(offerSummary({ protocols: ["mpp"], tiers: {} }).protocols) === '["mpp"]', "offerProtocols/offerSummary: an offer without the field means both; with it, exactly the enabled rails");
    ok(JSON.stringify(parsePayProtocols(undefined)) === '["x402","mpp"]', "parsePayProtocols(undefined) = both");
  }

  const work = await mkdtemp(join(tmpdir(), "shade-tree-registrar-protocols-"));
  const regs = [];
  try {
    const both = await startRegistrar(work, undefined), x402Only = await startRegistrar(work, "x402"), mppOnly = await startRegistrar(work, "mpp");
    regs.push(both, x402Only, mppOnly);
    const bodyLimit8 = JSON.stringify({ commitment: COMMITMENT, limit: 8 });

    console.log("\npublic and operator surface separation:");
    const boundaryHealth = await request(both.port, { path: "/health" });
    ok(boundaryHealth.status === 200 && !("orders" in JSON.parse(boundaryHealth.body)), "/health omits private order volume");
    ok((await request(both.port, { path: "/metrics" })).status === 404, "the onion-facing registrar listener has no /metrics route");

    console.log("\nPOST /pay metrics count every completed request exactly once with bounded labels:");
    {
      const observed = await startRegistrar(work, undefined);
      regs.push(observed);
      const reg = observed.metricRegistry;
      const expectOutcome = async (requestOptions, status, labels, message) => {
        const beforeTotal = paymentTotal(reg), beforeSeries = metricValue(reg, labels);
        const response = await request(observed.port, requestOptions);
        ok(response.status === status && paymentTotal(reg) === beforeTotal + 1 && metricValue(reg, labels) === beforeSeries + 1, message);
      };
      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "content-type": "application/json" }, body: bodyLimit8 },
        402, { protocol: "unknown", reason: "payment-required", result: "challenged" },
        "a headerless payment challenge increments unknown/challenged/payment-required once",
      );
      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "payment-signature": "zz" }, body: "{" },
        400, { protocol: "unknown", reason: "bad-json", result: "rejected" },
        "malformed JSON increments unknown/rejected/bad-json once",
      );
      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "content-type": "application/json", "payment-signature": "zz" }, body: JSON.stringify({ limit: 8 }) },
        400, { protocol: "unknown", reason: "bad-body", result: "rejected" },
        "an invalid body increments unknown/rejected/bad-body once",
      );
      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "content-type": "application/json", "payment-signature": "zz" }, body: JSON.stringify({ commitment: COMMITMENT, limit: 16 }) },
        400, { protocol: "unknown", reason: "unknown-limit", result: "rejected" },
        "an unknown tier increments unknown/rejected/unknown-limit once",
      );
      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "content-type": "application/json", "payment-signature": "A".repeat(9000) }, body: bodyLimit8 },
        400, { protocol: "x402", reason: "credential-too-large", result: "rejected" },
        "an oversized x402 credential increments x402/rejected/credential-too-large once",
      );
      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "content-type": "application/json", authorization: "Payment " + "A".repeat(9000) }, body: bodyLimit8 },
        402, { protocol: "mpp", reason: "credential-too-large", result: "rejected" },
        "an oversized MPP credential increments mpp/rejected/credential-too-large once",
      );

      const beforeRateTotal = paymentTotal(reg), beforeRateSeries = metricValue(reg, { protocol: "unknown", reason: "rate-limited", result: "rejected" });
      let attempts = 0, limited = null;
      while (attempts < 20 && !limited) {
        attempts++;
        const response = await request(observed.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json", "payment-signature": "zz" }, body: bodyLimit8 });
        if (response.status === 429) limited = response;
      }
      ok(limited?.status === 429 && paymentTotal(reg) === beforeRateTotal + attempts && metricValue(reg, { protocol: "unknown", reason: "rate-limited", result: "rejected" }) === beforeRateSeries + 1, "the pay bucket's 429 is counted once and every preceding parsed rejection is counted once");

      await expectOutcome(
        { method: "POST", path: "/pay", headers: { "payment-signature": "zz" }, body: "x".repeat(5000) },
        413, { protocol: "unknown", reason: "body-too-large", result: "rejected" },
        "an oversized body increments unknown/rejected/body-too-large once",
      );

      const sentinel = "payer-controlled-credential-value";
      const safe = paymentMetricLabels({ protocol: sentinel, result: sentinel, reason: sentinel });
      ok(JSON.stringify(safe) === '{"protocol":"unknown","result":"failed","reason":"other"}' && !JSON.stringify(safe).includes(sentinel), "unknown protocol/result/reason values collapse to closed labels without attacker text");
    }

    console.log("\n402 challenges carry ONLY the enabled rails:");
    for (const [name, r, wantX402, wantMpp] of [["both", both, true, true], ["x402-only", x402Only, true, false], ["mpp-only", mppOnly, false, true]]) {
      const q = await request(r.port, { path: "/pay/quote?limit=8" });
      const hasX = typeof q.headers["payment-required"] === "string" && q.headers["payment-required"].length > 0;
      const hasM = q.headers["www-authenticate"] !== undefined && String(q.headers["www-authenticate"]).includes("Payment");
      ok(q.status === 402 && hasX === wantX402 && hasM === wantMpp, `${name}: GET /pay/quote -> 402 with PAYMENT-REQUIRED=${hasX} WWW-Authenticate=${hasM}`);
      const pay = JSON.parse(q.body).pay;
      ok(JSON.stringify(pay.protocols) === JSON.stringify(r.offer.protocols) && pay.offered.join() === "8", `${name}: 402 body pay.protocols == [${r.offer.protocols.join(",")}]`);
      const p = await request(r.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json" }, body: bodyLimit8 });
      const pX = typeof p.headers["payment-required"] === "string", pM = p.headers["www-authenticate"] !== undefined;
      ok(p.status === 402 && pX === wantX402 && pM === wantMpp, `${name}: bodied POST /pay (no payment header) -> 402 challenge with the same rail set`);
      const h = await request(r.port, { path: "/health" });
      ok(h.status === 200 && JSON.stringify(JSON.parse(h.body).pay.protocols) === JSON.stringify(r.offer.protocols), `${name}: /health pay.protocols == the enabled rails`);
      const wantMsg = new RegExp("rails: " + r.offer.protocols.join(", "));
      ok(wantMsg.test(JSON.parse(q.body).detail || ""), `${name}: the 402 problem detail names the rails (${r.offer.protocols.join(", ")})`);
    }

    console.log("\nPOST /pay with a DISABLED rail's header -> 400 protocol-disabled (engine never called):");
    {
      const r1 = await request(mppOnly.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json", "payment-signature": "eyJmYWtlIjoxfQ" }, body: bodyLimit8 });
      const j1 = JSON.parse(r1.body);
      ok(r1.status === 400 && j1.err === "protocol-disabled" && j1.protocol === "x402" && JSON.stringify(j1.protocols) === '["mpp"]' && /does not serve x402/.test(j1.detail) && /SHADE_TREE_PAY_PROTOCOLS=mpp/.test(j1.detail), `mpp-only registrar refuses a PAYMENT-SIGNATURE (x402) payload: ${r1.status} ${j1.err} protocol=${j1.protocol} enabled=${JSON.stringify(j1.protocols)}`);
      ok(mppOnly.calls.length === 0, "…without touching the settlement engine");
      const r2 = await request(x402Only.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json", authorization: "Payment fake" }, body: bodyLimit8 });
      const j2 = JSON.parse(r2.body);
      ok(r2.status === 400 && j2.err === "protocol-disabled" && j2.protocol === "mpp" && JSON.stringify(j2.protocols) === '["x402"]' && /does not serve MPP/.test(j2.detail), `x402-only registrar refuses an Authorization: Payment (MPP) payload: ${r2.status} ${j2.err} protocol=${j2.protocol}`);
      ok(x402Only.calls.length === 0, "…without touching the settlement engine");
      ok(r1.headers["www-authenticate"] === undefined && r1.headers["payment-required"] === undefined, "the refusal carries no challenge for the disabled rail (nothing to retry against on this registrar)");
    }

    console.log("\nthe ENABLED rail still reaches the engine (request shape unchanged):");
    {
      // x402: a syntactically valid PAYMENT-SIGNATURE reaches parseX402Payment; a garbage one is a 402
      // (invalid_payment_payload) -- either way NOT a protocol-disabled refusal.
      const r3 = await request(x402Only.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json", "payment-signature": "eyJmYWtlIjoxfQ" }, body: bodyLimit8 });
      ok(r3.status === 402 && typeof r3.headers["payment-required"] === "string" && r3.headers["www-authenticate"] === undefined, `x402-only: an x402 payload is processed by the x402 path (${r3.status}; re-challenged with PAYMENT-REQUIRED only)`);
      const r4 = await request(mppOnly.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json", authorization: "Payment fake" }, body: bodyLimit8 });
      ok((r4.status === 402 || r4.status === 400) && JSON.parse(r4.body).err !== "protocol-disabled" && r4.headers["payment-required"] === undefined, `mpp-only: an MPP payload is processed by the MPP path (${r4.status} ${JSON.parse(r4.body).err || JSON.parse(r4.body).title || ""}; no x402 challenge)`);
      const r5 = await request(both.port, { method: "POST", path: "/pay", headers: { "content-type": "application/json", authorization: "Payment fake" }, body: bodyLimit8 });
      ok(r5.status !== 400 || JSON.parse(r5.body).err !== "protocol-disabled", "both rails: an MPP payload is never refused as protocol-disabled");
    }
  } finally {
    for (const r of regs) await r.stop();
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: registrar-protocols selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.log(`  FAIL (uncaught) ${e && e.stack ? e.stack : e}`); process.exit(1); });
