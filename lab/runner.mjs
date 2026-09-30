#!/usr/bin/env node

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { createClient } from "@shadenet/sdk/node";
import { envFlag } from "../packages/node/lib/admission.mjs";

export const LAB_TARGET = "https://example.com/";
export const DEFAULT_COOLDOWN_MS = 16_000;
const MAX_REQUEST_BYTES = 16;
const STREAM_HEADERS = {
  "Cache-Control": "no-store, no-transform",
  "Content-Type": "text/event-stream; charset=utf-8",
  "X-Accel-Buffering": "no",
  "X-Content-Type-Options": "nosniff",
};
const JSON_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
};

function digest(value) {
  return createHash("sha256").update(String(value)).digest();
}

export function authorized(header, token) {
  if (typeof token !== "string" || token.length < 32) return false;
  const prefix = "Bearer ";
  if (typeof header !== "string" || !header.startsWith(prefix)) return false;
  return timingSafeEqual(digest(header.slice(prefix.length)), digest(token));
}

function decimal(value) {
  const text = String(value ?? "");
  return /^-?[0-9]{1,90}$/.test(text) ? text : null;
}

function proofTuple(value, depth = 0) {
  if (depth > 2 || !Array.isArray(value) || value.length > 3) return null;
  const out = value.map((part) => Array.isArray(part) ? proofTuple(part, depth + 1) : decimal(part));
  return out.some((part) => part == null) ? null : out;
}

// Public codes are UPPER_SNAKE. SDK codes (BudgetExhausted) are converted; anything else is dropped.
function errorCode(value) {
  const code = String(value ?? "").replace(/^([A-Z][a-z]+)+$/, (name) => name.replace(/(?!^)([A-Z])/g, "_$1").toUpperCase());
  return /^[A-Z0-9_]{1,64}$/.test(code) ? code : undefined;
}

export function createEventSanitizer() {
  const aliases = new Map();
  const alias = (onion) => {
    const key = String(onion || "").replace(/\.onion$/, "");
    if (!key) return undefined;
    if (!aliases.has(key)) aliases.set(key, `node-${aliases.size + 1}`);
    return aliases.get(key);
  };

  return function sanitize(event) {
    if (!event || typeof event !== "object") return null;
    const phase = String(event.phase || "");
    const status = String(event.status || "");

    if (phase === "canopy" && ["query", "verified", "cache", "error"].includes(status)) {
      return {
        phase,
        status,
        ...(Number.isSafeInteger(event.count) ? { count: event.count } : {}),
        ...(Number.isSafeInteger(event.issued) ? { issued: event.issued } : {}),
      };
    }
    if (phase === "select" && ["done", "error"].includes(status)) {
      const candidates = Array.isArray(event.candidates) ? event.candidates.slice(0, 8).map((item) => alias(item?.onion)).filter(Boolean) : [];
      return { phase, status, ...(status === "done" ? { leafSource: event.leafSource || null, candidates } : {}) };
    }
    if (phase === "prove" && ["start", "done", "error"].includes(status)) {
      const base = { phase, status, ...(typeof event.artifact === "string" ? { artifact: event.artifact.slice(0, 64) } : {}) };
      if (status !== "done") return { ...base, ...(errorCode(event.code) ? { code: errorCode(event.code) } : {}) };
      const pub = event.pub && typeof event.pub === "object" ? {
        y: decimal(event.pub.y),
        root: decimal(event.pub.root),
        nullifier: decimal(event.pub.nullifier),
        x: decimal(event.pub.x),
        externalNullifier: decimal(event.pub.externalNullifier),
      } : null;
      const pi = event.pi && typeof event.pi === "object" ? {
        a: proofTuple(event.pi.a),
        b: proofTuple(event.pi.b),
        c: proofTuple(event.pi.c),
      } : null;
      if (!pub || Object.values(pub).some((value) => value == null) || !pi || Object.values(pi).some((value) => value == null)) return null;
      return {
        ...base,
        slot: Number.isSafeInteger(event.slot) ? event.slot : null,
        epoch: decimal(event.epoch),
        rlnIdentifier: decimal(event.rlnIdentifier),
        nullifier: decimal(event.nullifier),
        pub,
        pi,
      };
    }
    if (phase === "dial" && ["start", "done", "failover", "error"].includes(status)) {
      return { phase, status, ...(alias(event.onion) ? { node: alias(event.onion) } : {}), ...(Number.isFinite(event.latencyMs) ? { latencyMs: Math.max(0, Math.round(event.latencyMs)) } : {}) };
    }
    if (phase === "gate" && ["start", "done", "refused", "error"].includes(status)) {
      return { phase, status, ...(alias(event.onion) ? { node: alias(event.onion) } : {}), ...(errorCode(event.code) ? { code: errorCode(event.code) } : {}) };
    }
    if (phase === "receipt" && ["absent", "verified", "invalid"].includes(status)) {
      return { phase, status, ...(alias(event.onion) ? { node: alias(event.onion) } : {}) };
    }
    if (phase === "egress" && ["start", "done", "error"].includes(status)) {
      return { phase, status, ...(Number.isInteger(event.httpStatus) ? { httpStatus: event.httpStatus } : {}), ...(errorCode(event.code) ? { code: errorCode(event.code) } : {}) };
    }
    return null;
  };
}

export function extractAnswer(body) {
  const match = String(body || "").match(/<h1[^>]*>\s*([^<]{1,80})\s*<\/h1>/i);
  return match ? match[1].trim() : "Response received";
}

export function labClientOptions(env = process.env) {
  return {
    secret: env.SHADE_TREE_SECRET,
    limit: Number(env.SHADE_TREE_LIMIT || 8),
    leafSource: env.SHADE_TREE_LEAF_SOURCE || "invited",
    maxAnon: env.SHADE_TREE_MAX_ANON == null ? true : envFlag(env.SHADE_TREE_MAX_ANON),
    fetchTimeoutMs: 100_000,
    fetchMaxBodyBytes: 32_768,
    slotStateDir: env.SHADE_TREE_SLOT_STATE_DIR,
  };
}

function writeEvent(response, event, data) {
  response.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function json(response, status, value, extraHeaders = {}) {
  response.writeHead(status, { ...JSON_HEADERS, ...extraHeaders });
  response.end(`${JSON.stringify(value)}\n`);
}

async function readEmptyObject(request) {
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > MAX_REQUEST_BYTES) throw new Error("request_too_large");
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks).toString("utf8").trim();
  if (body && body !== "{}") throw new Error("unsupported_body");
}

export function createLabRunner({
  token = process.env.SHADE_TREE_LAB_RUNNER_TOKEN,
  cooldownMs = Number(process.env.SHADE_TREE_LAB_COOLDOWN_MS || DEFAULT_COOLDOWN_MS),
  clientFactory = () => createClient(labClientOptions()),
  now = Date.now,
} = {}) {
  if (!token || token.length < 32) throw new Error("SHADE_TREE_LAB_RUNNER_TOKEN must be at least 32 characters");
  let client;
  let active = false;
  let lastStartedAt = 0;

  return createServer(async (request, response) => {
    const url = new URL(request.url || "/", "http://runner.invalid");
    if (request.method === "GET" && url.pathname === "/health" && !url.search) {
      return json(response, 200, { ok: true, service: "shade-tree-lab-runner", target: "example.com", active });
    }
    if (request.method !== "POST" || url.pathname !== "/v1/run" || url.search) return json(response, 404, { error: "not_found" });
    if (!authorized(request.headers.authorization, token)) return json(response, 401, { error: "unauthorized" });
    try {
      await readEmptyObject(request);
    } catch (error) {
      return json(response, 400, { error: error.message });
    }
    if (active) return json(response, 429, { error: "run_in_progress" }, { "Retry-After": "5" });
    const remaining = cooldownMs - (now() - lastStartedAt);
    if (remaining > 0) return json(response, 429, { error: "cooldown", retryAfterMs: remaining }, { "Retry-After": String(Math.ceil(remaining / 1000)) });

    active = true;
    lastStartedAt = now();
    response.writeHead(200, STREAM_HEADERS);
    response.flushHeaders?.();
    const startedAt = now();
    const sanitize = createEventSanitizer();
    writeEvent(response, "trace", { phase: "run", status: "start", target: "example.com" });

    try {
      client ||= clientFactory();
      const result = await client.fetch(LAB_TARGET, {
        method: "GET",
        headers: { Accept: "text/html", "User-Agent": "ShadeTreeProtocolLab/1.0" },
        timeoutMs: 100_000,
        maxBodyBytes: 32_768,
        onEvent(event) {
          const safe = sanitize(event);
          if (safe) writeEvent(response, "trace", safe);
        },
      });
      writeEvent(response, "done", {
        status: result.status,
        answer: extractAnswer(result.body),
        target: "example.com",
        durationMs: Math.max(0, now() - startedAt),
      });
    } catch (error) {
      const code = errorCode(error?.code) || "LAB_RUN_FAILED";
      console.error(JSON.stringify({ event: "lab_run_failed", code }));
      writeEvent(response, "failed", { code, message: "The live route did not complete. Try again after the cooldown." });
    } finally {
      active = false;
      response.end();
    }
  });
}

function main() {
  const host = process.env.SHADE_TREE_LAB_HOST || "127.0.0.1";
  const port = Number(process.env.SHADE_TREE_LAB_PORT || 8790);
  const server = createLabRunner();
  server.listen(port, host, () => console.log(JSON.stringify({ event: "lab_runner_listening", host, port, target: "example.com" })));
  const close = () => server.close(() => process.exit(0));
  process.once("SIGINT", close);
  process.once("SIGTERM", close);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
