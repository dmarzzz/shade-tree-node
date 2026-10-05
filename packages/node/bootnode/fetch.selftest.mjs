// Offline unit test of parseHttp(buf) from packages/node/bootnode/fetch.mjs. The client reads a whole HTTP/1.1
// response off a closed onion socket and hands the raw bytes to parseHttp; that one function is
// the entire trust boundary between wire bytes and the JSON the client then verifies. So we feed
// it crafted Buffers (no network, no Tor) and pin the contract: a 200 yields the parsed body, any
// non-200 throws WITH its status in the message, and a truncated header throws instead of hanging.
//
//   node packages/node/bootnode/fetch.selftest.mjs
//
// Exit 0 = parseHttp holds its contract on every crafted case; nonzero = a check failed.

import { EventEmitter } from "node:events";
import { parseHttp, postOverTor, isRefusal } from "./fetch.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Build a well-formed HTTP/1.1 response Buffer with a correct Content-Length for `body`.
function resp(status, statusText, body, { extraHeaders = "", contentType = "application/json" } = {}) {
  const bodyBuf = Buffer.from(body, "utf8");
  let head = `HTTP/1.1 ${status} ${statusText}\r\n`;
  if (contentType) head += `Content-Type: ${contentType}\r\n`;
  head += `Content-Length: ${bodyBuf.length}\r\n`;
  head += extraHeaders;
  head += "\r\n";
  return Buffer.concat([Buffer.from(head, "utf8"), bodyBuf]);
}

// Assert a call throws, and that the thrown message satisfies `check`.
function throws(fn, check, msg) {
  try {
    fn();
    ok(false, msg + " (did not throw)");
  } catch (e) {
    ok(check(e), msg + (check(e) ? "" : ` (wrong message: ${e.message})`));
  }
}

async function main() {
  // --- happy path: 200 with a JSON body parses to the object -------------------
  console.log("parseHttp happy path:");
  const okObj = parseHttp(resp(200, "OK", JSON.stringify({ ok: true })));
  ok(okObj && okObj.ok === true, "200 application/json {\"ok\":true} parses to {ok:true}");

  // --- non-200 responses throw, and the status appears in the message ----------
  console.log("\nparseHttp error statuses:");
  for (const [status, text] of [[400, "Bad Request"], [404, "Not Found"], [500, "Internal Server Error"]]) {
    const buf = resp(status, text, JSON.stringify({ err: "nope" }));
    throws(() => parseHttp(buf), (e) => e.message.includes(String(status)), `HTTP ${status} throws with status in message`);
  }

  // --- no header terminator: throws rather than mis-parsing --------------------
  console.log("\nparseHttp malformed:");
  const noTerm = Buffer.from("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11", "utf8");
  throws(() => parseHttp(noTerm), (e) => /no HTTP header terminator/i.test(e.message),
    "missing \\r\\n\\r\\n terminator throws \"no HTTP header terminator\"");
  // Truly empty buffer: also no terminator.
  throws(() => parseHttp(Buffer.alloc(0)), (e) => /no HTTP header terminator/i.test(e.message),
    "empty buffer throws \"no HTTP header terminator\"");

  // --- unicode / nested JSON round-trips exactly -------------------------------
  console.log("\nparseHttp round-trip fidelity:");
  const nested = {
    version: 2,
    note: "onion → トール ☃ café",
    gateways: [{ onion: "abc.onion", weight: 100, meta: { health: "up", tags: ["a", "b"] } }],
    nested: { deep: { deeper: { value: [1, 2, 3, { k: "v" }] } } },
  };
  const parsed = parseHttp(resp(200, "OK", JSON.stringify(nested)));
  ok(JSON.stringify(parsed) === JSON.stringify(nested), "unicode + nested-object body round-trips byte-for-byte");
  ok(parsed.note.includes("→") && parsed.nested.deep.deeper.value[3].k === "v", "unicode arrow and deep-nested value preserved");

  // --- large body reads to end -------------------------------------------------
  console.log("\nparseHttp full-body read:");
  const bigArr = Array.from({ length: 5000 }, (_, i) => ({ i, s: "x".repeat(20) }));
  const bigObj = { count: bigArr.length, items: bigArr };
  const bigParsed = parseHttp(resp(200, "OK", JSON.stringify(bigObj)));
  ok(bigParsed.count === 5000 && bigParsed.items.length === 5000 && bigParsed.items[4999].i === 4999,
    "large body (5000-element array) reads fully to end");
  // A body far larger than a tiny example still parses (last byte not truncated).
  const tail = parseHttp(resp(200, "OK", JSON.stringify({ pad: "z".repeat(100000), tail: "END" })));
  ok(tail.tail === "END" && tail.pad.length === 100000, "100KB body parses with trailing field intact");

  console.log("\nonion destination routing:");
  const socket = new EventEmitter();
  const writes = [];
  socket.write = (chunk) => {
    writes.push(Buffer.from(chunk).toString("utf8"));
    if (writes.length === 1) queueMicrotask(() => {
      socket.emit("data", resp(200, "OK", '{"ok":true}'));
      socket.emit("end");
    });
  };
  socket.destroy = () => {};
  let dial = null;
  const socksClient = { createConnection: async (options) => { dial = options; return { socket }; } };
  const onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
  const routed = await postOverTor(onion, "/fleet-tally", { nullifier: "1", epoch: "2" }, {
    destinationPort: 8879,
    attempts: 1,
    timeoutMs: 1000,
    socksClient,
  });
  ok(routed.ok === true && dial.destination.host === onion && dial.destination.port === 8879, "SOCKS dials the configured onion virtual port, not hard-coded port 80");
  ok(writes.join("").includes(`Host: ${onion}:8879\r\n`), "the HTTP Host authority carries the non-default onion port");
  ok(dial.timeout === 1000, "the SOCKS dial gets the caller's timeout, not the library's 30 s default");
  try {
    await postOverTor(onion, "/", {}, { destinationPort: 70000, attempts: 1, socksClient });
    ok(false, "invalid destination port is rejected");
  } catch (error) {
    ok(/invalid onion destination port/.test(error.message), "invalid destination port is rejected");
  }

  console.log("\nrefusals are answers, not transport failures:");
  {
    const e400 = (() => { try { parseHttp(resp(400, "Bad Request", '{"ok":false,"err":"not-staked"}')); } catch (e) { return e; } })();
    ok(e400?.status === 400 && e400?.reply?.err === "not-staked" && isRefusal(e400), "HTTP 400 carries status and the parsed reply, and is a refusal");
    const e500 = (() => { try { parseHttp(resp(500, "Internal", "boom")); } catch (e) { return e; } })();
    ok(e500?.status === 500 && e500?.reply === null && !isRefusal(e500), "HTTP 500 keeps status, no reply, not a refusal (retried)");
    ok(!isRefusal({ status: 429 }) && !isRefusal({ status: 408 }) && !isRefusal(new Error("socks timeout")), "429, 408 and plain errors stay retryable");
    let dials = 0;
    const refusing = { createConnection: async () => {
      dials++;
      const s = new EventEmitter();
      s.write = () => queueMicrotask(() => { s.emit("data", resp(400, "Bad Request", '{"ok":false,"err":"not-staked"}')); s.emit("end"); });
      s.destroy = () => {};
      return { socket: s };
    } };
    const err = await postOverTor(onion, "/announce", {}, { attempts: 4, timeoutMs: 1000, socksClient: refusing }).then(() => null, (e) => e);
    ok(dials === 1 && err?.status === 400 && err?.reply?.err === "not-staked", "a 400 is not retried: one dial, the refusal comes back with its reply");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: fetch parseHttp selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((error) => { console.error(error); process.exit(1); });
