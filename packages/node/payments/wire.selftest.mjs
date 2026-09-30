// Fast, chainless proof of the 402 wire formats (packages/node/payments/wire.mjs + packages/node/payments/eip3009.mjs +
// packages/node/payments/http-client.mjs parsing) — the parse surfaces a hostile client or registrar can feed.
//
//   1. EIP-3009 typed data == the x402 spec's: the WORKED EXAMPLE signature in
//      coinbase/x402 specs/transports-v2/http.md (0x2d6a7588…) recovers to its `from`
//      (0x857b0651…) over {USDC, 2, eip155:84532, 0x036CbD53…} — a cross-implementation golden.
//   2. x402: PaymentRequired/PaymentPayload/SettlementResponse header round-trips; parseX402Payment
//      matrix (version, scheme, network, asset, payTo, amount->tier, shapes, signature length).
//   3. MPP: JCS canonicalization, the 7-slot HMAC challenge id (absent optionals as ""), nonce ==
//      keccak256(id ‖ realm), WWW-Authenticate format/parse round-trip (quoted-string escapes,
//      several challenges in one header, non-Payment schemes dropped), credential build/parse,
//      parseMppCredential matrix (tampered request/expires/opaque/digest, expired, wrong nonce/
//      recipient/value, unsupported type, malformed encodings), receipt round-trip, problems.
//   4. http-client parseHttp: repeated headers -> array, non-200 statuses returned (402 is normal).
//   5. parsePrices / tierForAmount / chainIdOfCaip2 / base64 decoders reject garbage.
//
//   node packages/node/payments/wire.selftest.mjs

import { createHmac } from "node:crypto";
import { ethers } from "ethers";
import { tokenDomain, recoverAuthorization, checkAuthorizationShape, signAuthorization, randomNonce, TRANSFER_WITH_AUTHORIZATION_TYPEHASH, TRANSFER_WITH_AUTHORIZATION_TYPES } from "./eip3009.mjs";
import * as W from "./wire.mjs";
import { parseHttp, splitChallenges } from "./http-client.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// ---- 1. spec golden ---------------------------------------------------------------------
console.log("1. EIP-3009 typed data vs the x402 spec worked example:");
{
  const domain = tokenDomain({ name: "USDC", version: "2", chainId: 84532, asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e" });
  const auth = { from: "0x857b06519E91e3A54538791bDbb0E22373e36b66", to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", value: "10000", validAfter: "1740672089", validBefore: "1740672154", nonce: "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480" };
  const sig = "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c";
  ok(recoverAuthorization(domain, auth, sig) === auth.from, "spec example PAYMENT-SIGNATURE recovers to authorization.from (same typed data as coinbase/x402)");
  ok(recoverAuthorization(domain, { ...auth, value: "10001" }, sig) !== auth.from, "…and not after editing value");
  ok(recoverAuthorization({ ...domain, version: "1" }, auth, sig) !== auth.from, "…and not under another domain version");
  ok(recoverAuthorization(domain, auth, "0x1234") === null && recoverAuthorization(domain, auth, null) === null, "malformed signature -> null (never throws)");
  ok(ethers.TypedDataEncoder.from(TRANSFER_WITH_AUTHORIZATION_TYPES).primaryType === "TransferWithAuthorization" && ethers.keccak256(ethers.toUtf8Bytes("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")) === TRANSFER_WITH_AUTHORIZATION_TYPEHASH, "type string == EIP-3009 TRANSFER_WITH_AUTHORIZATION_TYPEHASH (USDC's)");
  // Sepolia USDC domain separator (read with cast 2026-08-17): proves tokenDomain() matches the live token.
  ok(ethers.TypedDataEncoder.hashDomain(tokenDomain({ name: "USDC", version: "2", chainId: 11155111, asset: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238" })) === "0xb90e5057db141a932946e64d09ccb7ffc9b00bd79fec26f698d29af0c83320a6", "tokenDomain(Sepolia USDC) hashes to the on-chain DOMAIN_SEPARATOR()");
  ok(checkAuthorizationShape(auth) === null && checkAuthorizationShape({ ...auth, value: "1e5" }) && checkAuthorizationShape({ ...auth, nonce: "0x12" }) && checkAuthorizationShape({ ...auth, from: "857b" }) && checkAuthorizationShape([]) && checkAuthorizationShape({ ...auth, value: "-1" }), "checkAuthorizationShape: decimal strings / bytes32 / addresses enforced");
}

// ---- 2. x402 ----------------------------------------------------------------------------
console.log("2. x402 v2 wire:");
const offer = { chainId: 11155111, asset: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", assetName: "USDC", assetVersion: "2", decimals: 6, payTo: "0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02", tiers: { 8: "100000", 32: "400000" }, maxTimeoutSeconds: 600, realm: "bootnode.onion", resourceUrl: "http://bootnode.onion:8878/pay", description: "leaf" };
{
  const pr = W.x402PaymentRequired(offer, [8, 32]);
  const back = W.decodeX402Header(W.encodeX402Header(pr));
  ok(JSON.stringify(back) === JSON.stringify(pr) && back.x402Version === 2 && back.accepts.length === 2, "PaymentRequired base64 round-trip");
  ok(back.accepts[1].scheme === "exact" && back.accepts[1].network === "eip155:11155111" && back.accepts[1].amount === "400000" && back.accepts[1].extra.name === "USDC" && back.accepts[1].extra.version === "2" && back.accepts[1].extra.assetTransferMethod === "eip3009" && back.accepts[1].maxTimeoutSeconds === 600, "requirements: exact / CAIP-2 / amount / extra{name,version,assetTransferMethod}");
  const buyer = ethers.Wallet.createRandom();
  const domain = tokenDomain({ name: "USDC", version: "2", chainId: 11155111, asset: offer.asset });
  const auth = { from: buyer.address, to: offer.payTo, value: "100000", validAfter: "0", validBefore: "9999999999", nonce: randomNonce() };
  const sig = await signAuthorization(buyer, domain, auth);
  const hdr = W.encodeX402Header(W.x402PaymentPayload(pr, pr.accepts[0], auth, sig));
  const p = W.parseX402Payment(hdr, offer);
  ok(p.ok && p.limit === 8 && p.authorization.nonce === auth.nonce && p.signature === sig, "parseX402Payment accepts a well-formed payload -> tier 8");
  const mut = (f) => { const o = W.decodeX402Header(hdr); f(o); return W.parseX402Payment(W.encodeX402Header(o), offer).reason; };
  ok(mut((o) => { o.x402Version = 1; }) === "invalid_x402_version", "v1 -> invalid_x402_version");
  ok(mut((o) => { o.accepted.scheme = "upto"; }) === "invalid_scheme", "scheme upto -> invalid_scheme");
  ok(mut((o) => { o.accepted.network = "eip155:1"; }) === "invalid_network", "other chain -> invalid_network");
  ok(mut((o) => { o.accepted.asset = offer.payTo; }) === "invalid_exact_evm_payload_asset", "other asset -> rejected");
  ok(mut((o) => { o.accepted.payTo = buyer.address; }) === "invalid_exact_evm_payload_recipient_mismatch", "other payTo -> recipient_mismatch");
  ok(mut((o) => { o.accepted.amount = "123"; o.payload.authorization.value = "123"; }) === "invalid_exact_evm_payload_authorization_value_mismatch", "amount not a tier price -> value_mismatch");
  ok(mut((o) => { o.payload.authorization.value = "400000"; }) === "invalid_exact_evm_payload_authorization_value_mismatch", "authorization.value != accepted.amount -> value_mismatch");
  ok(mut((o) => { o.payload.authorization.to = buyer.address; }) === "invalid_exact_evm_payload_recipient_mismatch", "authorization.to != payTo -> recipient_mismatch");
  ok(mut((o) => { o.payload.signature = "0xabc"; }) === "invalid_exact_evm_payload_signature", "short signature -> invalid signature");
  ok(mut((o) => { delete o.payload.authorization.nonce; }) === "invalid_exact_evm_payload_authorization", "missing nonce -> invalid authorization");
  ok(mut((o) => { o.payload = "x"; }) === "invalid_payment_payload" && W.parseX402Payment("!!", offer).reason === "invalid_payment_payload" && W.parseX402Payment(W.encodeX402Header([1]), offer).reason === "invalid_payment_payload", "non-object payload / non-base64 / JSON array -> invalid_payment_payload");
  ok(W.parseX402Payment("A".repeat(20000), offer).reason === "invalid_payment_payload", "oversize header value -> rejected without decoding");
  const st = W.decodeX402Header(W.encodeX402Header(W.x402Settlement({ success: false, errorReason: "insufficient_funds", network: "eip155:11155111", payer: buyer.address })));
  ok(st.success === false && st.errorReason === "insufficient_funds" && st.transaction === "" && st.payer === buyer.address, "SettlementResponse failure shape (transaction \"\")");
}

// ---- 3. MPP -----------------------------------------------------------------------------
console.log("3. MPP wire:");
{
  ok(W.jcs({ b: 1, a: [true, null, "x", { z: "1", y: 2 }] }) === '{"a":[true,null,"x",{"y":2,"z":"1"}],"b":1}', "JCS: sorted keys, compact, arrays in order");
  let threw = false; try { W.jcs({ a: 1.5 }); } catch { threw = true; } ok(threw, "JCS refuses non-integer numbers (never emitted here)");
  const secret = "s3cret";
  const base = { realm: "r", method: "evm", intent: "charge", request: "eyJh", expires: "2026-01-01T00:00:00Z" };
  const id1 = W.mppChallengeId(secret, base);
  ok(id1 === createHmac("sha256", secret).update("r|evm|charge|eyJh|2026-01-01T00:00:00Z||", "utf8").digest("base64url"), "challenge id = base64url(HMAC-SHA256(secret, 7 pipe-joined slots; absent digest/opaque = \"\"))");
  ok(W.mppChallengeId(secret, { ...base, digest: "d" }) !== id1 && W.mppChallengeId(secret, { ...base, opaque: "o" }) !== id1 && W.mppChallengeId(secret, { ...base, expires: "" }) !== id1 && W.mppChallengeId("other", base) !== id1, "any slot or the secret changes the id");
  ok(W.mppNonce("aB3c", "api.example.com") === ethers.keccak256(ethers.toUtf8Bytes("aB3capi.example.com")), "nonce = keccak256(abi.encodePacked(id, realm)) == keccak of the concatenated UTF-8");
  const { params, header } = W.mppChallenge(offer, 32, secret, { nowMs: Date.parse("2026-08-17T00:00:00Z") });
  ok(header.startsWith("Payment id=\"") && /method="evm"/.test(header) && /intent="charge"/.test(header) && /expires="2026-08-17T00:10:00Z"/.test(header) && /realm="bootnode\.onion"/.test(header) && !/digest=/.test(header), `challenge header: ${header.slice(0, 60)}…`);
  const parsed = W.parseWwwAuthenticate(header);
  ok(parsed.length === 1 && parsed[0].scheme === "Payment" && parsed[0].params.id === params.id && parsed[0].params.request === params.request && parsed[0].params.opaque === params.opaque && parsed[0].params.description === params.description, "format -> parse round-trip (all params)");
  const req = W.jsonParseSafe(W.b64decode(params.request, { url: true }));
  ok(req.amount === "400000" && req.currency === offer.asset && req.recipient === offer.payTo && req.externalId === "limit=32" && req.methodDetails.chainId === 11155111 && req.methodDetails.credentialTypes[0] === "authorization" && req.methodDetails.eip712Domain.name === "USDC" && W.b64url(W.jcs(req)) === params.request, "request: JCS-canonical base64url {amount,currency,recipient,externalId,methodDetails{chainId,credentialTypes,eip712Domain}}");
  ok(W.mppChallengeId(secret, params) === params.id, "issued id verifies over the issued params");
  // parse edge cases
  const multi = W.parseWwwAuthenticate(`Basic realm="x", Payment id="a", realm="r1", method="evm", intent="charge", request="AA", Payment id="b", realm="r,2", method="evm", intent="charge", request="BB", description="say \\"hi\\" \\\\ ok"`);
  ok(multi.length === 2 && multi[0].params.id === "a" && multi[1].params.id === "b" && multi[1].params.realm === "r,2" && multi[1].params.description === 'say "hi" \\ ok', "parses several Payment challenges per header, drops non-Payment schemes, unescapes quoted-strings");
  ok(W.parseWwwAuthenticate("Payment id=bare, realm=r").length === 1 && W.parseWwwAuthenticate("Payment id=bare, realm=r")[0].params.id === "bare", "bare-token param values accepted");
  ok(W.parseWwwAuthenticate(null).length === 0 && W.parseWwwAuthenticate("").length === 0 && W.parseWwwAuthenticate("Payment").length === 1 && W.parseWwwAuthenticate("A".repeat(70000)).length === 0, "garbage / oversize / empty -> [] (never throws)");
  ok(splitChallenges('Payment id="a", realm="r", Payment id="b", realm="s"').length === 2 && splitChallenges("x").length === 1, "http-client splitChallenges re-splits a joined header on the scheme boundary");
  ok(W.formatWwwAuthenticate({ id: 'a"b', realm: "r\\", method: "evm", intent: "charge", request: "AA" }) === 'Payment id="a\\"b", realm="r\\\\", method="evm", intent="charge", request="AA"', "formatter escapes quotes/backslashes");

  // credential build/parse
  const buyer = ethers.Wallet.createRandom();
  const domain = tokenDomain({ name: "USDC", version: "2", chainId: 11155111, asset: offer.asset });
  const now = Date.parse("2026-08-17T00:05:00Z");
  const auth = { from: buyer.address, to: offer.payTo, value: "400000", validAfter: "0", validBefore: String(Date.parse(params.expires) / 1000), nonce: W.mppNonce(params.id, params.realm) };
  const sig = await signAuthorization(buyer, domain, auth);
  const cred = W.mppCredential(params, { type: "authorization", ...auth, signature: sig }, { source: `did:pkh:eip155:11155111:${buyer.address}` });
  ok(/^[A-Za-z0-9_-]+$/.test(cred), "credential is base64url without padding");
  const good = W.parseMppCredential(`Payment ${cred}`, secret, offer, { nowMs: now });
  ok(good.ok && good.limit === 32 && good.authorization.nonce === auth.nonce && good.signature === sig && good.source.endsWith(buyer.address), "parseMppCredential accepts the credential -> tier 32");
  const cj = JSON.parse(W.b64decode(cred, { url: true }));
  const withCred = (f, opts = {}) => { const o = JSON.parse(JSON.stringify(cj)); f(o); return W.parseMppCredential(`Payment ${W.b64url(JSON.stringify(o))}`, secret, offer, { nowMs: now, ...opts }); };
  const tamperedReq = W.b64url(W.jcs({ ...req, amount: "1" }));
  ok(withCred((o) => { o.challenge.request = tamperedReq; }).reason === "invalid-challenge", "edited request -> HMAC id no longer verifies -> invalid-challenge");
  ok(withCred((o) => { o.challenge.expires = "2030-01-01T00:00:00Z"; }).reason === "invalid-challenge", "edited expires -> invalid-challenge");
  ok(withCred((o) => { o.challenge.opaque = W.b64url('{"limit":"8"}'); }).reason === "invalid-challenge", "edited opaque -> invalid-challenge");
  ok(withCred((o) => { o.challenge.realm = "other"; }).reason === "invalid-challenge", "other realm -> invalid-challenge");
  ok(withCred((o) => { o.challenge.method = "tempo"; }).reason === "method-unsupported", "other method -> method-unsupported");
  ok(withCred((o) => { o.challenge.id = "x"; }).reason === "invalid-challenge", "wrong id -> invalid-challenge");
  ok(withCred(() => {}, { nowMs: Date.parse(params.expires) + 1 }).reason === "payment-expired", "after expires -> payment-expired");
  ok(withCred((o) => { o.payload.nonce = randomNonce(); }).reason === "verification-failed", "nonce != keccak(id‖realm) -> verification-failed");
  ok(withCred((o) => { o.payload.to = buyer.address; }).reason === "verification-failed", "to != recipient -> verification-failed");
  ok(withCred((o) => { o.payload.value = "100000"; }).reason === "verification-failed", "value != amount -> verification-failed");
  ok(withCred((o) => { o.payload.type = "permit2"; }).reason === "verification-failed", "type=permit2 -> verification-failed (authorization only)");
  ok(withCred((o) => { o.payload.signature = "0x00"; }).reason === "malformed-credential" && withCred((o) => { delete o.payload; }).reason === "malformed-credential" && withCred((o) => { delete o.challenge.request; }).reason === "malformed-credential", "short signature / no payload / no request -> malformed-credential");
  ok(W.parseMppCredential("Payment ***", secret, offer).reason === "malformed-credential" && W.parseMppCredential("Bearer abc", secret, offer).reason === "malformed-credential" && W.parseMppCredential(`Payment ${W.b64url("[1]")}`, secret, offer).reason === "malformed-credential" && W.parseMppCredential(undefined, secret, offer).reason === "malformed-credential", "non-base64url / other scheme / JSON array / missing -> malformed-credential");
  // digest binding
  const dg = W.mppChallenge(offer, 8, secret, { digest: "sha-256=:abc=:", nowMs: now });
  const credD = W.mppCredential(dg.params, { type: "authorization", ...auth, value: "100000", nonce: W.mppNonce(dg.params.id, dg.params.realm), signature: sig });
  ok(W.parseMppCredential(`Payment ${credD}`, secret, offer, { nowMs: now, bodyDigest: "sha-256=:abc=:" }).ok && W.parseMppCredential(`Payment ${credD}`, secret, offer, { nowMs: now, bodyDigest: "sha-256=:zzz=:" }).reason === "invalid-challenge" && W.parseMppCredential(`Payment ${credD}`, secret, offer, { nowMs: now }).reason === "invalid-challenge", "digest-bound challenge: body digest must match (missing or different -> invalid-challenge)");
  ok(W.contentDigest(Buffer.from("hello")) === "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:", "RFC 9530 Content-Digest sha-256 format");
  // offer drift retires challenges
  ok(W.parseMppCredential(`Payment ${cred}`, secret, { ...offer, tiers: { 8: "100000", 32: "500000" } }, { nowMs: now }).reason === "invalid-challenge", "a price change retires outstanding challenges (invalid-challenge)");
  const rc = W.mppReceipt({ challengeId: params.id, txHash: "0x" + "ab".repeat(32), chainId: 11155111, nowMs: now });
  const rcBack = W.decodeMppReceipt(rc.header);
  ok(rcBack.status === "success" && rcBack.method === "evm" && rcBack.challengeId === params.id && rcBack.reference === "0x" + "ab".repeat(32) && rcBack.chainId === 11155111 && rcBack.timestamp === "2026-08-17T00:05:00Z", "Payment-Receipt round-trip {status,method,challengeId,reference,timestamp,chainId}");
  const pb = W.mppProblem("verification-failed", "x");
  ok(pb.type === "https://paymentauth.org/problems/verification-failed" && pb.status === 402 && pb.title === "Verification Failed", "RFC 9457 problem shape");
}

// ---- 4. http-client parseHttp ------------------------------------------------------------
console.log("4. http-client parseHttp:");
{
  const raw = Buffer.from('HTTP/1.1 402 Payment Required\r\nContent-Type: application/json\r\nWWW-Authenticate: Payment id="a"\r\nWWW-Authenticate: Payment id="b"\r\nPAYMENT-REQUIRED: eyJ4Ijox\r\n\r\n{"ok":false}');
  const r = parseHttp(raw);
  ok(r.status === 402 && Array.isArray(r.headers["www-authenticate"]) && r.headers["www-authenticate"].length === 2 && r.headers["payment-required"] === "eyJ4Ijox" && r.json.ok === false, "402 returned (not thrown), repeated headers -> array, single -> string, body parsed");
  let threw = false; try { parseHttp(Buffer.from("garbage")); } catch { threw = true; } ok(threw, "no header terminator -> throws (caller retries)");
}

// ---- 5. helpers ---------------------------------------------------------------------------
console.log("5. helpers:");
{
  ok(JSON.stringify(W.parsePrices("8=100000, 32=400000")) === '{"8":"100000","32":"400000"}', "parsePrices");
  for (const bad of ["", "8=", "=1", "8=0", "8=100000,8=2", "70000=1", "8=1e5", "abc"]) { let t = false; try { W.parsePrices(bad); } catch { t = true; } ok(t, `parsePrices rejects ${JSON.stringify(bad)}`); }
  ok(W.tierForAmount(offer, "400000") === 32 && W.tierForAmount(offer, "400001") === null && W.priceOf(offer, "8") === "100000" && W.priceOf(offer, 9) === null, "tierForAmount / priceOf");
  ok(W.chainIdOfCaip2("eip155:11155111") === 11155111 && W.chainIdOfCaip2("eip155:0x1") === null && W.chainIdOfCaip2("solana:x") === null && W.chainIdOfCaip2(5) === null, "chainIdOfCaip2");
  ok(W.b64decode("aGk=") === "hi" && W.b64decode("aGk", { url: true }) === "hi" && W.b64decode("a Gk=") === null && W.b64decode("aGk=", { url: true }) === null && W.b64decode("", { url: true }) === null, "base64 / base64url decoders are strict");
  ok(W.rfc3339(0) === "1970-01-01T00:00:00Z", "rfc3339 second precision");
}

console.log(failures ? `\n${failures} FAILED` : "\nall green");
process.exit(failures ? 1 : 0);
