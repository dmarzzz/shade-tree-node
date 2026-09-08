# Shade Tree wire formats and HTTP APIs

Wire-format and HTTP-API contract for the bootnode and its record types. This is the
reimplementation target for the Rust conformance client (T-RUST-1). Every claim cites a
`file:symbol`. Where source and this doc disagree, the source wins; report the drift.

Golden fixtures: [`testdata/vectors.json`](../testdata/vectors.json). See [Conformance](#9-conformance).

## 0. Version tags (do not conflate)

| Tag | Value | Meaning | Source |
| --- | --- | --- | --- |
| `ANNOUNCE_VERSION` | `1` | announce record `v` field | `bootnode/announce.mjs:34` |
| directory `version` | `1` | signed-directory `version` field | `bootnode/server.mjs:127` |
| envelope `v` | `4` | egress-envelope `v` field | `client/shade-tree-client.mjs` `buildEnvelope` |
| signal prefix | `shade-tree:v4` | tunnel-signal line 1 | `lib/rln.mjs` `requestSignal` |
| onion | v3 | Tor onion address version byte `0x03` | `lib/directory.mjs:104` |

Shade Tree protocol v4, Tor onion-service v3, and the announce/directory schema version `1`
are independent tags. Keep them distinct.

## 1. Canonical byte encodings

Both canonical encoders build a fresh object with a FIXED key order, then
`Buffer.from(JSON.stringify(obj), "utf8")`. JSON key order therefore follows object insertion
order exactly as written below. Whitespace: none (default `JSON.stringify`). Numbers are plain
JSON numbers. Unsigned / label fields are EXCLUDED from the signed bytes.

ed25519 (RFC 8032, `crypto.sign(null, msg, key)`) is deterministic, so a signature over these
bytes is byte-reproducible across implementations (`lib/directory.mjs:46` `ed25519Sign`).

### 1.1 `canonicalAnnounceBytes`: `bootnode/announce.mjs:38`

```
payload = { v, onion, weight, ts, nonce }      // exactly this order
bytes   = utf8( JSON.stringify(payload) )
```

Excluded from the signed bytes: `onionSig`, `operator`, `operatorSig`.

### 1.2 `canonicalDirectoryBytes`: `lib/directory.mjs:129`

```
payload = {
  version,
  issued,
  gateways: [ { onion, pubkey, weight, health }, ... ]   // per-entry order fixed
}
bytes = utf8( JSON.stringify(payload) )
```

Excluded from the signed bytes: top-level `signer`, `signature`; per-gateway `operator`,
`staked`, and any other field. Only the four listed gateway fields are covered, in that order.

## 2. v3 onion <-> ed25519 identity key

A v3 `.onion` address IS its ed25519 public key. `lib/directory.mjs:96` `onionToPubkey` /
`:114` `pubkeyToOnion`.

```
addr56  = base32_nopad_lower( pubkey[32] || checksum[2] || version[1] )
version = 0x03
checksum = SHA3-256( b".onion checksum" || pubkey || 0x03 )[:2]
```

- base32 alphabet: `abcdefghijklmnopqrstuvwxyz234567`, lowercase, NO padding
  (`lib/directory.mjs:63` `B32`).
- The address string is the 56 base32 chars WITHOUT the `.onion` suffix; decoded it is 35
  bytes (`32 + 2 + 1`).
- Recovery checks: 56 chars, decodes to 35 bytes, `version == 0x03`, checksum matches.
- `pubkey` is reported as lowercase hex.

`onionToPubkey` throw messages (they appear verbatim inside reason codes below):

| Condition | message |
| --- | --- |
| bad base32 char | `bad base32 char in onion` |
| length != 56 | `not a v3 onion (expected 56 chars)` |
| decode length != 35 | `v3 onion decodes to 35 bytes` |
| version byte != 0x03 | `not onion version 3` |
| checksum mismatch | `onion checksum mismatch` |

## 3. Announce record

Built by `bootnode/announce.mjs:51` `buildAnnounce`; verified by `:80` `verifyAnnounce`.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `v` | number | yes | `== ANNOUNCE_VERSION` (`1`) |
| `onion` | string | yes | v3 `.onion` (with suffix) |
| `weight` | number | yes | default `100`; selection weight (clamped by bootnode, section 5) |
| `ts` | number | yes | unix seconds; freshness-checked |
| `nonce` | string | yes | 16 random bytes hex (32 hex chars) via `cryptoNonce` (`:67`); replay key |
| `onionSig` | hex string | yes | ed25519 over `canonicalAnnounceBytes(rec)`, signed by the onion identity key (`:59`) |
| `operator` | string | no | Ethereum address, lowercased (`:62`) |
| `operatorSig` | hex string | no | EIP-191 `personal_sign` over `operatorAuthMessage` (`:63`) |
| `caps` | object | no | T-FEAT-10 signed capabilities, `canonicalCaps` form (`lib/directory.mjs`): fixed field order `ports, region, proto, artifacts, admits, pay`, each present only when valid; covered by `onionSig` (appended after `nonce` in `canonicalAnnounceBytes`) |
| `capsSig` | hex string | with `caps` | durable onion-key signature over `canonicalCapsBytes(onion, caps)` (`CAPS_DOMAIN` + `{onion,caps}`); copied verbatim onto the directory entry |

#### 3.0.1 `caps` fields (all bucketed, TOTAL canonicalization: junk dropped, never thrown)

| Field | Canonical form | Bound | Task |
| --- | --- | --- | --- |
| `ports` | deduped, ascending integers in 1..65535 | none | T-FEAT-10 |
| `region` | one of `na sa eu af as oc aq unknown` | none | T-FEAT-10 |
| `proto` | `{min,max}`, `min>=1`, `max>=min` | none | T-FEAT-11 |
| `artifacts` | deduped, sorted ids `^[a-z0-9][a-z0-9._-]{0,63}$` | ≤ 8 (`MAX_CAPS_ARTIFACTS`) | T-HARD-8 |
| `admits` | subset of `invited, staked, paid` in THAT order (the anonymity order, `ADMIT_PATHS`), deduped, lowercased | ≤ 3 by construction | T-FEAT-9 |
| `pay` | `{ protocols: subset of [x402, mpp] in that order (non-empty), onion?: lowercased v3 onion (only when the registrar rides ANOTHER onion than the gateway's), port: 1..65535, asset: lowercased 0x-hex-40, chain: "eip155:<1..16 digits>", tiers: { "<limit 1..65535, canonical integer key>": "<atomic price, 1..40 decimal digits>" } sorted by numeric limit }`; a `pay` missing any of protocols/port/asset/chain/tiers is dropped WHOLE | 1..8 tiers (`MAX_CAPS_PAY_TIERS`) | T-FEAT-9 |

`admits` is the gateway's ADMISSION POLICY (`SHADE_TREE_ADMIT`, `docs/adr/0008`): which membership
roots it trusts. Absent = a legacy gateway (a client assumes it may admit any path during the
rollout). `pay` is present iff the provider SELLS access (`SHADE_TREE_REGISTRAR_ADVERTISE=1` on its
heartbeat); its shape is the bootnode `/health` `pay` object plus `onion`. Both are unforgeable
by the bootnode: they ride under `onionSig` and `capsSig`, so a widened/narrowed policy fails
`bad-caps-sig` at `verifyAnnounce` / `verifyDirectory`. Pinned: `testdata/vectors.json`
`admission.capsWithAdmission` (§9).

### 3.1 Onion-control signature (proof 1, always required)

`onionSig = ed25519Sign( canonicalAnnounceBytes(rec), onionSeedHex )` where `onionSeedHex` is
the 32-byte ed25519 seed behind the onion. Verified with `verifyOnionControl(onion, bytes,
sig)` (`lib/directory.mjs:179`), which re-derives the key from the address. Never trusts the
bootnode.

### 3.2 Operator authorization (proof 2, optional; enforced when `admission=stake`)

Durable (no timestamp): one signature authorizes the onion for as long as the operator stays
staked. Message string, `bootnode/announce.mjs:45` `operatorAuthMessage`:

```
Shade Tree gateway operator authorization\nonion=<onion>\noperator=<operator-lowercased>
```

`\n` are literal newline bytes (`0x0a`). `<operator>` is `String(operator).toLowerCase()`.
Verified by recovering the EIP-191 signer with `ethers.verifyMessage` and requiring
`recovered.toLowerCase() === operator.toLowerCase()` (`:131` `verifyOperatorSig`). Stake is
then confirmed via `GatewayRegistry.isStaked(operator)` (`lib/gateway-registry.mjs`).

### 3.3 Freshness + nonce replay

- Freshness (`:94`): reject unless `typeof ts === "number"` and `|now - ts| <= skew`.
  `skew = DEFAULT_ANNOUNCE_SKEW = 120` seconds (`:35`).
- Nonce replay (`:97`,`:124`): the replay key is the string `` `${onion}:${nonce}` ``. If a
  `seenNonce` guard is supplied and already `has` the key, reject; otherwise `add` it only on
  full success. The bootnode's guard is a bounded `Map` swept on the TTL
  (`bootnode/server.mjs:59` `makeNonceGuard`).

### 3.4 `verifyAnnounce` reason codes: `bootnode/announce.mjs:80`

Checks run in this order; the FIRST failure is returned. `<...>` are interpolations.

| # | Reason | Condition |
| --- | --- | --- |
| 1 | `no-announce` | `rec` not an object |
| 2 | `bad-version:<rec.v>` | `rec.v !== 1` |
| 3 | `no-onion` | `typeof rec.onion !== "string"` |
| 4 | `bad-onion:<msg>` | `onionToPubkey` threw (`<msg>` from section 2 table) |
| 5 | `stale-ts:<rec.ts>` | `ts` not a number, or `|now - ts| > skew` |
| 6 | `replayed-nonce` | `seenNonce.has("<onion>:<nonce>")` |
| 7 | `bad-onion-sig` | `onionSig` missing OR `verifyOnionControl` false |
| 8 | `bad-operator-sig` | `operator`+`operatorSig` present but recovery != operator |
| 9 | `stake-check-failed:<msg>` | `isStaked` threw AND `requireStake` |
| 10 | `not-staked` | `requireStake && !staked` |
| none | success | `{ ok:true, onion, pubkey, operator, staked }` |

Notes: proof 2 (rows 8-10) is only entered when `rec.operator && rec.operatorSig` are both
present. If `isStaked` is omitted, stake is not checked and `staked` stays `false` (a valid
`operatorSig` still populates `operator`). `requireStake` is set by the bootnode when
`admission === "stake"`.

## 4. Signed directory

Built by `bootnode/server.mjs:118` `directory()` -> `signDirectory` (`lib/directory.mjs:143`);
verified by `:152` `verifyDirectory`.

### 4.1 Shape

```jsonc
{
  "version": 1,
  "issued": <unix-seconds>,
  "gateways": [
    {
      "onion":  "<v3 .onion>",
      "pubkey": "<hex ed25519, == onionToPubkey(onion)>",
      "weight": <number>,
      "health": "up",
      "operator": "<addr>",   // present only when the entry had an operator
      "staked":   <bool>,     // present only when the entry had an operator
      "caps":     { "ports": [...], "region": "eu", "proto": {...}, "artifacts": [...], "admits": ["invited","staked","paid"], "pay": {...} },  // T-FEAT-10/9: the gateway's SIGNED caps, passed through verbatim (present only when it advertised any)
      "capsSig":  "<hex ed25519 over canonicalCapsBytes(onion, caps), by the gateway's onion key>"  // required whenever `caps` is present
    }
  ],
  "signer":    "<hex ed25519 pubkey of the pinned signer>",
  "signature": "<hex ed25519 over canonicalDirectoryBytes(dir)>"
}
```

`operator`/`staked` are labels only; they are NOT covered by the signature (section 1.2).
`caps`/`capsSig` ARE covered (appended after the four legacy fields, `canonicalDirectoryBytes`),
and `capsSig` is re-verified per entry against the entry's OWN onion key (`bad-caps-sig:<onion>`),
so neither the bootnode nor the directory signer can alter a gateway's advertised policy/offer.
The bootnode stores the verified caps + capsSig from the announce and emits them unchanged
(`bootnode/server.mjs directory()`); an entry announced with caps but no standalone `capsSig`
is listed cap-free. The delta protocol (`/directory/delta`) re-ships an entry whose body changed
in place (e.g. its `admits`) in `added`.
`health` is `"up"` for every live entry the bootnode emits (`bootnode/server.mjs:123`);
clients still probe and fail over (`lib/directory.mjs:264` `reportHealth`).

### 4.2 Pinned-signer model

The client pins ONE signer pubkey (`SHADE_TREE_DIR_SIGNER`, printed at bootnode startup,
`bootnode/server.mjs:197`). `verifyDirectory(dir, pinnedSignerHex)`:

1. `dir.signature` must exist.
2. If `dir.signer` is present, it must equal `pinnedSignerHex` (case-insensitive).
3. The signature must verify against `pinnedSignerHex` over `canonicalDirectoryBytes(dir)`.
4. For every gateway, `onionToPubkey(onion)` must equal `pubkey` (case-insensitive).

The pinned signer is a discovery authority. Its signature authenticates the list,
not live onion control. A compromised signer can omit, reorder, or add an internally
consistent onion/pubkey entry, including an onion it controls. Re-deriving `pubkey`
prevents an existing onion from being paired with a different key. When capabilities
are present, `capsSig` makes them independently verifiable. `verifyDirectory` does not
verify the stored announce or prove liveness.

### 4.3 `verifyDirectory` reason codes: `lib/directory.mjs:152`

| # | Reason | Condition |
| --- | --- | --- |
| 1 | `no-directory` | `dir` not an object |
| 2 | `unsigned` | no `dir.signature` |
| 3 | `signer-not-pinned` | `dir.signer` present and != pinned (case-insensitive) |
| 4 | `bad-signature` | ed25519 verify over canonical bytes fails |
| 5 | `bad-onion:<onion[:12]>..:<msg>` | `onionToPubkey(g.onion)` threw |
| 6 | `pubkey-onion-mismatch:<onion[:12]>..` | derived key != `g.pubkey` |
| none | success | `{ ok:true }` |

`<onion[:12]>` is the first 12 chars of the onion string.

### 4.4 Threshold (M-of-N) directory: T-FEAT-9, `lib/directory.mjs`

The single-signer directory trusts ONE bootnode key for fleet selection. Compromise it and
a client's view can be steered with omitted, reordered, or added entries. A directory MAY
instead be signed by an M-of-N set of independent signers (composes with T-FEAT-1 federation:
each federated bootnode is one signer), so one compromised key cannot produce an accepted
directory when the threshold is greater than one.

The extension is **additive**. Three OPTIONAL top-level fields carry it, and they are
**excluded from `canonicalDirectoryBytes` exactly like `signer`/`signature`** (section 1.2),
so every signer signs the *same* canonical bytes as the single-sig directory over the same
`{version,issued,gateways}`, and the byte encoding is unchanged:

```jsonc
{
  "version": 1, "issued": <unix>, "gateways": [ /* … */ ],
  "signers":    ["<hex ed25519 pubkey>", …],   // index-aligned with signatures
  "signatures": ["<hex ed25519 over canonicalDirectoryBytes(dir)>", …],
  "threshold":  <M>                            // distinct valid pinned sigs required
}
```

A directory carrying NONE of `signers`/`signatures`/`threshold` takes the unchanged
single-`signer` path (`verifyDirectory`, section 4.2). The classic single-signer directory is
the 1-of-1 case and verifies byte-for-byte as before. Produced by
`signDirectoryThreshold(dir, [seedHex…], M)`; verified by `verifyDirectoryThreshold` (which
`verifyDirectory` delegates to when any threshold field is present).

**Verify rule.** Accept iff at least `threshold` **distinct** signers from the client's PINNED
allowlist (`normalizePinnedSigners`, the T-HARD-5 set) each produced a valid signature over
`canonicalDirectoryBytes(dir)`. A signer counted **once** (one key cannot self-satisfy M-of-N
by signing twice); an unpinned signer is **ignored**; a malformed entry is **skipped**. The
per-gateway onion↔pubkey binding (section 4.3, reasons 5–6) is then checked identically.

| # | Reason | Condition |
| --- | --- | --- |
| 1 | `no-directory` | `dir` not an object |
| 2 | `bad-threshold` | `threshold` not an integer ≥ 1 |
| 3 | `bad-signatures` | `signers`/`signatures` not equal-length arrays |
| 4 | `threshold-exceeds-signers` | `threshold` > number of provided signers (unsatisfiable) |
| 5 | `threshold-not-met:<got>/<want>` | fewer than `threshold` distinct valid pinned sigs |
| 6 | `bad-onion:…` / `pubkey-onion-mismatch:…` | as section 4.3 |
| none | success | `{ ok:true, signers:[matched…], threshold }` |

Golden vector: `testdata/vectors.json` `thresholdDirectory` (2-of-3, fixed seeds; its canonical
bytes equal `canonicalDirectoryBytesHex`). Rust parity: `rust/shade-tree-proto`
`verify_directory_threshold(dir, pinned_signers)` consumes this shape (T-FEAT-9b);
`verify_directory` remains the single-signer path.

## 5. Bootnode HTTP API

Server: `bootnode/server.mjs:151` `makeServer`. All responses
`content-type: application/json`. Listens on loopback (`127.0.0.1:SHADE_TREE_BOOTNODE_PORT`, default
`8877`) behind its own onion service.

Public copy may call the bootnode the **Elder Tree** and its signed directory the
**Canopy**. Those are presentation names only. The normative route remains
`GET /directory`, and the signed shape remains the directory schema in section 4.
`GET /health` carries the informational header `x-shade-tree-role: elder-tree`.
`GET /directory` and `GET /directory/delta` carry that header plus
`x-shade-tree-view: canopy`. Clients must not treat these unsigned headers as evidence.

### 5.1 Routes

| Method | Path | Success | Source |
| --- | --- | --- | --- |
| GET | `/health` | `200 { ok:true, count, admission, signer[, pay] }` | `:155` |
| GET | `/directory` | `200 <signed directory>` (section 4.1) | `:158` |
| GET | `/gateway/<onion>` | `200 <stored announce rec>` (section 3) | `:162` |
| POST | `/announce` | `200 { ok:true, onion, staked, ttl }` | `:167` |
| POST | `/telemetry/relay` | `200 { ok:true }` for a private signed report bound to a live announcement | `makeServer` |
| GET | `/telemetry/aggregate` | `200 <signed delayed cohort aggregate>`; raw reports are never returned | `makeServer` |

- `/health`: `count` = live entry count; `admission` = `"open"|"stake"`; `signer` = pinned
  signer pubkey hex; `pay` (T-FEAT-7, ONLY when `SHADE_TREE_REGISTRAR_ADVERTISE` is set) =
  `{ port, protocols:["x402","mpp"], asset, chain:"eip155:<id>", tiers:{"<limit>":"<amount>"} }`,
  the discovery pointer to the operator's 402 registrar on this same onion (section 5.4).
- `/gateway/<onion>`: `<onion>` is `decodeURIComponent`-ed; the registry appends `.onion` if
  absent (`:131` `record`). Returns the exact stored announce for zero-trust re-verification.
- `/announce`: request body is the announce record JSON (section 3). `ttl` in the reply is
  `registry.ttlSec` (default `900`).
- `/telemetry/relay` is separate from `/announce`: exact-key
  `shade-tree-relay-report-v1`, onion-key signature, boot/sequence/interval/counter reset metadata,
  and no destination/member/nullifier/flow fields. The Elder requires a currently live announcement
  and rejects replay, overlap, rollback, wraparound, future/stale time, and implausible deltas.
- `/telemetry/aggregate` is the only relay telemetry read. Its signed 6h/24h windows end on a fixed
  hour boundary at least six hours behind collection time, use fixed 1-GiB rounding, and omit
  `roundedBytes` below five reporters or when unavailable. See `docs/RELAY-TELEMETRY.md`.

The API has no pulse route and publishes no client-query sequence. Local Proxy progress
events and the public Grove animation are interface behavior, not additional wire state.

### 5.2 Error responses

| Status | Body | When | Source |
| --- | --- | --- | --- |
| 400 | `{ ok:false, err:"bad-json:<msg>" }` | `/announce` body not JSON, or body too large | `:169` |
| 400 | `{ ok:false, err:"<reason>" }` | `/announce` verify failed; `<reason>` = a section-3.4 code or a section-5.3 cap reason | `:171` |
| 429 | `{ ok:false, err:"global-rate-limited" }` + `Retry-After: <s>` | `/announce` refused by the GLOBAL announce bucket before verify (T-HARD-4); retry at the next heartbeat | `makeServer` |
| 408 / 431 | (Node http built-in) | request headers/body slower than `HTTP_LIMITS` / headers over `maxHeaderSize` (T-HARD-4) | `HTTP_LIMITS` |
| 404 | `{ ok:false, err:"not-found" }` | `/gateway/<onion>` unknown | `:165` |
| 404 | `{ ok:false, err:"no-route" }` | no route matched | `:173` |
| 500 | `{ ok:false, err:"bootnode-error:<msg>" }` | unhandled exception | `:175` |

### 5.3 Admission modes + DoS caps

Registry: `bootnode/server.mjs:76` `makeRegistry`.

| Control | Default | Env | Effect |
| --- | --- | --- | --- |
| `admission` | `open` | `SHADE_TREE_BOOTNODE_ADMISSION` | `open` = onion-sig only; `stake` sets `requireStake` (operator sig + live stake enforced) |
| `ttlSec` | `900` | `SHADE_TREE_BOOTNODE_TTL` | seconds an entry stays live without re-announce |
| `maxEntries` | `10000` | `SHADE_TREE_BOOTNODE_MAX_ENTRIES` | a NEW onion is refused `registry-full` when full (after a sweep); existing onions still refresh |
| `minReannounceSec` | `5` | `SHADE_TREE_BOOTNODE_MIN_REANNOUNCE` | a resident onion re-announcing sooner is refused `rate-limited` |
| `MAX_WEIGHT` | `1000` | (const) | stored weight = `max(0, min(1000, weight))`; `weight` non-finite -> `100` (`:97`,`:100`) |
| request body cap | `64 KiB` | (const) | `readBody` max (`:142`); overflow -> `400 bad-json:body too large` |
| global announce bucket | `66.7/s`, burst `1000` | `SHADE_TREE_BOOTNODE_ANNOUNCE_RATE` / `_BURST` | `makeAnnounceBucket`: the LAST gate before `verifyAnnounce`; overflow -> `429 global-rate-limited` + `Retry-After` (T-HARD-4) |
| HTTP slow-client limits | 10 s / 30 s / 5 s / 8 KiB | `SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS` etc. | `HTTP_LIMITS`: headers / request / keep-alive timeouts (`408`) + max header size (`431`) (T-HARD-4) |

Registry-level announce reasons (returned as `400 { err:<reason> }`), checked BEFORE the
signature verify (`:87`,`:88`):

| Reason | Condition |
| --- | --- |
| `rate-limited` | resident onion, `now - lastAt < minReannounceSec` |
| `registry-full` | new onion, `live.size >= maxEntries` after a sweep |
| `global-rate-limited` (HTTP `429`) | the global announce bucket has no token (checked LAST before verify; not charged by the two rejects above; store reload exempt) |

The signed `/directory` response is bounded transitively by `maxEntries` (one gateway object
per live entry); there is no separate byte-cap on the response. See ambiguity note in the
report.

### 5.4 Registrar HTTP API (402 rails, T-FEAT-7): `payments/registrar.mjs` `makeServer`

The operator's payment endpoint, published as an EXTRA virtual port of an onion the box runs:
the bootnode onion (`http://<bootnode-onion>:8878/`) or, for T-FEAT-9, the GATEWAY onion on a
gateway-only box (`http://<gateway-onion>:8878/`; the gateway's signed `caps.pay` says where,
§3.0.1); loopback `127.0.0.1:SHADE_TREE_REGISTRAR_PORT`. Both machine-payment dialects on one route
set; but only the rails the provider ENABLED (`SHADE_TREE_PAY_PROTOCOLS`, default both) are served:
a disabled rail gets NO challenge header in any 402, is absent from `pay.protocols`, and a
`POST /pay` carrying its header is refused `400 { ok:false, err:"protocol-disabled",
protocol:"x402"|"mpp", protocols:[<enabled>], detail }` before any parsing. Wire formats in
`payments/wire.mjs`, exact headers/fields in `docs/PAYMENTS.md` "Headers (both rails, exact)".

| Method | Path | Success | Notes |
| --- | --- | --- | --- |
| GET | `/pay/quote[?limit=N]` | `402` + `PAYMENT-REQUIRED` (x402 v2 `PaymentRequired`, one `accepts[]` entry per offered tier) + one `WWW-Authenticate: Payment …` per tier (MPP `evm`/`charge`, `credentialTypes:["authorization"]`) + `application/problem+json` body `{ type:"…/payment-required", …, pay:{protocols, chain, chainId, asset, assetName, assetVersion, decimals, payTo, tiers, maxTimeoutSeconds, routes, offered} }`, `Cache-Control: no-store` | `?limit` narrows to one tier; unknown tier → `400 { err:"unknown-limit", tiers }` |
| POST | `/pay` (no payment header) | the same `402`; the MPP challenges carry `digest="sha-256=:…:"` over the request body (RFC 9530) | the MPP challenge step for a bodied request; body `{ commitment, limit }` |
| POST | `/pay` + `PAYMENT-SIGNATURE: <b64 PaymentPayload>` | `200 { ok:true, protocol:"x402", state:"inserted", asset, payer, nonce, commitment, limit, settleTx, insertTx, leafIndex, root, replayed }` + `PAYMENT-RESPONSE: <b64 { success:true, transaction:<settleTx>, network, payer }>` | body `{ commitment:<decimal field element>, limit:<tier> }`; `limit` must equal the tier `accepted.amount` prices |
| POST | `/pay` + `Authorization: Payment <b64url credential>` | `200 { …same…, protocol:"mpp" }` + `Payment-Receipt: <b64url { status:"success", method:"evm", challengeId, reference:<settleTx>, timestamp, chainId }>` | credential `payload.type` MUST be `"authorization"` (EIP-3009); `nonce == keccak256(id ‖ realm)`; body must match the challenge `digest` |
| GET | `/pay/status/<nonce>` | `200 { ok:true, orders:[{ state, asset, payer, nonce, commitment, limit, settleTx, insertTx, leafIndex, root }] }` | `state` ∈ `settling|settled|inserted|failed`; `404 not-found`; `400 bad-nonce` |
| GET | `/health` | `200 { ok:true, pay:{…offer…}, paidAccessSet, leafCount, root }` | Private order volume is omitted. |

`/metrics` is deliberately absent from the onion-facing registrar listener. Optional
operator metrics use a separate loopback-only listener on `SHADE_TREE_METRICS_PORT`.
`shade_tree_registrar_payments_total` counts each completed `POST /pay` exactly
once. Its `protocol` is `unknown|x402|mpp`, its `result` is
`challenged|inserted|replayed|rejected|failed`, and non-success reasons come from
a closed registrar-owned vocabulary. Early rejects before rail selection use
`protocol="unknown"`; unexpected dependency values collapse to `reason="other"`.

Errors (`payments/registrar.mjs` `makeServer` / `makeEngine`):

| Status | When | Body / headers |
| --- | --- | --- |
| 402 | x402: payload rejected (`invalid_payment_payload`, `invalid_x402_version`, `invalid_scheme`, `invalid_network`, `invalid_exact_evm_payload_*`, `insufficient_funds`, `expired`, `not-yet-valid`, `bad-signature`, `nonce-used` (chain), `settle-failed`, `limit-mismatch`) | fresh `PAYMENT-REQUIRED` + `PAYMENT-RESPONSE { success:false, errorReason }` |
| 402 | MPP: `malformed-credential`, `invalid-challenge` (HMAC/realm/digest/offer drift), `payment-expired`, `verification-failed` (type/nonce/to/value/signature…), `payment-insufficient` | fresh `WWW-Authenticate: Payment …` + `application/problem+json { type:"https://paymentauth.org/problems/<code>", title, status:402, detail, pay }` |
| 400 | bad JSON / bad body (`bad-body`, `bad-commitment`, `unknown-limit`); MPP `method-unsupported`; a payload for a rail this registrar does not serve (`protocol-disabled`, T-FEAT-9) | `{ ok:false, err }` / problem; `protocol-disabled` adds `protocol` + `protocols:[enabled]` |
| 409 | `nonce-used` (same authorization, different commitment), `already-member` (commitment live in the set; refused BEFORE settlement), `in-progress` | `{ ok:false, err, detail }` |
| 413 / 431 / 408 | body > 4 KiB / headers > `maxHeaderSize` / slow client (`HTTP_LIMITS`, T-HARD-4) | |
| 429 | quote or pay token bucket empty | `{ err:"rate-limited" }` + `Retry-After` |
| 502 / 503 | `rpc-error`, `insert-failed` (settled; retried on boot / on an identical re-POST) / `busy` (in-flight cap) | `Retry-After: 5` on 503 |

Idempotency: an identical re-POST of a finished order returns `200` with `replayed:true` and the
stored receipt (no second settle/insert).

## 6. Egress envelope v4

The envelope is NOT part of the bootnode HTTP API. The client sends it to a GATEWAY onion over
a Tor SOCKS tunnel (`client/shade-tree-client.mjs:184` `_dial`, destination port `80`) as
`JSON.stringify(envelope) + "\n"` (`:218`). The gateway replies with ONE newline-terminated
JSON line: `{ ok:true }` on admit, else `{ ok:false, err:"<reason>" }` (sometimes with
negotiation metadata). Documented here because the same wire format the
Rust client emits must satisfy `verifyEnvelope`.

### 6.1 Wire shape: `client/shade-tree-client.mjs:82` `buildEnvelope`

```jsonc
{
  "v": 4,
  "target": "<host:port>",
  "nonce":  "<16 random bytes hex, 32 chars>",
  "artifact": "rln-<16 hex>",    // OPTIONAL (T-HARD-8): id of the ZK artifact set the proof was made with
  "proof": {                     // wireProof, lib/rln.mjs:227
    "snarkProof": { "proof": {...}, "publicSignals": { "y","root","nullifier","x","externalNullifier" } },
    "epoch": "<decimal string>",
    "rlnIdentifier": "<decimal string>"
  },
  "nullifier": "<decimal string>",
  "externalNullifier": "<decimal string>",
  "share": { "x": "<decimal string>", "y": "<decimal string>" }
}
```

`artifact` (T-HARD-8, `lib/zk-artifacts.mjs`) names the ZK artifact set (wasm + zkey + vkey from one
phase-2 output) the proof was generated with, so a gateway running a dual-VK rollout window
(`docs/CEREMONY.md` §6) verifies under the matching vkey. Value = `<circuit>-<sha256(verification_
key.json bytes) hex[0:16]>`; grammar `^[a-z0-9][a-z0-9._-]{0,63}$`; i.e. literally the vkey's
hash prefix in `testdata/zk-artifacts.lock.json` (`circuits.rln.artifactId`), derived identically
by the JS client (`artifactIdOf`), the Rust client (`shade_tree_proto::artifact_id_of`, from its embedded
bytes) and the gateway (from the files `SHADE_TREE_ZK_ARTIFACTS` names). OPTIONAL and additive: an
envelope WITHOUT it is treated as the gateway's LEGACY id (`SHADE_TREE_ZK_ARTIFACT_LEGACY`, default the
lock's `previousArtifactId` else the built-in id), so an un-upgraded client keeps working while
that id is accepted and is rejected `artifact-retired:<id>` once it is not; a gateway that predates
the field ignores it. The client sends the NEWEST of its own sets that the gateway advertises in
its signed caps (`caps.artifacts`, §3), else optimistically its newest (`selectArtifact`).

`nullifier`, `externalNullifier`, and `share` are copies of the proof's public signals but are
NON-authoritative: `verifyEnvelope` reads them from `proof.snarkProof.publicSignals` (`ps`), not
from the envelope copies (`lib/rln.mjs:288` header). `publicSignals` field set is
`{ y, root, nullifier, x, externalNullifier }` (`client/shade-tree-client.mjs:214`).

**Reputation tiers carry NO wire field (T-FEAT-8, `docs/adr/0006-reputation-tiers.md`).** The
member's per-epoch budget (`userMessageLimit`) is a PRIVATE circuit input hashed into its leaf and
range-checking the private `messageId`; the envelope, the public-signal set, and the gateway's
reply are byte-identical for a tier-8 and a tier-32 member. There is no `limit`/`tier` field, and a
gateway MUST NOT be sent one. Enforcement is the root (`wrong-group-root`) + the nullifier set.

### 6.2 Tunnel signal + target binding

`lib/rln.mjs:124` `requestSignal`:

```
requestSignal(target, nonce) = `shade-tree:v4\n${target}\n${nonce}`
```

The circuit public `x` is `calculateSignalHash(message)` = `keccak256(utf8(message)) >> 8`
(`lib/rln.mjs:122`,`:253`), deterministic. Target-binding invariant (`:322`):

```
calculateSignalHash( requestSignal(env.target, env.nonce) )  ==  ps.x
```

so a captured proof cannot be redirected to a different target/nonce.

### 6.3 `signalFieldSafe` bounds: `lib/rln.mjs:132`

```
signalFieldSafe(s, maxLen) = (typeof s === "string") && s.length > 0
                             && s.length <= maxLen && !/[\n\r]/.test(s)
```

In `verifyEnvelope`: `signalFieldSafe(target, 256)` and `signalFieldSafe(nonce, 128)`
(`:316`). Enforced BEFORE hashing so no crafted delimiter or oversized field can make two
distinct `(target, nonce)` pairs collide to one signal.

### 6.4 `verifyEnvelope` check order: `lib/rln.mjs:288`

Fail-closed, FIRST failure returned. `ps = proof.snarkProof.publicSignals`;
`share = env.share || { x: ps.x, y: ps.y }`.

| # | Reason on failure | Check |
| --- | --- | --- |
| pre | `no-envelope` | `env` not an object |
| pre | `no-proof` | missing `proof` / `snarkProof` / `publicSignals` |
| 1 | `stale-external-nullifier` | `ps.externalNullifier` not `externalNullifierFor(now)` nor `...(now-1)` (one-epoch skew) |
| 2 | `signal-mismatch` | `String(share.x) !== String(ps.x)` |
| 2b | `unbound-target` | `env.nonce == null` or `env.target == null` |
| 2b | `bad-signal-field` | `!signalFieldSafe(target,256)` or `!signalFieldSafe(nonce,128)` |
| 2b | `target-not-bound` | `calculateSignalHash(requestSignal(target,nonce)) !== ps.x` |
| 3 | `wrong-group-root` | `String(ps.root)` not in `recentRoots` |
| 3b | `bad-artifact:<repr>` | `env.artifact` present but not an artifact id (repr bounded to 16 chars) |
| 3b | `artifact-retired:<id>` | the (legacy) id resolved for this envelope is known but no longer in the accepted set (rollout window closed) |
| 3b | `artifact-unknown:<id>` | an id this gateway holds no vkey for (incl. id spoofing to an unheld key) |
| 4 | `verify-threw:<msg>` | Groth16 verify threw (under the resolved artifact's vkey) |
| 4 | `invalid-proof` | Groth16 verify returned false (incl. a proof claiming an accepted id it was not made with) |
| none | success | `{ ok:true, reason:"ok", nullifier, externalNullifier, share:{x,y}, artifact }` from `ps` |

Step 3b (`lib/zk-artifacts.mjs` `resolveArtifact`) is a cheap map lookup on the accepted set
`{artifactId -> vkey}` (`SHADE_TREE_ZK_ARTIFACTS`; default = the built-in vkey under its own id): absent
field ⇒ the legacy id, then the same rules. Its three rejections additionally return `label` (the
bounded metrics key: `bad-artifact` / `artifact-retired` / `artifact-unknown`, never the id) and
`artifacts` (the accepted ids), which the gateway writes back as `{ ok:false, err:"gate:<reason>",
artifacts:[...] }`; the client uses that list to re-select a mutual set (or fail closed with
`no-mutual-artifact:client=…,gateway=…`). Reason labels are pinned in `testdata/vectors.json`
`artifacts.reasons`.

Ordering is load-bearing (`:319` INVARIANT): 2b binds `target -> ps.x` cheaply, but `ps.x` is
only AUTHORITATIVE once check 4 proves the Groth16 membership proof. Both are required; never
trust 2b without 4. Do not reorder 2b apart from 4.

Epoch clock: `epoch = floor(nowMs/1000 / EPOCH_SECONDS)`, `EPOCH_SECONDS` default `120`
(`lib/rln.mjs:78`,`:80`). `externalNullifier(epoch) = Poseidon(epoch, RLN_IDENTIFIER)`,
`RLN_IDENTIFIER` default `1` (`:72`,`:115`).

### 6.5 Determinism

| Value | Deterministic? | Conformance method |
| --- | --- | --- |
| ed25519 signatures (announce, directory) | YES (RFC 8032) | byte-equality |
| onion address, checksum, canonical bytes | YES | byte-equality |
| `calculateSignalHash(message)` = `x` | YES | byte/decimal-equality |
| RLN Groth16 proof bytes (`proof.snarkProof.proof`) | NO (randomized per call, `lib/rln.mjs:238`) | verify for validity/equivalence, NOT byte-equality |
| RLN public signals `x,y,nullifier,externalNullifier,root` | YES given inputs | value-equality |

## 7. Cross-check for a second implementation

1. Reproduce `onionToPubkey` / `pubkeyToOnion` (SHA3-256 checksum, base32 no-pad).
2. Reproduce `canonicalAnnounceBytes` and `canonicalDirectoryBytes` byte-for-byte.
3. ed25519 sign/verify with raw 32-byte seed/pubkey (RFC 8032, null-digest).
4. `verifyAnnounce` / `verifyDirectory` / `verifyEnvelope` reason codes and ordering.
5. EIP-191 `personal_sign` recover for `operatorAuthMessage` (secp256k1).
6. `requestSignal` string, `signalFieldSafe`, and the target-binding hash.
7. `artifactIdOf` (sha256 prefix of the vkey bytes), `canonicalCaps.artifacts`, and `selectArtifact`
   (T-HARD-8; the Rust client also hash-checks its embedded artifacts against the embedded lock at
   startup, `rust/shade-tree-rln/src/artifacts.rs`).
8. `canonicalCaps.admits` (anonymity order, deduped) and `canonicalCaps.pay` (bounded, numeric tier
   order) + the admission-aware selection rule (T-FEAT-9: keep gateways whose `admits` include the
   client's leaf source; absent `admits` = keep; `--max-anon` = exactly `["invited"]`), `shade_tree_proto`
   `canonical_admits` / `canonical_pay`, `shade-tree-client` `filter_by_admission`.

## 8. Ambiguities / notes

- The `readBody` cap (64 KiB) is on the REQUEST body; there is no explicit byte-cap on the
  `/directory` RESPONSE. Response size is bounded only transitively by `maxEntries`.
- `verifyEnvelope` reads `nullifier`/`share` from the proof's public signals, so the
  envelope's own copies are advisory. A Rust client should still send them (the gateway ack
  path and older tooling read them), but they must equal the public signals or the proof is
  self-inconsistent and rejected at check 2 (`signal-mismatch`).

## 9. Conformance

Fixture file: [`testdata/vectors.json`](../testdata/vectors.json). Test-only fixed seeds. The
Rust client MUST reproduce every BYTE-PINNED value below exactly.

| Key | Byte-pinned | Produced by |
| --- | --- | --- |
| `signerSeed` | input | 32-byte ed25519 signer seed (hex) |
| `signerPub` | YES | `ed25519PublicKey(signerSeed)` raw pubkey hex |
| `onionSeed` | input | 32-byte onion identity seed (hex) |
| `onionPub` | YES | onion identity pubkey hex |
| `onion` | YES | `pubkeyToOnion(onionPub)` |
| `canonicalDirectoryBytesHex` | YES | hex of `canonicalDirectoryBytes(dir)` for `version:1, issued:1000000, gateways:[{onion,pubkey:onionPub,weight:100,health:"up"}]` |
| `directorySignature` | YES | `ed25519Sign(canonicalDirectoryBytes, signerSeed)` |
| `announce` | YES | the record `{v:1, onion, weight:100, ts:1000000, nonce:"abcdef0123456789abcdef0123456789"}` |
| `canonicalAnnounceBytesHex` | YES | hex of `canonicalAnnounceBytes(announce)` |
| `announceOnionSig` | YES | `ed25519Sign(canonicalAnnounceBytes, onionSeed)` |
| `operator` | input | `0x000000000000000000000000000000000000dEaD` (note mixed-case input) |
| `operatorAuthMessage` | YES | `operatorAuthMessage(onion, operator)` (operator lowercased in the string) |
| `artifacts.sample` | YES | `artifactIdOf("rln", utf8("hello"))` = `rln-2cf24dba5fb0a30e` (T-HARD-8 artifact id = `<circuit>-<sha256[0:16]>`) |
| `artifacts.reasons` | YES | bounded reason labels `bad-artifact` / `artifact-retired` / `artifact-unknown` / `no-mutual-artifact` / `no-client-artifact` |
| `artifacts.selection` | YES | `selectArtifact` pick (newest client id the gateway lists) + the byte-exact `no-mutual-artifact:client=…,gateway=…` string |
| `artifacts.capsWithArtifacts` | YES | `canonicalCaps` with an `artifacts` list (sorted, appended after `proto`), its `canonicalCapsBytes` hex and onion `capsSig`; the no-artifacts `capabilities` vectors are byte-unchanged |
| `admission.admitPaths` / `payProtocols` / `maxPayTiers` | input | the canonical name orders + the tier bound (T-FEAT-9) |
| `admission.capsWithAdmission` | YES | `canonicalCaps` with `admits` (deduped, anonymity order) + `pay` (protocol order, lowercased onion/asset, numeric tier keys), appended after `artifacts`; its `canonicalCapsBytes` hex and onion `capsSig`; every earlier caps vector is byte-unchanged |
| `admission.junk` | input | admits / pay values that MUST canonicalize to ABSENT (unknown names, an empty tier map, an unknown rail, port 70000, 9 tiers, non-canonical tier keys) |

NOT pinned (verify by equivalence, never byte-equality):

- RLN Groth16 proofs (`proof.snarkProof.proof`); non-deterministic; see 6.5.
- `operatorSig`; not in the fixture; validated by EIP-191 recovery, not byte-match.
