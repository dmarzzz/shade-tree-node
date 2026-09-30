# Signed egress success receipts (T-FEAT-13)

A gateway that accepts a valid RLN proof could still silently **drop** the actual egress
(gate-then-drop). Egress receipts give a client cryptographic, self-authenticating evidence
that a gateway is actually serving traffic, **without adding any channel that links a receipt
to the member who connected or the target they reached.**

After a gateway *successfully* opens the egress tunnel, it returns — alongside the normal
`{ ok: true }` ack — a small **receipt** signed by its **onion-control key**. A client holding
the gateway's directory pubkey verifies it offline and can accumulate it as evidence of that
gateway's liveness/quality, feeding quality-aware rotation (T-FEAT-4).

This is **optional and additive**. It is **off by default** and, when off, the success reply is
byte-for-byte the pre-existing `{ ok: true }`.

## What the receipt attests

> "I, *this onion*, served a request at epoch *E*."

That is deliberately a **per-gateway liveness attestation**, not a **per-tunnel** proof. A
per-tunnel binding is exactly the linkability channel we refuse to add (see below).

## Schema

```jsonc
{
  "v": 1,                 // receipt schema version
  "onion": "<56-char>.onion",  // the GATEWAY's own v3 address (== its ed25519 pubkey)
  "epoch": "12345",       // COARSE epoch bucket, decimal string (EPOCH_SECONDS, default 120s)
  "ok": true,             // constant success flag
  "sig": "<hex>"          // ed25519 signature by the onion-control key
}
```

The receipt's **only** keys are `{v, onion, epoch, ok, sig}`. Nothing else is present.

## Canonical bytes + domain separation

The signed bytes are a fixed **domain prefix** followed by a fixed-field-order JSON payload
(same whitespace-independent style as `canonicalAnnounceBytes` / `canonicalDirectoryBytes` in
`packages/node/lib/directory.mjs`):

```
Shade Tree egress success receipt v1\n{"v":1,"onion":"...","epoch":"12345","ok":true}
```

The onion-control key **also** signs the gateway's *announce* (`packages/node/bootnode/announce.mjs`), which is
bare versioned JSON with no such prefix. The receipt-only domain string
(`RECEIPT_DOMAIN`) makes a receipt signature **impossible to confuse** with an announce or
directory signature by that same key: a receipt sig never validates as an announce, and an
announce's `onionSig` never validates as a receipt. (Proven in `packages/node/gateway/receipt.selftest.mjs`.)

## Verification

`verifyReceipt(rec, { onion, epoch, epochSkew })` in `packages/node/lib/receipt.mjs`:

1. version is `1`, `ok === true`, `onion` is present;
2. if `onion` is supplied, `rec.onion` must equal it — **bind the receipt to the gateway the
   client actually dialed**;
3. recover the ed25519 pubkey from `rec.onion` itself (checksummed v3 decode, `onionToPubkey`) —
   the receipt is **self-authenticating**, verifiable by anyone with the gateway's directory
   entry, offline;
4. `epoch` is a canonical non-negative decimal string; if a current `epoch` is supplied it must be
   within `epochSkew` (default 1 bucket) — a stale receipt is **not** counted as fresh evidence;
5. the ed25519 signature verifies over the canonical bytes.

Returns `{ ok, reason }` and, on success, `{ onion, pubkey, epoch }`. It is **total** — arbitrary/
malformed input returns `{ ok:false, reason }`, never throws.

## Privacy argument — why each field is safe, and what is absent

| field   | why it leaks nothing about the member or the target                                       |
|---------|--------------------------------------------------------------------------------------------|
| `v`     | a constant version tag.                                                                     |
| `onion` | the gateway's **public** identity, already in the signed directory. It *is* the pubkey. Says nothing about who connected or where they egressed. |
| `epoch` | the **coarse** time bucket the RLN rate cap already uses. Every request in a bucket shares one value, so it does not pin a request in time. |
| `ok`    | a constant success flag.                                                                    |
| `sig`   | a signature over only the four fields above.                                                |

**Deliberately absent** (and must stay absent): member identity/commitment, the **nullifier**
(not even a prefix), the RLN share, the **target** host/port, the request **nonce**, a **fine
timestamp**, and any **per-tunnel counter**. Any one of them would tie a receipt to a specific
member or request and hand a colluding relay/gateway a correlation handle — and a gateway keeping
receipts would then hold a log of *which members it served*.

We specifically use the **coarse epoch** instead of a wall-clock `ts` or a monotonic counter: a
fine timestamp or counter is itself a distinguishing per-tunnel tag (a covert linkability /
logging channel), which a coarse bucket is not.

### Deliberate divergence from the backlog sketch

The backlog note (`docs/history/SHIP-PLAN.md`, T-FEAT-13) sketched `{nullifier-prefix, ts, ok}`. We drop
the **nullifier prefix** (a partial member handle) and replace the fine **ts** with the coarse
**epoch**, trading a small amount of verifiability for airtight unlinkability. The consequence,
stated honestly: two receipts from the same gateway in the same epoch are byte-identical, so a
receipt proves gateway **liveness/quality over an epoch**, not that *your specific* request
egressed. That per-tunnel binding is the channel we refuse to add. An honest gateway emits a
receipt only on the egress-success path, so a gateway that drops every request produces none.

## Enabling it

**Gateway** (signer) — off by default:

- `SHADE_TREE_RECEIPTS=1` — turn receipts on.
- `SHADE_TREE_GW_IDENTITY` — path to the onion identity `{ onion, seed }` (default
  `tor/hs/identity.local.json`, the same file the heartbeat announces with).

If receipts are requested but the identity can't load, receipts are **disabled** (logged) and
egress is unaffected — it never fails closed on a missing key.

**Client** — automatic and additive. `ShadeTreeClient.connect()` verifies any `receipt` on the ack
against the dialed onion + current epoch and exposes the result:

- `tunnel.shadeTree.receipt` → `{ present, valid, epoch?, onion?, reason? }`
- an `onEvent({ phase: "receipt", status: "verified" | "invalid" | "absent", ... })` progress event.

`present:false` is the normal legacy case (a gateway with receipts off) and is **not** a failure.
A malformed/invalid receipt is reported (`valid:false` + `reason`) but **never** breaks the tunnel
— the egress already succeeded; the receipt is best-effort quality evidence, not a gate.

## Files

- `packages/node/lib/receipt.mjs` — `buildReceipt` / `verifyReceipt` / `canonicalReceiptBytes` (pure, shared).
- `packages/node/gateway/gateway.mjs` — `receiptsEnabled()`, `successAck()`, the onion-seed signer; emits the
  receipt on egress success behind the flag.
- `packages/node/client/shade-tree-client.mjs` — verifies + surfaces the receipt.
- `packages/node/gateway/receipt.selftest.mjs` — round-trip, tamper, domain-separation, privacy, default-off.
