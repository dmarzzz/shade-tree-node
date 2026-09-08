# Wire specification moved

The canonical document is [WIRE-SPEC.md](WIRE-SPEC.md). This compatibility index preserves
older section links; new links should point to the canonical document.

## 0. Version tags (do not conflate)

[Read this section](WIRE-SPEC.md#0-version-tags-do-not-conflate).

## 1. Canonical byte encodings

[Read this section](WIRE-SPEC.md#1-canonical-byte-encodings).

### 1.1 `canonicalAnnounceBytes`: `bootnode/announce.mjs:38`

[Read this section](WIRE-SPEC.md#11-canonicalannouncebytes-bootnodeannouncemjs38).

### 1.2 `canonicalDirectoryBytes`: `lib/directory.mjs:129`

[Read this section](WIRE-SPEC.md#12-canonicaldirectorybytes-libdirectorymjs129).

## 2. v3 onion <-> ed25519 identity key

[Read this section](WIRE-SPEC.md#2-v3-onion-ed25519-identity-key).

## 3. Announce record

[Read this section](WIRE-SPEC.md#3-announce-record).

#### 3.0.1 `caps` fields (all bucketed, TOTAL canonicalization: junk dropped, never thrown)

[Read this section](WIRE-SPEC.md#301-caps-fields-all-bucketed-total-canonicalization-junk-dropped-never-thrown).

### 3.1 Onion-control signature (proof 1, always required)

[Read this section](WIRE-SPEC.md#31-onion-control-signature-proof-1-always-required).

### 3.2 Operator authorization (proof 2, optional; enforced when `admission=stake`)

[Read this section](WIRE-SPEC.md#32-operator-authorization-proof-2-optional-enforced-when-admissionstake).

### 3.3 Freshness + nonce replay

[Read this section](WIRE-SPEC.md#33-freshness-nonce-replay).

### 3.4 `verifyAnnounce` reason codes: `bootnode/announce.mjs:80`

[Read this section](WIRE-SPEC.md#34-verifyannounce-reason-codes-bootnodeannouncemjs80).

## 4. Signed directory

[Read this section](WIRE-SPEC.md#4-signed-directory).

### 4.1 Shape

[Read this section](WIRE-SPEC.md#41-shape).

### 4.2 Pinned-signer model

[Read this section](WIRE-SPEC.md#42-pinned-signer-model).

### 4.3 `verifyDirectory` reason codes: `lib/directory.mjs:152`

[Read this section](WIRE-SPEC.md#43-verifydirectory-reason-codes-libdirectorymjs152).

### 4.4 Threshold (M-of-N) directory: T-FEAT-9, `lib/directory.mjs`

[Read this section](WIRE-SPEC.md#44-threshold-m-of-n-directory-t-feat-9-libdirectorymjs).

## 5. Bootnode HTTP API

[Read this section](WIRE-SPEC.md#5-bootnode-http-api).

### 5.1 Routes

[Read this section](WIRE-SPEC.md#51-routes).

### 5.2 Error responses

[Read this section](WIRE-SPEC.md#52-error-responses).

### 5.3 Admission modes + DoS caps

[Read this section](WIRE-SPEC.md#53-admission-modes-dos-caps).

### 5.4 Registrar HTTP API (402 rails, T-FEAT-7): `payments/registrar.mjs` `makeServer`

[Read this section](WIRE-SPEC.md#54-registrar-http-api-402-rails-t-feat-7-paymentsregistrarmjs-makeserver).

## 6. Egress envelope v4

[Read this section](WIRE-SPEC.md#6-egress-envelope-v4).

### 6.1 Wire shape: `client/shade-tree-client.mjs:82` `buildEnvelope`

[Read this section](WIRE-SPEC.md#61-wire-shape-clientshade-tree-clientmjs82-buildenvelope).

### 6.2 Tunnel signal + target binding

[Read this section](WIRE-SPEC.md#62-tunnel-signal-target-binding).

### 6.3 `signalFieldSafe` bounds: `lib/rln.mjs:132`

[Read this section](WIRE-SPEC.md#63-signalfieldsafe-bounds-librlnmjs132).

### 6.4 `verifyEnvelope` check order: `lib/rln.mjs:288`

[Read this section](WIRE-SPEC.md#64-verifyenvelope-check-order-librlnmjs288).

### 6.5 Determinism

[Read this section](WIRE-SPEC.md#65-determinism).

## 7. Cross-check for a second implementation

[Read this section](WIRE-SPEC.md#7-cross-check-for-a-second-implementation).

## 8. Ambiguities / notes

[Read this section](WIRE-SPEC.md#8-ambiguities-notes).

## 9. Conformance

[Read this section](WIRE-SPEC.md#9-conformance).
