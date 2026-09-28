# Onion identity continuity (verify-before-cutover + restore)

`scripts/onion-identity.mjs` is the safety rail for the single most unrecoverable operation in a
rebuild: **bringing a gateway or bootnode back on the SAME `.onion`.** It is a focused complement to
the encrypted backup in [`scripts/backup.mjs`](BACKUP.md) — backup *moves the key off the box*;
this tool *proves the key is the right one and lays it down correctly on the new box*.

## Why onion continuity is operationally critical

A v3 onion address **is** an ed25519 public key: `onion = base32(pubkey ‖ checksum ‖ 0x03)`. The
fleet directory ([`lib/directory.mjs`](../lib/directory.mjs)) is a signed list of
`{ onion, pubkey, weight, health }`, and clients **pin** those onions. Two consequences:

- If a rebuilt box comes up on a **new** onion, it is not in the directory anyone pinned. Clients
  cannot reach it, the live-control challenge (`verifyOnionControl`) is against the old key, and the
  gateway is silently dark until the directory is re-signed and re-shipped.
- The HS descriptor is stored under a **blinded** key on the HSDir hashring, so you cannot discover
  "which onion did this box used to be" from the network. The only source of truth is the
  `hs_ed25519_secret_key` you backed up.

So the key must survive a rebuild, **and** an operator must be able to confirm — *before* cutting Tor
over — that the key they are about to restore resolves to the onion the fleet expects. A wrong or
truncated key that Tor happily accepts just publishes a different onion.

## What the tool does

Both subcommands work from a **bare `hs_ed25519_secret_key`** — the only HS file
[`scripts/backup.mjs`](BACKUP.md) stores (it deliberately skips `hs_ed25519_public_key` and
`hostname`). That is sufficient because the public key, and therefore the onion, is fully determined
by the secret key.

```bash
# 1) VERIFY BEFORE CUTOVER — derive and print the onion a secret key resolves to.
node scripts/onion-identity.mjs derive ./hs_ed25519_secret_key
#   => xxxxxxxx…xxxxxx.onion

# 2) RESTORE — rebuild a HiddenServiceDir Tor can publish, from the secret alone.
node scripts/onion-identity.mjs restore ./hs_ed25519_secret_key /var/lib/tor/shade-tree-gateway
#   (add --force to overwrite an existing populated dir)
```

`derive` prints **only** the `.onion` on stdout (script-friendly). `restore` writes Tor's required
three-file layout and prints the onion plus a cutover reminder. **The secret key's bytes are never
printed or logged** by any path.

### File layout + permissions written by `restore`

| file | contents | mode |
|---|---|---|
| `hs_ed25519_secret_key` | the input secret, byte-for-byte | `0600` |
| `hs_ed25519_public_key` | reconstructed `== ed25519v1-public: type0 ==` ‖ pubkey | `0600` |
| `hostname` | reconstructed `<onion>\n` | `0644` |
| *(the HiddenServiceDir itself)* | — | `0700` |

Tor refuses a group/other-accessible HS dir, so the dir is forced to `0700` and the secret to `0600`
(matching what [`bootnode/keygen.mjs`](../bootnode/keygen.mjs) mints and what
[`scripts/backup.mjs`](BACKUP.md) restores). `restore` refuses to clobber an existing populated HS
dir unless you pass `--force`.

## The verify-before-cutover procedure

Run this on the **new** box before pointing Tor at the restored dir and starting it:

1. **Recover the secret.** `shade-tree restore <backup>.shade-tree-backup <deploy-state>` (see
   [BACKUP.md](BACKUP.md)) decrypts `hs_ed25519_secret_key` back out of the encrypted envelope.
2. **Derive and compare.** `node scripts/onion-identity.mjs derive <path>/hs_ed25519_secret_key`.
   Confirm the printed onion **exactly equals** the onion the fleet directory advertises for this
   box (`shade-tree directory` / the signed directory JSON). If it does not match, **stop** — you have the
   wrong key; do not start Tor, or you will publish a stranger onion.
3. **Lay it down.** `node scripts/onion-identity.mjs restore <path>/hs_ed25519_secret_key
   /var/lib/tor/shade-tree-<role>`. This writes the secret + public + hostname with correct perms.
4. **Cut over.** Point the `HiddenServiceDir` in the torrc include
   ([`bootnode/deploy/torrc.hardened`](../bootnode/deploy/torrc.hardened)) at that dir and
   `systemctl restart tor`. Tor's own `hostname` will now match step 2.
5. **Confirm live.** Once the descriptor republishes, the directory's `verifyOnionControl` challenge
   succeeds against the same key and clients reach the box on the original onion.

The one-line safety property: **step 2 catches a bad key while it is still harmless, before step 4
makes it a live, wrong onion.**

## How it composes with the rest of the toolchain

- **`scripts/backup.mjs` (T-FEAT-15 / T-DEPLOY-5 backup half)** is the *transport*: it encrypts the
  secret off-box (AES-256-GCM + scrypt) and restores the raw file. It does not know or check *which*
  onion a key is. This tool is the *verification + Tor-layout* half: it turns a bare secret into a
  checked onion and a publishable HS dir. Typical flow: `shade-tree restore …` (get the secret back) →
  `onion-identity.mjs derive …` (verify) → `onion-identity.mjs restore …` (place it for Tor).
- **T-DEPLOY-3 infra-as-code** (OpenTofu + Ansible in `agent-devops`) provisions a *fresh* box and,
  by default, **mints new onions** via [`bootnode/keygen.mjs`](../bootnode/keygen.mjs). To rebuild
  an *existing* identity instead of minting a new one, skip the keygen step and run `restore` against
  the backed-up secret so the box rejoins on its original onion. The HS dir path this writes is the
  same one the generated torrc include and the hardened systemd unit's `ReadWritePaths` already
  expect, so no unit changes are needed.
- **`bootnode/keygen.mjs`** is the inverse of this tool: keygen makes a *new* identity (seed → files);
  this tool *reconstructs* an existing one (secret → files + onion). Both produce byte-identical HS
  file layouts, so a restored dir is indistinguishable from a freshly minted one to Tor.

## How the derivation works (and what was hand-rolled)

The onion encoding (`base32(pubkey ‖ checksum ‖ 0x03)`, `checksum = SHA3-256(".onion checksum" ‖
pubkey ‖ 0x03)[:2]`) is **reused** from [`lib/directory.mjs`](../lib/directory.mjs) (`pubkeyToOnion`).

The one piece that is **not** already in the repo, and that `node:crypto` cannot do, is recovering
the public key from the *expanded* secret key. Tor's `hs_ed25519_secret_key` stores
`clamp(SHA512(seed)[:32]) ‖ SHA512(seed)[32:]` behind a 32-byte ASCII tag. SHA-512 is one-way, so
the original seed is unrecoverable — but the public key `A = a·B` is fixed by the clamped scalar `a`
(the first 32 bytes of the expanded key). `node:crypto`'s ed25519 only derives `A` from a 32-byte
*seed*, never from a bare scalar, so this tool computes `A = a·B` with a small self-contained
ed25519 base-point multiplication (BigInt field math over `p = 2²⁵⁵ − 19`, standard RFC 8032
addition formulas, point compression). It is **cross-checked against `node:crypto`** in
`scripts/onion-identity.selftest.mjs` (20 random keys derive identically), so the hand-rolled math is
verified equivalent to the platform implementation rather than trusted blind. No new dependency is
added — `node:crypto` plus the existing `lib` encoder only.

## Test

```bash
node scripts/onion-identity.selftest.mjs        # focused invariants (mint → derive → restore → round-trip)
node scripts/test-all.mjs --no-contracts        # full node suite (auto-discovers the selftest)
```
