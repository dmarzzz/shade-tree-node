# Encrypted key backup / restore

`shade-tree backup` and `shade-tree restore` encrypt and recover the secret key material an operator cannot
afford to lose. This replaces the manual `tar | gpg` recipe in [OPERATOR.md](./OPERATOR.md#backup):
it uses only Node's built-in crypto (`node:crypto`), so it works with no `gpg` installed.

## What it backs up

It walks a source directory and collects, **by filename**, the three secrets:

| file | what it is |
|---|---|
| `identity.local.json` | the 32-byte onion seed (announce-signing). Losing it loses the onion address. |
| `hs_ed25519_secret_key` | Tor's expanded hidden-service secret key. |
| `bootnode-signer.key` | the `{pub,priv}` that signs the directory (`pub` is what clients pin as `--dir-signer`). |

Everything else in the tree (e.g. `hostname`, `hs_ed25519_public_key`) is ignored.

## Usage

The passphrase is passed **only** via the `SHADE_TREE_BACKUP_PASSPHRASE` environment variable — never on
the command line (so it never lands in your shell history or the process list) and never logged.

```bash
# Back up: encrypt every secret under deploy-state/ into one file.
export SHADE_TREE_BACKUP_PASSPHRASE='…a long, unique passphrase…'
shade-tree backup deploy-state shade-tree-keys-$(date +%F).shade-tree-backup
# then move the .shade-tree-backup file to an off-box, encrypted-at-rest location.

# Restore: decrypt back into a directory (refuses to clobber existing files).
export SHADE_TREE_BACKUP_PASSPHRASE='…the same passphrase…'
shade-tree restore shade-tree-keys-2026-08-13.shade-tree-backup deploy-state          # add --force to overwrite
```

Restored files are written with restrictive perms (secrets `0600`, directories `0700`), so the
onion address and pinned signer survive a rebuild and clients keep working. Restore refuses to
overwrite existing files unless you pass `--force`.

Paths may also be supplied via env (`SHADE_TREE_BACKUP_SRC` / `SHADE_TREE_BACKUP_OUT` for backup,
`SHADE_TREE_BACKUP_IN` / `SHADE_TREE_BACKUP_DEST` for restore) for non-interactive/automated runs.

## Crypto

- **Key derivation:** `scrypt` with a fresh random 16-byte salt per backup (N=2¹⁵, r=8, p=1 → a
  32-byte key). The salt is stored in the backup file; the passphrase never is.
- **Encryption:** AES-256-GCM with a random 12-byte IV. The 16-byte GCM auth tag makes the backup
  **tamper-evident**: a wrong passphrase or any modified byte fails authentication on restore, which
  aborts loudly and writes nothing.
- **The plaintext bundle never touches disk.** Secrets are collected into memory, encrypted, and
  only the ciphertext envelope (`{version, cipher, kdf, kdfParams, salt, iv, authTag, ciphertext}`,
  all base64) is written out.

## The passphrase is your responsibility

There is **no recovery path** for a lost passphrase — that is the point. A wrong or forgotten
passphrase means the backup is unrecoverable, by design. Store the passphrase separately from the
backup file (a password manager or your normal secrets vault), and treat it with the same care as
the keys themselves.

The operator EOA key (`SHADE_TREE_GW_OPERATOR_KEY` / `SHADE_TREE_REGISTER_KEY` / `SHADE_TREE_SLASH_KEY`) is **not**
covered here — back it up with your normal wallet backups.

## Operator wallet keys (not covered by `shade-tree backup`)

`shade-tree backup` covers onion seeds, Tor keys and the directory signer. The Ethereum keys an
operator holds are separate and must be backed up separately:

| Key | Used for | Where the reference deployment keeps it |
|---|---|---|
| gateway operator | GatewayRegistry stake; signs node announces | SOPS-encrypted (age) in the operator's infrastructure repository; delivered to nodes as the systemd credential `SHADE_TREE_GW_OPERATOR_KEY` |
| slasher | Gas for permissionless member slashes | Same, credential `SHADE_TREE_SLASH_KEY` |
| registrar | Settles and inserts paid leaves (when paid admission is on) | Same, credential `SHADE_TREE_REGISTRAR_KEY` |
| registry owner | GatewayRegistry `owner` (governed gateway slash) | Controller only; never on a host |

Rules that follow from the 2026-09-28 rotation ([KEY-ROTATIONS.md](KEY-ROTATIONS.md)):

- One key per role. A leaked slasher key must not also move the operator's stake.
- Keep the age identity that decrypts the SOPS files offline or on one controller, and keep a
  second encrypted copy of it off that machine. Losing it loses every key above.
- Record every rotation in `docs/KEY-ROTATIONS.md` with addresses and transaction hashes.
- To recover a lost node, restore its onion identity with `shade-tree restore`, re-run the
  bootstrap with the same `SHADENET_NETWORK`, and place the credential files again. The operator
  address, not the host, holds the stake.
