# Install the Rust client

The checksummed `-live` binary is the agent distribution. It includes identity
creation, the RLN prover, embedded Arti, the loopback HTTP CONNECT Proxy, and
the process-scoped `run` wrapper. The agent machine needs neither Node.js nor a
system Tor daemon.

Tagged releases publish two variants:

| Variant | Includes | Published targets |
| --- | --- | --- |
| default | directory and receipt verification, selection, cache | Linux x86_64/aarch64 (GNU and musl), macOS x86_64/aarch64, Windows x86_64 |
| `-live` | default features plus identity creation, RLN proving, embedded Tor, Proxy, and `run` | Linux x86_64/aarch64 (GNU and musl), macOS aarch64, Windows x86_64 |

Every binary has a matching `.sha256`, SPDX SBOM, GitHub build-provenance
attestation, and SBOM attestation. The `-live` build embeds the repository's
testnet RLN artifacts; review
[`../circuits/rln/ARTIFACTS.md`](../circuits/rln/ARTIFACTS.md) before use.

> [!WARNING]
> v0.6 is an unaudited research preview built with testnet-only RLN setup
> artifacts. Do not use it as a production anonymity or security boundary.

## One-line install

The POSIX `sh` installer detects the supported OS, CPU, and Linux libc; fetches
the binary and its matching `.sha256`; verifies both the digest and filename;
and installs atomically into a user-writable directory without sudo. Curl user
configuration is disabled so a local `.curlrc` cannot weaken its HTTPS policy.

```sh
curl -q -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh | sh
```

The default probes the selected release for its self-contained `-live` agent.
Only a missing live checksum or binary triggers a clearly reported fallback to
that same release's verifier-only binary; network, TLS, and integrity failures
remain fail-closed. `SHADE_TREE_LIVE=1` disables fallback. On Apple Silicon the
installer detects an x86_64 shell running under Rosetta and selects the native
arm64 live asset. Intel macOS (`x86_64-apple-darwin`) has no live asset.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SHADE_TREE_VERSION` | latest release | Pin a release, such as `v0.6.0` or `0.6.0` |
| `SHADE_TREE_LIVE` | `auto` | `auto` probes live, falling back only when that release lacks it; `1` requires live; `0` installs verifier-only |
| `SHADE_TREE_INSTALL_DIR` | `$HOME/.local/bin` | User-writable destination directory, created if missing |
| `SHADE_TREE_FORCE` | `0` | `1` explicitly permits replacing a destination symlink to a file; directory links are always refused |
| `SHADE_TREE_TARGET` | detected | Override with one of the exact published target triples above |
| `SHADE_TREE_LIBC` | detected | Set `gnu` or `musl` only when Linux libc detection is unavailable |
| `SHADE_TREE_RELEASE_BASE` | GitHub Releases | Alternate network bases must use HTTPS; local schemes exist only for the offline selftest |

For example, pin the patched research preview while keeping automatic
target selection:

```sh
curl -q -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh \
  | SHADE_TREE_VERSION=v0.6.0 sh
```

The one-liner downloads code before you inspect it. To review it first, save it
locally, read it, and run `sh install.sh`. Git Bash or MSYS2 is required for the
installer on x86_64 Windows; PowerShell users can use the manual process below.

## Manual download and verification

Choose the `-live` asset for your platform from the
[latest release](https://github.com/dmarzzz/shade-tree-node/releases/latest).
Linux users can choose GNU for ordinary glibc distributions or musl for a
statically linked libc target. This x86_64 GNU example installs v0.6.0; change
`TARGET` to another published target from the table above when needed. `-q`
must be curl's first option so user configuration cannot disable TLS checks:

```sh
VERSION=0.6.0
TARGET=x86_64-unknown-linux-gnu
ASSET="shade-tree-$VERSION-$TARGET-live"
curl -q -fLO --proto '=https' --proto-redir '=https' \
  "https://github.com/dmarzzz/shade-tree-node/releases/download/v$VERSION/$ASSET"
curl -q -fLO --proto '=https' --proto-redir '=https' \
  "https://github.com/dmarzzz/shade-tree-node/releases/download/v$VERSION/$ASSET.sha256"
sha256sum -c "$ASSET.sha256"
chmod +x "$ASSET"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$ASSET" "$HOME/.local/bin/shade-tree"
shade-tree --version
```

The checksum detects transfer corruption or mismatch, but does not establish
publisher provenance when it arrives through the same channel. With the GitHub
CLI installed, verify the repository-bound build attestation as the stronger
provenance step:

```sh
gh attestation verify "$ASSET" --repo dmarzzz/shade-tree-node
```

On macOS, use `shasum -a 256 -c` instead of `sha256sum`. Only Apple Silicon has
a published `-live` binary; Intel macOS is verifier-only. The project does not
currently configure Apple Developer ID signing/notarization credentials, so
the macOS asset is checksummed and attested but not notarized. After verifying
the checksum, remove a Gatekeeper quarantine attribute if macOS added one:

```sh
xattr -d com.apple.quarantine ./shade-tree-0.6.0-aarch64-apple-darwin-live
```

On Windows, compare the digest printed by PowerShell with the contents of the
downloaded `.sha256` file before renaming the binary:

```powershell
Get-FileHash .\shade-tree-0.6.0-x86_64-pc-windows-msvc-live.exe -Algorithm SHA256
```

## No-Node agent quickstart

For the bundled public Sepolia Grove, create an owner-only identity and let the
client validate the secret/leaf/tier tuple before it contacts an RPC:

```sh
shade-tree enroll --limit 1 --out identity.json
chmod 600 funded-sepolia.key
shade-tree register-member --identity identity.json --key-file funded-sepolia.key
shade-tree member-status --identity identity.json --json
```

The payer may register an agent's public leaf as a sponsor without receiving its
identity file. The sponsor's address, leaf, amount, and timing are public and the
sponsor bears the slashing risk; only the identity holder can use or recover the
membership.

To reclaim an unslashed Sepolia bond, begin the ZK-authorized exit, wait for the
reported unbonding time, and withdraw to an explicit fresh recipient:

```sh
shade-tree exit-member --identity identity.json --key-file gas.key
shade-tree member-status --identity identity.json
shade-tree withdraw-member --identity identity.json \
  --recipient 0xFRESH_SEPOLIA_ADDRESS --key-file gas.key
```

The proof is made and checked locally before the exact transaction is simulated.
The gas wallet can differ from the registration payer and withdrawal recipient.
Losing `identity.json` makes the bond unrecoverable; exposing it gives away use and
exit authority.

For an invited, paid, or alternate Grove, continue with its operator-supplied
parameters.

First ask the Grove operator for:

- the exact rate tier (`limit`) for the leaf you will admit;
- an admission path (invited, staked, or paid);
- the Elder Tree onion and its raw 64-hex Canopy signer, or one pinned node;
- the matching membership input after admission.

Generate a new owner-only identity locally. `enroll` writes the secret material
to `identity.json` and prints only its public leaf to stdout:

```sh
read -r SHADE_TREE_LIMIT
shade-tree enroll --limit "$SHADE_TREE_LIMIT" --out identity.json > public-leaf.txt
```

Send only `public-leaf.txt` through the operator's admission process. This
command does **not** add the leaf to a remote Grove, submit an on-chain
transaction, or change a remote membership set. The optional `--members`
updates only an explicit local version-2 demo set. Do not continue until the
operator confirms that the leaf is in the exact member root its nodes use and,
for invited admission, gives you the corresponding `members.json`.

If you already have a Shade Tree secret, derive the same identity
deterministically instead of creating a new one:

```sh
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
shade-tree identity --limit "$SHADE_TREE_LIMIT" --out identity.json
unset SHADE_TREE_SECRET
```

Start the embedded-Arti Proxy in one terminal:

```sh
read -r SHADE_TREE_BOOTNODE_ONION
read -r SHADE_TREE_DIR_SIGNER
(umask 077; set -C; shade-tree proxy-token > proxy-token.txt)
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree proxy \
  --bootnode-onion "$SHADE_TREE_BOOTNODE_ONION" \
  --signer "$SHADE_TREE_DIR_SIGNER" \
  --identity identity.json \
  --members members.json \
  --listen 127.0.0.1:8118
```

If the operator gives you a static signed Canopy, replace
`--bootnode-onion "$SHADE_TREE_BOOTNODE_ONION"` with `--directory
directory.json`. If the operator gives you one pinned node, replace both
discovery flags with `--onion "$SHADE_TREE_ONION"`. Staked and paid profiles can replace
`--members members.json` with the operator's `--contract` and `--rpc-url`
values.

In a second terminal, launch only the agent through that Proxy:

```sh
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
shade-tree run --proxy http://127.0.0.1:8118 -- your-agent
```

The Proxy requires this unpredictable, URL-safe token even on loopback; another
local OS account must not be able to spend the member's RLN slots. `run` refuses
to launch the child if its authenticated preflight fails. It sets authenticated
HTTP, HTTPS, and WSS proxy URLs only for the child, removes the raw token and
other Shade Tree operator configuration from that environment, and leaves the
parent shell unchanged. An application that ignores standard proxy variables
must be configured directly with
`http://shade-tree:$SHADE_TREE_PROXY_TOKEN@127.0.0.1:8118`.

Token-file creation refuses to overwrite an existing path. Reuse that file only
for the same running Proxy, and remove it after the Proxy stops before generating
a replacement.

`identity.json` contains the member secret and must remain local. RLN slot
allocation is default-on and coordinates with JavaScript clients under the
public leaf in `SHADE_TREE_SLOT_STATE_DIR` (or the OS user-state directory).
`--slot-cursor <file>` is an exact state-path override, not an opt-in. The
manual `--slot` bypass requires
`--unsafe-allow-slot-reuse-for-slashing-tests` and must never be used with a
live or funded member.

Each accepted tunnel is also subject to the gateway's combined payload allowance
(40 MiB per RLN epoch slot by default). If an already-spent proof is refused before
CONNECT acceptance, the Rust client reports a payload-budget error and exits with
status 4 without rotating to another gateway. If the boundary is reached after
acceptance, the opaque TLS stream ends normally: the gateway cannot inject a reason
without corrupting end-to-end TLS, so the client deliberately treats that close as EOF.

## Other commands

The default and live variants can verify signed data without opening a tunnel:

```sh
shade-tree verify-directory directory.json --signer <ed25519-hex>
shade-tree select directory.json --signer <ed25519-hex> --seed 42
shade-tree fetch-directory --signer <ed25519-hex> \
  --bootnode-tcp 127.0.0.1:8080 --cache lkg.json
shade-tree verify-receipt receipt.json --onion <onion>
```

The live binary also exposes a one-shot tunnel:

```sh
shade-tree egress \
  --directory directory.json \
  --signer <ed25519-hex> \
  --identity identity.json \
  --members members.json \
  --target example.com:443
```

Run `shade-tree --help` for discovery, cache, capability, admission, and
transport options.

## Build from source

Repository contributors can use the pinned Rust toolchain and a C compiler:

```sh
git clone https://github.com/dmarzzz/shade-tree-node.git
cd shade-tree-node/rust

cargo build --release -p shade-tree-client
cargo build --release -p shade-tree-client --features live
```

The result is `target/release/shade-tree` (or `shade-tree.exe` on Windows).
Node.js remains part of the operator stack and some cross-language repository
tests; it is not required by the installed agent binary.
