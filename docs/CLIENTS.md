# Proxy modes: local process or library

A proxy runs beside the agent. A node accepts the proof and provides egress. The Elder Tree serves the signed Canopy. The implementation and environment variables still use `client`, `gateway`, and `bootnode` in places. Those names remain compatible.

> **v4 status.** The current client speaks envelope v4 only. The current disposable v4 Sepolia
> Grove's Elder+signer pair is bundled as the discovery default. The legacy Sepolia contract and
> directory files remain incompatible pre-v4 history. Discovery is not admission: the public
> profile does not publish the invited membership inputs required to connect.

The node needs a **fresh RLN proof per tunnel**. That is what makes the nullifier,
the per-epoch rate cap, and the slashing work, so *something* client-side must mint it. What
varies is where that "something" lives. There are four shipped shapes and one planned.

## The irreducible part

Every CONNECT tunnel carries one Groth16 proof bound to a fresh `(epoch, slot)` nullifier. You
cannot set it once and reuse it: reusing a nullifier with a different signal is exactly the
over-spend the gateway slashes on. So every proxy, library, or CLI client regenerates the
proof per tunnel. The JavaScript library and Proxy share the same hardened core
(`client/shade-tree-client.mjs`): one proof per logical tunnel, deterministic across gateway
failover (same signal → same share), plus slot + gateway rotation. The Rust live binary is
wire-compatible, shares the same default-on slot-state format, and exposes one reusable
`shadenet-egress` implementation to both its CLI and Rust callers.

## Option A: library (`ShadeTreeClient`)

Use this when the client is **your own code** (e.g. an agent doing many queries). No local
proxy; just call a function. `client/shade-tree-client.mjs`:

```js
import { ShadeTreeClient, cleanUp } from "./client/shade-tree-client.mjs";

const shadeTree = new ShadeTreeClient({
  secret,        // enrolled member secret (or SHADE_TREE_SECRET)
  torPort: 9260, // client Tor SOCKS; discovery uses the bundled current-v4 Elder+signer
  // or: bootnode: "…", dirSigner: "…"  to select an alternate signed Canopy
  // or: onion: "…"  to pin a single gateway instead of fleet rotation
});

const res = await shadeTree.fetch("https://api.ipify.org");    // { status, headers, body }
// lower level; bring your own TLS/protocol over the raw tunnel:
const sock = await shadeTree.connect("api.ipify.org:443");     // duplex, tunneled via a gateway
// sock.shadeTree = { onion, slot, nullifier, receipt, artifact, leafSource }

cleanUp();  // terminate snarkjs workers so the process can exit
```

- `fetch(url, { method, headers, body })` → HTTPS over the tunnel; **TLS is end-to-end** to
  the target (the gateway relays ciphertext only). `https://` only (the gateway egresses :443).
- `connect("host:443")` → the raw duplex tunnel, if you want your own protocol.
- Each call rotates gateway + slot and reuses one proof across failover.

With no explicit discovery source, `new ShadeTreeClient({ secret, torPort })` uses the bundled
current-v4 Sepolia Elder+signer pair. Pass `{ bootnode, dirSigner }` (or set the corresponding
environment variables) to override them. For a single node, set `SHADE_TREE_ONION` or pass
`{ onion }`. The live Canopy is refreshed in the background about every five minutes with jitter.

Runnable example: `examples/agent-fetch.mjs`. Point it at your local fleet or an operator's
v4 configuration before running it.

## Egress selection and switching

For each new CONNECT tunnel, the client filters the verified Canopy by admission policy and
capabilities, then uses smooth weighted round-robin for the first healthy node. Equal-weight nodes
alternate evenly; unequal weights retain their long-run share. The remaining nodes form a weighted-
random failover order for that tunnel. Set `--no-rotation-spread` or
`SHADE_TREE_ROTATION_SPREAD=0` to opt out and make the first choice weighted-random too.

The same proof, slot, and Tor isolation credential are reused within one tunnel's failover attempt.
Dial/framing failures rotate to the next onion. Proof, policy, replay, and `payload-limit` refusals
are terminal and are not routed around. The Rust client treats every gateway refusal as terminal;
only transport/framing failures rotate. Two local dial failures mark a node down; future selections
skip it while healthy choices exist, and a later success recovers it. The JavaScript Proxy's
periodic Canopy refresh adds and removes onions without a restart while carrying forward health for
unchanged nodes. The Rust Proxy fetches a current signed Canopy at each new CONNECT instead, so its
next tunnel sees a new list even though it does not poll while idle.

## Leaf source + admission filtering + `--max-anon` (T-FEAT-9, both options)

Your leaf lives in one set: `members.json` (**invited**), a `StakedReputationSet` (**staked**), or
the `PaidAccessSet` (**paid**). Each gateway advertises which of those it admits as signed caps
(`admits`, in the anonymity order invited > staked > paid; `docs/adr/0008`). The client:

- discovers your **leaf source** (`makeLeafSourceLoader`: members.json first, then the staked sets,
  then the paid set; `SHADE_TREE_LEAF_SOURCE=invited|staked|paid` / `{ leafSource }` / `--leaf-source`
  pins the set if your leaf is in several), and
- routes ONLY to gateways whose `admits` include it (`selectCandidates(req, { leafSource, maxAnon })`
  → `filterByAdmission`). A gateway that advertises no policy is assumed to admit any path during
  the rollout (logged once); if NO gateway admits your leaf source the client fails closed:
  `no gateway admits a paid leaf (your leaf source); fleet: abcd..=[invited,staked] efgh..=[invited] …`.
- `--max-anon` / `SHADE_TREE_MAX_ANON=1` / `{ maxAnon: true }`: the maximum-anonymity mode. Only gateways
  whose `admits` is EXACTLY `["invited"]` (their whole population is invited; a policy-less gateway
  cannot prove it and is excluded), and the client REFUSES to run with a staked/paid leaf before any
  proof or dial; `--max-anon: your leaf is in the paid set (the buyer address -> operator transfer
  and tier bucket are public); an invited-only gateway would reject it (wrong-group-root)…`. No
  invited-only gateway in the directory: `--max-anon: no invited-only gateway in the directory …
  fleet: …` (if no node in an operator's v4 directory is invited-only, this refusal is the
  correct outcome).
- A pinned `onion` is honoured as-is (its policy is unknown to the client; a mismatch surfaces as
  the gateway's `wrong-group-root`), except that `--max-anon` still refuses a staked/paid leaf.
- Events: a live Elder refresh emits the local `canopy` phase with `query`, then `verified`, `cache`, or `error`. It contains only the signed issue time and node count when available. No event is sent to another service. Selection then emits `select` as before.

```bash
shade-tree proxy --max-anon

shade-tree proxy --leaf-source paid --limit 32 \
  --paid-access-contract <v4-paid-set-address>
```

## Option B: local proxy (`client/shim.mjs`)

Use this when the client is a **stock tool** you can't change (browser, curl, any
`http_proxy`-aware app). The shim is now a thin HTTP-CONNECT front-end over the same
`ShadeTreeClient`. Load `SHADE_TREE_SECRET` with the hidden prompt in the
[agent guide](AGENT.md), then run:

```bash
SHADE_TREE_TOR_PORT=9260 shade-tree proxy \
  --bootnode <v4-elder.onion> --dir-signer <v4-directory-signer-hex>
# then: curl -x http://127.0.0.1:8888 https://api.ipify.org
```

The default Elder onion and signer are a bundled pair. When overriding them, copy both from the
same v4 operator and pin the signer out of band. Add `SHADE_TREE_LIMIT=32` (`--limit 32`) if your
leaf is a tier-32 one, plus the v4 paid-set address if it is a paid leaf (`docs/PAYMENTS.md`).

Env, if you want to override discovery: `SHADE_TREE_SECRET`, then one discovery source:
`SHADE_TREE_BOOTNODE_ONION`+`SHADE_TREE_DIR_SIGNER` (operator's v4 fleet),
`SHADE_TREE_DIRECTORY`+`SHADE_TREE_DIR_SIGNER` (an operator-supplied static signed directory), or
`SHADE_TREE_ONION` (pin one gateway); plus `SHADE_TREE_TOR_HOST`/`SHADE_TREE_TOR_PORT`. The routed
`shade-tree proxy` command fails before startup when a directory or Elder Tree is configured without
its pinned signer. A direct SDK import or `node client/shim.mjs` bypasses that router validation and
can reach the local-development `tor/hs/hostname` fallback, so treat a missing signer there as a
configuration error too.

## Option C: self-contained Rust proxy (embedded Arti)

Use the Rust live binary when an agent or generic server should consume a local
HTTP CONNECT proxy without installing a client-side Tor daemon. The binary
contains Arti, the RLN prover, and the locked proof artifacts:

```bash
cargo build --release -p shadenet-cli --features live

(umask 077; set -C; ./target/release/shade-tree proxy-token > proxy-token.txt)
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
./target/release/shade-tree proxy \
  --onion <v4-gateway.onion>:80 \
  --identity identity.json \
  --members members.json \
  --listen 127.0.0.1:8118

# In the agent terminal:
IFS= read -r SHADE_TREE_PROXY_TOKEN < proxy-token.txt
export SHADE_TREE_PROXY_TOKEN
./target/release/shade-tree run -- your-agent
```

Omit the transport flags to use the bundled current-v4 Elder+signer. Use
`--directory <file> --signer <hex>` or `--bootnode-onion <onion> --signer <hex>`
to override signed discovery, or `--onion` to pin a node. Create a new
`identity.json` with `shade-tree enroll --limit N --out identity.json`, send
only its printed public leaf through the operator's admission process, and wait
for the matching root/member input. Identity creation does not itself admit the
leaf. Use `shade-tree identity` only to derive from an existing secret. The
resulting file contains secret material and must stay local.

The Proxy requires an unpredictable URL-safe token of at least 32 characters;
loopback alone does not isolate different OS accounts. It returns `200
Connection Established` only after a node accepts the proof and connects to the
target. It keeps one successfully bootstrapped base Arti client for the service
lifetime. Each logical CONNECT gets an isolated Arti view reused only across
that tunnel's gateway candidates. Launch one child with an authenticated,
fail-closed preflight and process-scoped proxy variables:

```bash
shade-tree run --proxy http://127.0.0.1:8118 -- your-agent
```

## Option D: in-process Rust client (`shadenet-egress`)

Rust services that own their networking can use the same async client behind
the live binary through a Git or path dependency. The workspace crate is not
currently published on crates.io. It accepts the CLI's verified candidates and
owns RLN proof construction, persistent slot allocation, one service-lifetime
`Arc<TorClient>`, gateway failover, and the accepted bidirectional stream.
Groth16 proving runs on a bounded blocking worker so it does not stall the
async network executor.

The CLI `egress` and `proxy` commands are consumers of this crate; they do not
fork the protocol or transport logic. FFI is deliberately out of scope. Other
languages should use Option C's loopback CONNECT boundary. See
[ROADMAP.md §2.6](ROADMAP.md#26-reusable-in-process-rust-client--p2) for the
implemented lifecycle and acceptance criteria.

## Planned: stock HTTP CONNECT + `Proxy-Authorization`

Teach the gateway to also speak a standard HTTP CONNECT proxy and read the proof from a
`Proxy-Authorization: RLN <base64>` header, so plain `curl -x http://<onion>:80` works with
no shim and no library; you just need a one-shot `shade-tree-prove <target>` to mint the header:

```bash
curl -x http://<onion>:80 \
  --proxy-header "Proxy-Authorization: RLN $(shade-tree-prove example.com:443)" \
  https://example.com
```

This removes the client software **for scripted one-shot requests**. It does **not** serve
multi-request clients (a browser/agent that sets the proxy once) safely: `Proxy-Authorization`
is static, but the proof must be fresh per tunnel; reusing it across targets either breaks
the rate cap or self-slashes. So B is a great gateway interface + a clean one-shot path, but
multi-request clients still need A or D (library), or B or C (local Proxy). Not
built yet.

Note: the proof (~400+ bytes) does **not** fit SOCKS5 username/password (RFC 1929 caps each
at 255 bytes), which is why B rides on HTTP CONNECT, not SOCKS auth.
