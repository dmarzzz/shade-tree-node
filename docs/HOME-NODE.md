# Running a node at home

For an operator who runs a Shade Tree node on a residential connection: what the node does to
that connection, how to set it up so it stays out of the way of the rest of the household, and
what to watch. The general runbook is [OPERATOR.md](OPERATOR.md); every knob is in
[CONFIG.md](CONFIG.md#operator-front-door-shadenet-node). Everything here is for the research
preview on Sepolia; the warning at the top of the [README](../README.md#research-preview) applies.

## What the node does to your connection

- **Your public IP becomes the exit IP** for other members' HTTPS tunnels. Destinations see your
  address, and so does any anti-bot vendor in front of them. That is the service a node
  provides, and it is the one real cost: reputation attached to your IP is shared with your own
  browsing. The [exit-blocking benchmark](exit-blocking-benchmark.md) measured what that looks
  like for Tor exits.
- **Tor runs as a client and an onion service only.** No relay, no exit flag, no inbound port, no
  router change. Your IP never appears on a Tor exit list.
- **Only port 443 by default.** The node sees the destination hostname, port, timing and byte
  counts. It never terminates TLS, so it never sees a URL, a request or a response. Keep
  `allow` at `*:443`; anything wider lets the node read plaintext.
- **Your LAN is fenced off.** The node resolves the destination, refuses loopback, private,
  link-local, carrier-grade NAT (`100.64.0.0/10`), multicast and every other special-purpose
  range, and dials the address it checked, so a DNS rebind cannot slip past. Treat this as one
  layer and add network isolation underneath it (below).
- **Logs and receipts carry no destination.** If a complaint ever arrives, you hold nothing that
  identifies the member or what they fetched.

## Before you start

- **Read your ISP's terms.** Many residential contracts forbid running a proxy service. An abuse
  complaint from a destination goes to your account, not the member's.
- **Use a fresh operator wallet.** The bond links the operator address to every onion it signs,
  and a member can always learn an onion's exit IP (any destination sees it, including one the
  member runs). Fund the wallet in a way you are comfortable having tied to your home address.
- **Put the node on its own network.** A guest Wi-Fi network, a VLAN or a separate device on an
  isolated port, with no route to the rest of the house. The address filter above is a code
  check; isolation is a wire check, and the two together mean a bug in one does not reach your
  router, NAS or printer. A Raspberry Pi or a mini PC on the guest network is enough.
- **Expect it to be quiet.** The network is small. With the settings below your node carries a
  trickle, which is the point.

## The configuration

The front door reads `SHADENET_*` variables or the same keys in `<state>/node.toml`. For a home
connection set the profile and list the services you personally depend on:

```toml
# /state/node.toml
record    = "https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json"
profile   = "home"
allow     = "*:443"
# deny wins over allow. list the services where a flagged ip would hurt your own account:
# a bank, an identity provider, a game launcher. `*.` matches subdomains only, so list the
# apex as well.
deny      = "yourbank.com:443,*.yourbank.com:443"
# optional: a public hosts-format blocklist (malware, phishing, adult), mounted read-only
# deny_file = "/blocklists/hosts.txt"
metrics   = "off"
```

`profile = "home"` presets five knobs and leaves anything you set yourself alone:

| Knob | Home preset | Node default | What it bounds |
|---|---|---|---|
| `weight` | `10` | `100` | How often canopy selection picks this node, relative to the fleet |
| `conns` | `32` | `1024` | Concurrent tunnels, decided at accept before a byte is read |
| `sessions` | `4` | `256` | Live session-ticket books; each book is paced at 512 KiB/s toward the agent and 64 KiB/s toward the destination |
| `bandwidth` | `2m` | unlimited | Bytes per second across every tunnel in both directions, one shared bucket with a second of burst. This is the hard ceiling on what the node draws from your line; `sessions` and `conns` bound the count, this bounds the rate |
| `canary` | `on` | `off` | The reputation canary below |

Every byte crosses your line twice (destination to node, then node to Tor), so `2m` is about
2 MiB/s of your uplink at most. `shadenet-node check` prints each knob with where it came from
(`profile home`, `env`, `node.toml` or `default`). Set any of them yourself to tune it to your
line; `0` on `conns`, `sessions` or `bandwidth` is unlimited.

Two things stay as the record sets them. The payload allowance per proof slot and the per-book
pacing are part of the signed rate policy clients compare against before choosing a node, so a
node that lowers them is skipped by clients. Leave `SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES` alone
and bound volume with `bandwidth`, `sessions` and `conns` instead.

Run the container with the hardening flags from the [operator guide](OPERATOR.md#one-container-one-record-url)
(no privilege escalation, no capabilities, read-only root, a memory cap) and nothing published:

```bash
docker run -d --name shadenet-node --restart unless-stopped \
  --security-opt no-new-privileges:true --cap-drop ALL --read-only --tmpfs /tmp \
  --memory 1g --log-opt max-size=20m \
  -e SHADENET_RECORD=https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json \
  -e SHADENET_PROFILE=home \
  -e SHADENET_OPERATOR=0x… -e SHADENET_OPERATOR_SIG=0x… \
  -v shadenet-node:/state ghcr.io/dmarzzz/shadenet-node:0.7.5
```

Metrics, when on, bind to loopback inside the container; read them with
`docker exec shadenet-node curl -s 127.0.0.1:9101/metrics`. Nothing needs a published port.

## The reputation canary

The thing a home operator most wants to know is whether their IP has started being scored, and
the first place that shows is not the node's logs but their own browser. The canary looks
before the browser does. With `canary = "on"` the node fetches a couple of pages behind anti-bot
vendors (by default the Cloudflare and DuckDuckGo front pages) from its own address, not through
Tor, every ten minutes. A `403`, a `429` or a Cloudflare challenge page counts as challenged; a
connection failure or a server error counts as nothing. Two challenged rounds in a row set the
drain flag, so the node announces `draining`, clients deprioritise it and open tunnels finish.
Three clean rounds in a row clear the flag again. The canary writes the word `canary` into the
flag and only ever removes a flag with that content, so a flag you set by hand is yours until you
remove it.

`SHADE_TREE_CANARY_URLS` picks other pages; choose ones behind the vendors that front the sites
you care about. `shade_tree_canary_challenged` and `shade_tree_canary_drained` show the state on
the metrics port, and a configured alert webhook gets `CanaryDrained` and `CanaryCleared`.

## If you also use ShadeNet at home

A node exits from its own public IP. If a client in your house picks your node, that client exits
from its own address and the tunnel hides nothing. The node adds its onion to the avoid-nodes file
of the user account it runs under, which covers a client on the same machine. For a client on
another machine behind the same connection, add the onion by hand:

```bash
shadenet-node identity                       # on the node: prints the onion
echo '<onion>' >> ~/.config/shadenet/avoid-nodes   # on the laptop
```

`SHADENET_AVOID_NODES` does the same for one session. Selection fails closed with
`only-own-nodes` rather than exit through a listed node.

## Pausing and stopping

- **Pause** without losing the onion: create the drain flag. The node announces `draining`,
  clients deprioritise it, and open tunnels finish.

  ```bash
  docker exec shadenet-node touch /state/draining    # pause
  docker exec shadenet-node rm /state/draining       # resume
  ```

- **Stop**: `docker stop shadenet-node`. The node leaves every Elder Tree's directory within the
  15-minute TTL. The identity stays in the volume; `docker volume rm shadenet-node` forgets it.

## What to watch

- **The canary drains the node, or your own browsing starts hitting captchas.** Leave it paused,
  wait a day, and come back with a lower `weight` or a lower `bandwidth`. Reputation scores
  decay; a quiet IP recovers.
- **A complaint from your ISP.** Stop the node and answer honestly: it is a proof-gated Tor
  onion service that forwards HTTPS on port 443, and you do not log destinations. Decide
  afterwards whether your contract allows it at all.
- **A dynamic IP changing.** Nothing to do. The onion is the node's name; the exit address can
  change underneath it.

## What the deny side can and cannot do

The deny list and the blocklist file match hostnames before DNS. They are the right tool for
keeping your own critical services off the node, and for refusing the hosts a maintained
blocklist names: malware, phishing, adult content. `deny_file` takes the hosts format the public
lists publish (`0.0.0.0 host` lines), covers subdomains of every entry, and is re-read within a
minute of the file changing, so a daily refresh of the file is enough. Mount it read-only into
the container.

They are not a content filter. The node cannot see what is fetched from a host it allows, and a
member who wants to know your IP can learn it from any server they control, so blocking IP-echo
sites hides nothing and breaks agents' egress checks. A refused target is `bad-target-policy`:
nothing was spent at your node, and both clients carry the same request to the next node, so a
refusal costs the member a little latency and your node nothing. A refusal everywhere is the
member's problem to solve with a destination that the canopy serves.
