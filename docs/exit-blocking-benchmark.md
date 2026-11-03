# Tor exit-blocking benchmark

How often, and in what way, do search engines and websites block a request that
arrives through a Tor exit IP? And is the blocking real IP-reputation hostility, or
just rate limiting on a shared address? This is the measurement behind the
"reputation, not more hops" thesis the egress is built on.

## Setup

Stock SearXNG in Docker with every outbound engine fetch routed through a Tor SOCKS
proxy (`outgoing.proxies: socks5h://tor:9050`). A driver rotates the Tor exit IP per
circuit via `NEWNYM`, labels each observation with the live exit IP, and fans each
query out to a frozen panel of engines (and a separate web-destination probe set),
recording one row per `(target, exit)` with a classified outcome. The fan-out is
free, so the budget is spent on exit-IP diversity, not request volume.

Engines are tiered by anti-bot protection: OPEN (wikipedia, wikidata), NICHE (mwmbl,
wiby), MID (mojeek, qwant, startpage), BIG (duckduckgo, bing, brave, google). The
discriminating contrast is off-diagonal: startpage (mid-size but Google-proxied) vs
mojeek (mid-size, unprotected). If protection rather than size drives the block, they
diverge. They do.

## Outcome classifier

Each `(target, exit)` observation is exactly one of: `OK`, `EMPTY` (no results, not a
block), `BLOCK`, `TIMEOUT` (reported as its own band, never folded into the
headline), `ERROR`, or `INFRA_FAIL` (SearXNG itself failed, excluded). Every `BLOCK`
also carries a `block_kind` so reputation blocking can be told apart from rate
limiting:

| block_kind | signal |
|---|---|
| `access_denied` | HTTP 403 / "forbidden" / "blocked" |
| `captcha` | CAPTCHA / interstitial |
| `challenge` | JS challenge page |
| `rate_limited` | HTTP 429 / "too many requests" |

## Result: how much is reputation, how much is rate limiting

The authoritative run (`run_max`, 51 exits) classified every block by kind, split by
arm:

| arm | observations | blocks | reputation (403 / captcha / challenge) | rate limit (429) |
|---|---:|---:|---:|---:|
| search engines | 6,024 | 2,217 (37%) | 62% | 38% |
| web destinations | 1,812 | 315 (17%) | 98% | 2% |

The two arms answer the rate-limiting question differently, and the difference is the
point. Search engines rate-limit a real fraction of the time, because SearXNG fans a
single query out to every engine on the panel from one shared Tor exit, so each engine
sees a burst. The actual websites, the ones an egress to the clearnet has to reach,
block almost entirely on reputation: 98 percent of their blocks are 403, CAPTCHA, or a
JS challenge, and only 2 percent are 429. The blocking that matters is reputation, not
throttling.

The blocking is also **bimodal by destination**: targets behind commercial anti-bot
vendors (Cloudflare, Akamai, DataDome) block in the 90 to 100 percent range, while the
open web (Amazon, Reddit, GitHub, Wikipedia, Hacker News) blocks roughly zero. The real
axis is the anti-bot wall, not Tor and not the size of the service.

## Controls against self-induced rate limiting

Even the search-engine 38 percent is an upper bound, because the run is built to not
provoke 429s in the first place:

- **K = 5 queries per exit** — a per-IP footprint indistinguishable from one person.
- **2.5 to 4 s jittered global spacing** between requests.
- **SearXNG's own limiter is off** (`server.limiter: false`), with a
  `searxng_self_limited` flag so SearXNG's own 429 can never masquerade as an engine
  block.
- **Auto-quarantine** of always-blockers after ~10 exits.
- **A block is the measurement, never retried** (the ethical invariant); only a
  circuit-level transport failure is retried once, on a fresh circuit, kept separate.

## Caveats

SearXNG normalizes upstream HTTP codes into reason strings, so bucketing is
approximate (a bare "http error" with no code is flagged `ambiguous_block` and not
counted as a block); a pilot is powered for the tier-level conclusion, not for
ranking engines within a tier; and pilot caps do not transfer to a scaled run, the
ethics change with the volume, not just the runtime.

## Re-running it on other exits

[`bench/egress/`](../bench/egress/README.md) generalizes this measurement to any exit
(direct, an HTTP CONNECT proxy such as the member Proxy, or SOCKS5 such as Tor) and four
clients (curl, Node, headless and headed Chromium), with the same outcome split (challenge,
CAPTCHA, 403 and 429 kept apart) and a JSONL plus markdown report.
