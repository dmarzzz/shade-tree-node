# Egress benchmark

Which sites does an exit let an agent reach, with which client, and how does each site
refuse? This harness runs one exit x a set of clients x a site list x n passes, labels every
cell with one outcome, and writes JSONL. `report.mjs` turns any number of runs into markdown
tables; `dial.mjs` times the first and following tunnels through an exit.

It generalizes the Tor-only [exit-blocking benchmark](../../docs/exit-blocking-benchmark.md)
to any exit and any client, because both turn out to matter per site.

## Historical prototype observations (November 2026, n=3)

These are exploratory observations from a separate Python prototype, not a
controlled comparison or a reproduction from this published harness. The full
1,404-cell raw dataset is not included here. Bundled browser profiles, mutable
budgets and sampled (not pinned) exits confound causal conclusions.

A run on 2026-11-03 (6 exits: four Hetzner datacenter IPs in three ASNs, Tor, and the
research canopy through a member Proxy; 3 clients; 26 sites; 3 passes; 1,404 cells) showed:

- **Exit type matters per site, not on average.** Tor reached reddit and amazon (headed 3/3)
  where every datacenter IP failed (0/3), and failed nike and indeed, which the datacenter IPs
  passed. Per-exit totals were within a few points of each other. A single "% blocked per
  exit" hides this, so the report leads with per-wall and per-site tables.
- **Within datacenter, the individual IP matters as much as the provider.** One datacenter IP
  got through DataDome on g2 9/9 while three others in the same provider got 0/9.
- **The client is a big lever.** Headed Chromium beat curl on every exit; default headless was
  the worst client on every exit (it lost ddg, google, startpage and x outright).
- **Some walls stop every exit tried.** medium (Cloudflare), nytimes (DataDome) and expedia
  (Akamai + DataDome) were 0/3 for every exit, client and pass: the residential and mobile
  columns are the open question.
- **Cold start through the member Proxy.** The first dial after an idle Proxy took 5.9 to 30.1 s
  (median 13.7 s, n=5); warm dials took 0.9 to 3.2 s (n=19). A 30 s tool timeout would have lost
  one of five cold dials. A browser page opens many CONNECTs, and direct-proof/session-init can spend RLN slots (session redemptions differ), so the
  Proxy's own per-epoch budget (`epoch-budget`) refused tunnels during browser cells.

These are one night's numbers on one site list; bot scores drift. Re-run before quoting.
`sample/` has an older scrubbed smoke run with a dirty-tree provenance stamp, not
a digest establishing this exact executable source.

## Run it

Real runs are manual. Read [Politeness](#politeness) first.

```bash
npm ci
npx playwright install chromium                  # only for the headless/headed clients

# direct from this machine
node bench/egress/run.mjs --real --label dc-fsn --kind datacenter --out runs/dc-fsn.jsonl

# through the ShadeNet member Proxy (shadenet connect, default 127.0.0.1:8888)
node bench/egress/run.mjs --real --label shadenet --kind shadenet --exit http://127.0.0.1:8888 --gap 6 --out runs/shadenet.jsonl

# through Tor, a fresh circuit per site (null-auth control port of a throwaway tor)
node bench/egress/run.mjs --real --label tor --kind tor --exit socks5://127.0.0.1:9050 --tor-control 127.0.0.1:9051 --out runs/tor.jsonl

# headed Chromium on a Linux box with no display
xvfb-run -a node bench/egress/run.mjs --real --clients headed ...

# tables
node bench/egress/report.mjs --exits dc-fsn,tor,shadenet --clients curl,node,headless,headed runs/*.jsonl > REPORT.md

# cold vs warm dial: 3 samples, each after 10 minutes of Proxy idleness
node bench/egress/dial.mjs --real --label shadenet --exit http://127.0.0.1:8888 --idle 600 --series 3 --out runs/dial.jsonl
node bench/egress/report.mjs runs/dial.jsonl
```

`run.mjs --help` lists every flag. Defaults: clients `curl,node,headless,headed`, 3 passes,
4 s (+0 to 2 s jitter) between cells, 60 s between passes, 45 s per-cell timeout, seed 7.

### Exits

| `--exit` | What | Notes |
|---|---|---|
| `direct` | this machine's address | the datacenter, residential or mobile column, depending on where you run it |
| `http://HOST:PORT` | any HTTP CONNECT proxy | the member Proxy is one. It re-picks a node per CONNECT, so its cells belong to "the canopy", not one exit |
| `socks5://HOST:PORT` | any SOCKS5 proxy, remote DNS | Tor's SocksPort. `--tor-control` sends NEWNYM before each site and tags cells with a separate sampled exit lookup, not stream attribution |

`--kind` (datacenter, tor, shadenet, residential, mobile, other) and `--label` are free labels
that become the report's columns. Credentials in an exit spec are refused.

### Clients

| Client | What it is | Why it is a column |
|---|---|---|
| `curl` | the system curl | what a shell agent sends; its TLS fingerprint is part of the measurement |
| `node` | Node `http` over the same tunnel code as `dial.mjs` | what an agent written in Node sends |
| `headless` | Playwright Chromium, default headless, default context | what most agent stacks ship (HeadlessChrome UA) |
| `headed` | Playwright Chromium with a window, 1920x1080, en-US, AutomationControlled off | the closest to a person's browser |

One fresh browser context per cell. Client order rotates per site so no client always gets the
first request from a fresh IP. `headed` refuses to run without `DISPLAY` rather than quietly
running headless.

### Sites file

`sites.txt`, one per line: `tier name wall url [min=<bytes>] [ok-marker regex]`.

- `tier`: `search`, `web` or `api` (for `api`, an unauthenticated 401/403 carrying the marker
  counts as reachable).
- `wall`: the anti-bot vendor or policy in front of the site (cloudflare, akamai, datadome,
  perimeterx, aws-waf, own, none). The report groups by it.
- `ok-marker`: positive evidence the real page rendered. Without one, a 2xx is `unverified`.
- `min=N`: a marker match under N bytes is an interstitial wearing the site's title (amazon's
  "continue shopping" page, reddit's JS proof-of-work page), so it is a challenge.

The parser fails closed with a line number on any malformed line, a bad regex, or a marker with
an obvious nested quantifier. This heuristic is not a hostile-regex execution bound;
use trusted operator-supplied markers only. Use `--sites FILE` for your own list and
`--only a,b` for a subset.

### Outcomes

Exactly one per cell, in this order of precedence (`lib/classify.mjs` explains each rule):

| Outcome | Meaning |
|---|---|
| `ok` | 2xx and the positive marker matched (the marker wins over block markers: real pages embed captcha widgets) |
| `blocked-429` | 429 or a rate-limit page. Kept apart: rate limiting is about volume, the rest is about reputation |
| `blocked-challenge` | a JS or managed interstitial: `cf-mitigated: challenge`, "Just a moment", AWS WAF, a CloudFront empty 202, proof-of-work pages, a size-guard hit |
| `captcha` | an interactive test: reCAPTCHA, hCaptcha, PerimeterX press-and-hold, DataDome, DuckDuckGo ducks, Yandex SmartCaptcha |
| `blocked-403` | 403/451 or a deny page with no challenge offered |
| `timeout` / `error` | transport timeout; proxy or transport error, no status, or 5xx |
| `cancelled` | operator interruption (`error:cancelled` transport), not a timeout or site refusal. Report abbreviation `can`; retained in the all-cell denominator with an interrupted-run warning. |
| `unverified` | a status with neither a positive nor a block marker; look at it by hand (`--shots DIR` saves a screenshot of every non-ok browser cell) |

No retries: a block is the measurement.

### Output

Each `run.mjs` invocation appends to `--out`: one `{"type":"meta"}` row (harness commit, Node,
Playwright, Chromium and curl versions, host, sites file hash, exit spec, exit ASN/country, the
arguments), then one row per cell (exit, client, pass, site, wall, status, outcome, marker,
title, vendor, bytes, time, failed requests including main-document failures, evidence headers). `dial.mjs` rows are
`{"type":"dial"}` with tunnel, TLS and total time per phase.

## Politeness

- Landing pages and one fixed search query only. No logins, no crawling past the first page.
- One human-scale footprint per IP: the defaults are 3 passes, a 4 to 6 s gap between cells and
  a minute between passes. The CLI will not go below a 2 s gap for real sites.
- `--ua polite` makes curl and Node send `shadenet-egress-bench/1 (+repo URL)` so a site can see
  what it is. The default is a stock Chrome UA, because the question is what an agent faking a
  browser gets; say which one you used.
- If a site asks you to stop, take it out of your sites file.
- Through the member Proxy, direct-proof/session-init requests spend RLN slots; session-ticket redemptions may reuse them. Raise `--gap` if the
  external proxy logs show `epoch-budget` errors (rows do not preserve that typed reason), or you measure your own budget instead of the site.

## What CI runs

`classify.selftest.mjs`, `parse.selftest.mjs` and `harness.selftest.mjs` run in `npm test` like
every other selftest. They start a loopback origin that serves caricatures of each wall, an HTTP
CONNECT proxy, a SOCKS5 server, hostile proxies (garbage reply, endless header, hang-up, 407,
silence) and a fake Tor control port, then drive every client and the CLIs through them. A host
name that only resolves inside the fixture proxies proves that "via proxy" traffic really went
through the proxy. Browser cases run when Chromium is installed and are reported as skipped
otherwise. Fixture servers bind loopback and fixture proxies reject external targets.
This is not proof of browser background/DNS isolation; use an OS sandbox for that.

## Not covered yet

Residential and mobile exits (run `direct` from such a connection; the columns appear in the
report by label), pinning the member Proxy to one node for per-exit attribution, stealth browser
builds, and IPv6-only runs.

## Measurement and repair limitations

Exit lookups are **samples**, including after Tor NEWNYM, not attribution of a
site, stream, or browser subresource to that exit. Headed vs headless is a bundled
profile comparison: binary mode, viewport, locale, timezone and automation flags
change together. Historical samples are exploratory smoke tests with different
gaps and shared mutable budgets, not controlled scheduling or exit-quality evidence.
The historical dirty-tree stamp is not a digest of the executable source.

Without `--real`, and under CI, exit lookup is disabled, proxy/control hosts must
be loopback, Node rejects off-loopback redirect hops, curl refuses redirects, and
browser request routing blocks off-loopback URLs and service workers. This is NOT
an OS network sandbox: browser background traffic, DNS and WebRTC are not certified
isolated. For strict offline execution use an OS network namespace/firewall; never
run untrusted pages relying on the initial URL check as a sandbox.

Browser cell deadlines include lazy process launch on the first cell of each mode,
context/page setup, settling and screenshots, with context cancellation. Later cells
reuse the process, so their timings are not fresh-process cold starts. Cleanup may
finish after a timeout result. SIGINT/SIGTERM cancel active clients and pacing;
control-port waits retain their bounded timeout. SIGKILL cannot guarantee cleanup.
Playwright launch cancellation closes a late-arriving process; launch's own timeout
also bounds startup. This is not an OS-level process-tree containment guarantee.

Node oversized bodies are errors, not successful truncated content. Curl requests
have a 12 MiB max-filesize plus a bounded stdout collector for decoded content (no
body downloads to disk); browser CDP counts 12 MiB across received subresources
and closes the context. These are application limits, not a hard OS memory/disk
quota. Browser DOM expansion and in-flight bytes can exceed the threshold. Do not
run hostile resource-exhaustion fixtures without OS resource limits.

Screenshots are attempted only for non-ok browser cells, best effort within the
cell deadline. Timeout cells may have no screenshot. Browser failed_reqs includes
main-document failures, not solely subresources. Raw files remain private research
artifacts: argv URL values and remote proxy specs are redacted, but page titles,
headers, URLs and screenshots can still contain identifying content. Review and
scrub before publication; do not publish arbitrary output automatically. New CLI
files use a private umask. Report warnings identify incomplete/unverified cohorts;
duplicates and mixed runs under the same label are rejected.
