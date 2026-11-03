# Sample run

A small real run made with this exact code on 2026-11-03 between 05:14 and 05:25 UTC, to show
the output format and to prove the harness works against real sites through a real member
Proxy. It is a smoke test, not a result: 5 sites, 2 passes, one machine, ten minutes.

- `datacenter.jsonl`: `--exit direct` from a datacenter host (AS24940, DE).
- `shadenet.jsonl`: the same host, through a member Proxy (`shadenet connect`,
  `http://127.0.0.1:8888`) on the research canopy, run at the same time with `--gap 6`.
- `dial.jsonl`: one cold and four warm dials through the same member Proxy.
- `REPORT.md`: `node bench/egress/report.mjs --exits datacenter,shadenet --clients curl,node,headless,headed bench/egress/sample/*.jsonl`.

Commands:

```bash
xvfb-run -a node bench/egress/run.mjs --real --label datacenter --kind datacenter \
  --only hn,wikipedia,reddit,nike,amazon --passes 2 --pass-gap 20 --out datacenter.jsonl
xvfb-run -a node bench/egress/run.mjs --real --label shadenet --kind shadenet --exit http://127.0.0.1:8888 \
  --only hn,wikipedia,reddit,nike,amazon --passes 2 --pass-gap 20 --gap 6 --out shadenet.jsonl
node bench/egress/dial.mjs --real --label shadenet --exit http://127.0.0.1:8888 --warm 4 --out dial.jsonl
```

Scrubbed before commit: exit IPs (the meta rows keep ASN and country only) and local paths in
the recorded arguments. The dial rows predate the salted exit hash and carry neither.

How to read it:

- reddit (403 on every client from the datacenter IP) and amazon (AWS WAF challenge for
  curl and Node) behave as in the November 2026 matrix.
- The ShadeNet errors are `ERR_TUNNEL_CONNECTION_FAILED` and `connect-refused-502`: the
  member Proxy refused the tunnel. Its log over the window shows 587 `epoch-budget` refusals.
  That is the Proxy's own per-epoch slot budget (each CONNECT spends a slot, and a browser
  page opens many), not the site. This is the effect the README's Politeness section warns
  about, and it is why `--gap` exists.
- The Proxy had restarted a few minutes before the run, which is why the cold dial (1.2 s
  tunnel) is far faster than the 5.9 to 30.1 s seen after ten minutes idle.
- Two cells are worth a look by hand, which is what the labels are for: headed amazon pass 1
  through ShadeNet is `unverified` (a 35 KB page with an empty title and no marker, neither the
  real 580 KB homepage of pass 2 nor a known interstitial), and headed hn pass 1 direct is an
  `error` because Hacker News answered 503 (its own rate limiter).
