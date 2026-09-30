# Fleet map (privacy-preserving diversity view)

A tiny, zero-dependency generator that renders the fleet's **geographic / network diversity** —
how many independent vantage points the rotation spreads across — as a **self-contained** HTML page
(inline CSS + inline SVG, no CDN, no map tiles, no fonts, no `<script>`). It opens straight from
`file://` with no network.

It is a *diversity view, not a location map*. There is no world map, no pin, no coordinate.

## The data-source honesty note (read this first)

Onion services **have no clearnet IP by design**, and the fleet is deliberately non-enumerable. The
signed directory ([`packages/node/lib/directory.mjs`](../packages/node/lib/directory.mjs)) is exactly
`{ onion, pubkey, weight, health }` and carries **no geo/ASN field**. So:

- **There is nothing to geolocate, and this tool never tries.** `onion → country` is both
  impossible (no IP) and against the threat model (it would deanonymize an operator).
- Every bar comes **only** from *optional, operator-self-declared, coarse* labels a gateway may
  voluntarily advertise, added to its directory entry:

  ```jsonc
  { "onion": "…", "pubkey": "…", "weight": 100, "health": "up",
    "region": "eu-west",     // OPTIONAL coarse region slug — never a city / lat-long
    "asn": "AS13335" }       // OPTIONAL coarse AS group
  ```

  A gateway that declares nothing lands in the `undeclared` aggregate. These labels are a
  **self-declared hint**, not a signed guarantee — the map is illustrative, not a trust root.
- For the demo, [`fleet-map.sample.json`](fleet-map.sample.json) is a static example dataset.

## Privacy model

- **Aggregate only.** Output is per-bucket **counts** (+ summed weight). No onion, no pubkey, no
  operator, no per-gateway row ever reaches the page.
- **Small-bucket fold (k-anonymity).** A region or ASN declared by **fewer than `k`** gateways is
  never shown under its own name — it merges into a single **unnamed `other`** bucket. Default
  `k = 2` (a named bar always stands for ≥ 2 gateways, so it can never mean "exactly one"). This is
  the line that stops the map from revealing *"the only gateway in region X is …"*: the region's
  **name** is dropped at the fold and never reaches the page. The `other` bar is intentionally
  nameless, so the folded remainder is attributable to no specific region/network. Raise `k` with
  `SHADE_TREE_FLEET_MAP_K` for a larger anonymity set.

## Run it

```bash
# sample dataset -> ./fleet-map.html
node web/fleet-map.mjs

# a real directory JSON -> ./fleet-map.html
node web/fleet-map.mjs path/to/directory.json

# explicit output path
node web/fleet-map.mjs directory.json out.html

# stronger fold threshold (larger anonymity set)
SHADE_TREE_FLEET_MAP_K=3 node web/fleet-map.mjs
```

The generated `.html` is fully self-contained — open it directly in a browser, no server needed.

## Test

```bash
node web/fleet-map.selftest.mjs   # fold invariant + self-contained/aggregate-only
```

The selftest pins the **small-bucket-fold invariant** (a region/ASN with `< k` gateways is not
shown individually, in neither the bucket output nor the rendered HTML), that raising `k` folds
more, that the page contains **no external URL** (no `http(s)://`, no protocol-relative host, no
`<script>`/`<link>`/`<img>`/`url(http…)`/`@import`) and leaks **no onion or pubkey**. It is
auto-discovered by `node scripts/test-all.mjs`.
