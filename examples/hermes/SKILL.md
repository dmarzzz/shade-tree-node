---
name: shadenet
description: Fetch web pages from an anonymous, unlinkable IP through ShadeNet when a site blocks Tor, VPN or datacenter IPs, or when a request must not be linked to this machine.
---

# ShadeNet

ShadeNet routes a request through a Shade Tree node reached over Tor. The
destination sees the node's IP, never this machine's, and the node cannot tell
which member is asking. Each fetch spends one tunnel from a small budget that
resets every epoch (60 seconds on the public network).

## Use `shadenet_fetch` when

- a site refuses the normal connection (captcha wall, 403 from a datacenter IP);
- the request should not be linkable to this machine or this operator;
- the task is reading public web content over https.

## Do not use it for

- model or API calls (they have their own network path and would waste budget);
- anything behind a login, or anything that needs cookies from another session;
- `http://` URLs or ports other than 443 (refused with `port_not_allowed`);
- localhost or private addresses.

## Budget

Call `shadenet_status` before a batch: `slotsLeft` is how many fetches remain
this epoch and `epochResetsInSeconds` when the budget refills. Prefer one fetch
of a page that links to what you need over many small fetches.

## Errors

Every error has a `code`, a `cause` (why, in plain words: which RPC dropped
history, which node is restarting, that the identity is in another network's
set) and a `fix` (what to run). Read the cause before deciding; the code alone
often points the wrong way.

- `budget_exhausted`: wait `retryAfterSeconds`, then retry.
- `not_admitted` or `not_finalized`: stop and tell the operator the `cause` and `fix`; retrying will not help.
- `port_not_allowed`: use the https URL.
- `no_eligible_node`, `transport`, `canopy`, `rpc`: temporary; retry once after `retryAfterSeconds`.
- `node_refused`: retry once (the proxy rotates nodes); if it repeats, report the `cause`.

Before retrying anything, call `shadenet_status` and read `problems`: each
entry has `kind`, `code`, `cause` and `fix`. `kind: incident` entries are what
the canopy's operators declared (a node being restarted, an Elder down) and
carry `instance` and `since`; wait them out rather than retrying hard. When a
`fix` says to run `shadenet doctor`, tell the operator; it is a shell command.

## Search

When `shadenet_search` is available, prefer it to fetching a search engine's
result page yourself: it queries a SearXNG instance whose blocked engines are
already routed through ShadeNet.
