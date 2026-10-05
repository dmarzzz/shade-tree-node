// The one place that says which network record the site is built from.
//
// Since the ShadeNet launch (M8, 2026-09-30) the fleet, the Lab and the agent examples run on the
// production record (network/sepolia), so the Get access page and its same-origin status API
// build from it too. The staging record (network/sepolia-staging) stays for rehearsals.
//
// scripts/build-stake-site.mjs and scripts/site-record-loader.mjs redirect this import when
// SHADENET_SITE_NETWORK names another record (the staging rehearsal builds a private page that way).
import deployment from "../network/sepolia/deployment.json" with { type: "json" };

export const SITE_NETWORK = "sepolia";
// The newest release whose installer puts a `shadenet` binary on the PATH (v0.6.0 shipped only
// `shade-tree`, without `init`, `status` or `mcp`). Install lines pin it until it is Latest.
export const CLIENT_RELEASE = "v0.7.1";
export default deployment;
