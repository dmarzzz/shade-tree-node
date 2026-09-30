// The one place that says which network record the site is built from.
//
// Today the fleet, the Lab and the agent examples all run on the Sepolia staging record
// (network/sepolia-staging), so the Get access page and its same-origin status API build from it
// too; a page pinned to the retired production set would take a stake no node reads.
// M8 (production launch): point this at ../network/sepolia/deployment.json in the same PR that
// records the production contracts, and bump CLIENT_RELEASE to the launch tag.
//
// scripts/build-stake-site.mjs and scripts/site-record-loader.mjs redirect this import when
// SHADENET_SITE_NETWORK names another record (the staging rehearsal builds a private page that way).
import deployment from "../network/sepolia-staging/deployment.json" with { type: "json" };

export const SITE_NETWORK = "sepolia-staging";
// The newest release whose installer puts a `shadenet` binary on the PATH (v0.6.0 shipped only
// `shade-tree`, without `init`, `status` or `mcp`). Install lines pin it until it is Latest.
export const CLIENT_RELEASE = "v0.7.0-rc.1";
export default deployment;
