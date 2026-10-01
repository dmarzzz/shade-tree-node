// Launch-boundary regression checks: public docs must distinguish the current disposable v4
// research Grove from the retired runtime records, monitoring must cover the public consumer,
// and the next-node recipe must improve provider/ASN independence without weakening host safety.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(join(ROOT, path), "utf8");
const checks = [];

function check(name, condition) {
  assert.ok(condition, name);
  checks.push(name);
  console.log(`  ok   ${name}`);
}

const frontDoors = [
  "README.md",
  "docs/README.md",
  "docs/OVERVIEW.md",
  "docs/QUICKSTART.md",
  "docs/JOIN.md",
  "docs/CLIENTS.md",
].map(read);
const deployment = JSON.parse(read("network/sepolia/deployment.json"));
const sepoliaReadme = read("network/sepolia/README.md");
const deploymentPlan = read("docs/DEPLOYMENT-PLAN.md");
const operator = read("docs/OPERATOR.md");
const uptime = read("monitoring/UPTIME.md");
const uptimeEnv = read("monitoring/uptime/uptime-probe.env.example");
const workflow = read(".github/workflows/uptime-probe.yml");
const groveLoader = read("docs/post/grove/network.js");

check(
  "public front doors no longer claim that the Grove observes only the retired fleet",
  frontDoors.every((doc) => !/public (?:aggregate )?Grove observes (?:that|the) old fleet/i.test(doc)),
);
check(
  "public front doors distinguish current v4 metadata from legacy runtime records",
  frontDoors.every((doc) => /(?:deployment\.json|disposable v4|v4 research (?:Grove|canopy))/i.test(doc)),
);
check(
  "current deployment receipt is explicitly v4, invited-and-staked, disposable research on ceremony proof keys",
  deployment.status === "live"
    && deployment.protocol?.min === 4
    && deployment.protocol?.max === 4
    && deployment.admission?.paths?.includes("invited")
    && deployment.admission?.paths?.includes("staked")
    && /^0x[0-9a-f]{40}$/i.test(deployment.admission?.roots?.staked?.contract || "")
    && /^https:\/\//.test(deployment.admission?.roots?.staked?.rpcUrl || "")
    && Number.isInteger(deployment.admission?.roots?.staked?.deployBlock)
    && deployment.admission?.operatorAuthorization?.approved === true
    && deployment.security?.proofArtifacts === "trusted-ceremony"
    && deployment.security?.scope === "disposable-research",
);
check(
  "Sepolia index publishes the explicit testnet staking profile without reviving the legacy preset",
  /deployment\.json[\s\S]*live disposable Protocol v4/.test(sepoliaReadme)
    && /Live discovery and testnet staking/.test(sepoliaReadme)
    && /retired legacy preset stays disabled|retired network preset/.test(sepoliaReadme)
    && /Invited membership\s+material remains private/.test(sepoliaReadme),
);
check(
  "deployment plan records the launched research preview on ceremony proof keys",
  /ShadeNet research preview launched on Sepolia \(M8\) · proof keys from the PSE trusted setup/.test(deploymentPlan)
    && /trusted-ceremony/.test(deploymentPlan)
    && /issue #6/.test(deploymentPlan),
);
check(
  "second-provider recipe requires ASN independence and an SSH-only host boundary",
  /second provider \/ ASN/i.test(operator)
    && /AS14061/.test(operator)
    && /ipinfo\.io\/<new-node-public-ip>\/org/.test(operator)
    && /only TCP 22 from the reviewed operator CIDR inbound/.test(operator)
    && /operator `\/32`/.test(operator),
);
check(
  "second-provider recipe pins the existing Elder and requires end-to-end verification",
  /SHADE_TREE_BOOTNODE_ONION=<v4-elder\.onion>/.test(operator)
    && /SHADE_TREE_BOOTNODE_SIGNER=<pinned-canopy-signer>/.test(operator)
    && /same\s+reviewed immutable ref/.test(operator)
    && /real invited CONNECT returns the new provider address/.test(operator)
    && /provider abuse contact/.test(operator),
);
check(
  "hosted observer keeps legacy capability verification disabled for the current Grove",
  /SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS=0/.test(uptime)
    && /SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS=0/.test(uptimeEnv)
    && /keep 0 for the current v4 Grove/.test(workflow),
);
check(
  "browser falls back from v2 to the separately verified v1 head before bundled data",
  /fetchSnapshot\(LIVE_URL\)[\s\S]*fetchSnapshot\(COUNT_FALLBACK_URL\)/.test(groveLoader)
    && /fetchSnapshot\(FALLBACK_URL\)/.test(groveLoader),
);
check(
  "publisher success is followed by a bounded production page and API check",
  /verify-public:[\s\S]*needs: publish/.test(workflow)
    && /\/grove\//.test(workflow)
    && /api\/v1\/data\/grove\/sepolia\/head/.test(workflow)
    && /api\/v2\/data\/grove\/sepolia\/head/.test(workflow)
    && /for attempt in \$\(seq 1 12\)/.test(workflow),
);

console.log(`\n${checks.length} launch-readiness checks passed`);
