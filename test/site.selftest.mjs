// Static-site regression checks for the compact landing page, research note,
// signed public Grove, and privacy-preserving Three.js scenes.

import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { grovePublicKeyRawBase64, verifyPublicGroveAttestation } from "../lib/public-grove.mjs";
import * as THREE from "../docs/post/vendor/three-0.185.1/three.module.min.js";
import { orientGroundBeam } from "../docs/post/grove.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SITE = join(ROOT, "docs", "post");
const read = (path) => readFileSync(join(SITE, path), "utf8");
const checks = [];

function check(name, condition) {
  assert.ok(condition, name);
  checks.push(name);
  console.log(`  ok   ${name}`);
}

function visibleWords(html) {
  const text = html
    .replace(/<head[\s\S]*?<\/head>/gi, " ")
    .replace(/<(pre|code)\b[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&[^;]+;/g, " ")
    .replace(/[·↗…]/g, " ");
  return (text.match(/[A-Za-z0-9][A-Za-z0-9'-]*/g) || []).length;
}

function structuredData(html) {
  return [...html.matchAll(/<script type="application\/ld\+json">\s*([\s\S]*?)\s*<\/script>/g)]
    .map((match) => JSON.parse(match[1]));
}

const landing = read("index.html");
const landingCss = read("site.css");
const fusionCss = read("fusion.css");
const glyphGrove = read("glyphgrove.js");
const dapple = read("dapple.js");
const agentPage = read("agent/index.html");
const operatorPage = read("operator/index.html");
const stakePage = read("stake/index.html");
const stakeCss = read("stake/stake.css");
const stakeScript = read("stake/stake.js");
const research = read("research/index.html");
const notFoundPage = read("404.html");
const sitemap = read("sitemap.xml");
const readme = readFileSync(join(ROOT, "README.md"), "utf8");
const agentGuide = readFileSync(join(ROOT, "docs", "AGENT.md"), "utf8");
const joinGuide = readFileSync(join(ROOT, "docs", "JOIN.md"), "utf8");
const quickstartGuide = readFileSync(join(ROOT, "docs", "QUICKSTART.md"), "utf8");
const postJoinGuide = read("JOIN.md");
const currentGuides = [
  "ADAPTERS.md",
  "BOOTNODE.md",
  "CLI.md",
  "CLIENTS.md",
  "JOIN.md",
  "OVERVIEW.md",
  "QUICKSTART.md",
].map((path) => readFileSync(join(ROOT, "docs", path), "utf8"));
const currentGuideShellBlocks = currentGuides.flatMap((guide) =>
  [...guide.matchAll(/```(?:bash)?\n([\s\S]*?)```/g)].map((match) => match[1]),
);
const payGuideOutput = readFileSync(join(ROOT, "group", "pay.mjs"), "utf8");
const protocol = readFileSync(join(ROOT, "specs", "protocol.md"), "utf8");
const deploymentPlan = readFileSync(join(ROOT, "docs", "DEPLOYMENT-PLAN.md"), "utf8");
const packageJson = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const loader = read("site.js");
const landingScene = read("grove.js");
const grovePage = read("grove/index.html");
const labPage = read("lab/index.html");
const labCss = read("lab/lab.css");
const labScript = read("lab/lab.js");
const labApi = read("api/lab-run.mjs");
const labRunner = readFileSync(join(ROOT, "lab", "runner.mjs"), "utf8");
const groveCss = read("grove/grove.css");
const groveLoader = read("grove/network.js");
const groveFilePreview = read("grove/file-preview.js");
const groveScene = read("grove/scene.js");
const groveFreshness = read("grove/freshness.js");
const groveVisualModel = read("grove/visual-model.js");
const groveApi = read("api/grove.mjs");
const groveApiContract = read("api/_grove-contract.mjs");
const groveV2Api = read("api/grove-v2.mjs");
const groveV2ApiContract = read("api/_grove-v2-contract.mjs");
const groveOnchainApiContract = read("api/_grove-onchain-contract.mjs");
const groveV2OpenApi = JSON.parse(read("openapi-v2.json"));
const uptimeWorkflow = readFileSync(join(ROOT, ".github", "workflows", "uptime-probe.yml"), "utf8");
const pathGraphic = read("fig/shade-tree-path.svg");
const mobilePathGraphic = read("fig/shade-tree-path-mobile.svg");
const reputationGraphic = read("fig/shade-tree-reputation.svg");
const mobileReputationGraphic = read("fig/shade-tree-reputation-mobile.svg");
const readmeGraphic = read("fig/shade-tree-readme.svg");
const fallbackSnapshot = JSON.parse(read("grove/network.fallback.json"));
const grovePublicKey = readFileSync(join(ROOT, "network", "grove-signing-public.pem"), "utf8");
const config = JSON.parse(read("vercel.json"));
const csp = config.headers[0].headers.find((header) => header.key === "Content-Security-Policy")?.value || "";
const handoffBrief = landing.match(/<code[^>]+id="agent-setup-task"[^>]*>([\s\S]*?)<\/code>/)?.[1] || "";
const handoffBriefWords = (handoffBrief.match(/[A-Za-z0-9][A-Za-z0-9'-]*/g) || []).length;
const pngMagic = "89504e470d0a1a0a";

check("landing stays compact beside the full research note", landing.length < 12_000 && visibleWords(landing) <= 260 && research.length > 40_000);
check("Grove stays concise while exposing useful aggregate context", grovePage.length < 7_500 && visibleWords(grovePage) <= 155);
check("Protocol Lab is a one-screen live request inspector", (labPage.match(/<h1\b/g) || []).length === 1 && /One request, under the trees\./.test(labPage) && /Send live request/.test(labPage) && /height:\s*100dvh/.test(labCss) && /body\.lab-page[\s\S]*?overflow:\s*hidden/.test(labCss));
check("Protocol Lab binds six UI stages to real streamed client phases", ["discover", "select", "prove", "dial", "gate", "egress"].every((name) => labPage.includes(`data-stage="${name}"`) && labScript.includes(name)) && /consumeEvents\(response\)/.test(labScript) && !/setTimeout\([^)]*walk|scenarios\s*=|failAt/.test(labScript));
check("Protocol Lab shows the actual public signals and Groth16 curve points", ["pub.root", "pub.nullifier", "pub.x", "pub.y", "pub.externalNullifier"].every((name) => labPage.includes(`data-proof="${name}"`)) && ["a", "b", "c"].every((name) => labPage.includes(`data-proof-panel="${name}"`)) && /renderProof\(event\)/.test(labScript));
check("Protocol Lab reveals safe next actions only after a successful run", /data-lab-next[\s\S]*?hidden/.test(labPage) && /Give this to my agent/.test(labPage) && /href="\.\.\/operator\/index\.html">Grow the Grove/.test(labPage) && /data-share-lab>Share \/ copy/.test(labPage) && /github\.com\/dmarzzz\/shade-tree-node\/blob\/main\/docs\/AGENT\.md/.test(labPage) && /public-stake-v1 profile without members\.json/.test(labPage) && /one CONNECT tunnel per fixed 60-second epoch/.test(labPage) && /40 MiB combined traffic cap/.test(labPage) && /nextActions\.hidden = true/.test(labScript) && /nextActions\.hidden = false/.test(labScript) && /navigator\.share/.test(labScript) && /navigator\.clipboard\.writeText\(labShareUrl\)/.test(labScript));
check("Protocol Lab has one fixed destination and cannot become an open proxy", /<strong>example\.com<\/strong>/.test(labPage) && !/<input|<select|<textarea/.test(labPage) && /fetch\("\.\.\/api\/lab-run"/.test(labScript) && /body:\s*"\{\}"/.test(labScript) && /LAB_TARGET = "https:\/\/example\.com\/"/.test(labRunner) && !/req(?:uest)?\.body.*target|searchParams\.get\(["']target/.test(labRunner + labApi));
check("Protocol Lab runner redacts secrets and node identities while preserving proof material", /createEventSanitizer/.test(labRunner) && /`node-\$\{aliases\.size \+ 1\}`/.test(labRunner) && /pub:\s*sp\.publicSignals/.test(readFileSync(join(ROOT, "client", "shade-tree-client.mjs"), "utf8")) && !/SHADE_TREE_SECRET[^\n]*writeEvent/.test(labRunner));
check("Protocol Lab route is responsive and reduced-motion safe", /@media \(max-width: 700px\)/.test(labCss) && /grid-template-rows:\s*minmax\(0, 1\.1fr\) minmax\(0, 0\.9fr\)/.test(labCss) && /@media \(prefers-reduced-motion: reduce\)/.test(labCss));
check("Protocol Lab opens as a styled direct-file preview and a live hosted app", /href="\.\/lab\/index\.html">Lab/.test(landing) && /href="\.\.\/site\.css"/.test(labPage) && /href="\.\/lab\.css"/.test(labPage) && /src="\.\/lab\.js"/.test(labPage) && /href="\.\.\/index\.html"/.test(labPage) && !/(?:href|src)="\/(?:site|favicon|lab|agent|grove|research)/.test(labPage) && /window\.location\.protocol === "file:"/.test(labScript) && /Open hosted Lab/.test(labScript));
check("landing hides the Lab shortcut without removing the Lab route", /class="nav-lab" href="\.\/lab\/index\.html">Lab/.test(landing) && /\.home-hero \.nav-lab\s*\{\s*display:\s*none;\s*\}/.test(landingCss));
check("Grove opens as a styled, honest preview from direct-file and a live app when hosted", /href="\.\.\/site\.css"/.test(grovePage) && /href="\.\/grove\.css"/.test(grovePage) && /src="\.\/network\.js"/.test(grovePage) && /src="\.\/file-preview\.js"/.test(grovePage) && /href="\.\.\/index\.html"/.test(grovePage) && /href="\.\.\/research\/index\.html"/.test(grovePage) && !/(?:href|src)="\/(?:site|favicon|fig|grove|research)/.test(grovePage) && /window\.location\.protocol === "file:"/.test(groveFilePreview) && /data-snapshot-state\]", "Local preview"/.test(groveFilePreview) && /data-node-count\]", "—"/.test(groveFilePreview) && /if \(window\.location\.protocol !== "file:"\) \{\s*load\(\);[\s\S]*?addEventListener\("visibilitychange", onVisibilityChange\);\s*\}/.test(groveLoader));
check("Protocol Lab has a dedicated static social image", /og:image" content="https:\/\/shade-tree-node\.vercel\.app\/fig\/shade-tree-lab-og\.png"/.test(labPage));
check("landing has one H1 and three decorative canvases", (landing.match(/<h1\b/g) || []).length === 1 && (landing.match(/<canvas[^>]+aria-hidden="true"/g) || []).length === 3);
check("Grove has one H1, one main landmark, and one live status", (grovePage.match(/<h1\b/g) || []).length === 1 && (grovePage.match(/<main\b/g) || []).length === 1 && (grovePage.match(/<section\b/g) || []).length === 0 && /role="status" aria-live="polite"/.test(grovePage));

for (const [name, page] of [["landing", landing], ["agent guide", agentPage], ["operator guide", operatorPage], ["Grove", grovePage]]) {
  check(`${name} has no eyebrow, tiny semantic text, or em dash`, !/eyebrow|preview-label|preview-note|<small\b|<sup\b|<sub\b|<figcaption\b|\u2014/.test(page));
}

check("both sites use the same nocturnal palette", /--understory:\s*#07100c/.test(landingCss) && /--wet-bark:\s*#102219/.test(landingCss) && /--pulse:\s*#e2be67/.test(landingCss) && !/#f3f0e7|--paper\b/.test(landingCss) && /background:\s*var\(--understory\)/.test(groveCss));
check("tree imagery remains behind every surface", /body:not\(\.home-page\)::before/.test(landingCss) && /shade-tree-banner\.webp/.test(landingCss) && /forest-fallback/.test(landing) && /canopy-fallback/.test(grovePage));
check("landing reveals fully formed trees and reserves its fallback for WebGL failure", /grove\.scale\.y = 1/.test(landingScene) && !/grove\.scale\.y = Math\.max|easeOutCubic/.test(landingScene) && /\.grove-stage\.use-fallback \.forest-fallback\s*\{\s*opacity:\s*0\.84;\s*\}/.test(landingCss) && /stage\.classList\.add\("use-fallback"\)/.test(loader));

check("landing and README lead with the agent and provider outcomes", /<h2>For agents<\/h2>/.test(landing) && !/Install the Proxy/.test(landing) && /<h2>For shade providers<\/h2>/.test(landing) && /Add Shade Tree to an agent/.test(readme) && /Run a Shade Tree node to provide cover/.test(readme));
check("landing hero jumps to both role starts and the canonical protocol", /href="#proxy">For agents/.test(landing) && /href="#node">Run a Shade Tree node/.test(landing) && /href="https:\/\/github\.com\/dmarzzz\/shade-tree-node\/blob\/main\/specs\/protocol\.md">How it works/.test(landing) && /class="role-link" href="\.\/operator\/">Operator guide/.test(landing));
check("About and README carry the approved linked tagline", /<section class="about-panel"[\s\S]*?<h2 id="about-title">About<\/h2>[\s\S]*?<p>The grove of Shade Trees gives agents anonymous egress when the clearnet <a href="\.\/research\/">won’t let them through<\/a>\.<\/p>[\s\S]*?<\/section>/.test(landing) && /# Shade Tree Grove\s+Cover for local agents\.\s+The grove of Shade Trees gives agents anonymous egress when the clearnet \[won’t let them\s+through\]\[research-note\]\./.test(readme));
check("public site branding names Shade Tree Grove without renaming protocol roles", /<title>Tor Egress for AI Agents · Shade Tree Grove<\/title>/.test(landing) && /<span>Shade Tree Grove<\/span>/.test(landing) && /<title>Tor Proxy Setup for AI Agents · Shade Tree Grove<\/title>/.test(agentPage) && /<title>Run a Proof-Gated Egress Node for AI Agents · Shade Tree Grove<\/title>/.test(operatorPage) && /<title>Privacy-Preserving Network Stats · Shade Tree Grove<\/title>/.test(grovePage) && /<title>Anonymous AI Agent Egress over Tor · Shade Tree Grove<\/title>/.test(research) && /<h2>For shade providers<\/h2>/.test(landing) && /Prepare a Shade Tree node/.test(operatorPage));
check("primary navigation exposes staking and Research", /<div class="nav-links">[\s\S]*?<a href="\.\/stake\/">Stake<\/a>[\s\S]*?<a href="\.\/grove\/">Grove<\/a>[\s\S]*?<a href="\.\/research\/">Research<\/a>[\s\S]*?<a href="https:\/\/github\.com\/dmarzzz\/shade-tree-node">Source<\/a>[\s\S]*?<\/div>/.test(landing));
check("landing explains the gate and traffic path in one compact graphic", /Shade Tree is a Tor-based egress layer/.test(landing) && /proof of membership in an admitted set/.test(landing) && /<img src="\.\/fig\/shade-tree-readme\.svg"/.test(landing) && /reputation gate/i.test(readmeGraphic) && /network path/i.test(readmeGraphic) && /Elder Tree/.test(readmeGraphic));
check("landing uses one compact keyboard-scrollable protocol figure", /<figure class="how-figure" role="region" aria-label="Shade Tree protocol diagram" tabindex="0">[\s\S]*shade-tree-readme\.svg[\s\S]*<\/figure>/.test(landing) && /<code tabindex="0" aria-label="v0\.6\.0 live binary installation command">/.test(landing) && (landing.match(/class="how-figure"/g) || []).length === 1 && !/class="how-mechanism"/.test(landing));
check("landing has role-specific copyable installs", /<p class="step-label">Install the live Rust binary<\/p>[\s\S]*?<div class="command agent-install"/.test(landing) && /--proto '=https' --proto-redir '=https'/.test(landing) && /scripts\/install\.sh \| SHADE_TREE_VERSION=v0\.6\.0 sh/.test(landing) && /selects a published <code>-live<\/code> asset and verifies its checksum/.test(landing) && /data-copy="git clone https:\/\/github\.com\/dmarzzz\/shade-tree-node\.git &amp;&amp; cd shade-tree-node &amp;&amp; npm ci &amp;&amp; npm link"/.test(landing) && /data-copy="shade-tree join node"/.test(landing) && /aria-label="Copy v0\.6\.0 live binary installation command"/.test(landing) && /aria-label="Copy node installation commands"/.test(landing) && !/npm install --global git\+https:\/\/github\.com\/dmarzzz\/shade-tree-node\.git/.test(landing));
check("landing places both role paths in animated grove clearings", /class="role-trails glyph-grove"/.test(landing) && /class="glyph-canvas"/.test(landing) && (landing.match(/class="role" data-clearing/g) || []).length === 2 && /class="grove-title" data-clearing/.test(landing) && /\.glyph-grove \.role/.test(fusionCss) && /prefers-reduced-motion/.test(glyphGrove));
check("landing provides a compact safe handoff for existing agents", /<p class="step-label">Agent setup<\/p>/.test(landing) && /data-copy="Set up Shade Tree Grove using https:\/\/github\.com\/dmarzzz\/shade-tree-node\/blob\/main\/docs\/AGENT\.md/.test(landing) && /verified v0\.6\.0 Rust -live binary/.test(landing) && /embedded Arti needs neither Node\.js nor system Tor/.test(landing) && /bundled public-stake-v1 profile/.test(landing) && /0\.1 ETH plus gas/.test(landing) && /one CONNECT tunnel per fixed 60-second epoch/.test(landing) && /40 MiB combined traffic/.test(landing) && /Do not add members\.json/.test(landing) && /Keep identity\.json, the key, and proxy-token\.txt private/.test(landing) && /data-copy-target="agent-setup-task" data-copy-noun="Setup brief"/.test(landing) && /aria-label="Copy Shade Tree Grove setup brief for an AI agent"/.test(landing) && /<code id="agent-setup-task" class="copy-fallback" hidden>/.test(landing));
check("agent handoff stays bounded even though command text is outside the prose budget", handoffBriefWords >= 70 && handoffBriefWords <= 100);
check("agent page gives the complete Rust live-binary integration path", /--proto '=https' --proto-redir '=https'/.test(agentPage) && /scripts\/install\.sh/.test(agentPage) && /SHADE_TREE_VERSION=v0\.6\.0 sh/.test(agentPage) && /downloads the matching v0\.6\.0 <code>-live<\/code> binary and checksum/.test(agentPage) && /shade-tree enroll --out identity\.json/.test(agentPage) && /shade-tree register-member --identity identity\.json/.test(agentPage) && /shade-tree member-status/.test(agentPage) && /shade-tree exit-member/.test(agentPage) && /shade-tree withdraw-member/.test(agentPage) && /shade-tree proxy-token/.test(agentPage) && /bundled current-v4 Elder, signer, contract, RPC, tier, and rate policy/.test(agentPage) && /--identity identity\.json/.test(agentPage) && /--listen 127\.0\.0\.1:8118/.test(agentPage) && !/--secret/.test(agentPage) && /shade-tree run -- your-agent/.test(agentPage) && /replace <code>your-agent<\/code> with <code>hermes<\/code>/.test(agentPage) && /0\.1 Sepolia ETH stake admits one CONNECT tunnel per fixed 60-second epoch with a 40 MiB combined payload ceiling/.test(agentPage) && /needs neither Node\.js nor a system Tor daemon/.test(agentPage) && !/npm install --global/.test(agentPage));
const agentCopies = [...agentPage.matchAll(/data-copy="([^"]+)"/g)].map((match) => match[1]);
const identityEnrollCopy = agentCopies.find((command) => command.includes("shade-tree enroll")) || "";
const proxyTokenCopy = agentCopies.find((command) => command.includes("shade-tree proxy-token")) || "";
const proxyStartCopy = agentCopies.find((command) => command.includes("shade-tree proxy ") && command.includes("--identity identity.json")) || "";
check("identity, Proxy token, and Proxy launch remain separate copy actions", /register-member --identity identity\.json/.test(identityEnrollCopy) && /member-status/.test(identityEnrollCopy) && !/proxy-token/.test(identityEnrollCopy) && /shade-tree proxy-token/.test(proxyTokenCopy) && !/--bootnode-onion/.test(proxyTokenCopy) && /--identity identity\.json/.test(proxyStartCopy) && !/--members members\.json/.test(proxyStartCopy) && /--listen 127\.0\.0\.1:8118/.test(proxyStartCopy));
check("operator page is guided from a source checkout and keeps only current deployment blockers", /git clone https:\/\/github\.com\/dmarzzz\/shade-tree-node\.git &amp;&amp; cd shade-tree-node &amp;&amp; npm ci &amp;&amp; npm link/.test(operatorPage) && !/npm install --global/.test(operatorPage) && /shade-tree join node/.test(operatorPage) && /Local research only/.test(operatorPage) && /rejects non-public destination addresses after DNS resolution/.test(operatorPage) && /public-stake-v1/.test(operatorPage) && /0\.1 Sepolia ETH stake admits one CONNECT tunnel per fixed 60-second epoch with a 40 MiB combined traffic ceiling/.test(operatorPage) && /untrusted development Groth16 artifacts/.test(operatorPage) && /issues\/6/.test(operatorPage) && !/issues\/73/.test(operatorPage) && /It does not configure Tor/.test(operatorPage) && /manual local quickstart uses the checkout/.test(operatorPage));
check("README and canonical agent doc give an honest current integration path", /## Agent developers/.test(readme) && /docs\/AGENT\.md/.test(readme) && /scripts\/install\.sh\s*\| sh/.test(readme) && /--proto '=https' --proto-redir '=https'/.test(readme) && /first tries the selected release's self-contained `-live` agent/.test(readme) && /falls back to its verifier-only binary only when that live asset is absent/.test(readme) && /shade-tree enroll/.test(readme) && /shade-tree register-member/.test(readme) && /shade-tree proxy-token/.test(readme) && /SHADE_TREE_PROXY_TOKEN/.test(readme) && !/shade-tree proxy[^\n]*--secret/.test(readme) && /shade-tree run --proxy[^\n]*your-agent/.test(readme) && /bundled Sepolia Grove defaults to public staked tier 1/i.test(readme) && /(shade-tree-\$VERSION-\$TARGET-live|scripts\/install\.sh)/.test(agentGuide) && /bundled public Sepolia Grove[\s\S]*one CONNECT tunnel per fixed 60-second epoch/i.test(agentGuide) && /shade-tree enroll/.test(agentGuide) && /shade-tree register-member/.test(agentGuide) && /shade-tree proxy-token/.test(agentGuide) && /SHADE_TREE_PROXY_TOKEN/.test(agentGuide) && !/shade-tree proxy[^\n]*--secret/.test(agentGuide) && /shade-tree run -- hermes/.test(agentGuide));
check("README distinguishes implementation maturity from whole-stack parity", /## Implementation maturity/.test(readme) && /Node\.js \/ JavaScript[\s\S]*Full-stack reference preview/.test(readme) && /Rust[\s\S]*Primary agent distribution preview/.test(readme) && /creates identities, runs the embedded-Arti CONNECT Proxy, launches one proxy-scoped agent, and exposes the reusable Rust egress client/.test(readme) && /does not provide a Shade Tree node or Elder Tree/.test(readme) && /not security assurance/.test(readme));
check("current guidance keeps bearer secrets out of Proxy argv", [...currentGuides, payGuideOutput].every((guide) => !/shade-tree (?:proxy|client|shim)[^\n]*--secret(?!-file)\b/.test(guide)) && currentGuideShellBlocks.every((block) => !/shade-tree (?:proxy|client|shim)[\s\S]{0,120}--secret(?!-file)\b/.test(block)) && /do not pass it on argv/.test(payGuideOutput));
check("setup guides never place a member secret in argv or inline shell history", [joinGuide, quickstartGuide, postJoinGuide, agentPage].every((guide) => !/SHADE_TREE_SECRET\s*=\s*<(?:hex|member|your)/i.test(guide) && !/shade-tree (?:proxy|client)[^\n]*--secret(?!-file)\b/.test(guide) && !/scripts\/join\.sh\s+<[^>\n]*secret/i.test(guide)));
check("setup guides require the operator's exact tier and invited member file", [joinGuide, quickstartGuide, postJoinGuide].every((guide) => /read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET/.test(guide) && /--limit "\$SHADE_TREE_LIMIT"/.test(guide) && /SHADE_TREE_MEMBERS_FILE=\/path\/from-operator\/members\.json/.test(guide) && /--leaf-source invited/.test(guide)));
check("Git install payload carries every routed CLI runtime", ["bin/", "bootnode/", "client/", "gateway/", "group/", "lib/", "network/", "payments/", "scripts/", "circuits/", "contracts/"].every((path) => packageJson.files.includes(path)));
check("deployment plan records the live Elder and keeps production safety gates", /Elder Tree \(`bootnode` in source\)/.test(deploymentPlan) && /\[#73\]/.test(deploymentPlan) && /untrusted-testnet/.test(deploymentPlan) && /production blocked on trusted setup/.test(deploymentPlan) && /Target inventory and[\s\S]*provider state remain operator-controlled and uncommitted/.test(deploymentPlan));
check("existing Discussions provide lightweight support", /shade-tree-node\/discussions/.test(landing));
check("landing and README use the compact protocol flow", /<img src="\.\/fig\/shade-tree-readme\.svg"[^>]+width="1200" height="700"/.test(landing) && /docs\/post\/fig\/shade-tree-readme\.svg/.test(readme));
check("landing resolves local assets and routes when opened directly", /href="\.\/site\.css"/.test(landing) && /href="\.\/fusion\.css"/.test(landing) && /src="\.\/site\.js"/.test(landing) && /src="\.\/glyphgrove\.js"/.test(landing) && /src="\.\/dapple\.js"/.test(landing) && /href="\.\/favicon\.svg"/.test(landing) && !/(?:href|src|srcset)="\/(?:site|fusion|glyphgrove|dapple|favicon|fig|agent|operator|grove|research)/.test(landing));
check("landing links to the canonical protocol from the hero and how-it-works lede", (landing.match(/href="https:\/\/github\.com\/dmarzzz\/shade-tree-node\/blob\/main\/specs\/protocol\.md"/g) || []).length === 2 && /class="hero-actions"[\s\S]*How it works/.test(landing) && /class="how-lede"[\s\S]*full protocol specification/.test(landing));
check("landing links contextual terms to the authoritative Tor site", /href="https:\/\/www\.torproject\.org\/">Tor<\/a>/.test(landing) && (landing.match(/torproject\.org/g) || []).length === 1 && /\.how-lede a\s*\{[\s\S]*text-decoration:\s*underline/.test(landingCss));
check("landing sections use grove-specific clearings and canopy light", /--clearing-about:\s*#0a1912/.test(landingCss) && /--clearing-how:\s*#0d1f16/.test(landingCss) && /\.home-main\s*\{[\s\S]*?width:\s*100%/.test(landingCss) && /\.about-panel\s*\{[\s\S]*?background:\s*var\(--clearing-about\)/.test(landingCss) && /\.glyph-grove \.role:first-child\s*\{[^}]*background:\s*rgba\(14, 32, 23, 0\.94\)/.test(fusionCss) && /\.glyph-grove \.role:last-child\s*\{[^}]*background:\s*rgba\(11, 28, 20, 0\.94\)/.test(fusionCss) && /class="shade-canvas"/.test(landing) && /prefers-reduced-motion/.test(dapple));
check("Tor boundary copy remains precise in the README", /Tor exit addresses are public/.test(readme) && /publishes no\s+egress-IP list/.test(readme) && /Destinations still see and can block a node IP/.test(readme));
check("public vocabulary stays paired with protocol names", /Elder Tree/.test(readme) && /bootnode/.test(readme) && /Canopy/.test(readme) && /controls discovery/.test(readme) && /\| Proxy \| client \|/.test(protocol));

check("Grove links only the aggregate-report phrase to the canonical Data API", /<p>A privacy-preserving view of the Grove, built from <a href="https:\/\/github\.com\/dmarzzz\/shade-tree-node\/blob\/main\/specs\/data-api\.md">signed aggregate reports<\/a>\. One tree appears per announced identity, with no identity or location attached\.<\/p>/.test(grovePage) && (grovePage.match(/specs\/data-api\.md/g) || []).length === 1 && !/specs\/protocol\.md/.test(grovePage));
check("Grove keeps the intro as one inline sentence with natural wrapping", !/<p>A privacy-preserving view[\s\S]*?<br\b/.test(grovePage) && /\.network-copy p a\s*\{[^}]*text-decoration:\s*underline/.test(groveCss) && !/\.network-copy p a\s*\{[^}]*(?:display|white-space):/.test(groveCss));

check("path graphic has accessible text and separates the two planes", /<title[^>]*>[^<]+<\/title>/.test(pathGraphic) && /<desc[^>]*>[^<]+<\/desc>/.test(pathGraphic) && /Discovery plane/i.test(pathGraphic) && /Traffic path/i.test(pathGraphic) && /target-bound RLN proof \+ nullifier/.test(pathGraphic) && /stays out of this path/i.test(pathGraphic) && !/<script\b|\u2014/.test(pathGraphic));
check("mobile path graphic remains accessible, short, and traffic-only", /<svg[^>]+width="720"[^>]+height="820"[^>]+role="img"[^>]+aria-labelledby="title desc"/.test(mobilePathGraphic) && /<title[^>]*>[^<]+<\/title>/.test(mobilePathGraphic) && /<desc[^>]*>[^<]+<\/desc>/.test(mobilePathGraphic) && /Agent[\s\S]*Proxy[\s\S]*Tor[\s\S]*Shade Tree node[\s\S]*Destination/.test(mobilePathGraphic) && /proof-gated tunnel/.test(mobilePathGraphic) && !/Discovery plane|signed heartbeat|signed Canopy|epoch nullifier/.test(mobilePathGraphic) && !/<script\b|\u2014/.test(mobilePathGraphic));
check("desktop reputation graphic preserves detail", /role="img"[^>]+aria-labelledby="title desc"/.test(reputationGraphic) && /Operator admission/i.test(reputationGraphic) && /Groth16 RLN proof/.test(reputationGraphic) && /without revealing which leaf/i.test(reputationGraphic) && /epoch[^<]+nullifier/i.test(reputationGraphic) && /local (?:view of the )?tunnel budget|Local tunnel[\s\S]*budget view/i.test(reputationGraphic));
check("mobile reputation graphic is accessible and reduced to three steps", /<svg[^>]+width="720"[^>]+height="570"[^>]+role="img"[^>]+aria-labelledby="title desc"/.test(mobileReputationGraphic) && /<title[^>]*>[^<]+<\/title>/.test(mobileReputationGraphic) && /<desc[^>]*>[^<]+<\/desc>/.test(mobileReputationGraphic) && /Admitted root[\s\S]*Private membership[\s\S]*proof[\s\S]*Node enforces budget/.test(mobileReputationGraphic) && /without revealing which member/.test(mobileReputationGraphic) && /local tunnel budget/.test(mobileReputationGraphic) && !/invited|staked|paid|epoch nullifier/i.test(mobileReputationGraphic) && !/<script\b|\u2014/.test(mobileReputationGraphic));
const mobileDiagramFontSizes = [mobilePathGraphic, mobileReputationGraphic]
  .flatMap((graphic) => [...graphic.matchAll(/font-size:\s*(\d+)px/g)].map((match) => Number(match[1])));
check("mobile diagram labels remain readable after responsive scaling", mobileDiagramFontSizes.length >= 5 && Math.min(...mobileDiagramFontSizes) >= 34);

check("Grove keeps no duplicate status beneath the globe", /<canvas id="network-canvas" aria-hidden="true"><\/canvas>\s*<\/div>\s*<\/div>/.test(grovePage) && !/network-foot|class="snapshot-state"|state-pulse|data-view-state|network-caption|Elder Tree handles discovery and stays off the traffic path|class="(?:scene-key|elder-label)"|data-elder-label|Census field/.test(grovePage) && !/\.network-foot|\.snapshot-state|\.state-pulse/.test(groveCss));
check("Grove keeps its outer gutter solid instead of leaking the page banner", /body\.network-page::before\s*\{\s*background:\s*none;\s*content:\s*none;\s*\}/.test(groveCss) && !/shade-tree-banner\.webp/.test(groveCss));
check("compact navigation and controls keep full touch targets", /\.wordmark\s*\{[\s\S]*?min-height:\s*2\.75rem/.test(landingCss) && /\.nav-links a\s*\{[\s\S]*?min-width:\s*2\.75rem;[\s\S]*?min-height:\s*2\.75rem/.test(landingCss) && /\.copy-command\s*\{[\s\S]*?min-width:\s*7\.6rem;[\s\S]*?min-height:\s*2\.75rem/.test(landingCss) && /\.site-footer a\s*\{[\s\S]*?min-width:\s*2\.75rem;[\s\S]*?min-height:\s*2\.75rem/.test(landingCss));
check("Grove ends after the live network hero without a redundant footer or analytics panel", /<main id="grove-main">\s*<header class="network-hero"[\s\S]*?<\/header>\s*<\/main>\s*<\/body>/.test(grovePage) && !/<footer\b|24 hours of shade|history-panel|history-chart|history-summary|relay-ledger|onchain-ledger/.test(grovePage));
check("Grove keeps count and age-bearing status in its signed snapshot detail table", /<aside class="provenance-panel" aria-label="Snapshot provenance">[\s\S]*?<span>Snapshot<\/span>[\s\S]*?<strong data-snapshot-state role="status" aria-live="polite" aria-atomic="true">Verifying<\/strong>[\s\S]*?<div class="provenance-count"><dt>Announced nodes<\/dt><dd data-node-count>…<\/dd><\/div>\s*<div><dt>Network<\/dt><dd data-network>…<\/dd><\/div>\s*<div><dt>Scope<\/dt><dd>Pre-v4 research fleet<\/dd><\/div>\s*<div><dt>Observed<\/dt><dd data-view-time>…<\/dd><\/div>\s*<div><dt>Refresh target<\/dt><dd data-snapshot-cadence>15 min<\/dd><\/div>[\s\S]*?<\/aside>/.test(grovePage) && /`\$\{status\.snapshotState\} · \$\{status\.age\.long\}`/.test(groveLoader) && (grovePage.match(/<aside class="provenance-panel"/g) || []).length === 1 && (grovePage.match(/<dt>/g) || []).length === 5 && !/network-data|data-view-age|data-node-hours|24h node-hours|A view with boundaries|Signed view|Observer attests|Browser verifies|A scheduled observer|<dt>Definition<\/dt>|Announced within TTL/.test(grovePage) && !/\.network-data/.test(groveCss));
check("Grove keeps the restored detail table left of the globe on desktop and stacked on mobile", /\.network-dashboard\s*\{[^}]*grid-template-columns:\s*minmax\(14rem, 25rem\) minmax\(28rem, 43rem\);[^}]*justify-content:\s*space-between;/.test(groveCss) && /\.network-visual\s*\{[^}]*grid-row:\s*span 2;/.test(groveCss) && /\.provenance-panel\s*\{[^}]*grid-column:\s*1;/.test(groveCss) && /@media \(max-width: 760px\)[\s\S]*?\.network-visual\s*\{[\s\S]*?grid-row:\s*auto;[\s\S]*?\}[\s\S]*?\.provenance-panel\s*\{\s*grid-column:\s*auto;\s*width:\s*100%;\s*\}/.test(groveCss));
check("Grove composes one desktop viewport and a compact natural-height mobile hero", /\.network-page\s*\{[^}]*height:\s*100svh;[^}]*min-height:\s*0;[^}]*padding:\s*0\.75rem;[^}]*overflow:\s*hidden;/.test(groveCss) && /\.network-page > main\s*\{[^}]*height:\s*100%;[^}]*min-height:\s*0;[^}]*\}/.test(groveCss) && /\.network-hero\s*\{[^}]*display:\s*grid;[^}]*height:\s*100%;[^}]*min-height:\s*0;[^}]*grid-template-rows:\s*auto minmax\(0, 1fr\);[^}]*margin:\s*0;/.test(groveCss) && /\.network-dashboard\s*\{[^}]*height:\s*100%;[^}]*min-height:\s*0;/.test(groveCss) && /\.network-stage\s*\{[^}]*width:\s*min\(100%, calc\(100svh - 10rem\)\);/.test(groveCss) && /@media \(max-width: 760px\)[\s\S]*?\.network-page\s*\{[^}]*height:\s*auto;[^}]*min-height:\s*100svh;[^}]*overflow-y:\s*auto;[^}]*\}[\s\S]*?\.network-page > main\s*\{[^}]*height:\s*auto;[^}]*\}[\s\S]*?\.network-hero\s*\{[^}]*height:\s*auto;[^}]*\}[\s\S]*?\.network-dashboard\s*\{[^}]*height:\s*auto;[^}]*\}[\s\S]*?\.network-copy h1\s*\{[^}]*max-width:\s*none;[^}]*font-size:\s*clamp\(2\.75rem, 8vw, 4rem\);[^}]*line-height:\s*0\.9;[^}]*\}[\s\S]*?\.network-copy p\s*\{[^}]*font-size:\s*0\.8rem;[^}]*line-height:\s*1\.5;[^}]*\}[\s\S]*?\.network-stage\s*\{[^}]*width:\s*min\(76vw, 29rem\);[^}]*\}/.test(groveCss) && /@media \(max-width: 480px\)[\s\S]*?\.network-copy h1\s*\{[^}]*font-size:\s*clamp\(2\.25rem, 10\.5vw, 2\.75rem\);[^}]*\}[\s\S]*?\.network-stage\s*\{[^}]*width:\s*min\(78vw, 20\.5rem\);[^}]*\}/.test(groveCss));
check("Grove ships no orphaned secondary analytics UI", !/\.grove-main|\.history-panel|\.history-chart|\.history-summary|\.relay-ledger|\.onchain-ledger/.test(groveCss) && !/function (?:drawHistory|renderRelay|formatPayloadBytes)|renderOnchainLedger/.test(groveLoader));
check("Grove inline Data API link has visible hover and keyboard focus", /\.network-copy p a:hover,[\s\S]*?\.network-copy p a:focus-visible\s*\{[\s\S]*?color:\s*var\(--lichen\);[\s\S]*?text-decoration-color:\s*var\(--pulse\)/.test(groveCss) && /:focus-visible\s*\{[\s\S]*?outline:\s*2px solid var\(--pulse\)/.test(landingCss));
check("Grove removes globe overlays without blocking pinch zoom", !/touch-action\s*:|\.scene-key|\.elder-label|\.network-caption|\.network-foot|\.snapshot-state/.test(groveCss) && /\.provenance-panel dt\s*\{[\s\S]*?font-size:\s*0\.74rem/.test(groveCss) && /\.provenance-panel dd\s*\{[\s\S]*?font-size:\s*0\.76rem/.test(groveCss));

check("full research article is preserved at /research", /id="references"/.test(research) && /id="further-reading"/.test(research));
check("landing and research canonical URLs are distinct", /rel="canonical" href="https:\/\/shade-tree-node\.vercel\.app\/"/.test(landing) && /rel="canonical" href="https:\/\/shade-tree-node\.vercel\.app\/research\/"/.test(research));
check("Grove has its own canonical URL", /rel="canonical" href="https:\/\/shade-tree-node\.vercel\.app\/grove\/"/.test(grovePage));

const researchImages = [...research.matchAll(/<img[^>]+src="([^"]+)"/g)].map((match) => match[1]);
check("research-note image paths remain intact", researchImages.length === 6 && researchImages.every((src) => src.startsWith("../fig/")));
for (const src of researchImages) check(`research asset exists: ${src}`, existsSync(resolve(SITE, "research", src)));

for (const asset of [
  "site.css",
  "fusion.css",
  "site.js",
  "glyphgrove.js",
  "dapple.js",
  "grove.js",
  "fig/shade-tree-banner.webp",
  "fig/shade-tree-og.png",
  "fig/shade-tree-lab-og.png",
  "fig/shade-tree-path.svg",
  "fig/shade-tree-path-mobile.svg",
  "fig/shade-tree-reputation.svg",
  "fig/shade-tree-reputation-mobile.svg",
  "fig/shade-tree-readme.svg",
  "favicon.svg",
  "vendor/three-0.185.1/three.module.min.js",
  "vendor/three-0.185.1/three.core.min.js",
  "vendor/three-0.185.1/LICENSE.txt",
  "grove/index.html",
  "grove/grove.css",
  "grove/network.js",
  "grove/file-preview.js",
  "grove/scene.js",
  "grove/freshness.js",
  "grove/history.js",
  "grove/visual-model.js",
  "grove/onchain.js",
  "grove/network.fallback.json",
  "lab/index.html",
  "lab/lab.css",
  "lab/lab.js",
  "stake/index.html",
  "stake/stake.css",
  "stake/stake.js",
  "api/grove.mjs",
  "api/_grove-contract.mjs",
  "api/grove-v2.mjs",
  "api/_grove-v2-contract.mjs",
  "api/_grove-onchain-contract.mjs",
  "api/lab-run.mjs",
  "openapi-v2.json",
  "agent/index.html",
  "operator/index.html",
  "404.html",
  "sitemap.xml",
]) check(`site asset exists: ${asset}`, existsSync(join(SITE, asset)));

check("Open Graph images are real PNG files", [
  join(SITE, "fig/shade-tree-og.png"),
  join(SITE, "fig/shade-tree-lab-og.png"),
  join(ROOT, "assets", "shade-tree-og.png"),
].every((path) => existsSync(path) && readFileSync(path).subarray(0, 8).toString("hex") === pngMagic));

check("Three.js is pinned locally with its license", /three-0\.185\.1\/three\.module\.min\.js/.test(landingScene) && /\.\.\/vendor\/three-0\.185\.1\/three\.module\.min\.js/.test(groveScene) && statSync(join(SITE, "vendor/three-0.185.1/LICENSE.txt")).size > 1000);
check("home scene uses WebGL when available, including mobile", /connection\?\.saveData/.test(loader) && /getContext\("webgl2"/.test(loader) && /import\("\.\/grove\.js"\)/.test(loader) && !/compactOrCoarse/.test(loader));
check("home scene camera follows the stacked-layout breakpoint", /matchMedia\("\(max-width: 900px\)"\)/.test(landingScene) && /@media \(max-width: 900px\)/.test(landingCss));
check("home scene is an irregular canopy map with a bidirectional through-running pixel route", /targetCount = mobile \? 18 : 29/.test(landingScene) && /crowded = trees\.some/.test(landingScene) && /SphereGeometry\(1, 7, 5\)/.test(landingScene) && /CatmullRomCurve3/.test(landingScene) && /segmentCount = mobile \? 36 : 52/.test(landingScene) && /new THREE\.Vector3\(-0\.7, 0\.34, 13\.5\)/.test(landingScene) && /new THREE\.Vector3\(18\.0, 0\.34, -7\.4\)/.test(landingScene) && /const destination = new THREE\.Mesh/.test(landingScene) && /const outbound = makePacket/.test(landingScene) && /const inbound = makePacket/.test(landingScene) && /direction: -1/.test(landingScene) && /positionPacket\(outbound, outboundProgress\)/.test(landingScene) && /positionPacket\(inbound, 1 - outboundProgress\)/.test(landingScene));
check("home scene uses larger trees, a feathered shade field, and three crossing sunbeams", /treeScale = mobile \? 1\.08 : 1\.07/.test(landingScene) && /height = \(2\.5 \+ random\(\) \* 1\.8\) \* treeScale/.test(landingScene) && /inCopyClearing/.test(landingScene) && /new THREE\.PlaneGeometry\(mobile \? 17 : 34, mobile \? 27 : 23\)/.test(landingScene) && /new THREE\.ShaderMaterial/.test(landingScene) && /smoothstep\(0\.56 \+ edge, 0\.99 \+ edge/.test(landingScene) && /const beamSpecs = mobile \? \[/.test(landingScene) && /\{ width: 1\.65, length: 48, angle: -1\.02/.test(landingScene) && /\{ width: 1\.02, length: 46, angle: 1\.01/.test(landingScene) && /\{ width: 2\.2, length: 66, angle: -1\.02/.test(landingScene) && /\{ width: 1\.3, length: 62, angle: 1\.01/.test(landingScene) && /beamSpecs\.forEach/.test(landingScene) && /beamStrength: \{ value: spec\.strength \}/.test(landingScene) && /orientGroundBeam\(beam, spec\.angle\)/.test(landingScene) && !/new THREE\.ShapeGeometry\(shape\)/.test(landingScene) && /new THREE\.Fog\(NIGHT, 35, 60\)/.test(landingScene) && /new THREE\.Vector3\(mobile \? 8 : 14, mobile \? 31 : 28, mobile \? 18 : 18\)/.test(landingScene) && /desktopViewHeight = Math\.min\(35, Math\.max\(22, 35 \/ aspect\)\)/.test(landingScene) && /viewHeight = mobile \? \(tabletClearing \? 34 : 36\) : desktopViewHeight/.test(landingScene) && /renderer\.shadowMap\.enabled = !mobile/.test(landingScene));
check("stacked cameras keep phones stable while lifting and right-shifting the tablet grove", /tabletClearing = mobile && width > 600/.test(landingScene) && /horizontalOffset = tabletClearing \? -2\.25 : 0/.test(landingScene) && /verticalOffset = mobile \? \(tabletClearing \? 7 : 8\.5\) : 0/.test(landingScene) && /camera\.left = -\(viewHeight \* aspect\) \/ 2 \+ horizontalOffset/.test(landingScene) && /camera\.right = \(viewHeight \* aspect\) \/ 2 \+ horizontalOffset/.test(landingScene) && /camera\.top = viewHeight \/ 2 \+ verticalOffset/.test(landingScene) && /camera\.bottom = -viewHeight \/ 2 \+ verticalOffset/.test(landingScene) && /@media \(max-width: 900px\)[\s\S]*?\.forest-fallback \{ inset: 52% -8% -6% 7%; \}/.test(landingCss));

const beamAngles = [-1.02, 0.02, 1.01, -1.02, 0.02, 1.01];
const beamDirections = beamAngles.map((angle) => {
  const beam = new THREE.Object3D();
  orientGroundBeam(beam, angle);
  const normal = new THREE.Vector3(0, 0, 1).applyQuaternion(beam.quaternion);
  const direction = new THREE.Vector3(0, 1, 0).applyQuaternion(beam.quaternion);
  const expected = new THREE.Vector3(-Math.sin(angle), 0, -Math.cos(angle));
  return { normal, direction, expected };
});
check("ground-beam rotations stay flat and produce three distinct directions per layout", beamDirections.every(({ normal, direction, expected }) => normal.distanceTo(new THREE.Vector3(0, 1, 0)) < 1e-6 && direction.distanceTo(expected) < 1e-6) && [beamDirections.slice(0, 3), beamDirections.slice(3)].every((layout) => new Set(layout.map(({ direction }) => `${direction.x.toFixed(4)},${direction.z.toFixed(4)}`)).size === 3));
check("Grove lowers quality on mobile instead of disabling WebGL", /const lowQuality = window\.matchMedia/.test(groveLoader) && /quality: lowQuality \? "low" : "high"/.test(groveLoader) && /getContext\("webgl2"/.test(groveLoader) && /import\("\.\/scene\.js"\)/.test(groveLoader));
check("both scenes handle reduced motion, visibility, DPR, and context loss", [landingScene, groveScene].every((scene) => /reducedMotion/.test(scene) && /IntersectionObserver/.test(scene) && /devicePixelRatio/.test(scene) && /webglcontextlost/.test(scene)));
check("both scenes stop frame scheduling offscreen and resume from BFCache", [landingScene, groveScene].every((scene) => /function stopFrames\(\)/.test(scene) && /function scheduleFrame\(\)/.test(scene) && /if \(event\.persisted\) \{\s*stopFrames\(\)/.test(scene) && /addEventListener\("pageshow", onPageShow\)/.test(scene) && /addEventListener\("visibilitychange", onVisibilityChange\)/.test(scene) && (scene.match(/requestAnimationFrame\(tick\)/g) || []).length === 1));
check("home scene uses the supported shadow filter without console fallback", /renderer\.shadowMap\.type = THREE\.PCFShadowMap/.test(landingScene) && !/PCFSoftShadowMap/.test(landingScene));

check("network scene builds a non-geographic canopy with announced identity trees", /non-geographic-canopy-sphere/.test(groveScene) && /IcosahedronGeometry\(SPHERE_RADIUS/.test(groveScene) && /CylinderGeometry/.test(groveScene) && /InstancedMesh/.test(groveScene) && /announced-identity-trees/.test(groveScene));
check("network scene crosses a nonempty canopy in several census directions", /groveArcCount\(field\.patchCount, quality\)/.test(groveScene) && /quality === "low" \? 3 : 6/.test(groveVisualModel) && /QuadraticBezierCurve3/.test(groveScene) && /TubeGeometry/.test(groveScene) && /aggregate-observation-signal/.test(groveScene) && /elder-discovery-satellite/.test(groveScene));
check("abstract canopy renders exactly one tree per announced identity", /grovePatchCount\(announced, quality\)/.test(groveScene) && /hashSeed\(`\$\{snapshot\.observedAt\}:\$\{announced\}`\)/.test(groveScene) && /announced <= 0\) return 0/.test(groveVisualModel) && /return announced/.test(groveVisualModel) && /const treeCount = patchCount/.test(groveScene));
check("scene controller exposes the complete query lifecycle", /return \{[\s\S]*beginQuery,[\s\S]*failQuery,[\s\S]*finishQuery,[\s\S]*updateSnapshot: replaceSnapshot/.test(groveScene));
check("loader emits soft checks and strong new-census pulses", /sceneController\?\.beginQuery\(\)/.test(groveLoader) && /sceneController\?\.finishQuery\(snapshot, \{ freshCensus \}\)/.test(groveLoader) && /sceneController\?\.failQuery\(\)/.test(groveLoader) && /lastLiveObservedAt !== snapshot\.observedAt/.test(groveLoader));
check("Grove resumes signed-view polling after BFCache restore", /function onPageHide\(\)\s*\{\s*window\.clearTimeout\(pollTimer\);\s*window\.clearTimeout\(ageTimer\)/.test(groveLoader) && /function onPageShow\(event\)\s*\{\s*if \(!event\.persisted\) return;\s*updateFreshness\(\);\s*load\(\)/.test(groveLoader) && /addEventListener\("pageshow", onPageShow\)/.test(groveLoader));
check("Grove updates relative age on minute boundaries without redrawing the scene", /nextAgeRefreshDelay/.test(groveLoader) && /function scheduleAgeRefresh\(\)[\s\S]*?updateFreshness\(\);[\s\S]*?scheduleAgeRefresh\(\)/.test(groveLoader) && /snapshotFreshness/.test(groveLoader) && /60_000 - \(elapsed % 60_000\)/.test(groveFreshness));
check("Grove catches up after a hidden tab becomes visible", /function onVisibilityChange\(\)[\s\S]*?if \(document\.hidden\) return;[\s\S]*?updateFreshness\(\);[\s\S]*?Date\.now\(\) - lastLoadFinishedAt >= POLL_INTERVAL_MS\) load\(\)/.test(groveLoader) && /document\.addEventListener\("visibilitychange", onVisibilityChange\)/.test(groveLoader));
check("Grove preserves the last verified live view when refresh fails", /if \(currentSnapshot && !currentView\.bundled\)[\s\S]*?refreshFailed: true[\s\S]*?updateFreshness\(\)/.test(groveLoader) && /snapshotState: stale \? "Stale" : "Update delayed"/.test(groveFreshness) && /showUnavailable\(\)/.test(groveLoader));
check("Grove geometry is aggregate-only", /snapshot\.observedAt/.test(groveScene) && /snapshot\.nodes\.announced/.test(groveScene) && !/onion|pubkey|operator|wallet|region|location|asn/i.test(groveScene));
check("Grove dashboard stays inside the signed aggregate contract", ["data-node-count", "data-snapshot-state", "data-network", "data-view-time", "data-snapshot-cadence"].every((field) => grovePage.includes(field)) && !/data-view-state|data-history-|data-relay-|data-onchain-|data-view-age|data-node-hours|data-change|Observed changes?|sessions|throughput|latency|bandwidth|success rate|reputation band/i.test(grovePage));

const headingIds = [...research.matchAll(/<h[1-6][^>]+id="([^"]+)"/g)].map((match) => match[1]);
check("legacy article bookmarks are forwarded", headingIds.length >= 15 && headingIds.every((id) => loader.includes(`"${id}"`)));
check("malformed and same-page article bookmarks remain safe", loader.includes('"title-block-header"') && loader.includes('"TOC"') && /try\s*\{[\s\S]*decodeURIComponent/.test(loader) && /addEventListener\("hashchange", forwardArticleBookmark\)/.test(loader));
check("clipboard fallback copies the command without its prompt", /helper\.value = command/.test(loader) && /execCommand\?\.\("copy"\)/.test(loader));
check("copy feedback is announced with the right noun", /setAttribute\("aria-live", "polite"\)/.test(loader) && /button\.dataset\.copyNoun \|\| "Command"/.test(loader) && /\$\{copyNoun\} copied to clipboard\./.test(loader));
check("clipboard failure reveals and selects the requested copy target", /finally\s*\{\s*helper\.remove\(\)/.test(loader) && /document\.getElementById\(button\.dataset\.copyTarget\)/.test(loader) && /visibleCode\.hidden = false/.test(loader) && /range\.selectNodeContents\(visibleCode\)/.test(loader) && /\$\{copyNoun\} selected\. Press Control\+C or Command\+C to copy\./.test(loader) && /if \(wasHidden\) visibleCode\.hidden = true/.test(loader));
check("copyable commands remain inspectable", /\.command code\s*\{[\s\S]*?overflow-wrap:\s*anywhere/.test(landingCss) && !/\.command code\s*\{[\s\S]*?text-overflow:\s*ellipsis/.test(landingCss));
check("compact release install remains one line while long guide commands can wrap", /\.agent-install code\s*\{[\s\S]*?overflow-x:\s*auto;[\s\S]*?white-space:\s*nowrap/.test(landingCss) && /\.command code\s*\{[\s\S]*?white-space:\s*normal/.test(landingCss));
check("mobile keeps the grove twenty pixels below the text", /@media \(max-width: 600px\)[\s\S]*?\.grove-stage canvas,\s*\.forest-fallback\s*\{\s*transform:\s*translateY\(1\.25rem\)/.test(landingCss));
check("copy controls stack before mobile commands can clip", /@media \(max-width: 600px\)\s*\{[\s\S]*?\.command\s*\{\s*grid-template-columns:\s*1fr/.test(landingCss));

check("CSP permits only self-hosted scripts", csp.includes("default-src 'none'") && csp.includes("script-src 'self'") && !csp.includes("unsafe-eval") && !/https?:/.test(csp));
check("CSP limits reads and closes objects and workers", csp.includes("connect-src 'self'") && csp.includes("object-src 'none'") && csp.includes("worker-src 'none'"));
check("browser reads versioned same-origin Sepolia heads before its bundled reference", /const LIVE_URL = "\/api\/v2\/data\/grove\/sepolia\/head"/.test(groveLoader) && /const COUNT_FALLBACK_URL = "\/api\/v1\/data\/grove\/sepolia\/head"/.test(groveLoader) && /async function fetchLiveSnapshot\(\)[\s\S]*?fetchSnapshot\(LIVE_URL\)[\s\S]*?fetchSnapshot\(COUNT_FALLBACK_URL\)/.test(groveLoader) && /const NETWORK = "sepolia"/.test(groveLoader) && /value\.network === NETWORK/.test(groveLoader) && /const FALLBACK_URL = "\/grove\/network\.fallback\.json"/.test(groveLoader) && !/raw\.githubusercontent|fetch\([^)]*\.onion/i.test(groveLoader));
check("browser polling uses normal HTTP cache revalidation for API ETags", /const POLL_INTERVAL_MS = 5 \* 60 \* 1_000/.test(groveLoader) && /cache:\s*"default"/.test(groveLoader) && !/cache:\s*"no-store"/.test(groveLoader));
check("browser verifies a pinned Ed25519 snapshot before rendering", /crypto\.subtle\.verify/.test(groveLoader) && /invalid public snapshot/.test(groveLoader) && groveLoader.includes(grovePublicKeyRawBase64(grovePublicKey)));
check("Vercel exposes v1 unchanged and adds signed Grove v2 plus OpenAPI", config.rewrites?.length === 6 && config.rewrites.some((rewrite) => rewrite.source === "/api/v1/data/grove/sepolia/head" && rewrite.destination === "/api/grove") && config.rewrites.some((rewrite) => rewrite.source === "/api/v2/data/grove/sepolia/head" && rewrite.destination === "/api/grove-v2") && config.rewrites.some((rewrite) => rewrite.source === "/api/v2/openapi.json" && rewrite.destination === "/openapi-v2.json") && config.rewrites.some((rewrite) => rewrite.source === "/grove/network.json" && rewrite.destination === "/api/grove"));
check("Vercel resolves clean Lab asset URLs without breaking direct-file paths", config.rewrites?.some((rewrite) => rewrite.source === "/lab.css" && rewrite.destination === "/lab/lab.css") && config.rewrites?.some((rewrite) => rewrite.source === "/lab.js" && rewrite.destination === "/lab/lab.js"));
check("Vercel deploys bounded Grove functions instead of an external rewrite", config.functions?.["api/grove.mjs"]?.maxDuration === 5 && config.functions?.["api/grove-v2.mjs"]?.maxDuration === 5 && !/raw\.githubusercontent/.test(JSON.stringify(config)));
check("Vercel gives the streamed Lab proxy a bounded long-running function", config.functions?.["api/lab-run.mjs"]?.maxDuration === 120 && /AbortSignal\.timeout\(110_000\)/.test(labApi) && /text\/event-stream/.test(labApi));
check("Vercel ignores the generated network-state branch", config.git?.deploymentEnabled?.["network-state"] === false);
check("Grove API validates a fixed, bounded, signed Sepolia source", /GROVE_SNAPSHOT_URL = "https:\/\/api\.github\.com\/repos\/dmarzzz\/shade-tree-node\/contents\/grove\.json\?ref=network-state"/.test(groveApiContract) && /GROVE_NETWORK = "sepolia"/.test(groveApiContract) && /value\.network === GROVE_NETWORK/.test(groveApiContract) && /GROVE_MAX_BYTES = 64 \* 1024/.test(groveApiContract) && /verifyBytes/.test(groveApiContract));
check("Grove API controls caching and byte validators without CORS", /Vercel-CDN-Cache-Control/.test(groveApi) && /createHash\("sha256"\)/.test(groveApi) && /matchesIfNoneMatch/.test(groveApi) && /"Cache-Control": "no-store"/.test(groveApi) && /if-none-match/.test(groveApi) && /ETag/.test(groveApi) && !/Access-Control-Allow-Origin/i.test(groveApi));
check("Grove v2 validates exact relay and optional onchain keys, freshness, cohort suppression, and signed bytes", /GROVE_V2_SNAPSHOT_URL = "https:\/\/api\.github\.com\/repos\/dmarzzz\/shade-tree-node\/contents\/grove-v2\.json\?ref=network-state"/.test(groveV2ApiContract) && /exactKeys\(value, hasOnchain/.test(groveV2ApiContract) && /observedAt >= now - maxAgeMs/.test(groveV2ApiContract) && /minimumCohort\) && value\.minimumCohort >= 5/.test(groveV2ApiContract) && /validPublicOnchain/.test(groveV2ApiContract) && /finalizedBlockTime/.test(groveOnchainApiContract) && /verifyBytes/.test(groveV2ApiContract) && /Vercel-CDN-Cache-Control/.test(groveV2Api) && /matchesIfNoneMatch/.test(groveV2Api));
check("scheduled publisher preserves v1 and emits the separately signed v2 head", /--out "\$RUNNER_TEMP\/grove\.json"/.test(uptimeWorkflow) && /--relay 1/.test(uptimeWorkflow) && /--out "\$RUNNER_TEMP\/grove-v2\.json"/.test(uptimeWorkflow) && /path:"grove\.json"/.test(uptimeWorkflow) && /path:"grove-v2\.json"/.test(uptimeWorkflow));
check("scheduled publisher carries the network-state deployment exclusion", /vercel_config='\{"git":\{"deploymentEnabled":\{"network-state":false\}\}\}'/.test(uptimeWorkflow) && /path:"docs\/post\/vercel\.json"/.test(uptimeWorkflow));
check("scheduled publisher verifies the production Grove page and both public heads", /verify-public:[\s\S]*needs:\s*publish[\s\S]*GROVE_ORIGIN:\s*https:\/\/shade-tree-node\.vercel\.app[\s\S]*\/grove\/[\s\S]*\/api\/v1\/data\/grove\/sepolia\/head[\s\S]*\/api\/v2\/data\/grove\/sepolia\/head[\s\S]*shade-tree-public-grove-v1[\s\S]*shade-tree-public-grove-v2/.test(uptimeWorkflow));
check("Grove v2 OpenAPI excludes per-node telemetry and defines unavailable as omission", groveV2OpenApi.paths?.["/api/v2/data/grove/sepolia/head"] && groveV2OpenApi.components?.schemas?.Relay?.additionalProperties === false && /No node identities or per-node records/.test(groveV2OpenApi.components.schemas.Relay.description) && !JSON.stringify(groveV2OpenApi).includes("nodeId"));

check("bundled snapshot uses the public aggregate schema", fallbackSnapshot.schema === "shade-tree-public-grove-v1" && fallbackSnapshot.source?.directoryVerified === true && fallbackSnapshot.source?.definition === "announced-within-ttl");
check("bundled snapshot top level is allowlisted", Object.keys(fallbackSnapshot).sort().join(",") === "attestation,growth,history,network,nodes,observedAt,privacy,schema,source");
check("bundled snapshot source is allowlisted", Object.keys(fallbackSnapshot.source).sort().join(",") === "bootnodeReachable,cadenceMinutes,definition,directoryVerified");
check("bundled history contains count-only samples", fallbackSnapshot.history.every((sample) => Object.keys(sample).sort().join(",") === "announced,at"));
check("bundled reference has a valid pinned publication signature", verifyPublicGroveAttestation(fallbackSnapshot, grovePublicKey));
check("tampering with the bundled count breaks its signature", !verifyPublicGroveAttestation({ ...fallbackSnapshot, nodes: { announced: 3 } }, grovePublicKey));
const fallbackText = JSON.stringify(fallbackSnapshot);
check("bundled snapshot contains no identity, place, activity, or pulse field", !/\.onion|pubkey|operator|wallet|address|region|country|coordinates?|asn|destination|tunnels?|bytes|requests?|queries|pulse/i.test(fallbackText));

for (const script of ["site.js", "glyphgrove.js", "dapple.js", "grove.js", "grove/network.js", "grove/file-preview.js", "grove/scene.js", "grove/freshness.js", "grove/history.js", "grove/visual-model.js", "grove/onchain.js", "lab/lab.js", "stake/stake.js", "api/grove.mjs", "api/_grove-contract.mjs", "api/grove-v2.mjs", "api/_grove-v2-contract.mjs", "api/_grove-onchain-contract.mjs", "api/lab-run.mjs"]) {
  const result = spawnSync(process.execPath, ["--check", join(SITE, script)], { encoding: "utf8" });
  check(`${script} parses as JavaScript`, result.status === 0);
}

check("robots advertises the sitemap", /Sitemap: https:\/\/shade-tree-node\.vercel\.app\/sitemap\.xml/.test(read("robots.txt")));
const indexablePages = [
  ["home", landing, "/", "WebSite"],
  ["agent guide", agentPage, "/agent/", "BreadcrumbList"],
  ["operator guide", operatorPage, "/operator/", "BreadcrumbList"],
  ["private staking", stakePage, "/stake/", "WebApplication"],
  ["Grove", grovePage, "/grove/", "BreadcrumbList"],
  ["research", research, "/research/", "Article"],
];
for (const [name, page, path, schemaType] of indexablePages) {
  const canonical = new URL(path, "https://shade-tree-node.vercel.app").href;
  check(`${name} has one descriptive title, description, canonical URL, and H1`, (page.match(/<title>[^<]+<\/title>/g) || []).length === 1 && (page.match(/<meta name="description" content="[^"]+"/g) || []).length === 1 && page.includes(`<link rel="canonical" href="${canonical}"`) && (page.match(/<h1\b/g) || []).length === 1);
  check(`${name} social metadata matches its canonical page`, page.includes(`<meta property="og:url" content="${canonical}"`) && /<meta property="og:site_name" content="Shade Tree Grove"/.test(page) && /<meta property="og:image:width" content="1200"/.test(page) && /<meta property="og:image:height" content="630"/.test(page) && /<meta property="og:image:alt" content="[^"]+"/.test(page));
  check(`${name} structured data parses and includes ${schemaType}`, structuredData(page).some((item) => item["@type"] === schemaType));
}
check("research structured data records its author and current modification date", structuredData(research).some((item) => item["@type"] === "Article" && item.author?.name === "dmarz" && item.dateModified === "2026-09-01"));
check("hidden and error routes stay out of search results", /<meta name="robots" content="noindex, follow">/.test(labPage) && /<meta name="robots" content="noindex, follow">/.test(notFoundPage));
check("branded 404 gives visitors useful recovery routes", /<h1>This path leaves the grove\.<\/h1>/.test(notFoundPage) && /href="\/">Return home<\/a>/.test(notFoundPage) && /href="\/agent\/">Set up an agent<\/a>/.test(notFoundPage));
const sitemapLocations = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);
check("sitemap contains only the six indexable public pages", sitemapLocations.length === indexablePages.length && indexablePages.every(([, , path]) => sitemapLocations.includes(new URL(path, "https://shade-tree-node.vercel.app").href)) && !sitemap.includes("/lab/") && !sitemap.includes("404"));

check("staking surface is local-first, responsive, and visibly separates private from public state", /Stake without giving us an identity/.test(stakePage) && /data-leaf-tag/.test(stakePage) && /data-sponsor-step/.test(stakePage) && /@media \(max-width: 900px\)/.test(stakeCss) && /@media \(prefers-reduced-motion: reduce\)/.test(stakeCss) && stakeScript.length > 100_000);

console.log(`PASS: site selftest (${checks.length} checks)`);
