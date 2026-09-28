/* global document, fetch, navigator, TextDecoder, window */

const stages = ["discover", "select", "prove", "dial", "gate", "egress"];
const phaseToStage = { canopy: "discover", select: "select", prove: "prove", dial: "dial", gate: "gate", egress: "egress" };
const stageCopy = {
  discover: "Fetching the Elder Tree's signed Canopy through Tor, then checking its pinned signer.",
  select: "Filtering the verified Grove for an invited-capable Protocol v4 Shade Tree node.",
  prove: "Minting one target-bound RLN Groth16 membership proof with a fresh epoch slot.",
  dial: "Opening a Tor circuit to the selected Shade Tree node's onion service.",
  gate: "The node is checking the proof, root, nullifier, artifact, and local tunnel budget.",
  egress: "The admitted node opened an opaque CONNECT tunnel; TLS terminates only at example.com.",
};

const runButton = document.querySelector("[data-run]");
const runLabel = document.querySelector("[data-run-label]");
const routeMap = document.querySelector("[data-route-map]");
const traceStatus = document.querySelector("[data-trace-status]");
const eventIndex = document.querySelector("[data-event-index]");
const eventCopy = document.querySelector("[data-event-copy]");
const nodeAlias = document.querySelector("[data-node-alias]");
const proofState = document.querySelector("[data-proof-state]");
const responseStrip = document.querySelector("[data-response-strip]");
const responseCode = document.querySelector("[data-response-code]");
const responseAnswer = document.querySelector("[data-response-answer]");
const responseTime = document.querySelector("[data-response-time]");
const nextActions = document.querySelector("[data-lab-next]");
const shareButton = document.querySelector("[data-share-lab]");
const shareStatus = document.querySelector("[data-share-status]");
const labShareUrl = "https://shade-tree-node.vercel.app/lab/";
let currentStage = null;
let running = false;
let cooldownTimer = null;

function stageElement(stage) {
  return document.querySelector(`[data-stage="${stage}"]`);
}

function setStage(stage, state = "active") {
  const index = stages.indexOf(stage);
  if (index < 0) return;
  stages.forEach((name, at) => {
    const element = stageElement(name);
    if (at < index) element.dataset.state = "done";
    else if (at === index) element.dataset.state = state;
    else delete element.dataset.state;
  });
  currentStage = stage;
  routeMap.style.setProperty("--route-progress", String(Math.round(((index + (state === "done" ? 1 : 0.55)) / stages.length) * 100)));
  eventIndex.textContent = `${String(index + 1).padStart(2, "0")} / 06`;
}

function reset() {
  stages.forEach((stage) => delete stageElement(stage).dataset.state);
  routeMap.style.setProperty("--route-progress", "0");
  delete routeMap.dataset.failed;
  currentStage = null;
  traceStatus.textContent = "Contacting the live runner";
  eventIndex.textContent = "00 / 06";
  eventCopy.textContent = "The browser is opening a same-origin event stream. No member key or destination input is sent.";
  nodeAlias.textContent = "awaiting route";
  proofState.textContent = "Waiting";
  proofState.dataset.state = "live";
  document.querySelector("[data-artifact]").textContent = "not minted";
  document.querySelector("[data-slot]").textContent = "—";
  document.querySelector("[data-epoch]").textContent = "—";
  document.querySelectorAll("[data-proof]").forEach((element) => { element.textContent = "—"; element.removeAttribute("title"); });
  for (const section of ["a", "b", "c"]) document.querySelector(`[data-proof-panel="${section}"] dl`).replaceChildren();
  delete responseStrip.dataset.state;
  responseCode.textContent = "—";
  responseAnswer.textContent = "Request in progress";
  responseTime.textContent = "—";
  nextActions.hidden = true;
}

function setExact(element, value) {
  const text = String(value ?? "—");
  element.textContent = text;
  if (text !== "—") element.title = text;
}

function proofRow(label, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  const detail = document.createElement("dd");
  const code = document.createElement("code");
  term.textContent = label;
  setExact(code, value);
  detail.append(code);
  row.append(term, detail);
  return row;
}

function renderPoint(section, point) {
  const panel = document.querySelector(`[data-proof-panel="${section}"] dl`);
  const values = section === "b"
    ? [
        ["b 0,0", point?.[0]?.[0]], ["b 0,1", point?.[0]?.[1]],
        ["b 1,0", point?.[1]?.[0]], ["b 1,1", point?.[1]?.[1]],
        ["projective", point?.[2]?.join(", ")],
      ]
    : [[`${section} x`, point?.[0]], [`${section} y`, point?.[1]], ["projective", point?.[2]]];
  panel.replaceChildren(...values.map(([label, value]) => proofRow(label, value)));
}

function renderProof(event) {
  document.querySelector("[data-artifact]").textContent = event.artifact || "unknown";
  document.querySelector("[data-slot]").textContent = event.slot ?? "—";
  document.querySelector("[data-epoch]").textContent = event.epoch || "—";
  for (const [name, value] of Object.entries(event.pub || {})) {
    const element = document.querySelector(`[data-proof="pub.${name}"]`);
    if (element) setExact(element, value);
  }
  renderPoint("a", event.pi?.a);
  renderPoint("b", event.pi?.b);
  renderPoint("c", event.pi?.c);
  proofState.textContent = "Minted";
  proofState.dataset.state = "done";
}

function eventMessage(event) {
  if (event.phase === "canopy" && event.status === "query") return "Querying the Elder Tree for a fresh signed Canopy over Tor.";
  if (event.phase === "canopy" && event.status === "verified") return `Pinned signature verified. ${event.count ?? "The"} live Shade Tree nodes are in this Canopy.`;
  if (event.phase === "canopy" && event.status === "cache") return `Fresh discovery was unavailable; using a previously verified ${event.count ?? ""}-node Canopy.`;
  if (event.phase === "select" && event.status === "done") return `${event.candidates?.length ?? 0} invited-capable nodes passed local selection; the first is now being tried.`;
  if (event.phase === "prove" && event.status === "start") return `Loading ${event.artifact || "the accepted artifact"} and minting a target-bound proof.`;
  if (event.phase === "prove" && event.status === "done") return `Groth16 proof minted in slot ${event.slot}; its public signals and curve points are now visible.`;
  if (event.phase === "dial" && event.status === "start") return `Dialing ${event.node || "a selected node"} as a Tor onion service.`;
  if (event.phase === "dial" && event.status === "done") return `${event.node || "The node"} answered through Tor${event.latencyMs != null ? ` in ${event.latencyMs} ms` : ""}.`;
  if (event.phase === "dial" && event.status === "failover") return `${event.node || "A node"} did not complete; the same proof is moving to the next candidate.`;
  if (event.phase === "gate" && event.status === "start") return `${event.node || "The node"} is verifying the proof before it opens any destination socket.`;
  if (event.phase === "gate" && event.status === "done") return `${event.node || "The node"} accepted the private membership proof and local epoch slot.`;
  if (event.phase === "egress" && event.status === "start") return stageCopy.egress;
  if (event.phase === "egress" && event.status === "done") return `example.com returned HTTP ${event.httpStatus}. The TLS request completed through the admitted node.`;
  return stageCopy[phaseToStage[event.phase]] || "The live protocol emitted a new event.";
}

function handleTrace(event) {
  if (event.phase === "run") return;
  const stage = phaseToStage[event.phase];
  if (stage) setStage(stage, event.status === "done" || event.status === "verified" ? "done" : "active");
  if (event.node) nodeAlias.textContent = event.node;
  if (event.phase === "prove" && event.status === "done") renderProof(event);
  traceStatus.textContent = event.status === "done" || event.status === "verified" ? `${stage || event.phase} complete` : `${stage || event.phase} · ${event.status}`;
  eventCopy.textContent = eventMessage(event);
}

function handleDone(result) {
  setStage("egress", "done");
  routeMap.style.setProperty("--route-progress", "100");
  traceStatus.textContent = "Live route complete";
  eventCopy.textContent = "The destination response returned to this browser through the Shade Tree route.";
  responseStrip.dataset.state = "done";
  responseCode.textContent = String(result.status ?? "200");
  responseAnswer.textContent = result.answer || "Response received";
  responseTime.textContent = Number.isFinite(result.durationMs) ? `${(result.durationMs / 1000).toFixed(1)} s` : "complete";
  nextActions.hidden = false;
}

function handleFailed(result) {
  if (currentStage) stageElement(currentStage).dataset.state = "failed";
  routeMap.dataset.failed = "true";
  traceStatus.textContent = "Live route stopped";
  eventCopy.textContent = result.message || "The live route did not complete.";
  proofState.textContent = proofState.textContent === "Minted" ? "Minted" : "Stopped";
  if (proofState.textContent !== "Minted") proofState.dataset.state = "failed";
  responseStrip.dataset.state = "failed";
  responseCode.textContent = "ERR";
  responseAnswer.textContent = result.code || "Route unavailable";
}

function parseBlock(block) {
  let type = "message";
  const data = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) type = line.slice(6).trim();
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  }
  if (!data.length) return;
  const value = JSON.parse(data.join("\n"));
  if (type === "trace") handleTrace(value);
  else if (type === "done") handleDone(value);
  else if (type === "failed") handleFailed(value);
}

async function consumeEvents(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done }).replaceAll("\r\n", "\n");
    let boundary;
    while ((boundary = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      if (block.trim()) parseBlock(block);
    }
    if (done) break;
  }
  if (buffer.trim()) parseBlock(buffer);
}

function beginCooldown(seconds) {
  window.clearInterval(cooldownTimer);
  let remaining = Math.max(1, Number(seconds) || 16);
  runButton.disabled = true;
  const tick = () => {
    runLabel.textContent = `Available in ${remaining}s`;
    remaining -= 1;
    if (remaining < 0) {
      window.clearInterval(cooldownTimer);
      runButton.disabled = false;
      runLabel.textContent = "Send live request";
    }
  };
  tick();
  cooldownTimer = window.setInterval(tick, 1000);
}

async function run() {
  if (running) return;
  running = true;
  runButton.disabled = true;
  runLabel.textContent = "Route in motion";
  reset();
  try {
    const response = await fetch("../api/lab-run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
      cache: "no-store",
    });
    if (!response.ok) {
      const retryAfter = response.headers.get("retry-after");
      handleFailed({ code: response.status === 429 ? "COOLDOWN" : "RUNNER_UNAVAILABLE", message: response.status === 429 ? "Another live proof just used this bounded runner. The next slot opens shortly." : "The live runner is unavailable right now." });
      if (response.status === 429) beginCooldown(retryAfter);
      return;
    }
    await consumeEvents(response);
    beginCooldown(16);
  } catch {
    handleFailed({ code: "STREAM_INTERRUPTED", message: "The live event stream was interrupted before the route completed." });
  } finally {
    running = false;
    if (!cooldownTimer) {
      runButton.disabled = false;
      runLabel.textContent = "Send live request";
    }
  }
}

for (const tab of document.querySelectorAll("[data-proof-tab]")) {
  tab.addEventListener("click", () => {
    const section = tab.dataset.proofTab;
    document.querySelectorAll("[data-proof-tab]").forEach((button) => button.setAttribute("aria-selected", String(button === tab)));
    document.querySelectorAll("[data-proof-panel]").forEach((panel) => { panel.hidden = panel.dataset.proofPanel !== section; });
  });
  tab.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
    const tabs = [...document.querySelectorAll("[data-proof-tab]")];
    const direction = event.key === "ArrowRight" ? 1 : -1;
    tabs[(tabs.indexOf(tab) + direction + tabs.length) % tabs.length].click();
    document.querySelector("[data-proof-tab][aria-selected=\"true\"]")?.focus();
    event.preventDefault();
  });
}

shareButton.addEventListener("click", async () => {
  if (navigator.share) {
    try {
      await navigator.share({
        title: "Live Protocol Lab · ShadeNet",
        text: "One live Shade Tree request, with every routing and proof step visible.",
        url: labShareUrl,
      });
      shareStatus.textContent = "Lab link shared.";
      return;
    } catch (error) {
      if (error?.name === "AbortError") return;
    }
  }

  const idleLabel = shareButton.textContent;
  let copied = false;
  try {
    await navigator.clipboard.writeText(labShareUrl);
    copied = true;
  } catch {
    const helper = document.createElement("textarea");
    helper.value = labShareUrl;
    helper.readOnly = true;
    helper.style.position = "fixed";
    helper.style.left = "-9999px";
    document.body.append(helper);
    try {
      helper.select();
      copied = Boolean(document.execCommand?.("copy"));
    } finally {
      helper.remove();
    }
  }

  shareButton.textContent = copied ? "copied" : "copy unavailable";
  shareStatus.textContent = copied ? "Lab link copied to clipboard." : `Copy this Lab link: ${labShareUrl}`;
  window.setTimeout(() => {
    shareButton.textContent = idleLabel;
    shareStatus.textContent = "";
  }, copied ? 1800 : 6000);
});

if (window.location.protocol === "file:") {
  runButton.disabled = true;
  runLabel.textContent = "Open hosted Lab";
  traceStatus.textContent = "Local visual preview";
  eventCopy.textContent = "This direct-file preview keeps the interface styled, but live Tor requests run only from the hosted Lab.";
} else {
  runButton.addEventListener("click", run);
}
