// Own-node exclusion (roadmap #369 M0): a client never picks, from the canopy, a node that this
// machine runs or that the user says shares this machine's internet connection.
//
// Why: a node exits from its own public IP. If that IP is the client's own (the client's own node,
// or a node on the same home connection), the destination sees the user's own address and the
// tunnel hides nothing. Observed live: a client on the same home network as a canopy node exited
// from its own home IP. Tor's analogue is the rule against a path through relays in the client's
// own family or /16.
//
// What the client can know without leaking anything. Canopy records carry no egress IP, on
// purpose (ROADMAP §3.1: publishing onion -> IP would hand blocklisters the fleet), and a client
// must not ask a third-party IP-echo service for its own address over the clear net. So the rule
// is keyed by ONION, from three local sources:
//   1. SHADENET_AVOID_NODES (or SHADE_TREE_AVOID_NODES): onions, comma or space separated.
//   2. the avoid-nodes file, <config dir>/shadenet/avoid-nodes ($XDG_CONFIG_HOME, else
//      ~/.config; %APPDATA% on Windows): one onion per line, `#` comments. `shadenet-node run`
//      adds its own onion here, so a client on the same machine and user account skips that
//      node with no setup. Nodes on other machines behind the same connection (or in a container
//      whose home directory is not this one) are added here by hand.
//   3. $SHADENET_STATE/hs-gateway/hostname, when SHADENET_STATE is set in the client's
//      environment (the node's state directory).
// A node on the same connection that is in none of these is NOT detected: that needs the node's
// egress IP and the client's public IP, which this protocol does not provide yet (follow-up).
//
// Scope: canopy selection only. An explicitly pinned onion (SHADE_TREE_ONION, `--onion`) is the
// caller's choice and is honored, so an operator can still test their own node on purpose.
//
// The normalization and the rule are pinned in testdata/vectors.json `ownNodes`; the Rust client
// (crates/shadenet-proto `normalize_own_node`, `exclude_own_nodes`) reproduces them.

import { readFileSync, mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { onionToPubkey } from "./directory.mjs";

// Stable prefix of the fail-closed refusal (pinned in the vectors; both clients start with it).
export const REASON_ONLY_OWN_NODES = "only-own-nodes";
export const AVOID_NODES_FILE = "avoid-nodes";

// One user-supplied onion -> `<56 base32>.onion`, or null when it is not a checksummed v3 onion.
// Accepts surrounding whitespace, any case, a missing `.onion` suffix and a `:port` suffix.
export function normalizeOwnNode(raw) {
  if (typeof raw !== "string") return null;
  let s = raw.trim().toLowerCase();
  const port = /:(\d{1,5})$/.exec(s);
  if (port) s = s.slice(0, port.index);
  if (s.endsWith(".onion")) s = s.slice(0, -".onion".length);
  if (s.length !== 56) return null;
  try { onionToPubkey(s); } catch { return null; }
  return `${s}.onion`;
}

// Split a list (env value or file text) into normalized onions. Junk entries are dropped and
// returned separately so callers can warn about them.
export function parseOwnNodeList(text) {
  const nodes = [];
  const junk = [];
  for (const line of String(text ?? "").split(/\r?\n/)) {
    for (const item of line.replace(/#.*$/, "").split(/[\s,]+/)) {
      if (!item) continue;
      const onion = normalizeOwnNode(item);
      if (onion) { if (!nodes.includes(onion)) nodes.push(onion); } else junk.push(item);
    }
  }
  return { nodes, junk };
}

// The user config directory the Rust client also uses (crates/shadenet-cli config_file.rs).
export function configDir(env = process.env, platform = process.platform) {
  if (env.XDG_CONFIG_HOME) return join(env.XDG_CONFIG_HOME, "shadenet");
  if (platform === "win32") return env.APPDATA ? join(env.APPDATA, "shadenet") : null;
  if (env.HOME) return join(env.HOME, ".config", "shadenet");
  return null;
}

export function avoidNodesPath(env = process.env, platform = process.platform) {
  const dir = configDir(env, platform);
  return dir ? join(dir, AVOID_NODES_FILE) : null;
}

// Gather every locally known own node. Never touches the network; unreadable sources are skipped.
// Returns { nodes: Set<onion>, sources: [{ source, count }], junk: [string] }.
export function loadOwnNodes({ env = process.env, platform = process.platform, read = (p) => readFileSync(p, "utf8") } = {}) {
  const nodes = new Set();
  const sources = [];
  const junk = [];
  const add = (source, text) => {
    const parsed = parseOwnNodeList(text);
    for (const n of parsed.nodes) nodes.add(n);
    junk.push(...parsed.junk);
    if (parsed.nodes.length) sources.push({ source, count: parsed.nodes.length });
  };
  const listed = env.SHADENET_AVOID_NODES ?? env.SHADE_TREE_AVOID_NODES;
  if (listed) add("SHADENET_AVOID_NODES", listed);
  const file = avoidNodesPath(env, platform);
  if (file) { try { add(file, read(file)); } catch { /* absent: nothing to avoid */ } }
  if (env.SHADENET_STATE) {
    const hostname = join(String(env.SHADENET_STATE).trim(), "hs-gateway", "hostname");
    try { add(hostname, read(hostname)); } catch { /* no node state here */ }
  }
  return { nodes, sources, junk };
}

// THE RULE. Drop every gateway whose onion is an own node. Returns the SAME array reference when
// nothing is dropped (so the default path stays byte-identical), else a filtered copy, plus the
// dropped onions. Entries whose onion does not parse are kept: they are not known to be ours.
export function excludeOwnNodes(gateways, own) {
  if (!own || own.size === 0 || !Array.isArray(gateways)) return { gateways, excluded: [] };
  const excluded = [];
  const kept = gateways.filter((g) => {
    const onion = normalizeOwnNode(typeof g === "string" ? g : g?.onion);
    if (onion && own.has(onion)) { excluded.push(onion); return false; }
    return true;
  });
  return excluded.length ? { gateways: kept, excluded } : { gateways, excluded };
}

export function onlyOwnNodesMessage(count) {
  return `${REASON_ONLY_OWN_NODES}: every node the canopy offers (${count}) is one this machine or its connection runs, and exiting through it would show destinations your own IP; wait for other nodes, or remove the entry from SHADENET_AVOID_NODES / the avoid-nodes file if it is not on this connection`;
}

// Called by `shadenet-node run`: add this node's onion to the avoid-nodes file so a client run by
// the same user on the same machine never exits through it. Idempotent and best-effort.
export function registerOwnNode(onion, { env = process.env, platform = process.platform, read = (p) => readFileSync(p, "utf8"), now = () => new Date() } = {}) {
  const normalized = normalizeOwnNode(onion);
  const file = avoidNodesPath(env, platform);
  if (!normalized || !file) return { added: false, file };
  let existing = "";
  try { existing = read(file); } catch { /* first entry */ }
  if (parseOwnNodeList(existing).nodes.includes(normalized)) return { added: false, file };
  mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
  const sep = existing && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(file, `${sep}# added by shadenet-node run, ${now().toISOString().slice(0, 10)}\n${normalized}\n`, { mode: 0o600 });
  return { added: true, file };
}
