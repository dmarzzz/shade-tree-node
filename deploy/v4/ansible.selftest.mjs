// Static safety contract for the target-independent Ansible layer. Live behavior is exercised only
// against operator-selected hosts; this suite proves the committed role cannot silently float refs,
// skip the public record gate, expose runtime listeners, or select on-chain admission without keys.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const TASKS = readFileSync(join(HERE, "ansible/roles/shade_tree_v4/tasks/main.yml"), "utf8");
const DEFAULTS = readFileSync(join(HERE, "ansible/roles/shade_tree_v4/defaults/main.yml"), "utf8");
const PLAYBOOK = readFileSync(join(HERE, "ansible/playbook.yml"), "utf8");
const GATEWAY_SECRET = readFileSync(join(HERE, "ansible/roles/shade_tree_v4/templates/gateway-secrets.conf.j2"), "utf8");
const ELDER_STAKE = readFileSync(join(HERE, "ansible/roles/shade_tree_v4/templates/elder-stake.conf.j2"), "utf8");

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else { console.log(`  FAIL ${message}`); failures++; }
};

console.log("controller gate:");
const preflightAt = TASKS.indexOf("Run the fail-closed v4 record preflight");
const aptAt = TASKS.indexOf("Install controller prerequisites and host firewall");
ok(preflightAt >= 0 && aptAt > preflightAt, "live record validation runs before the first remote package mutation");
ok(/preflight\.mjs[\s\S]*--repo-root[\s\S]*--quiet/.test(TASKS), "controller verifies artifact bytes as part of deploy preflight");
ok(/services\.node/.test(TASKS) && /version: "\{\{ shade_tree_service_pin\.commit \}\}"/.test(TASKS), "checkout uses the record's full immutable service commit");
ok(!/version:\s*(main|master|HEAD)\b/.test(TASKS + DEFAULTS), "role has no floating git ref fallback");

console.log("identity and admission:");
ok(/shade_tree_target_mode in \['elder', 'elder-and-node', 'node'\]/.test(TASKS) && /SHADE_TREE_ELDER_ONLY/.test(TASKS), "dedicated Elder targets select bootstrap Elder-only mode");
ok(/onion-identity\.mjs[\s\S]*derive/.test(TASKS) && /canopySigner/.test(TASKS), "restored onion and Canopy signer are checked before cutover");
ok(/membersSha256/.test(TASKS) && /checksum_algorithm: sha256/.test(TASKS), "invited member bytes must match the reviewed root hash");
ok(/shade_tree_slash_key is match/.test(TASKS) && /shade_tree_gateway_operator_key is match/.test(TASKS), "on-chain private keys are syntactically required before mutation");
ok(/no_log: true/g.test(TASKS) && (TASKS.match(/no_log: true/g) || []).length >= 8, "secret-bearing validation, copies, templates, and bootstrap are redacted");
ok(!/SHADE_TREE_SLASH_KEY=/.test(GATEWAY_SECRET) && /SHADE_TREE_SLASH_CONTRACT/.test(GATEWAY_SECRET), "node drop-in binds the recorded slash contract and carries no key");
ok(/dest: \/etc\/credstore\/SHADE_TREE_SLASH_KEY/.test(TASKS) && /dest: \/etc\/credstore\/SHADE_TREE_GW_OPERATOR_KEY/.test(TASKS), "role secrets are systemd credentials (OPS-12)");
ok(!/Environment=SHADE_TREE_(SLASH_KEY|GW_OPERATOR_KEY)=/.test(TASKS), "no role secret is rendered into Environment=");
ok(/SHADE_TREE_STAKE_MODE=onchain/.test(ELDER_STAKE) && /SHADE_TREE_GATEWAY_REGISTRY/.test(ELDER_STAKE), "stake-gated Elder uses an explicit on-chain registry");

console.log("host hardening and idempotence:");
ok(/ufw default deny incoming/.test(TASKS) && /shade-tree-v4-admin/.test(TASKS) && /unexpected inbound allow rule/.test(TASKS), "firewall permits only the exact reviewed admin CIDR rule");
ok(/shade_tree_manage_firewall:\s*true/.test(DEFAULTS) && /when: shade_tree_manage_firewall \| bool/.test(TASKS), "external IaC can own SSH policy without the application role rewriting UFW");
ok(/SHADE_TREE_LOG_FORMAT: json/.test(TASKS) && /SHADE_TREE_BANNER: never/.test(TASKS), "bootstrap is pinned to JSON logs without terminal decoration");
ok(/shade_tree_tunnel_max_payload_bytes:\s*41943040/.test(DEFAULTS) && /SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES/.test(TASKS), "gateway deployment pins the provisional 40 MiB combined payload ceiling");
ok(/SHADE_TREE_ZK_ARTIFACTS/.test(TASKS) && /shade_tree_artifact_specs \| join/.test(TASKS), "node and heartbeat receive the record-derived explicit artifact set");
ok(/Refuse public service or metrics listeners/.test(TASKS) && /127\[\.\]0\[\.\]0\[\.\]1/.test(TASKS), "postflight rejects non-loopback service or metrics sockets");
ok(/shade_tree_reconcile_fingerprint/.test(TASKS) && /\.applied/.test(TASKS) && /only after every check passes/.test(TASKS), "re-runs use a configuration fingerprint written only after postflight success");
ok(/hosts: shade_tree_v4/.test(PLAYBOOK) && !/(ansible_host|[0-9]{1,3}(?:\.[0-9]{1,3}){3})/.test(PLAYBOOK), "playbook contains no target or provider address");

console.log("reachability gate (issue #254):");
const markerAt = TASKS.indexOf("Record successful reconciliation only after every check passes");
const readyAt = TASKS.indexOf("Wait until this host's onion answers through Tor and its heartbeat is accepted");
const readyTask = readyAt >= 0 ? TASKS.slice(readyAt) : "";
ok(markerAt >= 0 && readyAt > markerAt && !/\n- name:/.test(readyTask.slice(1)), "the wait is the last task, after the reconciliation marker (a slow descriptor never forces a second bootstrap)");
ok(/scripts\/onion-ready\.mjs/.test(readyTask) && /--onion \{\{ onion \| quote \}\}/.test(readyTask) && /shade_tree_remote_identity_checks \| map\(attribute='onion'\) \| unique/.test(readyTask), "it dials every onion this host serves, the same list the identity postflight verified");
ok(/\{% if shade_tree_runs_node %\}--heartbeat-metrics/.test(readyTask) && /shade_tree_heartbeat_metrics_port/.test(readyTask) && /--elders \{\{ shade_tree_ready_elders \| quote \}\}/.test(readyTask), "a node also needs its heartbeat accepted by the Elder Trees");
ok(/ActiveEnterTimestamp/.test(readyTask) && /tor@default\.service/.test(readyTask) && /--since "\$since"/.test(readyTask), "an announce from before the Tor or unit restart does not count");
ok(/--timeout \{\{ shade_tree_ready_timeout_seconds \| int \}\}/.test(readyTask) && /async: "\{\{ \(shade_tree_ready_timeout_seconds \| int\) \+ 120 \}\}"/.test(readyTask) && /poll: 10/.test(readyTask), "the wait is bounded on the host and on the controller");
ok(/when: shade_tree_wait_ready \| bool/.test(readyTask) && !/no_log|ignore_errors|failed_when: false/.test(readyTask), "a timeout fails the play with the script's message; the gate can be switched off explicitly");
ok(/shade_tree_wait_ready:\s*true/.test(DEFAULTS) && /shade_tree_ready_timeout_seconds:\s*600/.test(DEFAULTS) && /shade_tree_ready_elders:\s*all/.test(DEFAULTS) && /shade_tree_tor_socks_port:\s*9050/.test(DEFAULTS), "defaults: on, 600 s, every Elder, the host's system Tor");

console.log(failures ? `\n${failures} FAILED` : "\nall v4 Ansible safety checks passed");
process.exit(failures ? 1 : 0);
