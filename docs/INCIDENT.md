# Incident response

Operational playbook for the seven failure modes that matter. Each entry: symptoms, immediate
containment, root-cause investigation, recovery, prevention. Read `docs/AUDIT.md` first for the
trust model these procedures rely on. Where a step is still manual it says so and points at the
`docs/history/SHIP-PLAN.md` task (the "Honest gaps" list at the end is the current one).

The single fact that shapes every response: **the pinned directory signer is a discovery trust
boundary.** Clients trust it to choose the candidate list. A compromised signer can omit, reorder,
or add entries, including a malicious onion it controls. Onion/key binding prevents it from making
an existing onion terminate at another key. Optional stake checks and onion-signed capabilities
narrow the risk but do not remove signer trust. Keep that boundary in mind before escalating.

## 0. On-call, contact and escalation

**Who.** One maintainer operates the Sepolia research canopy on a best-effort basis; there is no
24/7 rotation. Reports and alerts are acknowledged within 24 hours.

**How problems reach the operator.**

| Source | Path |
|---|---|
| Canopy monitor (orbital-one) | Prometheus scrapes the Elder, every node and heartbeat, and each host over forwarding-only SSH tunnels; Alertmanager sends every firing and resolved alert to the operator's Matrix room through Hermes (`[shadenet] FIRING <alert> (<host>)`). Rules: `monitoring/alerts.yml` plus host, probe and pin-drift rules in the operator's `shadenet_monitor` role |
| Incident feed (every Elder) | `GET /incidents` on each Elder is a signed list of open incidents; Alertmanager posts firing and resolved alerts to `POST /incidents/alertmanager` (bearer `SHADE_TREE_BOOTNODE_INCIDENTS_TOKEN`), and an operator can edit `SHADE_TREE_BOOTNODE_INCIDENTS_FILE` by hand for planned work. Clients fetch it with the directory and show it in `problems[]`, so an agent sees "node-06 restarting since 22:11Z" instead of a bare timeout. Receiver config: `monitoring/alertmanager.incidents.example.yml` |
| Uptime probes | Hosted workflow (every 15 minutes) and the Lab runner (every 5 minutes); an Elder unreachable from the Lab for 15 minutes pages |
| Security reports | GitHub private vulnerability reporting (SECURITY.md) |
| Everyone else | GitHub issues |

**Severity.**

| Severity | Examples | Response |
|---|---|---|
| page | Elder down or unreachable, fleet under 2 nodes, host down, no fresh staked root, suspected key compromise | Start the matching playbook below the same day |
| warn | RPC endpoint failing over, verify latency high, pin drift, probe stale, disk or memory pressure | Fix within a week |
| security | A key or signer compromise, a proof or contract soundness issue | Contain first (playbooks 2, 3, 4), then disclose through a GitHub security advisory |

**Communicating an outage.** Open a GitHub issue titled `incident: <what>` with the start time, the
affected surface and the current state, and close it with a short cause and fix. The canopy page
shows the probe history, so no separate status host is needed.

**If the operator is unreachable.** The canopy is disposable Sepolia research infrastructure. Clients
keep working from the last-known-good canopy until nodes age out; nothing holds real funds.

---

## 1. Bootnode down / unreachable

**Symptoms.** `GET /directory` over Tor times out or refuses. Clients log a fresh-fetch failure and
fall back; `loadDirectory` returns `{ source: "cache" }` instead of `"fresh"`. `/health` unreachable.

**Why the fleet keeps working.** Clients cache the last-known-good directory
(`SHADE_TREE_DIRECTORY_CACHE`, default `cache/bootnode-directory.lkg`). `loadDirectory` re-verifies the
cached copy against the same pinned signer and serves it when the fresh fetch fails or is absent.
Gateways egress independently of the bootnode: they announce TO it, they do not route THROUGH it. A
member holding a valid directory (fresh or cached) keeps selecting and dialing gateways with no
bootnode in the path. A dead bootnode degrades to the previous good fleet, never to nothing.

**Immediate containment.** None required for existing clients. New clients with no cache and no
static `SHADE_TREE_DIRECTORY` fallback cannot bootstrap discovery until the bootnode returns; point them at
a static signed directory file (`SHADE_TREE_DIRECTORY` + `SHADE_TREE_DIR_SIGNER`) as a stopgap if one is
published.

**Root-cause investigation.** Check the box: process alive, `SHADE_TREE_BOOTNODE_PORT` bound on
`127.0.0.1`, Tor HS descriptor published for the bootnode onion, `node scripts/doctor.mjs` for
env/tor/deps. Confirm gateways can reach `POST /announce` (a network partition looks like a dead
bootnode from the client side only).

**Recovery.** Restart `packages/node/bootnode/server.mjs` (on a bootstrapped box: `systemctl restart
shade-tree-bootnode`). If the bootnode runs with `SHADE_TREE_BOOTNODE_STORE` set (the `bootstrap.sh` unit sets it
to `deploy-state/bootnode-state.json`), the live set is mirrored to that JSON file on every accepted
announce and reloaded on boot: `loadPersisted()` re-runs each stored record through the real announce
path (onion control + operator/stake re-verified; tampered, forged, or past-TTL entries are dropped),
so `/directory` is populated immediately and no re-announce settling window is needed (T-DEV-4;
`packages/node/bootnode/server.mjs`, `docs/BOOTNODE.md` "Surviving a restart"). Without the store the registry is
in-memory only, and a restart drops the fleet until every gateway re-announces on its next heartbeat
(up to `SHADE_TREE_BOOTNODE_HEARTBEAT`, default 300s). Either way the signer key persists on disk
(`SHADE_TREE_BOOTNODE_SIGNER_KEY`), so the pinned signer is unchanged and clients accept the rebuilt
directory with no re-pin.

**Prevention.** Set `SHADE_TREE_BOOTNODE_STORE` so a restart is not a fleet blank. Run redundant bootnodes,
federated with `SHADE_TREE_BOOTNODE_PEERS` so each learns the others' gateways (T-FEAT-1,
`packages/node/bootnode/federation.mjs`); clients pin one bootnode onion at a time (`SHADE_TREE_BOOTNODE_ONION`), so
re-pointing a client to a surviving peer is still a manual re-point. Keep the LKG cache path
writable so degradation actually works. Publish a static signed directory as a cold fallback.

---

## 2. Bootnode signer key compromised

**Symptoms.** A directory signed by the pinned signer lists gateways you did not authorize, drops
known-good ones, or reorders/reweights to concentrate traffic. Signature verifies (that is the
problem), so `verifyDirectory` returns `ok` on a list you distrust.

**What the attacker CAN do.** Sign a poisoned list: omit honest gateways, reorder, inflate a
weight (capped at `MAX_WEIGHT=1000` on the bootnode, but a raw signed file bypasses that clamp),
or list an onion whose stake has lapsed.

**What the attacker CANNOT do.** Inject a gateway it controls under an onion it does not hold the
key for. Every entry's `pubkey` must equal the key derived from its own `.onion` address, and the
client re-derives it (`verifyDirectory` enforces `pubkey-onion-mismatch`). A grafted onion fails the
client's own check. In stake mode the client can additionally re-check `isStaked(operator)` on chain.
So a stolen signer degrades to OMIT / reorder / stale-stake, not to a controlled malicious exit.

**Immediate containment.** Treat the signer as burned. Weight concentration is the real lever (it
narrows which gateway a member is likely to hit), so if the poisoned list is skewing selection,
push clients back onto a trusted static directory (`SHADE_TREE_DIRECTORY` + the OLD-but-trusted signer) or
a redundant bootnode with a different signer while you rotate.

**Root-cause investigation.** Compare the live `/directory` against a known-good snapshot: which
onions were dropped, added, reweighted. Every added onion is by definition one whose key the attacker
holds OR a public honest gateway (the binding guarantees no third option). Audit the box holding
`SHADE_TREE_BOOTNODE_SIGNER_KEY` for exfiltration.

**Recovery.** Rotate the pinned signer. `SHADE_TREE_DIR_SIGNER` accepts a comma-separated **allowlist**
of signer pubkeys (T-HARD-5, `packages/node/client/selection.mjs` `parsePinnedSigners`; a single value behaves as
before), so rotation has an overlap window: (1) push the NEW signer pubkey to every client's
allowlist alongside the old one, out of band; (2) mint the new signer key on the bootnode and
restart it (the bootnode re-signs the directory with whatever `SHADE_TREE_BOOTNODE_SIGNER_KEY` holds);
(3) once every client carries both, drop the OLD pubkey from the allowlist. Clients that only carry
the old pin reject the new directory (`signer-not-pinned` / `bad-signature`) and fall back to their
LKG cache until re-pinned, so step (1) must precede step (2). Redistribution of the new pubkey is
still an out-of-band step (there is no in-band signer-rotation message).

**Revoke.** Once clients are re-pinned to the new signer, the old signer's directories are inert (no
client trusts them). No on-chain revocation exists or is needed; the pin IS the trust anchor.

**Prevention.** Keep the signer key off the network-facing surface, minimal blast radius. Pre-stage
a second signer in clients' allowlists so a rotation is a re-key, not a redistribution. Keep
static-directory fallback ready so containment does not depend on the compromised bootnode.

---

## 3. Gateway compromised / malicious

**Symptoms.** A member reports a target it did not request, traffic amplification on one proof,
selective dropping, or you have out-of-band evidence an operator is misbehaving (censoring,
tampering, downtime).

**What a malicious gateway CAN do.**
- See the `host:port` targets (`:443` only, metadata) of requests routed to it. It never sees
  plaintext (TLS is end-to-end client-to-target).
- Drop, delay, or selectively censor requests routed to it.
- Replay an exact envelope. Against the SAME gateway this fails: `makeSpentSet` fingerprints
  `(nullifier, share.x, nonce)`, and an identical envelope seen again after `SHADE_TREE_REPLAY_WINDOW_MS`
  (5s, the honest-retry window) is rejected `replayed-envelope` (T-FEAT-12,
  `packages/node/gateway/gateway.mjs`). Against OTHER gateways it fails only when the fleet runs the shared
  per-epoch nullifier tally (`SHADE_TREE_FLEET_TALLY_PEERS` plus `SHADE_TREE_FLEET_TALLY_TOKEN`,
  T-FEAT-20/20b, `packages/node/gateway/fleet-tally.mjs`;
  off by default, fail-open); a fleet without the tally lets a captured envelope be fanned to
  peers, each of which sees it once and egresses it. Amplification is therefore bounded to
  one egress per non-tallying gateway per captured envelope, and it never slashes (identical `x`
  is deduped).

**What a malicious gateway CANNOT do.**
- Forge membership. A valid RLN Groth16 proof against a recent admission root is required; it cannot
  mint one.
- Redirect a captured proof to a DIFFERENT target. The proof's committed `x` is bound to
  `requestSignal(target, nonce)` and the gateway recomputes it (`verifyEnvelope`, T-DEV-3 DONE); a
  swapped target or nonce is rejected `target-not-bound` / `bad-signal-field`.
- De-anonymize the client. Onion rendezvous, no exit node; the gateway sees `127.0.0.1` for every
  request.

**Immediate containment.** Remove it from the fleet. There is no deregister endpoint by design; the
mechanism is TTL drop:
- If you control the operator: **stop its heartbeat.** The entry ages out after
  `SHADE_TREE_BOOTNODE_TTL` (default 900s) with no one deregistering it.
- If you do not: the bootnode cannot forcibly evict a still-announcing onion, but in stake mode you
  can cut its stake (see Recovery) so `isStaked` flips false and it drops on the next refresh.
Clients also route around a bad gateway locally: `reportHealth` marks it `down` after 2 failures and
`pickGateway` skips it, and `selectionOrder` fails over to the rest of the fleet on dial timeout.

**Root-cause investigation.** Pull the offending gateway's logs (`DROP` / `PASS` / `ERROR` lines,
`egress->` targets). Confirm the misbehavior class: redirect (should be impossible, `target-not-bound`
would have fired), replay/amplification (`replayed-envelope` drops on the victim gateways, or a
same-envelope `PASS` on several gateways when the fleet tally is off), or censorship/downtime.
Identify the operator address from its announce (`GET /gateway/<onion>` returns the stored signed
announce with `operator` + `operatorSig`).

**Recovery.** Gateway slashing is **governed, not permissionless** by design: gateway misbehavior is
a subjective judgment. The owner calls `GatewayRegistry.slash(operator, receiver)`. It works whether
the operator is active or mid-unbonding (the unbonding window keeps it slashable, closing the
exit-to-dodge escape). This is a deliberate asymmetry vs the member slash, which is a cryptographic
proof and therefore permissionless.

**Prevention.** Per-tunnel rotation across N non-colluding gateways spreads target metadata to
~1/N; RLN's fresh per-tunnel nullifiers stop even colluding gateways from rejoining a member's
requests. Require `admission=stake` so misbehavior has a bond behind it. Enable the shared fleet
tally (`SHADE_TREE_FLEET_TALLY_PEERS` plus `SHADE_TREE_FLEET_TALLY_TOKEN`,
`docs/OPERATOR.md` section 5) so a captured envelope cannot be
fanned across the fleet.

---

## 4. Onion identity SEED leak

**Symptoms.** Two gateways answering for the same `.onion`, an announce you did not send verifying
under your onion key, or direct evidence the 32-byte seed (`tor/hs/identity.local.json`, or Tor's
`hs_ed25519_secret_key`) leaked.

**What it means.** The seed IS the onion. Whoever holds it can publish the HS descriptor and sign
announces indistinguishably from the legitimate gateway (`onionSig` verifies against the address).
The onion is impersonable. Onion control is no longer yours.

**Immediate containment.** Stop trusting that onion. Stop its heartbeat so the honest entry ages out
(`SHADE_TREE_BOOTNODE_TTL`). Understand that stopping YOUR heartbeat does not stop the attacker's: they can
keep announcing the stolen onion, and the binding check passes for them because they hold the key.
The only real fix is to retire the onion.

**Root-cause investigation.** Audit the box holding the seed and identity file. Determine exposure
window. Any request routed to the impersonator during the window had its target metadata exposed to
the attacker (never plaintext, TLS stays end-to-end).

**Recovery.**
1. Retire the leaked onion. Consider it permanently burned; never reuse the seed.
2. Mint a new identity: `shade-tree keygen <hsDir>` writes fresh Tor HS key files + a new
   `identity.local.json` seed.
3. Re-announce under the new onion (heartbeat with the new `SHADE_TREE_GW_IDENTITY`). Clients pick it up on
   the next directory refresh.
4. **On-chain operator stake is separate and survives.** The `GatewayRegistry` stakes an operator
   ADDRESS, never an onion; one stake rotates across many onions. Re-sign the durable operator
   authorization for the NEW onion (`operatorAuthMessage(newOnion, operator)`,
   `SHADE_TREE_GW_OPERATOR_KEY`) and the same bond backs the new identity. No re-stake, no new bond.

**Prevention.** Guard the seed like any signing key. It is the one secret whose leak cannot be
contained by the trust model, only by retiring the identity. Rotate onions periodically so a silent
leak has a bounded lifetime.

---

## 5. Chain / RPC outage

**Symptoms.** `eth_call` / `eth_getLogs` failing. Stake checks and root refreshes error in logs.
Applies only to on-chain profiles (`SHADE_TREE_GROUP_CONTRACT` / `SHADE_TREE_STAKE_MODE=onchain` set); the
`members.json` PoC path is unaffected.

**Stake reads (bootnode admission=stake).** `verifyAnnounce` **fails closed**: if the chain read
throws under `requireStake`, the announce is rejected `stake-check-failed:<msg>`, not passed. A chain
outage therefore blocks NEW/renewing stake-mode announces rather than admitting unverified gateways.
Already-resident entries keep serving until their TTL, then age out (they cannot renew without a
successful stake check). Result: the fleet shrinks safely toward whatever was already admitted, never
admits an unverified operator. The 15s `isStaked` cache (`SHADE_TREE_STAKE_CACHE_MS`) briefly masks a very
short blip.

**Root reads (gateway).** `packages/node/lib/root-provider.mjs` `withCache` serves the last-known-good roots with a
`{ stale: true, error }` flag when a fresh fetch throws; `onChange` polling keeps the last-known-good
rather than crashing the gate. So the gateway keeps verifying member proofs against the last roots it
successfully read. A membership change during the outage is simply not seen until RPC returns (a
just-added member may be rejected; a just-removed member may still pass, bounded by the freshness
window).

**Gateway slashing.** Deferred, not lost. Without a reachable RPC (or without `SHADE_TREE_SLASH_KEY`) the
slasher logs a `SLASH (dry-run)` and the over-spend evidence is still detected locally; the on-chain
`slash()` tx is what is delayed. Re-submit once RPC returns.

**Immediate containment.** None forced. Confirm the outage is RPC, not consensus. Fail-closed stake +
last-known-good roots mean the system degrades safely on its own.

**Root-cause investigation.** Is `SHADE_TREE_RPC_URL` reachable? Provider down, rate-limited, or
partitioned? Check whether roots are being served stale (log shows `stale`/`error`).

**Recovery.** Restore RPC (prefer your own node for the solo-staker path). Stake-mode announces
resume admitting on the next successful check; root refresh catches up on the next poll; re-submit any
deferred slashes.

**Prevention.** Run your own RPC endpoint. Set `SHADE_TREE_CONFIRMATIONS` for reorg safety on a public
chain (stake reads default to `latest`, roots to `finalized`). Size the freshness window
(`SHADE_TREE_FRESHNESS_ROOTS`) so a brief outage does not strand recent members.

**Seen live — 2026-08-17 23:34 UTC, public RPC `eth_getLogs` range cap (both fleet gateways).**
Symptom: after enabling `SHADE_TREE_PAID_ACCESS_CONTRACT` + `SHADE_TREE_GROUP_CONTRACT`, `shade-tree-gateway`
crash-looped at startup with `eth_getLogs: exceed maximum block range: 50000` (publicnode's cap;
the scan asked for `[0x0, finalized]` in one call) — the process died before `listen`, so even
`members.json` members were down; not an outage, a permanent refusal that a restart cannot fix.
Containment: `Environment=SHADE_TREE_FROM_BLOCK=<deploy block>` in the gateway drop-in, restart.
Prevention (shipped right after): the scan is paged + halved on a range/size refusal
(`SHADE_TREE_LOGS_CHUNK`), starts at each contract's record deploy block (`SHADE_TREE_FROM_BLOCKS`), and an
unreadable chain source at boot no longer kills a gateway that has a static root — it starts
degraded (`shade_tree_gateway_root_source_degraded{source="staked"} 1` or
`shade_tree_gateway_root_source_degraded{source="paid"} 1`, log
`root source UNAVAILABLE at startup`) and heals on the next read.
Full write-up: `docs/history/GO-LIVE-LOG-2026-08-17.md`
"(payments, later)"; knobs: `docs/OPERATOR.md` "Public RPC log-range caps".

---

## 6. Mass-DROP spike (members failing the gate)

**Symptoms.** A surge of `DROP` lines in gateway logs, valid members reporting failures, egress rate
collapsing. The reason string on the `DROP` line is the diagnostic.

**Most likely cause: a root mismatch.** The proof's public root is not in the gateway's
`recentRoots`, so `verifyEnvelope` drops it. Candidates, in order:
- **`members.json` vs on-chain root divergence.** Client building proofs against one root source
  while the gateway reads another (`SHADE_TREE_GROUP_CONTRACT` set on one side only, or pointed at a
  different contract).
- **Epoch skew.** `verifyEnvelope` accepts only the current/previous epoch's external nullifier. A
  clock skew larger than one epoch between client and gateway drops otherwise-valid proofs. Look for
  the epoch-window reason on the DROP line.
- **`SHADE_TREE_EPOCH_SECONDS` mismatch** across sides (default 120). Different epoch lengths desynchronize
  the external nullifier immediately. Must match client and gateway.
- **`SHADE_TREE_SLOTS` / `SHADE_TREE_RLN_IDENTIFIER` mismatch.** Different rate cap or RLN identifier changes the
  external nullifier / circuit binding.
- **Freshness window too tight.** A membership change advanced the root and clients are still proving
  against a root that fell out of `SHADE_TREE_FRESHNESS_ROOTS`.

**Immediate containment.** Do not slash: these are gate rejections, not over-spends (no secret is
reconstructed on a DROP). Identify the dominant DROP reason from logs first.

**Root-cause investigation.** Read the bounded DROP reasons on the gateway; destination targets are
deliberately omitted from logs. Compare
the gateway's live `recentRoots` against the root clients are proving against. Check both sides'
`SHADE_TREE_EPOCH_SECONDS`, `SHADE_TREE_SLOTS`, `SHADE_TREE_RLN_IDENTIFIER`, and root source
(`SHADE_TREE_GROUP_CONTRACT` vs `members.json`). Confirm clocks. If on-chain, confirm the root provider is
not serving `stale` roots from a chain outage (see #5).

**Recovery.** Align the mismatched parameter across client and gateway, or widen
`SHADE_TREE_FRESHNESS_ROOTS` if the cause is a too-tight window during a membership change. No key rotation
or slashing involved.

**Prevention.** Pin `SHADE_TREE_EPOCH_SECONDS`, `SHADE_TREE_SLOTS`, `SHADE_TREE_RLN_IDENTIFIER`, and the root source
identically across every component (they are called out as must-match in `docs/CONFIG.md`). NTP-sync
gateway clocks.

---

## 7. Suspected over-spend / unexpected slashes

**Symptoms.** `SLASH` lines in gateway logs, a member reporting an unexpected on-chain slash, or a
bond drained you did not expect.

**What a legitimate slash requires.** A member over-spend is a cryptographic fact, not a judgment:
the gateway's spent-set (`packages/node/gateway/gateway.mjs` `makeSpentSet`) sees TWO DISTINCT signals (distinct
public `x`) under the SAME `nullifier`. That is the L+1-th RLN evaluation point, which reconstructs
the identity secret (Shamir) and derives the rate-commitment leaf. An IDENTICAL replay (same
`share.x`) is deduped and is NEVER slashed. So a slash means two genuinely different points were
presented on one per-slot nullifier: the member exceeded its `SHADE_TREE_SLOTS` rate cap within the epoch.

**Immediate containment.** Do not assume malice. First verify the slash was legitimate before
treating it as an incident.

**Root-cause investigation.**
1. Confirm the reconstruction was real: two DISTINCT `x` values on ONE nullifier, not a mishandled
   replay. The code slashes exactly once per nullifier and dedups identical `x`; a slash on identical
   `x` would be a bug, investigate the spent-set.
2. Verify the on-chain slash tx: find the `SLASH tx <hash>` log line, confirm it mined, confirm the
   `commitment` matches the reconstructed leaf and the `receiver` is the intended address
   (`SHADE_TREE_SLASH_RECEIVER`, else the slasher wallet).
3. If the member insists it did not over-spend: check for a client bug re-using a nullifier across
   requests, or a `SHADE_TREE_SLOTS` mismatch causing the client to think it had more slots than the
   gateway enforces.
4. Rule out cross-gateway amplification: an EXACT-envelope replay never slashes (identical `x` is
   deduped, and a late replay is rejected `replayed-envelope`, T-FEAT-12; with the fleet tally on,
   the same nullifier+epoch seen at a peer is rejected too, T-FEAT-20), but confirm no path produced
   two distinct signals illegitimately.

**Recovery.** A legitimate slash is final and correct; no recovery, the rate cap worked. If
investigation shows an illegitimate slash (a bug reconstructing on identical or mishandled shares),
that is a code defect: freeze slashing (`SHADE_TREE_SLASH_KEY` unset falls back to dry-run so evidence is
still logged without draining bonds) and fix the spent-set before re-enabling on-chain submission.

**Prevention.** Keep `SHADE_TREE_SLOTS` and `SHADE_TREE_EPOCH_SECONDS` identical across client and gateway so a
member's own rate accounting matches what the gateway enforces. Run the slasher in dry-run
(`SHADE_TREE_SLASH_KEY` unset) while validating a new deployment so a spent-set bug logs instead of slashes.

---

## Honest gaps (what is still manual)

- **Directory signer redistribution** (#2): the overlap window exists (allowlist, T-HARD-5), but
  getting the new pubkey into every client's allowlist is out of band; there is no in-band
  rotation message.
- **Automated bootnode failover** (#1): clients auto-degrade to the LKG cache and bootnodes can
  federate (T-FEAT-1), but a client pins one bootnode onion; re-pointing it to a healthy peer is
  manual.
- **Chain / RPC outage** (#5): `SHADE_TREE_RPC_URL` takes up to five endpoints with failover (OPS-8);
  a canopy with every endpoint down still refuses staked members after one root-freshness window.
- **Cross-node replay suppression is opt-in** (#3, #7): per-gateway replay rejection is always on
  (T-FEAT-12); the cross-gateway tally (T-FEAT-20/20b) must be enabled with
  `SHADE_TREE_FLEET_TALLY_PEERS` plus `SHADE_TREE_FLEET_TALLY_TOKEN` and is fail-open by design.
- **Client zero-trust operator re-verification is opt-in** (#3): `SHADE_TREE_VERIFY_STAKE=1` makes the
  client re-fetch `GET /gateway/<onion>` and re-check sigs + live stake itself (T-DEV-5,
  `packages/node/client/selection.mjs`); off by default, the client trusts the bootnode's `staked` label.

- **Planned maintenance is announced, unplanned loss is not** (#1, #3): `shade-tree-node drain on`
  tells clients a stop is coming and socket activation makes restarts warm (docs/OPERATOR.md
  "Day-2 operations"); a node that dies without draining still ages out only at the directory TTL
  (15 min) or on an Elder probe. In-process webhook alerts (`SHADE_TREE_ALERT_WEBHOOK`) tell the
  operator within one evaluation interval (30 s) that a heartbeat went stale.

Shipped since this playbook was written: bootnode persistence (T-DEV-4, `SHADE_TREE_BOOTNODE_STORE`),
per-gateway replay cache (T-FEAT-12), signer-rotation allowlist (T-HARD-5), client stake
re-verification (T-DEV-5), encrypted key backup/restore (`shade-tree backup` / `shade-tree restore`,
`docs/BACKUP.md`), socket-activated restarts + operator drain flag + webhook alerts + one-seed
operator keys (day-two ops, 2026-10-01).
</content>
</invoke>
