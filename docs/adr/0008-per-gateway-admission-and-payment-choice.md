# ADR 0008: Each gateway provider chooses what it admits and what it sells; the default is maximum anonymity

- Status: Accepted; shipped in T-FEAT-9 (this ADR's PR): gateway `SHADE_TREE_ADMIT`, registrar
  `SHADE_TREE_PAY_PROTOCOLS`, signed caps `admits` + `pay`, client filtering + `--max-anon`,
  bootstrap passthrough, JS + Rust conformance. Extends ADR 0007 (paid access) and ADR 0006
  (tiers); does not change any contract, proof, or wire envelope.
- Date: 2026-08-18
- Task: T-FEAT-9 — per-gateway admission policy + per-provider payment rails, as assigned by the
  2026-08-18 ship loop. NOTE: `docs/SHIP-PLAN.md` also uses the id T-FEAT-9 for the loop-3
  threshold-signed directory (shipped, `docs/WIRE-SPEC.md` §4.4); the two are unrelated. In
  code and docs "T-FEAT-9" next to `SHADE_TREE_ADMIT` / `admits` / `pay` / `--max-anon` means THIS ADR.

## Context

T-FEAT-7 gave the gateway three membership roots to trust: the static `members.json`
(invited friends), every `StakedReputationSet` in `SHADE_TREE_GROUP_CONTRACT`, and the `PaidAccessSet`
in `SHADE_TREE_PAID_ACCESS_CONTRACT`. Which of them a gateway trusted was decided by a heuristic
(`SHADE_TREE_ROOTS` unset = "the union of whatever is configured"), and — since `SHADE_TREE_NETWORK` fills
the contract addresses from the committed network record — a gateway that merely named a
network ended up admitting staked and paid leaves without its operator ever choosing to. The
registrar likewise served both 402 rails unconditionally and could only run on a bootnode box.

The three admission paths are NOT equal on the anonymity axis (`docs/THREAT-MODEL.md`):

| path | what is public | anonymity |
|---|---|---|
| `invited` | nothing on chain; a leaf in a file only the operator holds | most |
| `staked` | the staking wallet ↔ commitment (and tier bond) is on chain, linkable forever | middle |
| `paid` | the buyer address → operator transfer (amount = the tier's price bucket) is on chain; x402 and MPP are equal here | least |

A member's proof never reveals WHICH set it came from, but a gateway that admits several sets
mixes populations with different on-chain footprints, and a member who wants the strongest
guarantee has no way to say "only route me to gateways whose whole population is invited". The
user's decision (2026-08-18): each gateway PROVIDER chooses which paths it honours and which
rails (if any) it sells; the DEFAULT is the maximum-anonymity mode; the client can insist on it.

## Decision

1. **`SHADE_TREE_ADMIT=invited[,staked][,paid]` on the gateway; default `invited`.** The named paths
   are the ONLY root sources (`gateway/gateway.mjs resolveAdmission` → `initRoots`) and the
   ONLY routing targets of the slasher (`makeSlasher({ rootContracts })`); a configured but
   un-admitted contract is never read. The default is `invited` even when `SHADE_TREE_NETWORK` / env
   supply contract addresses — opting into a less anonymous path is explicit. A named path whose
   contract is missing FAILS CLOSED at startup (`SHADE_TREE_ADMIT names staked but no
   StakedReputationSet is configured … refusing to start`), never a silently smaller set. Startup
   logs the policy (`admits: invited+staked+paid`) above the T-FEAT-7 sources line
   (`roots: members.json + staked(0x…) + paid(0x…)`). `SHADE_TREE_ROOTS` stays as a DEPRECATED alias
   (`static`→invited, `onchain`→staked+paid over the configured contracts) with a warning;
   `SHADE_TREE_ADMIT` wins when both are set. A gateway with contracts configured but no policy WARNs
   at startup naming the exact `SHADE_TREE_ADMIT` that would trust them.

2. **The anonymity order `invited > staked > paid` is canonical.** It is the order of the
   startup line, of the signed `admits` field, of every error message, and of
   `lib/admission.mjs ADMIT_ORDER` / `lib/directory.mjs ADMIT_PATHS` / `shade_tree_proto::ADMIT_PATHS`.

3. **A provider sells on its own terms.** `SHADE_TREE_PAY_PROTOCOLS=x402,mpp` (any non-empty subset;
   default both when the registrar is enabled) selects the rails the registrar SERVES: a
   disabled rail gets no challenge in any 402 (`GET /pay/quote`, the bodied `POST /pay`), is
   absent from `/pay/quote` / `/health` `pay.protocols`, and a payload carrying its header is
   refused `400 protocol-disabled` naming the enabled rails before any parsing. The registrar
   remains opt-in (`SHADE_TREE_REGISTRAR=1`) and a GATEWAY-ONLY box may run its own registrar + its
   own `PaidAccessSet` on its own gateway onion (`HiddenServicePort 8878` in the gateway HS block,
   `bootstrap.sh`), so selling access needs no bootnode. Selling what you do not admit is a
   config error (`SHADE_TREE_REGISTRAR=1` requires `paid` in `SHADE_TREE_ADMIT`).

4. **The policy and the offer are advertised in the SIGNED caps.** `caps.admits` (subset of the
   three names, anonymity order, deduped, ≤3) and `caps.pay` (`{protocols, onion?, port, asset,
   chain, tiers}`, bounded: ≤8 tiers, canonical integer keys, 40-digit prices, `onion` only when
   the registrar rides another onion than the gateway's) are appended after `artifacts` in
   `canonicalCaps` (`lib/directory.mjs`), covered by the onion-key `capsSig` and by the announce
   signature, so a bootnode cannot widen or narrow a policy (verifyAnnounce / verifyDirectory
   reject `bad-caps-sig`); the bootnode passes caps + capsSig THROUGH into `/directory` verbatim
   and re-ships an entry whose policy changed in place in the delta protocol. Additive: every
   pre-T-FEAT-9 caps vector is byte-unchanged; `testdata/vectors.json` `admission` pins the
   canonical form, bytes and signature for JS + Rust (`shade-tree-proto` conformance).

5. **The client routes only to gateways that admit its leaf; `--max-anon` insists.** The client
   knows its leaf SOURCE (`makeLeafSourceLoader`: members.json → invited, a staked set → staked,
   the paid set → paid; `SHADE_TREE_LEAF_SOURCE=auto|invited|staked|paid` pins the set searched) and
   `selectCandidates(req, { leafSource, maxAnon })` keeps only gateways whose `admits` include
   it — failing CLOSED with a message naming every gateway's advertised policy when none does.
   `--max-anon` / `SHADE_TREE_MAX_ANON=1` keeps ONLY gateways whose `admits` is exactly `["invited"]`
   and refuses to run at all with a staked/paid leaf (before any proof or dial, saying why). Rust
   parity is minimal by design: `--leaf-source` (an explicit CLI input, since the Rust egress path
   reads an exported `--members` file and cannot discover the set) + `--max-anon`, same rules.

6. **Rollout compatibility: an absent `admits` is treated as "may admit any path".** During the
   window where some heartbeats do not yet advertise a policy, the client keeps such gateways for
   every leaf source (logged once) — the worst case is exactly what a pre-T-FEAT-9 client got: a
   `wrong-group-root` reject and a failover. Under `--max-anon` an absent policy cannot prove
   invited-only and is EXCLUDED (fail closed on the strongest guarantee). Once the fleet
   advertises everywhere this compat rule can be tightened (a follow-up, not a wire change).

7. **Bootstrap defaults follow.** `SHADE_TREE_ADMIT` (default `invited`) is rendered into BOTH the
   gateway and heartbeat units (the golden default render changed accordingly — regenerated);
   `staked`/`paid` render their contracts + RPC into the gateway unit and are validated up front;
   `SHADE_TREE_PAY_PROTOCOLS` renders into the registrar unit and both adverts (bootnode `/health`,
   heartbeat `caps.pay`).

## Consequences

- A fresh gateway is invited-only until its operator says otherwise; the sepolia demo fleet is
  heterogeneous on purpose (`network/sepolia/README.md`): gateway-1 `invited,staked,paid` +
  registrar, gateway-2 `invited,staked`. A paid buyer routes only to gateway-1; a `--max-anon`
  invited member refuses both (neither is invited-only) with a precise error — the correct outcome.
- Slashing routes only over admitted contracts: an over-spender whose leaf lives in a set this
  gateway does not admit could not have egressed here in the first place.
- Existing launchers that set `SHADE_TREE_GROUP_CONTRACT` and expected on-chain admission must now
  say `SHADE_TREE_ADMIT=…` (`scripts/integration-tiers.mjs`, `test/paid-access.selftest.mjs`,
  `scripts/integration-sepolia.mjs` were updated); a forgotten policy is loud (WARN + `admits:
  invited`), never silently wider.
- Members learn what their leaf reveals: an invited leaf can insist on `--max-anon`; a staked or
  paid one cannot, and the client says so instead of dialing an invited-only gateway that would
  reject it (`docs/THREAT-MODEL.md`, `docs/CLIENTS.md`).

## Alternatives considered

- **Keep the T-FEAT-7 heuristic (union of whatever is configured).** Rejected: it made
  `SHADE_TREE_NETWORK` silently widen admission; the provider never chose.
- **Default `invited,staked,paid` (widest) and let clients filter.** Rejected: the DEFAULT should
  be the safest mode; a provider who wants to sell must say so.
- **Per-set opt-out (`SHADE_TREE_ADMIT_DENY=paid`).** Rejected: an allow-list in anonymity order is
  the smaller, self-explaining surface.
- **Treat an absent `admits` as invited-only for compat.** Rejected for the rollout window: it
  would strand every paid/staked member the moment they upgraded, before their gateways did.
  Documented as the follow-up tightening instead.
- **A single fleet-wide registrar rail set.** Rejected: rails are the provider's business
  decision (fees, tooling); the buyer sees the enabled set in the 402 body and picks.

## References

- `lib/admission.mjs` (`ADMIT_ORDER`, `parseAdmit`, `admitsFromRoots`, `parsePayProtocols`,
  `parseLeafSource`), `gateway/gateway.mjs` (`resolveAdmission`, `initRoots`, `makeSlasher`),
  `bootnode/heartbeat.mjs` (`advertisedAdmits`, `advertisedPay`, `buildGatewayCaps`),
  `bootnode/server.mjs` (`payAdvertFromEnv`, directory passthrough, delta by body),
  `lib/directory.mjs` (`canonicalAdmits`, `canonicalPay`, `canonicalCaps`),
  `payments/registrar.mjs` (`offerProtocols`, `send402`, `protocol-disabled`),
  `client/selection.mjs` (`filterByAdmission`, `selectCandidates`), `client/shade-tree-client.mjs`
  (`makeLeafSourceLoader only`, `ShadeTreeClient.leafSource / _admission`), `rust/shade-tree-proto`
  (`ADMIT_PATHS`, `canonical_admits`, `canonical_pay`), `rust/shade-tree-client/src/capability.rs`
  (`Admission`, `filter_by_admission`), `bootnode/deploy/bootstrap.sh` (`SHADE_TREE_ADMIT`,
  `SHADE_TREE_PAY_PROTOCOLS`, gateway-only registrar), `testdata/vectors.json` `admission`.
- Tests: `gateway/admission.selftest.mjs`, `lib/admission-caps.selftest.mjs`,
  `payments/registrar-protocols.selftest.mjs`, `client/admission-filter.selftest.mjs`,
  `bootnode/deploy/bootstrap.selftest.mjs` §9, `test/vectors.selftest.mjs`,
  `test/paid-access.selftest.mjs` §7 (slow lane, real proofs), `rust/shade-tree-proto/tests/conformance.rs`
  `caps_with_admission_match_vector`.
- Docs: `docs/CONFIG.md`, `docs/OPERATOR.md` "Choose what you admit and what you sell",
  `docs/WIRE-SPEC.md`, `docs/PAYMENTS.md`, `docs/THREAT-MODEL.md`, `docs/CLIENTS.md`,
  `docs/JOIN.md`, `bootnode/deploy/README.md`.
