# Security policy

## Status

This is a research preview on Sepolia. A live canopy (one Elder Tree and three
Shade Tree nodes) admits invited members and permissionless Sepolia stakers; its
record is [`network/sepolia/deployment.json`](network/sepolia/deployment.json).
Everything in it is testnet material:

- The code is **unaudited** by a third party. An internal contract review found
  issues that need a fresh deployment
  ([issue #113](https://github.com/dmarzzz/shade-tree-node/issues/113)); the live
  `StakedReputationSet` (`0xEB67…4275`) predates those fixes and the self-slash
  change in #115, and is replaced at the ShadeNet launch.
- The ZK artifacts (`circuits/rln/`) come from an **untrusted testnet phase-2
  setup**. A holder of that setup's toxic waste could forge proofs. The
  production trusted-setup ceremony has not been run
  ([issue #6](https://github.com/dmarzzz/shade-tree-node/issues/6),
  `docs/CEREMONY.md`).
- The private-IP SSRF flaw in the default egress policy was fixed in
  [issue #73](https://github.com/dmarzzz/shade-tree-node/issues/73); nodes resolve
  and reject non-public destinations before dialing the checked numeric address.

Do not put real funds on the contracts or depend on this code for sensitive use
until the production ceremony is complete and the system has been independently
reviewed. Key rotations are recorded in
[`docs/KEY-ROTATIONS.md`](docs/KEY-ROTATIONS.md).

The full trust model, per-party threat model, and trust boundaries are in
[`docs/AUDIT.md`](docs/AUDIT.md). Read it before reporting: several sharp edges
are already known and documented, and a report against one of those is a
duplicate, not a finding.

## In scope

Reports that show a real defect in the shipped code, for example:

- A break in a cryptographic guarantee from `docs/AUDIT.md`: Proxy source-IP
  concealment on the onion leg, membership soundness, tunnel unlinkability, the
  onion-to-key binding, or the slash-on-over-spend control flow.
- A signature or parser that accepts input it must reject (directory, announce,
  envelope, onion derivation, on-chain reads).
- A way to poison the fleet view beyond the pinned signer's documented discovery
  authority (see below).
- A contract bug in `StakedReputationSet`, `PaidAccessSet` or `GatewayRegistry`
  (stake lifecycle, slash authorization, insert authorization, fund custody).
- A 402 registrar defect (`payments/`): settling without inserting, inserting
  without a valid settlement, replaying an authorization, or a challenge that
  can be edited without breaking its binding.
- A secret reaching a log or the wire (member identity secret, seed, onion
  secret key).

## Known and out of scope

These are documented limitations, not vulnerabilities. Please do not file them
as new reports; concrete improvements to them are welcome as pull requests
instead.

- **Unaudited, testnet ZK artifacts.** Untrusted ceremony output.
  (`docs/AUDIT.md` "Known unaudited surfaces"; residual T-HARD-1.)
- **Cross-gateway exact-envelope replay is opt-in.** Target binding stops a proof
  being redirected, and a single gateway rejects an exact-envelope replay outside
  the 5s honest-retry window (`replayed-envelope`, T-FEAT-12). Non-colluding
  gateways share a spent-nullifier tally only when the operator enables it
  (`SHADE_TREE_FLEET_TALLY_PEERS`, T-FEAT-20/20b; fail-open), so without it one captured
  envelope can still be fanned once per peer gateway.
- **Stale `staked` label by default.** In stake mode the client trusts the
  bootnode's `staked` label for the operator-to-onion pairing unless
  `SHADE_TREE_VERIFY_STAKE=1`, which makes it re-fetch `GET /gateway/<onion>` and
  re-verify the operator signature and live stake itself (T-DEV-5).
- **The pinned directory signer controls selection.** A compromised signer can
  omit, reorder, or add an internally consistent entry, including an onion it
  controls. Onion/key binding and signed capabilities narrow this authority but
  do not remove it. Protect and rotate the signer as a fleet-selection key.
- **Directory signer rotation is out of band.** `SHADE_TREE_DIR_SIGNER` accepts an
  allowlist so rotation has an overlap window (T-HARD-5), but distributing the new
  pubkey to clients is a manual step; there is no in-band rotation message.
- **Deploy bootstrap runs as root.** `bootnode/deploy/bootstrap.sh` is exercised
  end to end in CI inside a systemd container (`.github/workflows/bootstrap-e2e.yml`,
  T-TEST-8), but it still runs as root on a fresh box; read it before running it.
  (`docs/AUDIT.md`.)
- **Paid access is prepaid trust in the operator.** The buyer's address, the
  operator's address and the tier are public on chain by design; a payment the
  operator never inserts has public evidence but no on-chain recourse
  (`docs/PAYMENTS.md` "Leak ledger", `docs/THREAT-MODEL.md` §5).
- Anything under "What is and is not anonymous" and "Not done" in `docs/OVERVIEW.md`
  (and the README "What it does not protect against") that is called out as deliberately
  out of scope or an operator responsibility (sourcing clean egress IPs, rendezvous DoS with PoW off, one operator, and so on).

`docs/SHIP-PLAN.md` is the historical residual list; open work is tracked in the
issues.

## Reporting

Report privately. Do not open a public issue for a suspected vulnerability.

- Open a private security advisory on GitHub for
  `dmarzzz/shade-tree-node`
  (repository → Security → Advisories → "Report a vulnerability").

Private vulnerability reporting is enabled on the repository, so the advisory
stays private between you and the maintainers until a fix ships. There is no
dedicated security email.

Please include: the affected file and symbol, the trust boundary crossed, a
reproduction (a failing `*selftest.mjs` or `forge` test is ideal, since the
whole repo is tested that way), and the impact.

## Disclosure

This is a small reference project, so treat these as expectations, not a
contract. We aim to acknowledge a report within a few days and to work toward a
fix on a reasonable, coordinated timeline before public disclosure. If a report
turns out to match an already-documented limitation above, we will say so and
point at the tracking task rather than treat it as a new issue.
