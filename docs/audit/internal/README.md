# Internal smart-contract audit

[`shade-tree-internal-audit.pdf`](shade-tree-internal-audit.pdf) is an internal security
review of `contracts/` at commit `5bed894` (2026-09-04) by Florian Castet
([@Flocqst](https://github.com/Flocqst)), submitted in PR #112.

| Finding | Severity | Status |
|---|---|---|
| 2.1.1 Self-slash refunds the bond; redirectable payout | High | Fixed in #115 (mandatory burn, no caller-chosen payout to self) |
| 2.1.2 Non-canonical commitment (c + p) | High | Fixed in #136 |
| 2.1.3 Zero commitment collides with the empty-leaf sentinel | High | Fixed in #136 |
| 2.1.4 Tier declared, not proven | High | Fixed in #136: the contract derives the leaf |
| 2.2.1 Exit and withdraw proofs replayable after re-registration | Medium | Fixed in #136: contexts bind chain, contract and leaf index |
| 2.3.1 Proof blobs expose the identity commitment | Low | Documented trade-off: one identity per stake ([ONCHAIN.md](../../ONCHAIN.md)) |
| 2.3.2 Front-running a victim's commitment at another tier | Low | Moot once the tier is derived on chain (2.1.4) |
| 2.3.3 Slashed commitment re-inserted into the paid set | Low | Fixed in #181: burned at every tier, registrar refuses before charging |

Every fix has a regression test in `test/AuditReview112.t.sol`. The fixes take effect with
the fresh ShadeNet deployment (staging is live; production follows the trusted setup). The
report itself is unchanged from the submission.
