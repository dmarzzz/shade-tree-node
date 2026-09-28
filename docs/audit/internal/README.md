# Internal smart-contract audit

[`shade-tree-internal-audit.pdf`](shade-tree-internal-audit.pdf) is an internal security
review of `contracts/` at commit `5bed894` (2026-09-04) by Florian Castet
([@Flocqst](https://github.com/Flocqst)), submitted in PR #112.

| Finding | Severity | Status |
|---|---|---|
| 2.1.1 Self-slash refunds the bond; redirectable payout | High | Fixed in #115 (mandatory burn, no caller-chosen payout to self) |
| 2.1.2 Non-canonical commitment (c + p) | High | Fixed by the M1 contracts work (#136) |
| 2.1.3 Zero commitment collides with the empty-leaf sentinel | High | Fixed by the M1 contracts work (#136) |
| 2.1.4 Tier declared, not proven | High | Fixed by the M1 contracts work (#136): the contract derives the leaf |
| 2.2.1 Exit and withdraw proofs replayable after re-registration | Medium | Fixed by the M1 contracts work (#136): contexts bind chain, contract and leaf index |
| 2.3.1 Proof blobs expose the identity commitment | Low | Documented trade-off |
| 2.3.2 Front-running a victim's commitment at another tier | Low | Moot once the tier is derived on chain (2.1.4) |
| 2.3.3 Slashed commitment re-inserted into the paid set | Low | Fix from #112 being ported with the M1 contracts work |

Each fix is covered by a regression test. Statuses track the ShadeNet launch roadmap; the
report itself is unchanged from the submission.
