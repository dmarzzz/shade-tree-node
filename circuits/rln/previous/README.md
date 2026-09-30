# Previous (retired) RLN verification key

`verification_key.json` here is the **dev-set** RLN verification key that shipped before the
PSE ceremony adoption of 2026-09-30 (artifact id `rln-0b25f824a04da3a8`, circom 2.2.2 `--O1`,
circom-rln's two hard-coded contributions; untrusted). It is kept only so gateways can run the
dual-VK window of `docs/CEREMONY.md` §6: the deployment records list it as a second accepted
artifact with `legacy` pointing at it, so clients still on the dev set (v0.7.0-rc.1 and earlier)
keep working until the window closes. Close the window by removing it from the records'
`artifacts.accepted` (keep `legacy` naming it so old envelopes get a precise `artifact-retired`),
then delete this directory. It can verify proofs only; the matching proving key is gone from the tree.
