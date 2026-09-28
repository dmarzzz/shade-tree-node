// Ceremony bookkeeping, not cryptography. No network or dependency imports.
import { createHash } from 'node:crypto';

export const CIRCUITS = ['rln', 'withdraw'];
export const VERSION = 1;
export const EXPONENT = 10; // snarkjs beacon parameter: 2^10 hashes; not secret entropy.
export const QUICKNET = Object.freeze({
  public_key: '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  period: 3, genesis_time: 1692803367,
  hash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  schemeID: 'bls-unchained-g1-rfc9380',
  metadata: { beaconID: 'quicknet' },
});
export const PINNED_INPUTS = {
  'rln.r1cs': '452cd7f8830ef82244c481639bc44b354d9e72ec2504694ce4814b961a2f22a2',
  'withdraw.r1cs': '52dd6134d2223e585b4782f2f033fc882eb7fac567570bffdb9a763f3be88788',
  'rln.wasm': 'd06035923ab4c7fefedf92e05c9903d059af583b8a92a95ce72466a389ac6ab0',
  'withdraw.wasm': 'd0b6425f026a75a52fd2f324fac663b6f8986b8e4439b86a9e6d73ee03eef2bb',
  'powersOfTau28_hez_final_14.ptau': '489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d',
};
export function check(condition, message) { if (!condition) throw new Error(message); }
export function json(value) { return JSON.stringify(value, null, 2) + '\n'; }
export function hash(value) { return createHash('sha256').update(value).digest('hex'); }
export function hashJSON(value) { return hash(json(value)); }
export function equal(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
export function sha(value, label = 'SHA256') { check(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), `${label}: expected 64 lowercase hexadecimal characters`); return value; }
export function iso(value) {
  check(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value) && Number.isFinite(Date.parse(value)), 'Use an ISO UTC timestamp ending in Z');
  const canonical = new Date(value).toISOString();
  check(canonical === value || canonical.replace('.000Z', 'Z') === value, 'Invalid calendar date or timestamp');
  return Date.parse(value);
}
export function roundTime(round) {
  check(Number.isSafeInteger(round) && round > 0 && round < 1e10, 'Invalid drand round');
  return (QUICKNET.genesis_time + (round - 1) * QUICKNET.period) * 1000;
}
export function roundAtOrAfter(time) { return Math.ceil((iso(time) / 1000 - QUICKNET.genesis_time) / QUICKNET.period) + 1; }
export function alias(name) {
  check(typeof name === 'string' && /^[A-Za-z0-9][A-Za-z0-9_. -]{0,47}$/.test(name) && name.trim() === name, 'Name must be 1–48 ASCII letters, digits, spaces, dots, underscores or hyphens');
  return name;
}
export function validatePlan(p, preparing = false, now = Date.now()) {
  check(p?.version === VERSION, 'Unsupported plan version');
  check(typeof p.id === 'string' && /^[a-z0-9][a-z0-9-]{2,63}$/.test(p.id), 'Choose a lowercase ceremony id (3–64 characters)');
  check(['research-preview', 'rehearsal'].includes(p.mode), 'Mode must be research-preview or rehearsal');
  const deadline = iso(p.contributionDeadline);
  const beacon = roundTime(p.beaconRound);
  check(beacon >= deadline + 3600_000, 'Beacon must be at least one hour after the contribution deadline');
  check(Number.isSafeInteger(p.minContributors) && p.minContributors >= (p.mode === 'rehearsal' ? 1 : 3) && p.minContributors <= 100, 'Set minContributors between 3 and 100 (1 allowed only for rehearsal)');
  if (preparing && p.mode !== 'rehearsal') check(deadline > now, 'The contribution deadline must be in the future');
  return p;
}
export function initialState(manifestSha256) { return { version: VERSION, manifestSha256, contributions: [], closure: null, final: null }; }
export function contributionState(state, length = state.contributions.length) { return { ...initialState(state.manifestSha256), contributions: state.contributions.slice(0, length) }; }
export function closedState(state) { return { ...contributionState(state), closure: state.closure }; }
export function keyPath(index, circuit) { return `keys/${index === 'final' ? 'final' : String(index).padStart(4, '0')}/${circuit}.zkey`; }
export function beaconSeed(manifestHash, closedHash, circuit, randomness) {
  sha(manifestHash); sha(closedHash); sha(randomness);
  check(CIRCUITS.includes(circuit), 'Unknown circuit');
  return hash(['shade-tree-phase2-v1', manifestHash, closedHash, circuit, randomness].join('\0'));
}
export function assertAppend(previous, next, name, type = 0, beacon = null) {
  check(previous.csHash === next.csHash, 'Circuit hash changed');
  check(next.contributions.length === previous.contributions.length + 1, 'Expected exactly one new contribution');
  check(equal(previous.contributions, next.contributions.slice(0, -1)), 'Contribution history changed: fork, omission or metadata edit');
  const last = next.contributions.at(-1);
  check(last.name === name && last.type === type, 'Contribution name/type mismatch');
  check(equal(last.beacon, beacon), 'Beacon parameters mismatch');
  return last;
}
export function validateState(state, manifest, now = Date.now()) {
  check(state?.version === VERSION && Array.isArray(state.contributions), 'Invalid state schema');
  check(state.manifestSha256 === hashJSON(manifest), 'State belongs to a different manifest');
  check(state.contributions.length <= 100, 'Too many contributions');
  check(equal(Object.keys(state), Object.keys(initialState(state.manifestSha256))), 'Unexpected state fields/order');
  const names = new Set();
  for (const [i, step] of state.contributions.entries()) {
    check(step.index === i + 1, 'Nonsequential contribution index'); alias(step.name);
    check(!names.has(step.name), 'Duplicate contributor alias'); names.add(step.name);
    const at = iso(step.at);
    if (manifest.plan.mode !== 'rehearsal') {
      check(at <= iso(manifest.plan.contributionDeadline), 'Contribution after deadline');
      check(at >= iso(manifest.createdAt) && at <= now + 300_000, 'Invalid contribution timestamp');
      if (i) check(at >= iso(state.contributions[i - 1].at), 'Contribution timestamps out of order');
    }
    check(step.previousStateSha256 === hashJSON(contributionState(state, i)), 'Broken state hash chain');
    check(step.keys && equal(Object.keys(step.keys), CIRCUITS), 'Both circuit contributions are required');
  }
  if (state.closure) {
    check(state.contributions.length >= manifest.plan.minContributors, 'Not enough secret contributions to close');
    check(state.closure.contributionStateSha256 === hashJSON(contributionState(state)), 'Closure does not bind this contribution state');
    const at = iso(state.closure.at);
    if (manifest.plan.mode !== 'rehearsal') {
      check(at >= iso(state.contributions.at(-1).at) && at <= iso(manifest.plan.contributionDeadline), 'Closure must follow contributions and precede deadline');
    }
  }
  if (state.final) {
    check(state.closure, 'Finalize requires a closed transcript');
    check(state.final.closedStateSha256 === hashJSON(closedState(state)), 'Finalization does not bind the closed state');
    check(state.final.trust === (manifest.plan.mode === 'rehearsal' ? 'REHEARSAL-DO-NOT-USE' : 'RESEARCH-PREVIEW-NOT-PRODUCTION'), 'Incorrect trust label');
    check(iso(state.final.at) >= roundTime(manifest.plan.beaconRound), 'Finalization before the beacon round');
    check(state.final.beacon?.round === manifest.plan.beaconRound, 'Wrong beacon round');
  }
}
export function allowContribution(state, plan, now = Date.now()) {
  check(!state.closure && !state.final, 'Transcript is closed');
  if (plan.mode !== 'rehearsal') check(now <= iso(plan.contributionDeadline), 'Contribution deadline passed');
}
