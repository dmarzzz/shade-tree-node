// Fast bookkeeping regressions. No curve libraries, network, keys or private entropy.
// The normal test-all.mjs discovery includes this suite without ceremony npm install.
import assert from 'node:assert/strict';
import {
  CIRCUITS, EXPONENT, QUICKNET, alias, allowContribution, assertAppend,
  beaconSeed, closedState, contributionState, hashJSON, initialState, iso,
  roundAtOrAfter, roundTime, validatePlan, validateState,
} from './protocol.mjs';

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; }
  catch (error) { throw new Error(name, { cause: error }); }
}
const clone = value => structuredClone(value);
const NOW = Date.parse('2030-01-01T14:00:00Z');
const DEADLINE = '2030-01-01T12:00:00Z';
const plan = {
  version: 1, id: 'community-preview', mode: 'research-preview',
  contributionDeadline: DEADLINE,
  beaconRound: roundAtOrAfter('2030-01-01T13:00:00Z'), minContributors: 3,
};
// Synthetic public receipts test policy only; they are not zkey verification fixtures.
const receipt = label => ({ sha256: label.repeat(64), bytes: 123, mpc: {} });
const manifest = { version: 1, createdAt: '2030-01-01T10:00:00Z', plan };
function openState(count = 3, m = manifest) {
  const state = initialState(hashJSON(m));
  for (let i = 0; i < count; i++) {
    state.contributions.push({
      index: i + 1, name: ['alice', 'bob', 'carol'][i],
      at: `2030-01-01T10:${String((i + 1) * 10).padStart(2, '0')}:00Z`,
      previousStateSha256: hashJSON(state),
      keys: { rln: receipt('a'), withdraw: receipt('b') },
    });
  }
  return state;
}
function closeState(state = openState()) {
  return { ...state, closure: { at: '2030-01-01T11:00:00Z', contributionStateSha256: hashJSON(state) } };
}
function finalState(m = manifest) {
  const state = closeState(openState(3, m));
  return { ...state, final: {
    at: new Date(roundTime(m.plan.beaconRound)).toISOString(),
    closedStateSha256: hashJSON(state), beacon: { round: m.plan.beaconRound },
    trust: m.plan.mode === 'rehearsal' ? 'REHEARSAL-DO-NOT-USE' : 'RESEARCH-PREVIEW-NOT-PRODUCTION',
  } };
}
function rejectsState(mutate, pattern, state = openState(), m = manifest) {
  mutate(state);
  assert.throws(() => validateState(state, m, NOW), pattern);
}

test('open, closed and finalized receipt chains validate', () => {
  for (const state of [initialState(hashJSON(manifest)), openState(), closeState(), finalState()]) validateState(state, manifest, NOW);
});
test('changing the manifest invalidates an otherwise valid state', () => {
  assert.throws(() => validateState(openState(), { ...manifest, createdAt: '2030-01-01T09:00:00Z' }, NOW), /different manifest/);
});
test('receipt ordering cannot skip, duplicate or reorder contribution indices', () => {
  for (const index of [0, 1, 4]) rejectsState(s => { s.contributions[1].index = index; }, /Nonsequential/);
  rejectsState(s => { s.contributions.reverse(); }, /Nonsequential/);
});
test('a receipt must bind the exact preceding state', () => {
  rejectsState(s => { s.contributions[1].previousStateSha256 = '0'.repeat(64); }, /hash chain/);
  rejectsState(s => { s.contributions[0].keys.rln.sha256 = 'c'.repeat(64); }, /hash chain/);
});
test('each accepted step includes both circuit receipts in their prescribed order', () => {
  rejectsState(s => { delete s.contributions[0].keys.withdraw; }, /Both circuit/);
  rejectsState(s => { s.contributions[0].keys = { withdraw: receipt('b'), rln: receipt('a') }; }, /Both circuit/);
});
test('duplicate aliases do not satisfy multiple-contributor policy', () => {
  rejectsState(s => { s.contributions[1].name = 'alice'; }, /Duplicate/);
});
test('aliases cannot carry terminal controls, markup, paths or surrounding whitespace', () => {
  for (const name of [' alice', 'alice ', 'a\nb', 'a\u001b[2J', 'a/b', '<script>', 'a'.repeat(49), '']) assert.throws(() => alias(name), /Name must/);
  for (const name of ['alice', 'participant-01', 'A. Person_2']) assert.equal(alias(name), name);
});
test('live contributions must be after creation, ordered, before cutoff and not in the future', () => {
  rejectsState(s => { s.contributions[0].at = '2030-01-01T09:59:59Z'; }, /Invalid contribution timestamp/);
  rejectsState(s => { s.contributions[1].at = '2030-01-01T10:09:59Z'; }, /out of order/);
  rejectsState(s => { s.contributions[0].at = '2030-01-01T12:00:01Z'; }, /after deadline/);
  assert.throws(() => validateState(openState(), manifest, Date.parse('2030-01-01T10:00:00Z')), /Invalid contribution timestamp/);
});
test('old prefixes remain mathematically valid but change the externally pinned state digest', () => {
  const full = openState();
  const prefix = contributionState(full, 1);
  validateState(prefix, manifest, NOW);
  assert.notEqual(hashJSON(prefix), hashJSON(full));
  // This is why callers must acquire --expect-state out of band, not from a bundle.
});
test('closure requires sufficient contributions and the exact accepted state', () => {
  rejectsState(() => {}, /Not enough/, closeState(openState(2)));
  rejectsState(s => { s.closure.contributionStateSha256 = '0'.repeat(64); }, /Closure does not bind/, closeState());
});
test('live closure cannot precede the last contribution or follow cutoff', () => {
  for (const at of ['2030-01-01T10:29:59Z', '2030-01-01T12:00:01Z']) rejectsState(s => { s.closure.at = at; }, /Closure must/, closeState());
});
test('finalization requires closure and binds its exact public hash', () => {
  rejectsState(s => { s.closure = null; }, /requires a closed/, finalState());
  rejectsState(s => { s.final.closedStateSha256 = '0'.repeat(64); }, /does not bind/, finalState());
  rejectsState(s => { s.closure.at = '2030-01-01T11:01:00Z'; }, /does not bind/, finalState());
});
test('finalization accepts only the precommitted round, after its scheduled time', () => {
  rejectsState(s => { s.final.beacon.round++; }, /Wrong beacon round/, finalState());
  rejectsState(s => { s.final.at = new Date(roundTime(plan.beaconRound) - 1).toISOString(); }, /before the beacon/, finalState());
});
test('research and rehearsal trust labels cannot be substituted', () => {
  rejectsState(s => { s.final.trust = 'PRODUCTION'; }, /trust label/, finalState());
  const rehearsal = { ...manifest, plan: { ...plan, mode: 'rehearsal', minContributors: 1 } };
  const state = finalState(rehearsal);
  validateState(state, rehearsal, NOW);
  rejectsState(s => { s.final.trust = 'RESEARCH-PREVIEW-NOT-PRODUCTION'; }, /trust label/, state, rehearsal);
});
test('no contribution is accepted after closure, finalization or the live cutoff', () => {
  const deadline = iso(DEADLINE);
  allowContribution(openState(), plan, deadline);
  assert.throws(() => allowContribution(openState(), plan, deadline + 1), /deadline passed/);
  for (const state of [closeState(), finalState()]) assert.throws(() => allowContribution(state, plan, deadline - 1), /closed/);
});
test('receipt schema changes cannot silently alter canonical hashing', () => {
  rejectsState(s => { s.extra = true; }, /fields\/order/);
  const state = openState();
  const reordered = { manifestSha256: state.manifestSha256, version: 1, contributions: state.contributions, closure: null, final: null };
  assert.throws(() => validateState(reordered, manifest, NOW), /fields\/order/);
});

const contribution = (name, value) => ({ hash: value.repeat(128), name, type: 0, beacon: null });
const previous = { csHash: '1'.repeat(128), contributions: [contribution('alice', 'a'), contribution('bob', 'b')] };
const appended = () => ({ csHash: previous.csHash, contributions: [...clone(previous.contributions), contribution('carol', 'c')] });
test('MPC append accepts one new contribution and returns its public receipt', () => {
  assert.deepEqual(assertAppend(previous, appended(), 'carol'), contribution('carol', 'c'));
});
test('individually valid fork histories must not replace the accepted MPC prefix', () => {
  const fork = appended(); fork.contributions[0].hash = 'f'.repeat(128);
  assert.throws(() => assertAppend(previous, fork, 'carol'), /history changed/);
});
test('MPC prefix comparison includes metadata omitted from the upstream public-key hash', () => {
  for (const [key, value] of [['name', 'mallory'], ['type', 1], ['beacon', { hash: 'e'.repeat(64), exponent: EXPONENT }]]) {
    const changed = appended(); changed.contributions[0][key] = value;
    assert.throws(() => assertAppend(previous, changed, 'carol'), /history changed/);
  }
});
test('MPC no-op, skipped stages and circuit substitutions are rejected', () => {
  assert.throws(() => assertAppend(previous, clone(previous), 'carol'), /exactly one/);
  const skipped = appended(); skipped.contributions.push(contribution('dave', 'd'));
  assert.throws(() => assertAppend(previous, skipped, 'dave'), /exactly one/);
  const swapped = appended(); swapped.csHash = '2'.repeat(128);
  assert.throws(() => assertAppend(previous, swapped, 'carol'), /Circuit hash changed/);
});
test('a terminal receipt must match its announced name, type and beacon policy', () => {
  assert.throws(() => assertAppend(previous, appended(), 'mallory'), /name\/type/);
  const beacon = { hash: 'e'.repeat(64), exponent: EXPONENT };
  const next = appended(); next.contributions[2] = { ...next.contributions[2], name: 'drand', type: 1, beacon };
  assert.deepEqual(assertAppend(previous, next, 'drand', 1, beacon), next.contributions[2]);
  assert.throws(() => assertAppend(previous, next, 'drand'), /name\/type/);
  assert.throws(() => assertAppend(previous, next, 'drand', 1, { ...beacon, exponent: EXPONENT + 1 }), /Beacon parameters/);
  assert.throws(() => assertAppend(previous, next, 'drand', 1, { ...beacon, hash: 'f'.repeat(64) }), /Beacon parameters/);
});
test('beacon derivation binds manifest, closed transcript, circuit and verified randomness separately', () => {
  const args = ['a'.repeat(64), 'b'.repeat(64), 'rln', 'c'.repeat(64)];
  const seed = beaconSeed(...args);
  const variants = [0, 1, 3].map(i => { const changed = [...args]; changed[i] = 'd'.repeat(64); return changed; });
  variants.push([args[0], args[1], 'withdraw', args[3]], [args[1], args[0], args[2], args[3]]);
  const seeds = variants.map(v => beaconSeed(...v));
  assert.equal(new Set([seed, ...seeds]).size, seeds.length + 1);
  assert.match(seed, /^[a-f0-9]{64}$/);
});
test('beacon seed inputs reject alternate encodings and unknown circuits', () => {
  const args = ['a'.repeat(64), 'b'.repeat(64), 'rln', 'c'.repeat(64)];
  for (const value of ['0x' + args[0], args[0].toUpperCase(), args[0].slice(1), null]) {
    assert.throws(() => beaconSeed(value, ...args.slice(1)), /lowercase hexadecimal/);
  }
  assert.throws(() => beaconSeed(args[0], args[1], 'rln\0withdraw', args[3]), /Unknown circuit/);
});
test('round arithmetic follows quicknet genesis and three-second boundaries', () => {
  assert.equal(roundTime(1), QUICKNET.genesis_time * 1000);
  assert.equal(roundTime(2) - roundTime(1), 3000);
  const at = roundTime(plan.beaconRound);
  assert.equal(roundAtOrAfter(new Date(at).toISOString()), plan.beaconRound);
  assert.equal(roundAtOrAfter(new Date(at + 1).toISOString()), plan.beaconRound + 1);
});
test('invalid rounds cannot mean latest or trigger uncontrolled beacon work', () => {
  for (const round of [0, -1, 1.5, NaN, Infinity, '1', 1e10]) assert.throws(() => roundTime(round), /Invalid drand round/);
});
test('live plan enforces a one-hour gap and a future preparation cutoff', () => {
  validatePlan(plan, true, iso(DEADLINE) - 1);
  assert.throws(() => validatePlan(plan, true, iso(DEADLINE)), /in the future/);
  const boundary = { ...plan, contributionDeadline: new Date(roundTime(plan.beaconRound) - 3600_000).toISOString() };
  validatePlan(boundary);
  assert.throws(() => validatePlan({ ...boundary, contributionDeadline: new Date(iso(boundary.contributionDeadline) + 1).toISOString() }), /one hour/);
});
test('participant minimum cannot be bypassed by fractions, strings or research mode relabeling', () => {
  for (const count of [0, 1, 2, 3.5, '3', 101, NaN]) assert.throws(() => validatePlan({ ...plan, minContributors: count }), /minContributors/);
  validatePlan({ ...plan, mode: 'rehearsal', minContributors: 1 }, true, NOW);
  assert.throws(() => validatePlan({ ...plan, mode: 'production' }), /Mode must/);
});
test('timestamps require an explicit, unambiguous UTC format', () => {
  for (const value of ['2030-01-01', '2030-01-01T12:00:00', '2030-01-01T12:00:00+00:00', '2030-01-01T12:00:00.1Z', 'bad']) assert.throws(() => iso(value), /ISO UTC/);
  assert.equal(iso('2030-01-01T12:00:00Z'), iso('2030-01-01T12:00:00.000Z'));
});
test('calendar rollover cannot silently move a published cutoff or beacon target', () => {
  for (const value of ['2030-02-31T12:00:00Z', '2030-02-29T12:00:00Z', '2030-04-31T12:00:00.000Z', '2030-01-01T24:00:00Z']) assert.throws(() => iso(value), /Invalid calendar/);
  assert.equal(iso('2032-02-29T12:00:00Z'), Date.parse('2032-02-29T12:00:00Z'));
});
test('closed-state commitment excludes only the later finalization record', () => {
  const finalized = finalState();
  assert.equal(hashJSON(closedState(finalized)), finalized.final.closedStateSha256);
  assert.notEqual(hashJSON(contributionState(finalized)), finalized.final.closedStateSha256);
  assert.deepEqual(Object.keys(finalized.contributions[0].keys), CIRCUITS);
});

console.log(`ceremony protocol: ${passed} bookkeeping tests passed (no cryptographic claims)`);
