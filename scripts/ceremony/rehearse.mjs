#!/usr/bin/env node
// Explicit, opt-in real-curve integration test. NOT included in npm test: it
// performs many full verifications of the actual 12,390-constraint RLN circuit.
import { spawn } from 'node:child_process';
import { mkdir, readFile, writeFile, cp } from 'node:fs/promises';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { check, json, hash, QUICKNET } from './protocol.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const { values } = parseArgs({ options: { inputs: { type: 'string' }, out: { type: 'string' } } });
check(values.inputs && values.out, 'Usage: node scripts/ceremony/rehearse.mjs --inputs <build-inputs.json> --out <NEW-OUTSIDE-REPO-DIR>');
const out = resolve(values.out);
await mkdir(out);
const records = [];
const started = Date.now();
async function invoke(name, args, expectedCode = 0, needle = null) {
  console.log(`Rehearsal: ${name}…`);
  const begin = Date.now();
  const result = await new Promise((res, reject) => {
    const child = spawn(process.execPath, [join(HERE, 'cli.mjs'), ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', b => { stdout += b; process.stdout.write(b); });
    child.stderr.on('data', b => { stderr += b; });
    child.on('error', reject);
    child.on('exit', code => res({ code, stdout, stderr }));
  });
  await writeFile(join(out, `${name}.log`), result.stdout + result.stderr);
  check(result.code === expectedCode && (!needle || (result.stdout + result.stderr).includes(needle)), `${name} failed: ${result.stderr}`);
  records.push({ name, expectedCode, actualCode: result.code, seconds: (Date.now() - begin) / 1000 });
}
async function anchors(bundle) {
  return ['--bundle', bundle, '--expect-manifest', hash(await readFile(join(bundle, 'manifest.json'))), '--expect-state', hash(await readFile(join(bundle, 'state.json')))];
}
try {
  const plan = { version: 1, id: 'shade-tree-rehearsal-do-not-use', mode: 'rehearsal',
    contributionDeadline: new Date((QUICKNET.genesis_time - 3600) * 1000).toISOString(), beaconRound: 1, minContributors: 3 };
  await writeFile(join(out, 'plan.json'), json(plan));
  let bundle = join(out, '00-initial');
  await invoke('00-prepare', ['prepare', '--inputs', resolve(values.inputs), '--plan', join(out, 'plan.json'), '--out', bundle]);
  const initialAnchors = await anchors(bundle);
  await invoke('reject-entropy-argument', ['contribute', ...initialAnchors, '--name', 'rehearsal-1', '--out', join(out, 'must-not-exist'), '--entropy', 'NOT-A-SECRET'], 1, 'Unknown option');
  await invoke('reject-premature-close', ['close', ...initialAnchors, '--out', join(out, 'must-not-exist')], 1, 'Not enough contributors');
  await invoke('reject-overwrite', ['contribute', ...initialAnchors, '--name', 'rehearsal-1', '--out', bundle], 1, 'Output cannot be inside');
  const wrong = [...initialAnchors]; wrong[5] = '0'.repeat(64);
  await invoke('reject-wrong-state-hash', ['verify', ...wrong], 1, 'State hash');
  for (let i = 1; i <= 3; i++) {
    const next = join(out, `0${i}-contribution`);
    await invoke(`0${i}-contribute`, ['contribute', ...await anchors(bundle), '--name', `rehearsal-${i}`, '--out', next]);
    bundle = next;
  }
  const tampered = join(out, 'tampered');
  await cp(bundle, tampered, { recursive: true });
  const auth = await anchors(tampered);
  const badKeyPath = join(tampered, 'keys/0003/rln.zkey');
  const badKey = await readFile(badKeyPath); badKey[1000] ^= 1; await writeFile(badKeyPath, badKey);
  await invoke('reject-tampered-zkey', ['verify', ...auth], 1, 'File checksum mismatch');
  // A valid earlier key cannot be represented as a new friend's contribution.
  const fork = join(out, 'fork');
  await cp(bundle, fork, { recursive: true });
  const forkState = JSON.parse(await readFile(join(fork, 'state.json'), 'utf8'));
  for (const c of ['rln', 'withdraw']) {
    await cp(join(fork, `keys/0002/${c}.zkey`), join(fork, `keys/0003/${c}.zkey`));
    forkState.contributions[2].keys[c] = forkState.contributions[1].keys[c];
  }
  await writeFile(join(fork, 'state.json'), json(forkState));
  await invoke('reject-valid-key-fork', ['verify', ...await anchors(fork)], 1, 'Unexpected embedded contribution count');
  const closed = join(out, '04-closed');
  await invoke('04-close', ['close', ...await anchors(bundle), '--out', closed]);
  await invoke('reject-closed-contribution', ['contribute', ...await anchors(closed), '--name', 'late-person', '--out', join(out, 'must-not-exist')], 1, 'Transcript is closed');
  const final = join(out, '05-final');
  await invoke('05-finalize', ['finalize', ...await anchors(closed), '--out', final]);
  await invoke('06-independent-verify', ['verify', ...await anchors(final)]);
  const state = JSON.parse(await readFile(join(final, 'state.json'), 'utf8'));
  check(state.final.trust === 'REHEARSAL-DO-NOT-USE', 'Rehearsal lost its trust label');
  await writeFile(join(out, 'saved-beacon.json'), json(state.final.beacon));
  const replay = join(out, '07-replayed-final');
  await invoke('07-replay-finalization', ['finalize', ...await anchors(closed), '--out', replay, '--beacon', join(out, 'saved-beacon.json')]);
  for (const circuit of ['rln', 'withdraw']) {
    for (const path of [`keys/final/${circuit}.zkey`, `exports/${circuit}_verification_key.json`, `exports/${circuit}_verifier.sol`]) {
      check(hash(await readFile(join(final, path))) === hash(await readFile(join(replay, path))), `Deterministic replay differed: ${path}`);
    }
  }
  records.push({ name: 'replayed-zkeys-and-exports-byte-identical', expectedCode: 0, actualCode: 0 });
  // Signature verification, not only JSON hashing, must reject a forged beacon.
  const badBeacon = { ...state.final.beacon, signature: '00'.repeat(48) };
  await writeFile(join(out, 'bad-beacon.json'), json(badBeacon));
  await invoke('reject-invalid-beacon-signature', ['finalize', ...await anchors(closed), '--out', join(out, 'must-not-exist'), '--beacon', join(out, 'bad-beacon.json')], 1);
  const report = { kind: 'ceremony-rehearsal-validation', trust: 'REHEARSAL-DO-NOT-USE', finishedAt: new Date().toISOString(), seconds: (Date.now() - started) / 1000,
    finalBundle: final, manifestSha256: hash(await readFile(join(final, 'manifest.json'))), stateSha256: hash(await readFile(join(final, 'state.json'))), checks: records };
  await writeFile(join(out, 'rehearsal-report.json'), json(report));
  console.log(`Rehearsal passed. Report: ${join(out, 'rehearsal-report.json')}`);
} catch (e) {
  await writeFile(join(out, 'rehearsal-failure.json'), json({ error: e.message, checks: records }));
  console.error(e.message); process.exitCode = 1;
}
