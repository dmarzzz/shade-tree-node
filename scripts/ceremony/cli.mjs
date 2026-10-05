#!/usr/bin/env node
// Offline-first community phase-2 ceremony. Never writes active runtime artifacts.
import { readFile, writeFile, mkdir, copyFile, lstat, realpath, readdir } from 'node:fs/promises';
import { dirname, resolve, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { backend } from './backend.mjs';
import {
  CIRCUITS, PINNED_INPUTS, QUICKNET, EXPONENT, check, json, hash, hashJSON, equal, sha, iso,
  roundTime, roundAtOrAfter, alias, validatePlan, initialState,
  validateState, allowContribution, keyPath, beaconSeed, assertAppend,
} from './protocol.mjs';

const HERE = await realpath(dirname(fileURLToPath(import.meta.url)));
const ROOT = resolve(HERE, '../..');
const PTAU = 'inputs/powersOfTau28_hez_final_14.ptau';
const TOOL_FILES = ['cli.mjs', 'protocol.mjs', 'backend.mjs', 'package.json', 'package-lock.json', 'toolchain.json', 'build-inputs.mjs'];
const now = () => new Date().toISOString();
export async function digest(path) {
  const st = await lstat(path);
  check(st.isFile() && !st.isSymbolicLink() && st.size <= 50_000_000, `Expected regular public file <=50MB: ${path}`);
  const data = await readFile(path);
  return { sha256: hash(data), bytes: data.length };
}
async function readJSON(path) {
  const st = await lstat(path);
  check(st.isFile() && !st.isSymbolicLink() && st.size <= 2_000_000, `Expected regular JSON <=2MB: ${path}`);
  return JSON.parse(await readFile(path, 'utf8'));
}
async function toolsDigest() {
  const out = {};
  for (const name of TOOL_FILES) out[name] = await digest(join(HERE, name));
  return out;
}
async function safeFile(base, name) {
  // Callers provide only fixed filenames, never paths from downloaded metadata.
  check(!name.split('/').some(x => !x || x === '..' || x === '.'), 'Invalid bundle path');
  const file = join(base, name);
  let p = base;
  for (const part of name.split('/')) {
    p = join(p, part);
    const st = await lstat(p);
    check(!st.isSymbolicLink(), `Symlink in public bundle: ${name}`);
  }
  return file;
}
async function checkFile(base, name, expected) {
  sha(expected?.sha256, `Hash for ${name}`);
  check(Number.isSafeInteger(expected.bytes) && expected.bytes > 0, `Invalid size for ${name}`);
  const file = await safeFile(base, name);
  check(equal(await digest(file), { sha256: expected.sha256, bytes: expected.bytes }), `File checksum mismatch: ${name}`);
  return file;
}
async function writeNew(base, name, data) {
  const path = join(base, name);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, data, { flag: 'wx', mode: 0o644 });
}
async function createOutput(path, source = null) {
  check(typeof path === 'string' && path.length, '--out must name a new directory');
  const abs = resolve(path);
  // Parent must exist, so resolving it also catches symlink aliases into runtime dirs.
  const canonical = join(await realpath(dirname(abs)), abs.split(sep).at(-1));
  const rel = relative(ROOT, canonical);
  check(rel.startsWith('..' + sep) || (rel.startsWith('out' + sep + 'ceremony' + sep)), 'Output must be outside the repository or below out/ceremony/');
  if (source) check(canonical !== source && !canonical.startsWith(source + sep), 'Output cannot be inside its input bundle');
  await mkdir(canonical); // No overwrite, even for an empty destination.
  return canonical;
}
async function inventory(base, prefix = '') {
  const out = [];
  for (const name of await readdir(join(base, prefix))) {
    const p = prefix ? `${prefix}/${name}` : name;
    const st = await lstat(join(base, p));
    check(!st.isSymbolicLink(), `Symlink in bundle: ${p}`);
    if (st.isDirectory()) out.push(...await inventory(base, p));
    else { check(st.isFile(), `Not a regular file: ${p}`); out.push(p); }
  }
  return out.sort();
}
function expectedFiles(manifest, state) {
  const files = ['manifest.json', 'state.json', ...Object.keys(manifest.inputs)];
  for (let i = 0; i <= state.contributions.length; i++) for (const c of CIRCUITS) files.push(keyPath(i, c));
  if (state.final) for (const c of CIRCUITS) files.push(keyPath('final', c), `exports/${c}_verification_key.json`, `exports/${c}_verifier.sol`);
  return files.sort();
}
function preflightMetadata(mpc, index, name = null, beacon = null) {
  check(typeof mpc.csHash === 'string' && /^[0-9a-f]{128}$/.test(mpc.csHash), 'Invalid circuit hash');
  check(mpc.contributions.length === index, 'Unexpected embedded contribution count');
  for (const [i, c] of mpc.contributions.entries()) {
    check(/^[0-9a-f]{128}$/.test(c.hash), 'Invalid contribution hash'); alias(c.name);
    check(c.type === (beacon && i === index - 1 ? 1 : 0), 'Unexpected beacon or nonsecret contribution in transcript');
    check(equal(c.beacon, beacon && i === index - 1 ? beacon : null), 'Unexpected beacon parameters');
  }
  if (name) check(mpc.contributions.at(-1)?.name === name, 'Wrong terminal contributor name');
}
async function verifyKey(rt, base, circuit, file, expected, index, previous, name, beacon = null) {
  await checkFile(base, file, expected);
  const path = join(base, file);
  const mpc = await rt.metadata(path);
  // Bound type/exponent/count BEFORE snarkjs iterates beacon hashes.
  preflightMetadata(mpc, index, name, beacon);
  if (previous) assertAppend(previous, mpc, name, beacon ? 1 : 0, beacon);
  check(equal(mpc, expected.mpc), `MPC receipt mismatch: ${file}`);
  check(await rt.snarkjs.zKey.verifyFromR1cs(join(base, `inputs/${circuit}.r1cs`), join(base, PTAU), path) === true, `Cryptographic verification failed: ${file}`);
  return mpc;
}

export async function verifyBundle({ bundle, expectManifest, expectState, phase1 = false, quiet = false }) {
  sha(expectManifest, '--expect-manifest'); sha(expectState, '--expect-state');
  const base = await realpath(resolve(bundle));
  const manifest = await readJSON(await safeFile(base, 'manifest.json'));
  check((await digest(join(base, 'manifest.json'))).sha256 === expectManifest && hashJSON(manifest) === expectManifest, 'Manifest hash/canonical encoding mismatch');
  check(manifest.version === 1 && manifest.kind === 'shade-tree-phase2', 'Unsupported ceremony manifest');
  validatePlan(manifest.plan); iso(manifest.createdAt);
  check(equal(manifest.tools, await toolsDigest()), 'Local ceremony tools differ from the published manifest');
  check(equal(manifest.beacon, { chain: QUICKNET, exponent: EXPONENT, derivation: 'shade-tree-phase2-v1' }), 'Unexpected beacon policy');
  check(equal(Object.keys(manifest.inputs).sort(), Object.keys(PINNED_INPUTS).map(n => `inputs/${n}`).sort()), 'Unexpected circuit/phase1 input inventory');
  for (const [name, expected] of Object.entries(manifest.inputs)) {
    check(expected.sha256 === PINNED_INPUTS[name.slice(7)], `Unrecognized circuit/phase1 input: ${name}`);
    await checkFile(base, name, expected);
  }
  const state = await readJSON(await safeFile(base, 'state.json'));
  check((await digest(join(base, 'state.json'))).sha256 === expectState && hashJSON(state) === expectState, 'State hash/canonical encoding mismatch');
  validateState(state, manifest);
  check(equal(await inventory(base), expectedFiles(manifest, state)), 'Bundle contains missing or unexpected files');
  const rt = await backend();
  if (phase1) {
    if (!quiet) console.log('Verifying phase-one transcript (this can take several minutes)…');
    check(await rt.snarkjs.powersOfTau.verify(join(base, PTAU)) === true, 'Phase-one verification failed');
  }
  if (state.final) await rt.verifyBeacon(state.final.beacon, manifest.plan.beaconRound);
  const metadata = {};
  for (const circuit of CIRCUITS) {
    if (!quiet) console.log(`Verifying ${circuit}: initial key and ${state.contributions.length} secret contributions${state.final ? ' + beacon' : ''}…`);
    let mpc = await verifyKey(rt, base, circuit, keyPath(0, circuit), manifest.initial[circuit], 0);
    for (const step of state.contributions) {
      mpc = await verifyKey(rt, base, circuit, keyPath(step.index, circuit), step.keys[circuit], step.index, mpc, step.name);
    }
    if (state.final) {
      const seed = beaconSeed(expectManifest, state.final.closedStateSha256, circuit, state.final.beacon.randomness);
      mpc = await verifyKey(rt, base, circuit, keyPath('final', circuit), state.final.keys[circuit], state.contributions.length + 1, mpc, `drand-quicknet-${manifest.plan.beaconRound}`, { hash: seed, exponent: EXPONENT });
      for (const [suffix, generated] of [
        ['verification_key.json', json(await rt.snarkjs.zKey.exportVerificationKey(join(base, keyPath('final', circuit))))],
        ['verifier.sol', await rt.solidity(join(base, keyPath('final', circuit)))],
      ]) {
        const path = `exports/${circuit}_${suffix}`;
        await checkFile(base, path, state.final.exports[path]);
        check(hash(generated) === state.final.exports[path].sha256, `Export does not match final key: ${path}`);
      }
    }
    metadata[circuit] = mpc;
  }
  if (!quiet) console.log(`VERIFIED: ${manifest.plan.mode}; ${state.final ? 'finalized' : state.closure ? 'closed' : 'open'}; ${state.contributions.length} paired contributions. This is not production certification.`);
  return { base, manifest, state, metadata, rt };
}
async function cloneBundle(verified, out) {
  const base = await createOutput(out, verified.base);
  for (const name of expectedFiles(verified.manifest, verified.state).filter(n => n !== 'state.json')) {
    const source = await safeFile(verified.base, name);
    const expected = await digest(source);
    await mkdir(dirname(join(base, name)), { recursive: true });
    await copyFile(source, join(base, name));
    check(equal(await digest(join(base, name)), expected), `Copy checksum mismatch: ${name}`);
  }
  // Verify copied contents against authenticated receipts, not the mutable source.
  await writeNew(base, 'state.json', json(verified.state));
  await verifyBundle({ bundle: base, expectManifest: hashJSON(verified.manifest), expectState: hashJSON(verified.state), quiet: true });
  // The state is replaced atomically only after the next operation succeeds. An
  // interrupted copy/operation has extra files and fails exact inventory checks.
  return base;
}
async function finish(base, manifest, state, replace = false) {
  validateState(state, manifest);
  if (replace) {
    // Atomic state update. No active repository artifact is ever a target here.
    const { rename } = await import('node:fs/promises');
    await writeNew(base, 'state.next.json', json(state));
    await rename(join(base, 'state.next.json'), join(base, 'state.json'));
  } else await writeNew(base, 'state.json', json(state));
  console.log(json({ bundle: base, mode: manifest.plan.mode, manifestSha256: hashJSON(manifest), stateSha256: hashJSON(state), contributions: state.contributions.length, status: state.final ? state.final.trust : state.closure ? 'CLOSED-PUBLISH-HASH-BEFORE-BEACON' : 'OPEN-NOT-FINAL' }).trim());
}
async function prepare(o) {
  const plan = validatePlan(await readJSON(resolve(o.plan)), true);
  const inputs = await readJSON(resolve(o.inputs));
  check(inputs.kind === 'shade-tree-ceremony-inputs' && inputs.status === 'verified-inputs-only', 'Use build-inputs.mjs to prepare inputs');
  const toolchain = await digest(join(HERE, 'toolchain.json'));
  check(inputs.toolchainSha256 === toolchain.sha256, 'Input build used a different toolchain manifest');
  const base = await createOutput(o.out);
  const manifest = { version: 1, kind: 'shade-tree-phase2', createdAt: now(), plan,
    tools: await toolsDigest(), beacon: { chain: QUICKNET, exponent: EXPONENT, derivation: 'shade-tree-phase2-v1' }, inputs: {}, initial: {} };
  for (const [name, pinned] of Object.entries(PINNED_INPUTS)) {
    const [circuit, ext] = name.split('.');
    const entry = ext === 'ptau' ? inputs.ptau : inputs.circuits?.[circuit]?.[ext];
    check(entry?.path && entry.sha256 === pinned, `Missing or wrong input: ${name}`);
    const actual = await digest(entry.path);
    check(actual.sha256 === pinned && actual.bytes === entry.bytes, `Input file mismatch: ${name}`);
    await mkdir(join(base, 'inputs'), { recursive: true });
    await copyFile(entry.path, join(base, 'inputs', name));
    await checkFile(base, `inputs/${name}`, actual);
    manifest.inputs[`inputs/${name}`] = actual;
  }
  const rt = await backend();
  console.log('Verifying the pinned phase-one transcript before creating fresh phase-two keys…');
  check(await rt.snarkjs.powersOfTau.verify(join(base, PTAU)) === true, 'Phase-one verification failed');
  for (const circuit of CIRCUITS) {
    console.log(`Creating fresh ${circuit} phase-two initial key (no secret contribution yet)…`);
    const path = keyPath(0, circuit);
    await mkdir(dirname(join(base, path)), { recursive: true });
    const result = await rt.snarkjs.zKey.newZKey(join(base, `inputs/${circuit}.r1cs`), join(base, PTAU), join(base, path));
    check(result instanceof Uint8Array && result.length === 64, 'snarkjs setup did not return a circuit hash');
    const mpc = await rt.metadata(join(base, path)); preflightMetadata(mpc, 0);
    check(await rt.snarkjs.zKey.verifyFromR1cs(join(base, `inputs/${circuit}.r1cs`), join(base, PTAU), join(base, path)) === true, 'Fresh setup verification failed');
    manifest.initial[circuit] = { ...await digest(join(base, path)), mpc };
  }
  await writeNew(base, 'manifest.json', json(manifest));
  await finish(base, manifest, initialState(hashJSON(manifest)));
}
async function contribute(o) {
  alias(o.name);
  const v = await verifyBundle(o); allowContribution(v.state, v.manifest.plan);
  check(!v.state.contributions.some(c => c.name === o.name), 'Alias already contributed; use the agreed distinct participant alias');
  const base = await cloneBundle(v, o.out);
  const index = v.state.contributions.length + 1;
  const step = { index, name: o.name, at: now(), previousStateSha256: hashJSON(v.state), keys: {} };
  for (const circuit of CIRCUITS) {
    allowContribution(v.state, v.manifest.plan);
    console.log(`Contributing privately to ${circuit}; only public output hashes will be reported…`);
    const output = join(base, keyPath(index, circuit));
    await mkdir(dirname(output), { recursive: true });
    const contributionHash = await v.rt.contribute(join(base, keyPath(index - 1, circuit)), output, o.name);
    const mpc = await v.rt.metadata(output);
    const last = assertAppend(v.metadata[circuit], mpc, o.name);
    check(last.hash === contributionHash, 'Returned contribution hash differs from embedded transcript');
    step.keys[circuit] = { ...await digest(output), mpc };
    await verifyKey(v.rt, base, circuit, keyPath(index, circuit), step.keys[circuit], index, v.metadata[circuit], o.name);
  }
  allowContribution(v.state, v.manifest.plan);
  step.at = now();
  const state = { ...v.state, contributions: [...v.state.contributions, step] };
  await finish(base, v.manifest, state, true);
  console.log('Public contribution hashes:', json(Object.fromEntries(CIRCUITS.map(c => [c, step.keys[c].mpc.contributions.at(-1).hash]))).trim());
}
async function close(o) {
  const v = await verifyBundle(o); allowContribution(v.state, v.manifest.plan);
  check(v.state.contributions.length >= v.manifest.plan.minContributors, 'Not enough contributors to close');
  const base = await cloneBundle(v, o.out);
  allowContribution(v.state, v.manifest.plan);
  const state = { ...v.state, closure: { at: now(), contributionStateSha256: hashJSON(v.state) } };
  await finish(base, v.manifest, state, true);
  console.log('Publish this CLOSED state hash and have an independent observer witness it BEFORE the selected drand round. Local timestamps cannot establish this.');
}
async function finalize(o) {
  const v = await verifyBundle(o);
  check(v.state.closure && !v.state.final, 'Finalize requires a closed, unfinished transcript');
  check(Date.now() >= roundTime(v.manifest.plan.beaconRound), 'The precommitted beacon round has not occurred');
  const round = v.manifest.plan.beaconRound;
  let saved;
  if (o.beacon) saved = await readJSON(resolve(o.beacon));
  else {
    const url = `https://api.drand.sh/${QUICKNET.hash}/public/${round}`;
    console.log(`Fetching the precommitted public beacon: ${url}`);
    const response = await fetch(url, { signal: AbortSignal.timeout(20_000) });
    check(response.ok, `Beacon unavailable (HTTP ${response.status}); wait or use a saved response for THE SAME ROUND`);
    saved = await response.json();
  }
  const beacon = await v.rt.verifyBeacon(saved, round);
  const base = await cloneBundle(v, o.out);
  const final = { at: now(), closedStateSha256: hashJSON(v.state), beacon, keys: {}, exports: {},
    trust: v.manifest.plan.mode === 'rehearsal' ? 'REHEARSAL-DO-NOT-USE' : 'RESEARCH-PREVIEW-NOT-PRODUCTION' };
  for (const circuit of CIRCUITS) {
    const seed = beaconSeed(hashJSON(v.manifest), hashJSON(v.state), circuit, beacon.randomness);
    const name = `drand-quicknet-${round}`;
    const output = join(base, keyPath('final', circuit));
    await mkdir(dirname(output), { recursive: true });
    const result = await v.rt.snarkjs.zKey.beacon(join(base, keyPath(v.state.contributions.length, circuit)), output, name, seed, EXPONENT);
    check(result instanceof Uint8Array && result.length === 64, 'Beacon application failed');
    const mpc = await v.rt.metadata(output);
    const last = assertAppend(v.metadata[circuit], mpc, name, 1, { hash: seed, exponent: EXPONENT });
    check(last.hash === Buffer.from(result).toString('hex'), 'Beacon contribution hash mismatch');
    final.keys[circuit] = { ...await digest(output), mpc };
    await verifyKey(v.rt, base, circuit, keyPath('final', circuit), final.keys[circuit], v.state.contributions.length + 1, v.metadata[circuit], name, { hash: seed, exponent: EXPONENT });
    for (const [suffix, data] of [
      ['verification_key.json', json(await v.rt.snarkjs.zKey.exportVerificationKey(output))],
      ['verifier.sol', await v.rt.solidity(output)],
    ]) {
      const path = `exports/${circuit}_${suffix}`;
      await writeNew(base, path, data); final.exports[path] = await digest(join(base, path));
    }
  }
  const state = { ...v.state, final };
  await finish(base, v.manifest, state, true);
  console.log('Exports are staged inside this bundle. Active artifacts, lock, contracts and deployments have not been changed.');
}
const HELP = `ShadeNet community Groth16 setup — RESEARCH PREVIEW, NOT PRODUCTION

Install: npm ci --prefix scripts/ceremony --ignore-scripts

node scripts/ceremony/cli.mjs doctor
node scripts/ceremony/cli.mjs beacon-round --time <ISO-UTC>
node scripts/ceremony/cli.mjs prepare --inputs <build-inputs.json> --plan <plan.json> --out <NEW-DIR>
node scripts/ceremony/cli.mjs verify --bundle <DIR> --expect-manifest <SHA256> --expect-state <SHA256> [--phase1]
node scripts/ceremony/cli.mjs contribute --bundle <DIR> --expect-manifest <SHA256> --expect-state <SHA256> --out <NEW-DIR> --name <PUBLIC-ALIAS>
node scripts/ceremony/cli.mjs close --bundle <DIR> --expect-manifest <SHA256> --expect-state <SHA256> --out <NEW-DIR>
node scripts/ceremony/cli.mjs finalize --bundle <CLOSED-DIR> --expect-manifest <SHA256> --expect-state <CLOSED-SHA256> --out <NEW-DIR> [--beacon <saved-drand.json>]

No entropy argument. Fresh entropy is generated privately inside the contribution process.
Obtain both expected hashes independently from the event/preceding participant.
Output directories must be new, outside this repository or under out/ceremony/.
Read docs/CEREMONY.md before organizing the event. A rehearsal is never a live ceremony.
`;
export async function main(args = process.argv.slice(2)) {
  const command = args[0] || 'help';
  if (command === 'help' || command === '--help') { console.log(HELP); return; }
  const options = Object.fromEntries(['bundle', 'expect-manifest', 'expect-state', 'out', 'name', 'inputs', 'plan', 'time', 'beacon'].map(k => [k, { type: 'string' }]));
  options.phase1 = { type: 'boolean' };
  const { values, positionals } = parseArgs({ args: args.slice(1), options, strict: true, allowPositionals: false });
  check(positionals.length === 0, 'Unexpected arguments');
  const allowed = {
    doctor: [], 'beacon-round': ['time'], prepare: ['inputs', 'plan', 'out'],
    verify: ['bundle', 'expect-manifest', 'expect-state', 'phase1'],
    contribute: ['bundle', 'expect-manifest', 'expect-state', 'out', 'name'],
    close: ['bundle', 'expect-manifest', 'expect-state', 'out'],
    finalize: ['bundle', 'expect-manifest', 'expect-state', 'out', 'beacon'],
  }[command];
  check(allowed, `Unknown command: ${command}`);
  check(Object.keys(values).every(k => allowed.includes(k)), 'Option is not valid for this command');
  for (const k of allowed.filter(k => !['phase1', 'beacon'].includes(k))) check(values[k], `Missing --${k}`);
  const o = { ...values, expectManifest: values['expect-manifest'], expectState: values['expect-state'] };
  check(Number(process.versions.node.split('.')[0]) >= 22, 'Use Node.js 22 or newer (LTS recommended)');
  if (command === 'doctor') { await backend(); console.log(json({ node: process.version, snarkjs: '0.7.5', drandClient: '1.4.2', tools: await toolsDigest(), note: 'Tool readiness only. No ceremony or deployment has run.' })); }
  else if (command === 'beacon-round') { const round = roundAtOrAfter(o.time); console.log(json({ round, time: new Date(roundTime(round)).toISOString(), chainHash: QUICKNET.hash })); }
  else if (command === 'prepare') await prepare(o);
  else if (command === 'verify') await verifyBundle(o);
  else if (command === 'contribute') await contribute(o);
  else if (command === 'close') await close(o);
  else if (command === 'finalize') await finalize(o);
}
if (process.argv[1] && await realpath(resolve(process.argv[1])) === await realpath(fileURLToPath(import.meta.url))) {
  main().then(() => process.exit(0)).catch(error => {
    // No stacks or witnesses. Errors in our wrapper contain public paths/metadata only.
    console.error(`CEREMONY STOPPED: ${error.message}`);
    console.error('The input bundle is unchanged. Treat any incomplete output directory as unusable.');
    process.exit(1);
  });
}
