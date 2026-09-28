#!/usr/bin/env node
// Coordinator-only application compatibility checks over a finalized STAGED set.
// Needs the root app's npm ci as well as the isolated ceremony runtime.
import { readFile, writeFile, mkdir, realpath } from 'node:fs/promises';
import { dirname, resolve, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { RLN, MemoryRLNRegistry, MemoryMessageIDCounter } from 'rlnjs';
import { poseidon1, poseidon2 } from 'poseidon-lite';
import { AbiCoder, solidityPackedKeccak256, getAddress } from 'ethers';
import { verifyBundle } from './cli.mjs';
import { check, json, hashJSON, keyPath } from './protocol.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const { values: o } = parseArgs({ options: Object.fromEntries(['bundle', 'expect-manifest', 'expect-state', 'out'].map(k => [k, { type: 'string' }])) });
for (const k of ['bundle', 'expect-manifest', 'expect-state', 'out']) check(o[k], `Missing --${k}`);
async function main() {
  const v = await verifyBundle({ bundle: o.bundle, expectManifest: o['expect-manifest'], expectState: o['expect-state'] });
  check(v.state.final, 'Smoke test requires a finalized staged bundle');
  const candidate = resolve(o.out);
  const out = join(await realpath(dirname(candidate)), candidate.split(sep).at(-1));
  check(relative(ROOT, out).startsWith('..' + sep) || relative(ROOT, out).startsWith('out' + sep + 'ceremony' + sep), 'Smoke output must be outside repo or under out/ceremony/');
  check(!out.startsWith(v.base + sep) && out !== v.base, 'Smoke report must be outside the immutable bundle');
  await mkdir(out);
  const checks = [];
  function passed(condition, description) { check(condition, description); checks.push(description); console.log(`PASS: ${description}`); }
  const vk = JSON.parse(await readFile(join(v.base, 'exports/rln_verification_key.json'), 'utf8'));
  const oldVK = JSON.parse(await readFile(join(ROOT, 'circuits/rln/verification_key.json'), 'utf8'));
  for (const limit of [8n, 32n]) {
    const registry = new MemoryRLNRegistry(1n, 20);
    const settings = { rlnIdentifier: 1n, registry, treeDepth: 20, wasmFilePath: join(v.base, 'inputs/rln.wasm'), finalZkeyPath: join(v.base, keyPath('final', 'rln')), verificationKey: vk };
    const member = await RLN.create(settings);
    await member.register(limit, new MemoryMessageIDCounter(limit));
    const proof = await member.createProof(42n, 'ceremony-compatibility-check');
    passed(await member.verifyProof(42n, 'ceremony-compatibility-check', proof), `RLN proof verifies at tier ${limit}`);
    passed(!await member.verifyProof(43n, 'ceremony-compatibility-check', proof), `RLN wrong epoch rejected at tier ${limit}`);
    passed(!await member.verifyProof(42n, 'changed-message', proof), `RLN wrong message rejected at tier ${limit}`);
    const old = await RLN.create({ ...settings, verificationKey: oldVK });
    passed(!await old.verifyProof(42n, 'ceremony-compatibility-check', proof), `New RLN proof rejected by current active VK at tier ${limit}`);
  }
  const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  // Public demo witness, matching testdata/gen-withdraw-proof.mjs. This is an
  // application proof fixture; it is unrelated to private ceremony entropy.
  const secret = 111n;
  const identityCommitment = poseidon1([secret]);
  const commitment = poseidon2([identityCommitment, 8n]);
  const commitment32 = poseidon2([identityCommitment, 32n]);
  const recipient = getAddress('0x000000000000000000000000000000000000bEEF');
  const withdrawVK = JSON.parse(await readFile(join(v.base, 'exports/withdraw_verification_key.json'), 'utf8'));
  const oldWithdrawVK = JSON.parse(await readFile(join(ROOT, 'circuits/rln/withdraw_verification_key.json'), 'utf8'));
  const coder = AbiCoder.defaultAbiCoder();
  const ctxExit = c => solidityPackedKeccak256(['string', 'uint256'], ['SHADE_TREE_EXIT', c]);
  const ctxWithdraw = c => solidityPackedKeccak256(['string', 'uint256', 'address'], ['SHADE_TREE_WITHDRAW', c, recipient]);
  async function prove(context, label) {
    const address = BigInt(context) % FIELD;
    const { proof, publicSignals } = await v.rt.snarkjs.groth16.fullProve({ identitySecret: secret.toString(), address: address.toString() }, join(v.base, 'inputs/withdraw.wasm'), join(v.base, keyPath('final', 'withdraw')));
    passed(publicSignals[0] === identityCommitment.toString() && publicSignals[1] === address.toString(), `${label} public signal layout preserved`);
    passed(await v.rt.snarkjs.groth16.verify(withdrawVK, publicSignals, proof), `${label} proof verifies`);
    passed(!await v.rt.snarkjs.groth16.verify(withdrawVK, [publicSignals[0], ((address + 1n) % FIELD).toString()], proof), `${label} wrong action context rejected`);
    passed(!await v.rt.snarkjs.groth16.verify(oldWithdrawVK, publicSignals, proof), `${label} new proof rejected by current active VK`);
    const [a, b, c] = JSON.parse('[' + await v.rt.snarkjs.groth16.exportSolidityCallData(proof, publicSignals) + ']');
    return { context, address: address.toString(), proof: coder.encode(['uint256[2]', 'uint256[2][2]', 'uint256[2]', 'uint256'], [a, b, c, identityCommitment.toString()]) };
  }
  const fixture = {
    _comment: 'Staged compatibility fixture for later test/WithdrawVerifier.t.sol validation. Never an activation instruction.',
    _trust: v.state.final.trust, _secret_note: 'Public application test witness 111; unrelated to ceremony entropy.',
    circuit: 'circom-rln withdraw', pubSignalLayout: ['identityCommitment', 'address'], K: 8,
    commitment: commitment.toString(), identityCommitment: identityCommitment.toString(), recipient,
    exit: await prove(ctxExit(commitment), 'tier-8 exit'), withdraw: await prove(ctxWithdraw(commitment), 'tier-8 withdrawal'),
    tier32: { limit: 32, commitment: commitment32.toString(), exit: await prove(ctxExit(commitment32), 'tier-32 exit') },
  };
  await writeFile(join(out, 'withdraw-proof.json'), json(fixture), { flag: 'wx' });
  await writeFile(join(out, 'smoke-report.json'), json({ trust: v.state.final.trust, manifestSha256: hashJSON(v.manifest), stateSha256: hashJSON(v.state), completedAt: new Date().toISOString(), checks,
    limitation: 'Application-level JS proofs and action context checks only; Solidity execution and full network migration are separate release gates.' }), { flag: 'wx' });
  console.log(`Smoke checks passed. Staged fixture and report: ${out}`);
}
main().then(() => { RLN.cleanUp(); process.exit(0); }).catch(error => { console.error(`SMOKE FAILED: ${error.message}`); RLN.cleanUp(); process.exit(1); });
