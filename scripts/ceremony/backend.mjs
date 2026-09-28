// All curve operations stay in pinned upstream libraries. Internal snarkjs MPC
// readers are version-specific, which is why this runtime has its own lockfile.
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { randomBytes } from 'node:crypto';
import { check, QUICKNET, sha, EXPONENT } from './protocol.mjs';

let runtime;
export async function backend() {
  if (runtime) return runtime;
  const here = dirname(fileURLToPath(import.meta.url));
  // Explicit path refuses accidental resolution to the app's transitive snarkjs.
  const base = join(here, 'node_modules/snarkjs');
  const pkg = JSON.parse(await readFile(join(base, 'package.json'), 'utf8').catch(() => { throw new Error('Run npm ci --prefix scripts/ceremony --ignore-scripts first'); }));
  check(pkg.version === '0.7.5', 'Wrong snarkjs version; reinstall using the ceremony lock');
  const req = createRequire(join(base, 'main.js'));
  const snarkjs = await import(pathToFileURL(join(base, 'main.js')));
  const utils = await import(pathToFileURL(join(base, 'src/zkey_utils.js')));
  const { getCurveFromQ } = await import(pathToFileURL(join(base, 'src/curves.js')));
  const bin = await import(pathToFileURL(req.resolve('@iden3/binfileutils')));
  const Blake2b = req('blake2b-wasm');
  await Blake2b.ready();
  const drandPkg = JSON.parse(await readFile(join(here, 'node_modules/drand-client/package.json'), 'utf8'));
  check(drandPkg.version === '1.4.2', 'Wrong drand-client version');
  const { fetchBeacon } = await import('drand-client');
  const hex = (value) => Buffer.from(value).toString('hex');
  async function metadata(file) {
    const { fd, sections } = await bin.readBinFile(file, 'zkey', 2);
    try {
      const header = await utils.readHeader(fd, sections, false);
      check(header.protocol === 'groth16', 'Only Groth16 zkeys are allowed');
      const curve = await getCurveFromQ(header.q);
      const mpc = await utils.readMPCParams(fd, curve, sections);
      return {
        csHash: hex(mpc.csHash),
        contributions: mpc.contributions.map(c => {
          const h = Blake2b(64); utils.hashPubKey(h, curve, c);
          check(c.type === 0 || c.type === 1, 'Unknown MPC contribution type');
          if (c.type === 0) check(c.beaconHash === undefined && c.numIterationsExp === undefined, 'Secret contribution contains beacon metadata');
          else check(c.numIterationsExp === EXPONENT && c.beaconHash?.length === 32, 'Unexpected beacon exponent/hash length');
          return { hash: hex(h.digest()), name: c.name || '', type: c.type,
            beacon: c.type === 1 ? { hash: hex(c.beaconHash), exponent: c.numIterationsExp } : null };
        }),
      };
    } finally { await fd.close(); }
  }
  async function contribute(input, output, name) {
    // Separate fresh OS randomness for each circuit. snarkjs also mixes its own
    // OS random bytes. Never accept entropy from argv, env, stdin or a shared feed.
    const bytes = randomBytes(64);
    let entropy = bytes.toString('hex');
    try { return hex(await snarkjs.zKey.contribute(input, output, name, entropy)); }
    finally {
      bytes.fill(0); entropy = null;
      // JS strings/library state/OS swap cannot be reliably zeroized. Process exits
      // at the end of each command; docs deliberately make no erasure guarantee.
    }
  }
  async function verifyBeacon(beacon, round) {
    check(beacon?.round === round, 'Beacon round mismatch');
    sha(beacon.randomness, 'Beacon randomness');
    check(typeof beacon.signature === 'string' && /^[0-9a-f]{96}$/.test(beacon.signature), 'Expected a 48-byte quicknet signature');
    check(beacon.previous_signature === undefined, 'Unexpected chained beacon');
    // Public client API, offline: BLS verification against compiled-in chain info.
    // No remote /info response can replace the public key or the round schedule.
    const result = await fetchBeacon({
      options: { disableBeaconVerification: false, noCache: true },
      get: async () => beacon,
      latest: async () => beacon,
      chain: () => ({ baseUrl: '', info: async () => QUICKNET }),
    }, round);
    return { round: result.round, randomness: result.randomness, signature: result.signature };
  }
  runtime = { snarkjs, metadata, contribute, verifyBeacon,
    solidity: async file => snarkjs.zKey.exportSolidityVerifier(file, { groth16: await readFile(join(base, 'templates/verifier_groth16.sol.ejs'), 'utf8') }),
  };
  return runtime;
}
