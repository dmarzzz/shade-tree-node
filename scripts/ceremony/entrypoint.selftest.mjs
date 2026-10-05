import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// These subprocesses request help or import the modules. They never prepare
// inputs, create keys, contribute entropy, fetch a beacon, or activate artifacts.
const tools = realpathSync(dirname(fileURLToPath(import.meta.url)));
const scratch = mkdtempSync(join(tmpdir(), 'shade-tree-entrypoint-test-'));
const failures = [];
let passed = 0;

function check(label, args, expected) {
  const result = spawnSync(process.execPath, args, {
    cwd: scratch, encoding: 'utf8', timeout: 15_000, maxBuffer: 1_000_000,
  });
  try {
    assert.ifError(result.error);
    assert.equal(result.signal, null, `${label}: unexpected signal`);
    assert.equal(result.status, 0, `${label}: ${result.stderr}`);
    assert.equal(result.stderr, '', `${label}: unexpected stderr`);
    if (typeof expected === 'string') assert.equal(result.stdout, expected, label);
    else assert.match(result.stdout, expected, `${label}: successful exit must include actual help`);
    passed++;
    console.log(`PASS: ${label}`);
  } catch (error) {
    failures.push(`${label}: ${error.message}`);
    console.error(`FAIL: ${label}`);
  }
}

try {
  const alias = join(scratch, 'tools-alias');
  symlinkSync(tools, alias, process.platform === 'win32' ? 'junction' : 'dir');
  for (const [name, help, expected] of [
    ['cli.mjs', 'help', /ShadeNet community Groth16 setup[\s\S]*node scripts\/ceremony\/cli\.mjs verify/],
    ['build-inputs.mjs', '--help', /Usage: node scripts\/ceremony\/build-inputs\.mjs --out[\s\S]*Never runs a phase-2 ceremony\./],
  ]) {
    check(`${name}: physical entrypoint`, [join(tools, name), help], expected);
    check(`${name}: symlinked directory entrypoint`, [join(alias, name), help], expected);

    // A module imported through the alias must remain inert. Passing --help
    // makes an accidental invocation harmless but detectable by missing or
    // extra output, including a premature process.exit(0).
    const harness = join(scratch, `import-${name}`);
    writeFileSync(harness, `import ${JSON.stringify(pathToFileURL(join(alias, name)).href)};\nconsole.log('IMPORTED WITHOUT EXECUTION');\n`);
    check(`${name}: import remains inert`, [harness, '--help'], 'IMPORTED WITHOUT EXECUTION\n');
  }
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

assert.equal(failures.length, 0, failures.join('\n'));
console.log(`entrypoint checks: ${passed} passed`);
