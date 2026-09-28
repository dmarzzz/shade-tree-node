#!/usr/bin/env node
// Deterministic public-input preparation only. Never invokes setup, contribute,
// beacon, zkey generation, deployment, or writes into the active artifact tree.
import {
  closeSync, copyFileSync, existsSync, lstatSync, mkdirSync, openSync,
  readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync,
  writeFileSync, writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = realpathSync(dirname(fileURLToPath(import.meta.url)));
const REPO = realpathSync(resolve(HERE, "../.."));
const TOOLCHAIN_PATH = join(HERE, "toolchain.json");
const MARKER = ".shade-tree-ceremony-build.json";
const OWNER = "shade-tree-ceremony-build-inputs-v1";
const BN254 = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

function assert(condition, message) { if (!condition) throw new Error(message); }
function sha256(path) { return createHash("sha256").update(readFileSync(path)).digest("hex"); }
function measure(path) { return { path: realpathSync(path), sha256: sha256(path), bytes: statSync(path).size }; }
function isWithin(child, parent) {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

// Resolve through existing ancestors before writing, including /tmp -> /private/tmp
// on macOS. A symlink must not turn a requested scratch directory into runtime files.
export function canonicalFuturePath(path) {
  let cursor = resolve(path);
  const tail = [];
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    assert(parent !== cursor, `cannot resolve output path: ${path}`);
    tail.unshift(cursor.slice(parent.length).replace(/^[/\\]/, ""));
    cursor = parent;
  }
  return resolve(realpathSync(cursor), ...tail);
}

export function validateOutputPath(path, repo = REPO) {
  const out = canonicalFuturePath(path);
  const source = realpathSync(repo);
  assert(out !== parse(out).root, "output cannot be a filesystem root");
  assert(!isWithin(out, source) && !isWithin(source, out), "output must be outside, and not an ancestor of, the project directory");
  return out;
}

function noSymlink(path) {
  try {
    assert(!lstatSync(path).isSymbolicLink(), `refusing symlink in managed build directory: ${path}`);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function managedDir(out, ...parts) {
  let current = out;
  for (const part of parts) {
    assert(part !== ".." && !part.includes(sep), "invalid managed directory component");
    current = join(current, part);
    noSymlink(current);
    mkdirSync(current, { recursive: true });
  }
  return current;
}

function checkHash(path, expected, label = path) {
  noSymlink(path);
  const actual = sha256(path);
  assert(actual === expected, `${label}: SHA-256 mismatch; expected ${expected}, got ${actual}`);
}

function checkArtifact(path, hash, bytes, label) {
  checkHash(path, hash, label);
  assert(statSync(path).size === bytes, `${label}: byte length mismatch`);
  return measure(path);
}

function logRunner(logDirectory) {
  let sequence = 0;
  return (command, args, { cwd = REPO, label = command, timeout = 20 * 60 * 1000 } = {}) => {
    const name = `${String(++sequence).padStart(2, "0")}-${label.replace(/[^a-zA-Z0-9_-]/g, "-")}.log`;
    const path = join(logDirectory, name);
    noSymlink(path);
    console.log(`[build-inputs] ${label}`);
    const result = spawnSync(command, args, {
      cwd, encoding: "utf8", shell: false, timeout, maxBuffer: 32 * 1024 * 1024,
      env: { ...process.env, LC_ALL: "C", LANG: "C", CARGO_TERM_COLOR: "never" },
    });
    const output = `${result.stdout || ""}${result.stderr || ""}`;
    writeFileSync(path, `${JSON.stringify({ command, args, cwd })}\n${output}`, { mode: 0o644 });
    if (result.error || result.status !== 0) {
      throw new Error(`${label} failed (${result.error?.message || `exit ${result.status}`}); see ${path}\n${output.slice(-1500)}`);
    }
    return { output, log: measure(path) };
  };
}

function checkout(out, name, pin, run) {
  const sourceRoot = managedDir(out, "src");
  const path = join(sourceRoot, name);
  noSymlink(path);
  if (!existsSync(path)) {
    run("git", ["clone", "--no-checkout", "--filter=blob:none", pin.repository, path], { label: `clone-${name}` });
    run("git", ["-c", "core.hooksPath=/dev/null", "checkout", "--detach", pin.commit], { cwd: path, label: `checkout-${name}` });
  }
  const commit = run("git", ["rev-parse", "HEAD"], { cwd: path, label: `${name}-commit` }).output.trim();
  assert(commit === pin.commit, `${name}: checkout is ${commit}, expected ${pin.commit}; use a fresh --out directory`);
  const status = run("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: path, label: `${name}-clean` }).output.trim();
  assert(status === "", `${name}: tracked source files are modified; use a fresh --out directory`);
  return path;
}

function verifyPtauBytes(path, pin) {
  checkArtifact(path, pin.sha256, pin.bytes, "phase-1 Powers of Tau");
  const blake = createHash("blake2b512").update(readFileSync(path)).digest("hex");
  assert(blake === pin.blake2b512, "phase-1 Powers of Tau: BLAKE2b-512 mismatch");
}

async function obtainPtau(out, pin, supplied) {
  const dir = managedDir(out, "ptau");
  const destination = join(dir, pin.name);
  noSymlink(destination);
  if (supplied) {
    const input = realpathSync(resolve(supplied));
    verifyPtauBytes(input, pin);
    if (input !== destination) {
      assert(!existsSync(destination) || sha256(destination) === pin.sha256, "existing ptau differs; refusing replacement");
      if (!existsSync(destination)) copyFileSync(input, destination);
    }
    return { path: destination, source: { type: "local-file", path: input } };
  }
  if (existsSync(destination)) {
    verifyPtauBytes(destination, pin);
    return { path: destination, source: { type: "verified-cache" } };
  }
  const errors = [];
  for (const url of pin.urls) {
    assert(new URL(url).protocol === "https:", "ptau download requires HTTPS");
    const temporary = `${destination}.${process.pid}.partial`;
    let fd;
    try {
      console.log(`[build-inputs] downloading pinned phase-1 file: ${url}`);
      const response = await fetch(url, { signal: AbortSignal.timeout(180_000) });
      assert(response.ok && response.body, `HTTP ${response.status}`);
      fd = openSync(temporary, "wx", 0o644);
      let received = 0;
      for await (const chunk of response.body) {
        received += chunk.length;
        assert(received <= pin.bytes, "download exceeds pinned length");
        writeSync(fd, chunk);
      }
      closeSync(fd); fd = undefined;
      verifyPtauBytes(temporary, pin);
      renameSync(temporary, destination);
      return { path: destination, source: { type: "https", url } };
    } catch (error) {
      errors.push(`${url}: ${error.message}`);
      console.log(`[build-inputs] mirror unavailable or invalid: ${error.message}`);
    } finally {
      if (fd !== undefined) closeSync(fd);
      if (existsSync(temporary)) rmSync(temporary);
    }
  }
  throw new Error(`no mirror supplied the pinned phase-1 bytes; pass --ptau-file with a verified copy:\n${errors.join("\n")}`);
}

function parseStats(output) {
  const plain = output.replace(/\x1b\[[0-9;]*m/g, "");
  const names = { wires: "Wires", constraints: "Constraints", privateInputs: "Private Inputs", publicInputs: "Public Inputs", outputs: "Outputs" };
  const stats = {};
  for (const [field, label] of Object.entries(names)) {
    const match = plain.match(new RegExp(`# of ${label}:\\s*(\\d+)`));
    assert(match, `snarkjs r1cs info omitted ${label}`);
    stats[field] = Number(match[1]);
  }
  stats.nPublic = stats.publicInputs + stats.outputs;
  return stats;
}

export async function buildInputs({ out: requestedOut, ptauFile } = {}) {
  assert(requestedOut, "--out is required; choose a dedicated scratch directory outside the project");
  const out = validateOutputPath(requestedOut);
  const pins = JSON.parse(readFileSync(TOOLCHAIN_PATH, "utf8"));
  assert(pins.version === 1, "unsupported toolchain schema");
  const runtimeLockPath = join(HERE, "package-lock.json");
  const snarkPath = join(HERE, "node_modules/snarkjs/build/cli.cjs");
  assert(existsSync(snarkPath) && existsSync(runtimeLockPath), "install the pinned tools first: npm ci --prefix scripts/ceremony --ignore-scripts");
  const runtimeLock = JSON.parse(readFileSync(runtimeLockPath, "utf8"));
  const installed = JSON.parse(readFileSync(join(HERE, "node_modules/snarkjs/package.json"), "utf8"));
  assert(installed.version === pins.snarkjs.version && runtimeLock.packages?.["node_modules/snarkjs"]?.version === pins.snarkjs.version, "snarkjs version does not match toolchain.json");
  // Do not overwrite an arbitrary existing folder. Only our own scratch directory can resume.
  mkdirSync(out, { recursive: true });
  const markerPath = join(out, MARKER);
  noSymlink(markerPath);
  if (existsSync(markerPath)) {
    assert(JSON.parse(readFileSync(markerPath, "utf8")).owner === OWNER, "output has another owner's marker");
  } else {
    assert(readdirSync(out).length === 0, "output is nonempty and not owned by this builder; choose a fresh --out directory");
    writeFileSync(markerPath, JSON.stringify({ owner: OWNER, version: 1 }) + "\n", { flag: "wx" });
  }
  const lockPath = join(out, ".build-inputs.lock");
  const lock = openSync(lockPath, "wx", 0o600);
  writeSync(lock, `${process.pid}\n`);
  try {
    const logs = managedDir(out, "logs");
    const run = logRunner(logs);
    const environment = {
      node: process.version, npm: run("npm", ["--version"], { label: "npm-version" }).output.trim(),
      rustc: run("rustup", ["run", pins.compiler.rustToolchain, "rustc", "--version"], { label: "rustc-version" }).output.trim(),
      cargo: run("rustup", ["run", pins.compiler.rustToolchain, "cargo", "--version"], { label: "cargo-version" }).output.trim(),
      platform: process.platform, arch: process.arch,
    };
    const compilerSource = checkout(out, "circom", pins.compiler, run);
    const circuitSource = checkout(out, "circom-rln", pins.source, run);
    checkHash(join(compilerSource, "Cargo.lock"), pins.compiler.cargoLockSha256);
    checkHash(join(circuitSource, "package-lock.json"), pins.source.packageLockSha256);
    const sourceLock = JSON.parse(readFileSync(join(circuitSource, "package-lock.json"), "utf8"));
    const library = sourceLock.packages["node_modules/circomlib"];
    for (const field of ["version", "resolved", "integrity"]) assert(library[field] === pins.circomlib[field], `circomlib ${field} mismatch`);
    run("npm", pins.source.npmArgs, { cwd: circuitSource, label: "circuit-dependencies" });
    // npm lifecycle scripts and the upstream build script are deliberately never run.
    run("rustup", ["run", pins.compiler.rustToolchain, "cargo", ...pins.compiler.cargoArgs], { cwd: compilerSource, label: "build-circom" });
    const compiler = join(compilerSource, "target/release", process.platform === "win32" ? "circom.exe" : "circom");
    const compilerVersion = run(compiler, ["--version"], { label: "circom-version" }).output.trim();
    assert(compilerVersion === `circom compiler ${pins.compiler.version}`, `unexpected compiler: ${compilerVersion}`);
    const circuits = {};
    for (const [name, pin] of Object.entries(pins.circuits)) {
      const directory = managedDir(out, "build", name);
      // Existing compiler outputs must be ordinary files/directories, not symlink targets.
      managedDir(out, "build", name, `${name}_js`);
      for (const path of [`${name}.r1cs`, `${name}.sym`, `${name}_js/${name}.wasm`, `${name}_js/generate_witness.js`, `${name}_js/witness_calculator.js`]) noSymlink(join(directory, path));
      const compile = run(compiler, [pin.source, ...pins.compiler.flags, "-o", directory], { cwd: circuitSource, label: `compile-${name}` });
      const r1cs = checkArtifact(join(directory, `${name}.r1cs`), pin.r1csSha256, pin.r1csBytes, `${name} R1CS`);
      const wasm = checkArtifact(join(directory, `${name}_js/${name}.wasm`), pin.wasmSha256, pin.wasmBytes, `${name} WASM`);
      checkHash(join(REPO, pin.repositoryWasm), pin.wasmSha256, `${name} active WASM reference`);
      const info = run(process.execPath, [snarkPath, "r1cs", "info", r1cs.path], { label: `${name}-r1cs-info` });
      const stats = parseStats(info.output);
      for (const [key, value] of Object.entries(stats)) assert(pin[key] === value, `${name} ${key}: expected ${pin[key]}, got ${value}`);
      assert(stats.constraints + stats.nPublic + 1 <= 2 ** pins.ptau.power, `${name} exceeds phase-1 capacity`);
      circuits[name] = {
        r1cs, wasm, sym: measure(join(directory, `${name}.sym`)), ...stats,
        publicSignals: pin.publicSignals, compileLog: compile.log, infoLog: info.log,
        matchesRepositoryWasm: true,
      };
      console.log(`[build-inputs] ${name}: R1CS and WASM match all pins`);
    }
    const acquired = await obtainPtau(out, pins.ptau, ptauFile);
    verifyPtauBytes(acquired.path, pins.ptau);
    const verified = run(process.execPath, [snarkPath, "powersoftau", "verify", acquired.path], { label: "verify-phase1", timeout: 60 * 60 * 1000 });
    assert(/Powers [Oo]f [Tt]au [Ff]ile OK!|Powers of Tau Ok!/i.test(verified.output), "phase-1 verification did not report success");
    const manifest = {
      version: 1, kind: "shade-tree-ceremony-inputs", status: "verified-inputs-only",
      createdAt: new Date().toISOString(), root: out, field: BN254,
      toolchainSha256: sha256(TOOLCHAIN_PATH), runtimeLockSha256: sha256(runtimeLockPath),
      environment,
      source: { ...pins.source, path: circuitSource, circomlib: pins.circomlib },
      compiler: { ...pins.compiler, path: compiler, binarySha256: sha256(compiler) },
      snarkjs: { version: installed.version, cliSha256: sha256(snarkPath) },
      ptau: { ...measure(acquired.path), blake2b512: pins.ptau.blake2b512, power: pins.ptau.power, source: acquired.source, verificationLog: verified.log },
      circuits,
      notice: "Public deterministic build inputs only. No circuit-specific setup, contributions, beacon, or activation has been performed by this builder.",
    };
    const manifestPath = join(out, "build-inputs.json");
    noSymlink(manifestPath);
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o644 });
    console.log(`[build-inputs] verified input manifest: ${manifestPath}`);
    return manifest;
  } finally {
    closeSync(lock);
    rmSync(lockPath);
  }
}

function usage() {
  console.log("Usage: node scripts/ceremony/build-inputs.mjs --out /absolute/scratch/directory [--ptau-file /path/to/pinned.ptau]\n\nRequires Git, Node >=22, npm, rustup toolchain 1.98.0, and npm ci --prefix scripts/ceremony --ignore-scripts. Builds only public R1CS/WASM inputs and verifies the reused phase-1 transcript. Never runs a phase-2 ceremony.");
}

if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  try {
    const options = {};
    for (let i = 2; i < process.argv.length; i++) {
      const arg = process.argv[i];
      if (arg === "--help" || arg === "-h") { usage(); process.exit(0); }
      assert(arg === "--out" || arg === "--ptau-file", `unknown argument: ${arg}`);
      const value = process.argv[++i];
      assert(value && !value.startsWith("--"), `${arg} needs a path`);
      const key = arg === "--out" ? "out" : "ptauFile";
      assert(options[key] === undefined, `duplicate ${arg}`);
      options[key] = value;
    }
    await buildInputs(options);
  } catch (error) {
    console.error(`[build-inputs] ${error.message}`);
    process.exitCode = 1;
  }
}
