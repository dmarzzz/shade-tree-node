// Selftest for scripts/install.sh, the one-line installer for the prebuilt Rust `shade-tree`
// binary (issue #64). Everything runs OFFLINE against a fake release tree served over file://
// (and one loopback HTTP server, in a child process, for the "latest" redirect and HTTP error
// classification); it never touches github.com.
//
// What is asserted:
//   1. Every published default target (7) installs from the fake release when the host is
//      faked via shimmed `uname` and `ldd` (Linux gnu/musl, macOS, Git Bash on Windows), and
//      again when SHADE_TREE_TARGET overrides detection: exit 0, the installed file is
//      byte-identical to the asset, executable, named `shade-tree` (`shade-tree.exe` for the
//      Windows target), and the installer's temp dir is gone afterwards.
//   2. The default installs `-live` when the selected release has it, dynamically falls back
//      to its verifier when live is absent, and keeps SHADE_TREE_LIVE=1 fail-closed.
//   3. The checksum path FAILS CLOSED: a single flipped byte in the asset, a `.sha256` that names
//      a different file, a missing or garbage `.sha256`, or a missing asset each exit nonzero,
//      install nothing, leave no temp dir and no staging file behind.
//   4. Destination preflight: a symlink to a file at the destination (how npm installs its own
//      `shade-tree`) is refused and left intact unless SHADE_TREE_FORCE=1; a symlink to a
//      directory is refused even when forced, with nothing dropped inside it; a regular file is
//      replaced; a directory is refused; an install dir with spaces yields quoted, runnable hints.
//   5. "latest" is resolved from the release page redirect (302 -> /tag/vX.Y.Z), also with an
//      ambient http_proxy set (ignored for loopback) and via http://localhost; SHADE_TREE_VERSION
//      accepts `0.4.1` and `v0.4.1`; an HTTP 500 and a DNS failure are reported as such, not as
//      a missing asset.
//   6. Refusals: cleartext non-loopback base and loopback lookalikes (user-info, prefix hosts,
//      bad ports) before any fetch; SHADE_TREE_TARGET outside the seven published triples
//      (including a smuggled "-live"); unsupported OS/arch; a Linux host whose libc cannot be
//      identified (unless SHADE_TREE_LIBC says); stray arguments; HOME unset without an install dir.
//   7. Hints: PATH, next command, another same-name executable; the script never invokes sudo,
//      and every curl call ignores a hostile ~/.curlrc with `-q` first.
//
//   node scripts/install.selftest.mjs
//
// Exit 0 = every check passed; nonzero = a check failed (prints which). Needs `sh` and `curl`
// on PATH, which the installer itself needs anyway.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, existsSync, statSync, lstatSync, chmodSync, cpSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "install.sh");

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Mirrors .github/workflows/release.yml: 7 default targets, 6 of them also as `-live`.
const VERSION = "0.4.1";
const LEGACY_VERSION = "0.3.0";
const TARGETS = [
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
  "aarch64-unknown-linux-musl",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
];
const LIVE_TARGETS = [
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-unknown-linux-musl",
  "aarch64-unknown-linux-musl",
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
];
const ext = (target) => (target.includes("windows") ? ".exe" : "");
const assetName = (target, live = false, version = VERSION) => `shade-tree-${version}-${target}${live ? "-live" : ""}${ext(target)}`;
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// A fake release: <base>/download/v<VERSION>/<asset>{,.sha256}, exactly the GitHub layout, so the
// installer has ONE code path. Each asset is a tiny distinct sh script so the native-target case
// can prove it installed the right bytes by running them.
function makeRelease(root) {
  const assets = new Map();
  const addRelease = (version, liveTargets) => {
    const dir = join(root, "download", `v${version}`);
    mkdirSync(dir, { recursive: true });
    for (const target of TARGETS) {
      for (const live of liveTargets.includes(target) ? [false, true] : [false]) {
        const name = assetName(target, live, version);
        const body = Buffer.from(`#!/bin/sh\necho "fake shade-tree ${version} ${target}${live ? " live" : ""}"\n`);
        writeFileSync(join(dir, name), body);
        // Same "<hex>  <file>" framing release.yml writes (two spaces, sha256sum style).
        writeFileSync(join(dir, `${name}.sha256`), `${sha256(body)}  ${name}\n`);
        assets.set(name, body);
      }
    }
  };
  addRelease(VERSION, LIVE_TARGETS);
  // v0.3 did not publish live aarch64 Linux or musl binaries. This fixture proves that auto
  // follows the selected release's actual assets instead of a hard-coded current matrix.
  addRelease(LEGACY_VERSION, ["x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"]);
  return assets;
}

// A shim dir prepended to PATH so `uname` (and `ldd`) answer for a pretend host. The installer
// must resolve tools through PATH for this to work, which is also what a user's shell does.
function shimHost(root, { sysname, machine, ldd = null, translated = null }) {
  const bin = join(root, "shim-bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "uname"), `#!/bin/sh\ncase "$1" in -m) echo "${machine}";; *) echo "${sysname}";; esac\n`);
  chmodSync(join(bin, "uname"), 0o755);
  if (ldd === "musl") writeFileSync(join(bin, "ldd"), `#!/bin/sh\necho "musl libc (x86_64)" >&2\nexit 1\n`);
  if (ldd === "gnu") writeFileSync(join(bin, "ldd"), `#!/bin/sh\necho "ldd (GNU libc) 2.39"\n`);
  if (ldd) chmodSync(join(bin, "ldd"), 0o755);
  if (translated !== null) {
    writeFileSync(join(bin, "sysctl"), `#!/bin/sh\ncase "$*" in *sysctl.proc_translated*) echo "${translated}"; exit 0;; *) exit 1;; esac\n`);
    chmodSync(join(bin, "sysctl"), 0o755);
  }
  return bin;
}

// Minimal env: PATH + HOME + a private TMPDIR (so temp-dir cleanup is observable) + the
// installer's own knobs. Nothing from the developer's shell leaks in.
function runInstall(work, { env = {}, pathPrefix = null, timeout = 30_000, shell = "sh" } = {}) {
  const tmp = join(work, "tmp");
  const home = join(work, "home");
  mkdirSync(tmp, { recursive: true });
  mkdirSync(home, { recursive: true });
  const r = spawnSync(shell, [SCRIPT], {
    env: {
      PATH: pathPrefix ? `${pathPrefix}:${process.env.PATH}` : process.env.PATH,
      HOME: home,
      TMPDIR: tmp,
      ...env,
    },
    encoding: "utf8",
    timeout,
  });
  return { status: r.status, signal: r.signal, error: r.error, stdout: r.stdout ?? "", stderr: r.stderr ?? "", out: (r.stdout ?? "") + (r.stderr ?? ""), tmp, home };
}
// An expected failure must be a real nonzero exit: a timeout (status null + SIGTERM) or a
// spawn error would otherwise pass as "it refused".
const failedCleanly = (r) => typeof r.status === "number" && r.status !== 0 && r.signal === null && !r.error;
const tmpEmpty = (tmp) => readdirSync(tmp).length === 0;
// No `.shade-tree.XXXXXX` staging leftovers next to the destination either.
const noStage = (dir) => !existsSync(dir) || readdirSync(dir).every((f) => !f.startsWith(".shade-tree."));
const fresh = (label) => mkdtempSync(join(tmpdir(), `shade-tree-install-${label}-`));

// A loopback HTTP release server in its OWN process: the checks below drive the installer with
// spawnSync, which blocks this process's event loop, so an in-process http.Server could never
// answer curl. The child mimics GitHub's shape: /releases/latest -> 302 /releases/tag/<tag>,
// /releases/download/<tag>/<asset> -> bytes from the fake release tree; tag v5.0.0 answers 500.
const SERVER_SRC = String.raw`
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
const [root, tag] = process.argv.slice(2);
const server = createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname === "/releases/latest") {
    res.writeHead(302, { Location: "http://127.0.0.1:" + server.address().port + "/releases/tag/" + tag });
    return res.end();
  }
  const m = url.pathname.match(/^\/releases\/download\/(v[^/]+)\/([^/]+)$/);
  if (m && m[1] === "v5.0.0") { res.writeHead(500); return res.end("boom"); }
  if (m) {
    const p = join(root, "download", m[1], m[2]);
    if (existsSync(p)) { res.writeHead(200); return res.end(readFileSync(p)); }
  }
  res.writeHead(404); res.end();
});
server.on("error", (e) => { process.stderr.write("listen failed: " + e.message + "\n"); process.exit(2); });
server.listen(0, "127.0.0.1", () => { process.stdout.write(String(server.address().port) + "\n"); });
`;
function startReleaseServer(releaseRoot) {
  const src = join(releaseRoot, "release-server.mjs");
  writeFileSync(src, SERVER_SRC);
  const child = spawn(process.execPath, [src, releaseRoot, `v${VERSION}`], { stdio: ["ignore", "pipe", "pipe"] });
  const stop = () => { try { child.kill(); } catch { /* already gone */ } };
  return new Promise((resolve, reject) => {
    let buf = "";
    let errText = "";
    let settled = false;
    let timer = null;
    // Exactly one outcome: the startup timer is cleared on every path so it can never fire
    // later and kill a server that started fine; a late exit after success is ignored.
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (err) { stop(); reject(err); } else resolve(value);
    };
    timer = setTimeout(() => finish(new Error("release server did not report a port")), 10_000);
    child.stdout.on("data", (chunk) => {
      buf += chunk;
      const nl = buf.indexOf("\n");
      if (nl !== -1) finish(null, { port: Number(buf.slice(0, nl)), stop });
    });
    child.stderr.on("data", (chunk) => { errText += chunk; });
    child.once("error", (e) => finish(new Error(`release server failed to start: ${e.message}`)));
    child.once("exit", (code) => finish(new Error(`release server exited early (${code}): ${errText.trim()}`)));
  });
}
// Only a sandbox that forbids listening is a reason to skip the loopback checks; anything
// else (a syntax error in the server source, a crash) is a test failure, not coverage.
const isSocketPolicyError = (e) => /\b(EPERM|EACCES)\b/.test(e.message);

async function main() {
  console.log("scripts/install.sh selftest\n");

  ok(existsSync(SCRIPT), "scripts/install.sh exists");
  const text = existsSync(SCRIPT) ? readFileSync(SCRIPT, "utf8") : "";
  ok(text.startsWith("#!/bin/sh"), "shebang is #!/bin/sh (POSIX sh, not bash)");
  // "never uses sudo" means never INVOKES it. The word is allowed in comments, the help text
  // (a heredoc), and error strings, so strip those before looking for a bare sudo token. A
  // runtime shim below double-checks by making any real call fail loudly.
  const code = text
    .replace(/cat <<'EOF'[\s\S]*?\nEOF\n/g, "")
    .split("\n").filter((line) => !/^\s*#/.test(line)).join("\n")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'[^']*'/g, "''");
  ok(!/(^|[\s;&|(`])sudo(\s|$)/m.test(code), "the installer never invokes sudo (outside comments and messages)");
  const syntax = spawnSync("sh", ["-n", SCRIPT], { encoding: "utf8" });
  ok(syntax.status === 0, `sh -n parses the script${syntax.status === 0 ? "" : `: ${syntax.stderr}`}`);
  const curlCalls = text.split("\n").filter((line) => /^\s*curl\s/.test(line));
  ok(curlCalls.length > 0 && curlCalls.every((line) => /^\s*curl\s+-q(?:\s|$)/.test(line)), "every internal curl invocation puts -q first");

  const releaseRoot = fresh("release");
  let server = null;
  try {
    const assets = makeRelease(releaseRoot);
    const BASE = pathToFileURL(releaseRoot).href; // file:///.../release  (+ /download/vX/asset)
    const pinned = (extra = {}) => ({ SHADE_TREE_RELEASE_BASE: BASE, SHADE_TREE_VERSION: `v${VERSION}`, SHADE_TREE_LIVE: "0", ...extra });

    // --- 1. every target: detection through shimmed uname/ldd, then the override ------------
    console.log("\n-- detection via shimmed uname/ldd, all 7 targets");
    const HOSTS = [
      { target: "x86_64-unknown-linux-gnu", sysname: "Linux", machine: "x86_64", ldd: "gnu" },
      { target: "aarch64-unknown-linux-gnu", sysname: "Linux", machine: "aarch64", ldd: "gnu" },
      { target: "x86_64-unknown-linux-musl", sysname: "Linux", machine: "amd64", ldd: "musl" },
      { target: "aarch64-unknown-linux-musl", sysname: "Linux", machine: "arm64", ldd: "musl" },
      { target: "x86_64-apple-darwin", sysname: "Darwin", machine: "x86_64", translated: "0" },
      { target: "aarch64-apple-darwin", sysname: "Darwin", machine: "x86_64", translated: "1" },
      { target: "aarch64-apple-darwin", sysname: "Darwin", machine: "arm64" },
      { target: "x86_64-pc-windows-msvc", sysname: "MINGW64_NT-10.0-22631", machine: "x86_64" },
      { target: "x86_64-pc-windows-msvc", sysname: "MSYS_NT-10.0", machine: "x86_64" },
    ];
    for (const host of HOSTS) {
      const work = fresh("detect");
      const bin = shimHost(work, host);
      const dest = join(work, "bin");
      const r = runInstall(work, { pathPrefix: bin, env: pinned({ SHADE_TREE_INSTALL_DIR: dest }) });
      const installed = join(dest, `shade-tree${ext(host.target)}`);
      const label = `${host.sysname}/${host.machine}${host.ldd ? ` (ldd: ${host.ldd})` : ""}${host.translated === "1" ? " (Rosetta)" : ""} -> ${host.target}`;
      ok(r.status === 0, `${label}: exit 0${r.status === 0 ? "" : `\n${r.out}`}`);
      ok(existsSync(installed) && readFileSync(installed).equals(assets.get(assetName(host.target))), `  installed ${installed.split("/").pop()} == ${assetName(host.target)}`);
      ok(existsSync(installed) && (statSync(installed).mode & 0o111) !== 0, "  installed file is executable");
      ok(tmpEmpty(r.tmp) && noStage(dest), "  temp dir and staging file cleaned up");
      if (host.translated === "1") ok(/Rosetta translation detected/.test(r.stdout), "  Rosetta detection is reported");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // Linux with no ldd and no loader on disk (this host is not Linux): no guess, ask.
      const work = fresh("libc-unknown");
      const bin = shimHost(work, { sysname: "Linux", machine: "x86_64" });
      const dest = join(work, "bin");
      const r = runInstall(work, { pathPrefix: bin, env: pinned({ SHADE_TREE_INSTALL_DIR: dest }) });
      const decided = existsSync("/etc/alpine-release") || existsSync("/lib/ld-linux-x86-64.so.2") || existsSync("/lib64/ld-linux-x86-64.so.2");
      if (decided) console.log("  skip unknown-libc refusal (this host really is Linux; a loader is present)");
      else {
        ok(failedCleanly(r) && !existsSync(join(dest, "shade-tree")), "Linux, libc undetectable: refused rather than guessing gnu");
        ok(/SHADE_TREE_LIBC/.test(r.stderr), "  error names SHADE_TREE_LIBC");
      }
      const r2 = runInstall(work, { pathPrefix: bin, env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_LIBC: "musl" }) });
      ok(r2.status === 0 && readFileSync(join(dest, "shade-tree")).equals(assets.get(assetName("x86_64-unknown-linux-musl"))), "  SHADE_TREE_LIBC=musl resolves it");
      const r3 = runInstall(work, { pathPrefix: bin, env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_LIBC: "bionic" }) });
      ok(failedCleanly(r3) && /gnu or musl/.test(r3.stderr), "  SHADE_TREE_LIBC=bionic refused");
      rmSync(work, { recursive: true, force: true });
    }
    console.log("\n-- SHADE_TREE_TARGET override, all 7 targets");
    for (const target of TARGETS) {
      const work = fresh("target");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      const installed = join(dest, `shade-tree${ext(target)}`);
      ok(r.status === 0, `SHADE_TREE_TARGET=${target}: exit 0${r.status === 0 ? "" : `\n${r.out}`}`);
      ok(existsSync(installed) && readFileSync(installed).equals(assets.get(assetName(target))), `  installed ${installed.split("/").pop()} == ${assetName(target)}`);
      ok(tmpEmpty(r.tmp) && noStage(dest), "  temp dir and staging file cleaned up");
      rmSync(work, { recursive: true, force: true });
    }
    // The native target really runs: the fake binary is a sh script that names its target.
    {
      const native = process.platform === "darwin"
        ? (process.arch === "arm64" ? "aarch64-apple-darwin" : "x86_64-apple-darwin")
        : process.platform === "linux"
          ? (process.arch === "arm64" ? "aarch64-unknown-linux-" : "x86_64-unknown-linux-")
          : null;
      if (native) {
        const work = fresh("native");
        const dest = join(work, "bin");
        const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: BASE, SHADE_TREE_VERSION: VERSION, SHADE_TREE_INSTALL_DIR: dest } });
        ok(r.status === 0, `native host detection (no SHADE_TREE_TARGET, version without v): exit 0${r.status === 0 ? "" : `\n${r.out}`}`);
        const run = spawnSync(join(dest, "shade-tree"), [], { encoding: "utf8" });
        ok(run.status === 0 && run.stdout.includes(` ${native}`), `  installed binary runs and reports a ${native}* target (${run.stdout.trim() || run.stderr.trim()})`);
        rmSync(work, { recursive: true, force: true });
      } else console.log("  skip native-run check (unsupported host platform for the release binary)");
    }

    // --- 2. live variant ----------------------------------------------------------------------
    console.log("\n-- SHADE_TREE_LIVE and default agent selection");
    for (const target of LIVE_TARGETS) {
      const work = fresh("live");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "auto" }) });
      const installed = join(dest, `shade-tree${ext(target)}`);
      ok(r.status === 0 && existsSync(installed) && readFileSync(installed).equals(assets.get(assetName(target, true))), `default live ${target}: installs ${assetName(target, true)}${r.status === 0 ? "" : `\n${r.out}`}`);
      ok(/shadenet(?:\.exe)?' init/.test(r.stdout) && /stake to make/.test(r.stdout) && /docs\/AGENT\.md/.test(r.stdout) && !/#75|npm CLI|read -r SHADE_TREE_LIMIT/.test(r.stdout), "  next step is `shadenet init` and the agent guide, not the old invited flow");
      rmSync(work, { recursive: true, force: true });
    }
    {
      const target = "x86_64-apple-darwin"; // the only v0.4 target without `-live`
      const work = fresh("nolive");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "1" }) });
      ok(failedCleanly(r), `live ${target}: refused (no -live asset published)`);
      ok(/-live/.test(r.stderr) && /Intel macOS/.test(r.stderr) && new RegExp(target).test(r.stderr), "  error names -live, Intel macOS, and the target");
      ok(!existsSync(join(dest, "shade-tree")) && tmpEmpty(r.tmp) && noStage(dest), "  nothing installed, nothing left behind");
      const r2 = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "auto" }) });
      ok(r2.status === 0 && readFileSync(join(dest, "shade-tree")).equals(assets.get(assetName(target))), "  auto installs the verifier-only Intel macOS asset");
      ok(/no -live asset.*verifier-only/s.test(r2.stdout) && /Intel macOS cannot use this release/.test(r2.stdout), "  auto clearly explains the Intel macOS limitation");
      rmSync(work, { recursive: true, force: true });
    }
    {
      const target = "aarch64-unknown-linux-gnu";
      const work = fresh("legacy-auto");
      const dest = join(work, "bin");
      const legacy = { SHADE_TREE_RELEASE_BASE: BASE, SHADE_TREE_VERSION: `v${LEGACY_VERSION}`, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target };
      const r = runInstall(work, { env: legacy });
      const expected = assetName(target, false, LEGACY_VERSION);
      ok(r.status === 0 && readFileSync(join(dest, "shade-tree")).equals(assets.get(expected)), "auto on pinned v0.3 falls back to that release's verifier-only asset");
      ok(/no -live asset/.test(r.stdout) && /verifier-only/.test(r.stdout), "  pinned-release fallback is explicit");
      const r2 = runInstall(work, { env: { ...legacy, SHADE_TREE_LIVE: "1" } });
      ok(failedCleanly(r2) && /no -live asset/.test(r2.stderr), "  SHADE_TREE_LIVE=1 remains fail-closed on pinned v0.3");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // Exercise the second missing-artifact branch: the live checksum exists, but its binary
      // does not. Auto may fall back; a transport or checksum error still may not.
      const target = "x86_64-unknown-linux-gnu";
      const root = fresh("missing-live-binary");
      cpSync(releaseRoot, root, { recursive: true });
      rmSync(join(root, "download", `v${VERSION}`, assetName(target, true)));
      const work = fresh("missing-live-run");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: pathToFileURL(root).href, SHADE_TREE_VERSION: VERSION, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target } });
      ok(r.status === 0 && readFileSync(join(dest, "shade-tree")).equals(assets.get(assetName(target))), "auto falls back when the live checksum exists but the live binary is absent");
      rmSync(root, { recursive: true, force: true });
      rmSync(work, { recursive: true, force: true });
    }
    for (const bad of ["yes", "true", "2", " 1"]) {
      const work = fresh("badlive");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target0(), SHADE_TREE_LIVE: bad }) });
      ok(failedCleanly(r) && /SHADE_TREE_LIVE/.test(r.stderr) && !existsSync(join(dest, "shade-tree")), `SHADE_TREE_LIVE=${JSON.stringify(bad)}: refused, nothing installed`);
      rmSync(work, { recursive: true, force: true });
    }
    function target0() { return "x86_64-unknown-linux-gnu"; }

    // --- 3. checksum path fails closed --------------------------------------------------------
    console.log("\n-- checksum fails closed");
    const target = target0();
    const name = assetName(target);
    const tamperCase = (label, mutate, expectRe) => {
      const root = fresh(`tamper-${label.replace(/\W+/g, "-")}`);
      cpSync(releaseRoot, root, { recursive: true });
      mutate(join(root, "download", `v${VERSION}`));
      const work = fresh("tamperrun");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: pathToFileURL(root).href, SHADE_TREE_VERSION: `v${VERSION}`, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" } });
      ok(failedCleanly(r), `${label}: exit nonzero`);
      ok(expectRe.test(r.stderr), `  stderr explains (${expectRe})${expectRe.test(r.stderr) ? "" : `: ${r.stderr.trim()}`}`);
      ok(!existsSync(join(dest, "shade-tree")), "  nothing installed");
      ok(tmpEmpty(r.tmp) && noStage(dest), "  temp dir and staging file cleaned up");
      rmSync(root, { recursive: true, force: true });
      rmSync(work, { recursive: true, force: true });
    };
    tamperCase("one flipped byte in the asset", (dir) => {
      const p = join(dir, name);
      const b = readFileSync(p);
      b[b.length - 2] ^= 0x01;
      writeFileSync(p, b);
    }, /checksum mismatch/i);
    tamperCase(".sha256 names a different file", (dir) => {
      const p = join(dir, `${name}.sha256`);
      writeFileSync(p, readFileSync(p, "utf8").replace(name, assetName("aarch64-apple-darwin")));
    }, /names '.*', not/);
    tamperCase("missing .sha256", (dir) => rmSync(join(dir, `${name}.sha256`)), /\.sha256 not found/);
    tamperCase("missing asset", (dir) => rmSync(join(dir, name)), new RegExp(`release asset ${esc(name)} not found`));
    tamperCase("garbage .sha256 (no hex)", (dir) => writeFileSync(join(dir, `${name}.sha256`), "not a checksum line\n"), /malformed .*\.sha256/);
    tamperCase("short hex in .sha256", (dir) => writeFileSync(join(dir, `${name}.sha256`), `${"ab".repeat(20)}  ${name}\n`), /malformed .*\.sha256/);
    // The two framings the parser deliberately accepts must still verify: uppercase hex
    // (some tools print it) and sha256sum's binary-mode "*<file>" marker.
    const acceptCase = (label, mutate) => {
      const root = fresh(`accept-${label.replace(/\W+/g, "-")}`);
      cpSync(releaseRoot, root, { recursive: true });
      mutate(join(root, "download", `v${VERSION}`));
      const work = fresh("acceptrun");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: pathToFileURL(root).href, SHADE_TREE_VERSION: `v${VERSION}`, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" } });
      ok(r.status === 0 && existsSync(join(dest, "shade-tree")) && readFileSync(join(dest, "shade-tree")).equals(assets.get(name)), `${label}: still verifies and installs${r.status === 0 ? "" : `\n${r.out}`}`);
      rmSync(root, { recursive: true, force: true });
      rmSync(work, { recursive: true, force: true });
    };
    acceptCase("uppercase hex in .sha256", (dir) => writeFileSync(join(dir, `${name}.sha256`), `${sha256(assets.get(name)).toUpperCase()}  ${name}\n`));
    acceptCase("binary-mode '*file' in .sha256", (dir) => writeFileSync(join(dir, `${name}.sha256`), `${sha256(assets.get(name))} *${name}\n`));

    // --- 4. destination preflight -------------------------------------------------------------
    console.log("\n-- destination preflight");
    {
      const work = fresh("symlink");
      const dest = join(work, "bin");
      mkdirSync(dest, { recursive: true });
      const existingTool = join(work, "existing-tool");
      writeFileSync(existingTool, "existing installation\n");
      symlinkSync(existingTool, join(dest, "shade-tree"));
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(failedCleanly(r) && /symlink/.test(r.stderr) && /SHADE_TREE_FORCE/.test(r.stderr), "destination is a symlink: refused, SHADE_TREE_FORCE named");
      ok(lstatSync(join(dest, "shade-tree")).isSymbolicLink() && existsSync(existingTool), "  symlink and its target untouched");
      ok(tmpEmpty(r.tmp) && noStage(dest), "  nothing downloaded or staged");
      const r2 = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_FORCE: "1" }) });
      ok(r2.status === 0 && !lstatSync(join(dest, "shade-tree")).isSymbolicLink() && readFileSync(join(dest, "shade-tree")).equals(assets.get(name)), "  SHADE_TREE_FORCE=1: symlink replaced by the binary");
      ok(existsSync(existingTool), "  the symlink's target file is not deleted");
      const r3 = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_FORCE: "please" }) });
      ok(failedCleanly(r3) && /SHADE_TREE_FORCE/.test(r3.stderr), "  SHADE_TREE_FORCE=please refused");
      rmSync(work, { recursive: true, force: true });
    }
    {
      const work = fresh("regular");
      const dest = join(work, "bin");
      mkdirSync(dest, { recursive: true });
      writeFileSync(join(dest, "shade-tree"), "old build\n");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(r.status === 0 && readFileSync(join(dest, "shade-tree")).equals(assets.get(name)) && /will replace existing/.test(r.stdout), "destination is a regular file: replaced, with a note");
      rmSync(work, { recursive: true, force: true });
    }
    {
      const work = fresh("dirdest");
      const dest = join(work, "bin");
      mkdirSync(join(dest, "shade-tree"), { recursive: true });
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(failedCleanly(r) && /not a regular file/.test(r.stderr) && statSync(join(dest, "shade-tree")).isDirectory(), "destination is a directory: refused, untouched");
      rmSync(work, { recursive: true, force: true });
    }
    for (const force of ["0", "1"]) {
      // A symlink to a DIRECTORY: `mv` would follow it and drop the binary inside, leaving the
      // symlink in place and a false "installed". Must be refused even when forced.
      const work = fresh("dirlink");
      const dest = join(work, "bin");
      const realDir = join(work, "real-dir");
      mkdirSync(dest, { recursive: true });
      mkdirSync(realDir, { recursive: true });
      symlinkSync(realDir, join(dest, "shade-tree"));
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_FORCE: force }) });
      ok(failedCleanly(r) && /symlink to a directory/.test(r.stderr), `destination is a symlink to a directory (FORCE=${force}): refused, exit nonzero`);
      ok(lstatSync(join(dest, "shade-tree")).isSymbolicLink() && readdirSync(realDir).length === 0, "  symlink intact, nothing installed inside its target");
      ok(tmpEmpty(r.tmp) && noStage(dest), "  no temp or staging residue");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // An install dir with spaces: the printed next command must be quoted so it copy-pastes.
      const work = fresh("spaces");
      const dest = join(work, "my bin dir");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      const helpLine = r.stdout.split("\n").map((l) => l.trim()).find((l) => l.endsWith(" --help")) ?? "";
      const run = spawnSync("sh", ["-c", helpLine], { encoding: "utf8" });
      ok(r.status === 0 && existsSync(join(dest, "shade-tree")), "install dir with spaces: installs");
      ok(run.status === 0 && /fake shade-tree/.test(run.stdout), `  printed next command runs verbatim through sh -c (${helpLine.length ? "quoted" : "no --help line found"})`);
      const pathLine = r.stdout.split("\n").map((l) => l.trim()).find((l) => l.startsWith("export PATH=")) ?? "";
      const pathRun = spawnSync("sh", ["-c", `${pathLine}; command -v shade-tree`], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
      ok(pathRun.status === 0 && pathRun.stdout.trim() === join(dest, "shade-tree"), "  printed PATH hint runs verbatim and resolves the installed binary");
      rmSync(work, { recursive: true, force: true });
    }

    // --- 5. latest via redirect, version forms, error classification (loopback http) ---------
    console.log("\n-- latest via redirect, version forms, HTTP errors (loopback http)");
    try {
      server = await startReleaseServer(releaseRoot);
    } catch (e) {
      if (!isSocketPolicyError(e)) throw e;
      console.log(`  skip loopback HTTP checks (socket policy: ${e.message})`);
    }
    if (server) {
      const httpBase = `http://127.0.0.1:${server.port}/releases`;
      {
        // An ambient http_proxy (unroutable here) must not capture loopback requests.
        const work = fresh("latest");
        const dest = join(work, "bin");
        const proxyEnv = { http_proxy: "http://192.0.2.1:1", HTTP_PROXY: "http://192.0.2.1:1", ALL_PROXY: "http://192.0.2.1:1" };
        const r = runInstall(work, { env: { ...proxyEnv, SHADE_TREE_RELEASE_BASE: httpBase, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" }, timeout: 20_000 });
        ok(r.status === 0 && existsSync(join(dest, "shade-tree")) && readFileSync(join(dest, "shade-tree")).equals(assets.get(name)), `no SHADE_TREE_VERSION: latest resolved from the redirect and installed, with http_proxy set and ignored${r.status === 0 ? "" : `\n${r.out}`}`);
        ok(new RegExp(`release: v${esc(VERSION)} \\(latest\\)`).test(r.stdout), "  resolved tag printed");
        rmSync(work, { recursive: true, force: true });
      }
      {
        const work = fresh("localhost");
        const dest = join(work, "bin");
        const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: `http://localhost:${server.port}/releases`, SHADE_TREE_VERSION: VERSION, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" }, timeout: 20_000 });
        ok(r.status === 0 && existsSync(join(dest, "shade-tree")), `http://localhost:<port> accepted as loopback${r.status === 0 ? "" : `\n${r.out}`}`);
        rmSync(work, { recursive: true, force: true });
      }
      {
        const work = fresh("bare-version");
        const dest = join(work, "bin");
        const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: httpBase, SHADE_TREE_VERSION: VERSION, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" } });
        ok(r.status === 0 && existsSync(join(dest, "shade-tree")), `SHADE_TREE_VERSION=${VERSION} (no v) accepted`);
        rmSync(work, { recursive: true, force: true });
      }
      {
        const work = fresh("bad-version");
        const dest = join(work, "bin");
        const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: httpBase, SHADE_TREE_VERSION: "v9.9.9", SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" } });
        ok(failedCleanly(r) && /not found/.test(r.stderr) && /SHADE_TREE_VERSION/.test(r.stderr), "unknown version (404): reported as not found, hints at SHADE_TREE_VERSION");
        ok(!existsSync(join(dest, "shade-tree")) && tmpEmpty(r.tmp) && noStage(dest), "  installs nothing, cleans up");
        rmSync(work, { recursive: true, force: true });
      }
      {
        const work = fresh("http-500");
        const dest = join(work, "bin");
        const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: httpBase, SHADE_TREE_VERSION: "v5.0.0", SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target, SHADE_TREE_LIVE: "0" }, timeout: 60_000 });
        ok(failedCleanly(r) && /HTTP error 500/.test(r.stderr) && !/not found/.test(r.stderr), "server error (500): reported as an HTTP error, not as a missing asset");
        rmSync(work, { recursive: true, force: true });
      }
      server.stop();
      server = null;
    }
    {
      // .invalid never resolves (RFC 2606): a DNS failure must not read as "asset not found".
      const work = fresh("dns");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_RELEASE_BASE: "https://releases.nonexistent.invalid/releases", SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }), timeout: 60_000 });
      ok(failedCleanly(r) && /could not fetch/.test(r.stderr) && !/not found/.test(r.stderr), "DNS failure: reported as a fetch/network problem, not as a missing asset");
      ok(tmpEmpty(r.tmp) && noStage(dest), "  cleans up");
      rmSync(work, { recursive: true, force: true });
    }

    // --- 6. refusals ---------------------------------------------------------------------------
    console.log("\n-- refusals");
    {
      const work = fresh("cleartext");
      const dest = join(work, "bin");
      // TEST-NET-1 is unroutable: if the script wrongly tried to fetch, this would hang and time out.
      const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: "http://192.0.2.1/releases", SHADE_TREE_VERSION: `v${VERSION}`, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }, timeout: 15_000 });
      ok(failedCleanly(r), "cleartext non-loopback base: refused without a fetch");
      ok(/https/.test(r.stderr), "  error says https is required");
      rmSync(work, { recursive: true, force: true });
    }
    // Loopback lookalikes: user-info that makes curl connect elsewhere, hostnames that merely
    // start with a loopback name, and malformed ports. All must fail before any fetch (the
    // remote hosts are unroutable TEST-NET, so a wrongly attempted fetch would time out).
    for (const base of [
      "http://127.0.0.1:pw@192.0.2.1/releases",
      "http://user@127.0.0.1/releases",
      "http://[::1]@192.0.2.1/releases",
      "http://127.0.0.1.192.0.2.1.nip.io/releases",
      "http://localhost.example/releases",
      "http://127.0.0.1:99999/releases",
      "http://127.0.0.1:0/releases",
      "http://127.0.0.1:/releases",
      "http://[::1]:x/releases",
      "http://127.0.0.10/releases",
    ]) {
      const work = fresh("lookalike");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: { SHADE_TREE_RELEASE_BASE: base, SHADE_TREE_VERSION: `v${VERSION}`, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }, timeout: 15_000 });
      ok(failedCleanly(r) && /https|port/.test(r.stderr) && !existsSync(join(dest, "shade-tree")) && tmpEmpty(r.tmp) && noStage(dest), `${base}: refused before any fetch`);
      rmSync(work, { recursive: true, force: true });
    }
    // Target allowlist: only the seven published triples, exactly; "-live" cannot be smuggled
    // into the target to bypass SHADE_TREE_LIVE.
    for (const bad of ["x86_64-unknown-linux-gnu-live", "X86_64-apple-darwin", "aarch64-linux-android", "x86_64-pc-windows-msvc.exe", "x86_64-unknown-linux-gnu "]) {
      const work = fresh("badtarget");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: bad }) });
      ok(failedCleanly(r) && /not a published target/.test(r.stderr) && !existsSync(join(dest, "shade-tree")) && tmpEmpty(r.tmp) && noStage(dest), `SHADE_TREE_TARGET=${JSON.stringify(bad)}: refused`);
      rmSync(work, { recursive: true, force: true });
    }
    {
      const r = spawnSync("sh", [SCRIPT, "-h"], { env: { PATH: process.env.PATH }, encoding: "utf8" });
      ok(r.status === 0 && /SHADENET_INSTALL_DIR/.test(r.stdout), "-h works with HOME unset");
      const r2 = runInstall(fresh("nohome"), { env: pinned({ SHADE_TREE_TARGET: target }) });
      // runInstall always sets HOME; emulate an unset HOME by passing an empty one.
      const r3 = spawnSync("sh", [SCRIPT], { env: { PATH: process.env.PATH, HOME: "", SHADE_TREE_RELEASE_BASE: BASE, SHADE_TREE_VERSION: `v${VERSION}`, SHADE_TREE_TARGET: target }, encoding: "utf8" });
      ok(r2.status === 0, "  (control: same run with HOME set installs)");
      ok(failedCleanly(r3) && /HOME is unset/.test(r3.stderr), "  install with HOME unset and no SHADE_TREE_INSTALL_DIR: refused with a hint");
    }
    for (const host of [
      { label: "unsupported OS (FreeBSD)", sysname: "FreeBSD", machine: "amd64", re: /unsupported OS/ },
      { label: "unsupported arch (Linux i686)", sysname: "Linux", machine: "i686", re: /unsupported CPU/ },
      { label: "Windows on aarch64 (no release)", sysname: "MINGW64_NT-10.0", machine: "aarch64", re: /Windows releases cover x86_64/ },
    ]) {
      const work = fresh("refuse");
      const bin = shimHost(work, host);
      const dest = join(work, "bin");
      const r = runInstall(work, { pathPrefix: bin, env: pinned({ SHADE_TREE_INSTALL_DIR: dest }) });
      ok(failedCleanly(r) && !existsSync(join(dest, "shade-tree")), `${host.label}: refused, nothing installed`);
      ok(host.re.test(r.stderr) && /INSTALL\.md/.test(r.stderr), `  error explains (${host.re}) and points at crates/INSTALL.md`);
      rmSync(work, { recursive: true, force: true });
    }
    {
      const r = spawnSync("sh", [SCRIPT, "--live"], { env: { PATH: process.env.PATH, HOME: tmpdir() }, encoding: "utf8" });
      ok(failedCleanly(r) && /unknown argument/.test(r.stderr), "stray argument: refused with a pointer to the env knobs");
      const h = spawnSync("sh", [SCRIPT, "-h"], { env: { PATH: process.env.PATH, HOME: tmpdir() }, encoding: "utf8" });
      ok(h.status === 0 && /SHADENET_RELEASE_BASE/.test(h.stdout) && /SHADENET_FORCE/.test(h.stdout) && /SHADE_TREE_\*/.test(h.stdout), "-h lists every knob and says the old names still work");
    }

    // --- 6b. the ShadeNet rename --------------------------------------------------------------
    console.log("\n-- shadenet names: assets, installed binaries, knobs");
    {
      // A release that publishes shadenet-* assets: they win over shade-tree-* ones.
      const work = fresh("rename");
      const target = "x86_64-unknown-linux-gnu";
      const renamedRoot = join(work, "release");
      const dir = join(renamedRoot, "download", `v${VERSION}`);
      mkdirSync(dir, { recursive: true });
      const newName = `shadenet-${VERSION}-${target}`;
      const oldName = assetName(target);
      const newBody = Buffer.from("#!/bin/sh\necho shadenet-asset\n");
      const oldBody = Buffer.from("#!/bin/sh\necho shade-tree-asset\n");
      writeFileSync(join(dir, newName), newBody);
      writeFileSync(join(dir, `${newName}.sha256`), `${sha256(newBody)}  ${newName}\n`);
      writeFileSync(join(dir, oldName), oldBody);
      writeFileSync(join(dir, `${oldName}.sha256`), `${sha256(oldBody)}  ${oldName}\n`);
      const dest = join(work, "bin");
      const env = { SHADENET_RELEASE_BASE: pathToFileURL(renamedRoot).href, SHADENET_VERSION: `v${VERSION}`, SHADENET_LIVE: "0", SHADENET_INSTALL_DIR: dest, SHADENET_TARGET: target };
      const r = runInstall(work, { env });
      ok(r.status === 0 && readFileSync(join(dest, "shadenet")).equals(newBody), `a release with shadenet-* assets installs ${newName}${r.status === 0 ? "" : `\n${r.out}`}`);
      ok(existsSync(join(dest, "shade-tree")) && readFileSync(join(dest, "shade-tree")).equals(newBody), "  the same program is also installed as shade-tree");
      ok(!/pre-rename/.test(r.stdout) && noStage(dest) && tmpEmpty(r.tmp), "  no fallback note, nothing left behind");
      // SHADENET_* and SHADE_TREE_* naming one knob differently is refused before any fetch.
      const r2 = runInstall(work, { env: { ...env, SHADE_TREE_VERSION: "v9.9.9" } });
      ok(failedCleanly(r2) && /SHADENET_VERSION and SHADE_TREE_VERSION/.test(r2.stderr), "  conflicting SHADENET_VERSION / SHADE_TREE_VERSION: refused");
      // The same value under both names is fine.
      const r3 = runInstall(work, { env: { ...env, SHADE_TREE_VERSION: `v${VERSION}` } });
      ok(r3.status === 0, "  equal values under both names: accepted");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // A pre-rename release (only shade-tree-* assets): falls back and says so; installs both names.
      const work = fresh("prerename");
      const dest = join(work, "bin");
      const r = runInstall(work, { env: { SHADENET_RELEASE_BASE: BASE, SHADENET_VERSION: VERSION, SHADENET_LIVE: "0", SHADENET_INSTALL_DIR: dest, SHADENET_TARGET: target } });
      ok(r.status === 0 && /pre-rename name/.test(r.stdout), "pre-rename release: falls back to shade-tree-* assets with a note");
      ok(readFileSync(join(dest, "shadenet")).equals(assets.get(assetName(target))) && readFileSync(join(dest, "shade-tree")).equals(assets.get(assetName(target))), "  both names installed from the verified asset");
      rmSync(work, { recursive: true, force: true });
    }

    // --- 7. hints --------------------------------------------------------------------------------
    console.log("\n-- hints");
    {
      const work = fresh("hints");
      const dest = join(work, "not-on-path");
      const r = runInstall(work, { env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(r.status === 0 && /PATH/.test(r.stdout), "install dir not on PATH: PATH hint printed");
      ok(/shadenet' --help/.test(r.stdout), "  next command printed, path quoted ('...shadenet' --help)");
      ok(new RegExp(esc(dest)).test(r.stdout), "  installed path printed");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // Default install dir is $HOME/.local/bin when SHADE_TREE_INSTALL_DIR is unset. A `sudo`
      // shim sits first on PATH and leaves a marker if anything calls it.
      const work = fresh("default-dir");
      const bin = join(work, "shim-bin");
      mkdirSync(bin, { recursive: true });
      const marker = join(work, "sudo-was-called");
      writeFileSync(join(bin, "sudo"), `#!/bin/sh\necho "sudo called: $*" > '${marker}'\nexit 99\n`);
      chmodSync(join(bin, "sudo"), 0o755);
      const r = runInstall(work, { pathPrefix: bin, env: pinned({ SHADE_TREE_TARGET: target }) });
      ok(r.status === 0 && existsSync(join(r.home, ".local", "bin", "shade-tree")), "default install dir is $HOME/.local/bin");
      ok(!existsSync(marker), "  sudo shim on PATH was never called");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // A hostile ~/.curlrc must not affect any transfer. `write-out` gives us an observable
      // marker that appears immediately if `-q` is ever removed or moved away from first place.
      const work = fresh("curlrc");
      const home = join(work, "home");
      const dest = join(work, "bin");
      mkdirSync(home, { recursive: true });
      writeFileSync(join(home, ".curlrc"), 'write-out = "HOSTILE_CURLRC_LOADED\\n"\ninsecure\n');
      const r = runInstall(work, { env: pinned({ HOME: home, CURL_HOME: home, SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(r.status === 0 && existsSync(join(dest, "shade-tree")), `hostile ~/.curlrc: install still succeeds${r.status === 0 ? "" : `\n${r.out}`}`);
      ok(!/HOSTILE_CURLRC_LOADED/.test(r.out), "  curl -q prevents the hostile config from being loaded");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // Another `shade-tree` earlier on PATH: warn, do not fail.
      const work = fresh("collision");
      const other = join(work, "other-bin");
      mkdirSync(other, { recursive: true });
      writeFileSync(join(other, "shade-tree"), "#!/bin/sh\necho npm cli\n");
      chmodSync(join(other, "shade-tree"), 0o755);
      const dest = join(work, "bin");
      const r = runInstall(work, { pathPrefix: other, env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(r.status === 0 && existsSync(join(dest, "shade-tree")), "foreign shade-tree earlier on PATH: still installs");
      ok(new RegExp(esc(other)).test(r.out) && /shadow/.test(r.out) && new RegExp(`run ${esc(join(other, "shade-tree"))} first`).test(r.out), "  warns, names the other path, and says the other one wins");
      // Same collision with the install dir FIRST on PATH: `command -v` would now report our own
      // binary, so only a full PATH walk can still surface the other executable behind it.
      const r2 = runInstall(work, { pathPrefix: `${dest}:${other}`, env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
      ok(r2.status === 0 && new RegExp(esc(join(other, "shade-tree"))).test(r2.out) && /run this Rust client first/.test(r2.out), "  other executable BEHIND the install dir on PATH: still named, and told it is shadowed");
      rmSync(work, { recursive: true, force: true });
    }
    {
      // Stricter shells when available: dash is Debian/Ubuntu's /bin/sh (and ships on macOS).
      const dash = spawnSync("sh", ["-c", "command -v dash"], { encoding: "utf8" }).stdout.trim();
      if (dash) {
        const work = fresh("dash");
        const dest = join(work, "bin");
        const r = runInstall(work, { shell: dash, env: pinned({ SHADE_TREE_INSTALL_DIR: dest, SHADE_TREE_TARGET: target }) });
        ok(r.status === 0 && existsSync(join(dest, "shade-tree")), "runs under dash");
        rmSync(work, { recursive: true, force: true });
      } else console.log("  skip dash run (dash not on PATH)");
      const shellcheck = spawnSync("sh", ["-c", "command -v shellcheck"], { encoding: "utf8" }).stdout.trim();
      if (shellcheck) {
        const r = spawnSync(shellcheck, ["-s", "sh", SCRIPT], { encoding: "utf8" });
        ok(r.status === 0, `shellcheck -s sh clean${r.status === 0 ? "" : `\n${r.stdout ?? ""}${r.stderr ?? ""}`}`);
      } else console.log("  skip shellcheck (not on PATH)");
    }
  } finally {
    if (server) server.stop();
    rmSync(releaseRoot, { recursive: true, force: true });
  }

  console.log(`\n${failures ? "issues found" : "ready"}: ${failures} failure(s)`);
  process.exit(failures ? 1 : 0);
}

await main();
