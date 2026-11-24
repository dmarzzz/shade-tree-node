import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { makeDestinationLog } from "./destination-log.mjs";

const record = { host: "example.invalid", ip: "192.0.2.1", port: 443,
  openedAt: "2026-01-01T00:00:00.000Z", durationMs: 1,
  agentToDestinationBytes: 12, destinationToAgentBytes: 24, closeReason: "peer-close" };
const clock = 30000000 * 60000;
async function fixture(t, factory = makeDestinationLog, cap = "50331648") {
  const directory = await fs.mkdtemp(join(tmpdir(), "destination-recovery-"));
  await fs.chmod(directory, 0o700);
  const env = { SHADE_TREE_DESTINATION_LOG: "1", SHADE_TREE_DESTINATION_LOG_DIR: directory,
    SHADE_TREE_DESTINATION_LOG_RETENTION: "forever", SHADE_TREE_DESTINATION_LOG_MAX_BYTES: cap };
  let errors = 0;
  const sinks = [];
  t.after(async () => { for (const sink of sinks) await sink.close(); await fs.rm(directory, { recursive: true, force: true }); });
  const start = async () => { const sink = await factory({ env, now: () => clock, onError: () => errors++ }); sinks.push(sink); return sink; };
  return { directory, env, start, errors: () => errors };
}
async function contents(directory) {
  return Promise.all((await fs.readdir(directory)).sort((a, b) => Number(a.match(/-(\d+)\.jsonl$/)[1]) - Number(b.match(/-(\d+)\.jsonl$/)[1]))
    .map(async (name) => ({ name, text: await fs.readFile(join(directory, name), "utf8") })));
}

test("record preparation failures are isolated and objects cannot escape the field allowlist", async (t) => {
  const f = await fixture(t); const sink = await f.start();
  const circular = {}; circular.self = circular;
  let serialized = false;
  const object = { toJSON() { serialized = true; return "not metadata"; } };
  for (const bad of [null, { ...record, host: circular }, { ...record, port: 1n },
    { ...record, host: object }, { get host() { throw Error("private detail"); } }]) {
    assert.doesNotThrow(() => sink.write(bad));
  }
  sink.write({ ...record, extra: object }); await sink.flush();
  assert.equal(serialized, false);
  const files = await contents(f.directory);
  assert.equal(files.length, 1); assert.deepEqual(files[0].text.trim().split("\n").map(JSON.parse),
    [{ event: "destination.tunnel.closed", ...record }]);
  assert.equal(f.errors(), 1);
});

test("directory spelling and exact private permission bits", async (t) => {
  const f = await fixture(t);
  const linked = `${f.directory}-link`; await fs.symlink(f.directory, linked);
  t.after(() => fs.rm(linked, { force: true }));
  for (const directory of [linked, `${linked}/`, `${linked}/.`, `${f.directory}/../${f.directory.split("/").at(-1)}`]) {
    await assert.rejects(makeDestinationLog({ env: { ...f.env, SHADE_TREE_DESTINATION_LOG_DIR: directory } }));
  }
  await fs.chmod(f.directory, 0o750); await assert.rejects(f.start(), /0700/);
  await fs.chmod(f.directory, 0o700);
  const path = join(f.directory, "destination-30000000-1.jsonl");
  await fs.writeFile(path, "", { mode: 0o600 });
  await fs.chmod(path, 0o640); await assert.rejects(f.start(), /unsafe/);
  await fs.chmod(path, 0o600);
  // POSIX may reject or silently clear special bits. Inject only the observed mode,
  // keeping real ownership, type, identity and filesystem operations in every case.
  for (const [target, modes, error] of [[f.directory, [0o1700, 0o2700, 0o4700], /0700/],
    [path, [0o1600, 0o2600, 0o4600], /unsafe/]]) {
    for (const mode of modes) {
      let observed = 0;
      const factory = await injectedFactory(undefined, (stat, name) => {
        if (name !== target) return stat;
        observed++;
        return new Proxy(stat, { get(object, key) {
          return key === "mode" ? (object.mode & ~0o7777) | mode : Reflect.get(object, key);
        } });
      });
      await assert.rejects(factory({ env: f.env }), error);
      assert.ok(observed > 0, `mode ${mode.toString(8)} was observed`);
    }
  }
});

test("active deletion or size mutation recovers on the next write without a sweep", async (t) => {
  for (const action of ["delete", "resize"]) {
    const f = await fixture(t); const sink = await f.start(); sink.write(record); await sink.flush();
    const path = join(f.directory, (await fs.readdir(f.directory))[0]);
    if (action === "delete") await fs.unlink(path); else await fs.appendFile(path, "partial");
    sink.write(record); await sink.flush(); // The affected record may be dropped; recovery must not be sticky.
    sink.write({ ...record, durationMs: 2 }); await sink.flush();
    const files = await contents(f.directory);
    assert.equal(JSON.parse(files.at(-1).text).durationMs, 2);
    assert.equal(f.errors(), 1);
  }
});

test("rotation never backfills older same-minute segments", async (t) => {
  const f = await fixture(t); const sink = await f.start();
  const big = { ...record, host: "x".repeat(5 * 1024 * 1024) };
  sink.write(big); await sink.flush();
  const first = (await contents(f.directory))[0];
  const overhead = Buffer.byteLength(JSON.stringify({ event: "destination.tunnel.closed", ...record, host: "" }) + "\n");
  sink.write({ ...record, host: "x".repeat(8 * 1024 * 1024 - overhead - 1) }); await sink.flush();
  sink.write(record); await sink.flush();
  const files = await contents(f.directory);
  assert.equal(files.length, 3); assert.equal(files[0].text, first.text);
  assert.deepEqual(JSON.parse(files[2].text), { event: "destination.tunnel.closed", ...record });
});

// Fault injection is confined to this test's independently loaded module. No production
// API or global fs patch: filesystem bindings use closure-owned wrappers.
async function injectedFactory(wrap = (file) => file, wrapLstat = (stat) => stat) {
  const source = await fs.readFile(new URL("./destination-log.mjs", import.meta.url), "utf8");
  const original = 'import { lstat, open, readdir, unlink } from "node:fs/promises";';
  assert.ok(source.includes(original));
  const patched = source.replace(original,
    'import { lstat as realLstat, open as realOpen, readdir, unlink } from "node:fs/promises";\nlet open = realOpen;\nlet lstat = realLstat;\nexport function setFsForTest(wrap, wrapLstat) { open = async (...args) => wrap(await realOpen(...args)); lstat = async (...args) => wrapLstat(await realLstat(...args), args[0]); }');
  const module = await import(`data:text/javascript;base64,${Buffer.from(patched).toString("base64")}#${Math.random()}`);
  module.setFsForTest(wrap, wrapLstat);
  return module.makeDestinationLog;
}

test("partial append rollback and failed rollback/stat retain cap accounting and isolate later records", async (t) => {
  for (const fault of ["partial", "truncate", "stat", "post-write-stat"]) {
    let armed = false; let fired = false; let afterWrite = false;
    let truncateFired = false; let statFired = false; let rolledBack = false;
    const factory = await injectedFactory((file) => new Proxy(file, { get(target, key) {
      if (key === "writeFile") return async (line) => {
        if (armed && !fired) {
          fired = true; afterWrite = true;
          if (fault === "post-write-stat") return target.writeFile(line);
          await target.writeFile(line.slice(0, 17)); throw Error("write failure");
        }
        return target.writeFile(line);
      };
      if (key === "truncate") return async (size) => {
        truncateFired = true;
        if (fault === "truncate") throw Error("truncate failure");
        await target.truncate(size); rolledBack = true;
      };
      if (key === "stat") return async () => {
        if ((fault === "stat" || fault === "post-write-stat") && afterWrite) {
          afterWrite = false; statFired = true; throw Error("stat failure");
        }
        return target.stat();
      };
      const value = target[key]; return typeof value === "function" ? value.bind(target) : value;
    } }));
    const bytes = Buffer.byteLength(JSON.stringify({ event: "destination.tunnel.closed", ...record }) + "\n");
    const f = await fixture(t, factory, String(bytes * 2)); const sink = await f.start();
    sink.write(record); await sink.flush(); armed = true;
    sink.write(record); await sink.flush();
    assert.equal(fired, true, `${fault}: append hook fired`);
    assert.equal(truncateFired, fault !== "post-write-stat", `${fault}: rollback attempted`);
    assert.equal(rolledBack, fault === "partial" || fault === "stat", `${fault}: rollback completed`);
    assert.equal(statFired, fault === "stat" || fault === "post-write-stat", `${fault}: stat fault fired`);
    if (rolledBack) assert.deepEqual((await contents(f.directory)).map((file) => file.text),
      [JSON.stringify({ event: "destination.tunnel.closed", ...record }) + "\n"]);
    sink.write({ ...record, durationMs: 2 }); await sink.flush();
    const files = await contents(f.directory);
    assert.ok(files.reduce((n, file) => n + Buffer.byteLength(file.text), 0) <= bytes * 2);
    assert.equal(JSON.parse(files.at(-1).text.trim().split("\n").at(-1)).durationMs, 2);
    if (fault !== "truncate") for (const file of files) for (const line of file.text.trim().split("\n")) if (line) assert.doesNotThrow(() => JSON.parse(line));
    if (rolledBack) {
      assert.equal(files.length, 2, `${fault}: original segment was not evicted`);
      assert.deepEqual(files.flatMap((file) => file.text.trim().split("\n").map(JSON.parse)),
        [{ event: "destination.tunnel.closed", ...record },
          { event: "destination.tunnel.closed", ...record, durationMs: 2 }]);
    }
    assert.equal(f.errors(), 1); await sink.close();
  }
});

test("maintenance rejects directory permission drift, then recovers after restoration", async (t) => {
  const f = await fixture(t); const sink = await f.start(); sink.write(record); await sink.flush();
  assert.equal(f.errors(), 0);
  await fs.chmod(f.directory, 0o750); await sink.sweep();
  assert.equal(f.errors(), 1);
  sink.write(record); await sink.flush();
  assert.deepEqual((await contents(f.directory)).flatMap((file) => file.text.trim().split("\n").map(JSON.parse)),
    [{ event: "destination.tunnel.closed", ...record }]);
  await fs.chmod(f.directory, 0o700);
  sink.write({ ...record, durationMs: 2 }); await sink.flush();
  assert.deepEqual((await contents(f.directory)).flatMap((file) => file.text.trim().split("\n").map(JSON.parse)),
    [{ event: "destination.tunnel.closed", ...record },
      { event: "destination.tunnel.closed", ...record, durationMs: 2 }]);
  assert.equal(f.errors(), 1);
});

test("maintenance rejects directory replacement, then recovers after restoration", async (t) => {
  const f = await fixture(t); const sink = await f.start(); sink.write(record); await sink.flush();
  assert.equal(f.errors(), 0);
  // Writes close their file handles; maintenance validates the remembered directory
  // identity and appendable segment, not a persistent open handle.
  const before = await contents(f.directory);
  const moved = `${f.directory}-moved`;
  await fs.rename(f.directory, moved); await fs.mkdir(f.directory, { mode: 0o700 });
  t.after(() => fs.rm(moved, { recursive: true, force: true }));
  await sink.sweep(); assert.equal(f.errors(), 1);
  sink.write(record); await sink.flush();
  assert.deepEqual(await fs.readdir(f.directory), []);
  assert.deepEqual(await contents(moved), before);
  await fs.rmdir(f.directory); await fs.rename(moved, f.directory);
  sink.write({ ...record, durationMs: 2 }); await sink.flush();
  assert.deepEqual((await contents(f.directory)).flatMap((file) => file.text.trim().split("\n").map(JSON.parse)),
    [{ event: "destination.tunnel.closed", ...record },
      { event: "destination.tunnel.closed", ...record, durationMs: 2 }]);
  assert.equal(f.errors(), 1);
});

test("restart seals an incomplete existing segment without corrupting the next record", async (t) => {
  const f = await fixture(t);
  const name = "destination-30000000-1.jsonl";
  await fs.writeFile(join(f.directory, name), '{"event":', { mode: 0o600 });
  const sink = await f.start(); sink.write(record); await sink.flush();
  const files = await contents(f.directory);
  assert.equal(files.length, 2); assert.equal(files[0].text, '{"event":');
  assert.deepEqual(JSON.parse(files[1].text), { event: "destination.tunnel.closed", ...record });
});

test("clock preparation failure and close-reason getters remain isolated", async (t) => {
  const f = await fixture(t);
  let failClock = false; let errors = 0;
  const sink = await makeDestinationLog({ env: f.env, now() { if (failClock) throw Error("clock failure"); return clock; }, onError() { errors++; throw Error("callback failure"); } });
  t.after(() => sink.close());
  failClock = true; assert.doesNotThrow(() => sink.write(record)); failClock = false;
  let reads = 0;
  sink.write({ ...record, get closeReason() { if (++reads === 1) return "peer-close"; return { toJSON() { throw Error("unexpected object"); } }; } });
  await sink.flush(); assert.equal(reads, 1); assert.equal(errors, 1);
  assert.equal(JSON.parse((await contents(f.directory))[0].text).closeReason, "peer-close");
});

test("closed sweeps are no-ops", async (t) => {
  const f = await fixture(t); const sink = await f.start(); await sink.close(); await sink.sweep(); assert.equal(f.errors(), 0);
});
