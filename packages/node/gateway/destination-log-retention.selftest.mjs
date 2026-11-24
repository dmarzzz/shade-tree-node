import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeDestinationLog } from "./destination-log.mjs";

const MINUTE = 60000;
const root = await mkdtemp(join(tmpdir(), "destination-retention-"));
const record = { host: "example.invalid", ip: "192.0.2.1", port: 443, openedAt: "2026-01-01T00:00:00.000Z",
  durationMs: 1, agentToDestinationBytes: 12, destinationToAgentBytes: 24, closeReason: "peer-close" };
const sinks = [];
let next = 0;
async function fixture(options = {}) {
  const directory = join(root, String(next++));
  await mkdir(directory, { mode: 0o700 });
  const env = { SHADE_TREE_DESTINATION_LOG: "1", SHADE_TREE_DESTINATION_LOG_DIR: directory, ...options };
  let clock = 30000000 * MINUTE;
  let errors = 0;
  const start = async ({ onError = () => {} } = {}) => {
    const sink = await makeDestinationLog({ env, now: () => clock, onError: () => { errors++; onError(); } });
    sinks.push(sink);
    return sink;
  };
  return { directory, env, start, advance: (ms) => { clock += ms; }, clock: () => clock, errors: () => errors };
}
async function usage(directory) {
  let bytes = 0;
  for (const name of await readdir(directory)) bytes += (await stat(join(directory, name))).size;
  return bytes;
}
let failed = false;
try {
  // Disabled means no validation or filesystem work, even with invalid other knobs.
  const disabled = join(root, "disabled");
  for (const flag of [undefined, "0"]) {
    assert.equal(await makeDestinationLog({ env: { SHADE_TREE_DESTINATION_LOG: flag,
      SHADE_TREE_DESTINATION_LOG_DIR: disabled, SHADE_TREE_DESTINATION_LOG_RETENTION: "bad",
      SHADE_TREE_DESTINATION_LOG_MAX_BYTES: "bad" } }), null);
  }
  await assert.rejects(stat(disabled), { code: "ENOENT" });
  const invalid = await fixture();
  for (const value of ["", "0", "0m", "-1h", "1.5d", "30", "1s", "7D", "forever ", "Infinity", "9999999999999999d"]) {
    await assert.rejects(makeDestinationLog({ env: { ...invalid.env, SHADE_TREE_DESTINATION_LOG_RETENTION: value } }), /retention/);
  }
  for (const value of ["", "0", "-1", "1.5", "1e6", "Infinity", "9007199254740992", " 10"]) {
    await assert.rejects(makeDestinationLog({ env: { ...invalid.env, SHADE_TREE_DESTINATION_LOG_MAX_BYTES: value } }), /max bytes/);
  }
  await assert.rejects(makeDestinationLog({ env: { ...invalid.env, SHADE_TREE_DESTINATION_LOG_DIR: "relative" } }), /absolute/);
  await assert.rejects(makeDestinationLog({ env: { SHADE_TREE_DESTINATION_LOG: "1" } }), /absolute/);

  // Minute bucket end is the expiry boundary. No early deletion; less than a minute
  // of bucket rounding; manual idle sweeps exercise the maintenance entry point.
  for (const [setting, minutes] of [[undefined, 7 * 24 * 60], ["30m", 30], ["6h", 360], ["1m", 1], ["2d", 2880]]) {
    const f = await fixture(setting ? { SHADE_TREE_DESTINATION_LOG_RETENTION: setting } : {});
    const sink = await f.start();
    f.advance(12345);
    sink.write(record);
    await sink.flush();
    f.advance(minutes * MINUTE - 12346);
    await sink.sweep();
    assert.equal((await readdir(f.directory)).length, 1, `${setting ?? "7d default"}: not deleted early`);
    f.advance(MINUTE);
    await sink.sweep();
    assert.equal((await readdir(f.directory)).length, 1, "one ms before bucket end plus retention");
    f.advance(1);
    const sweep = sink.sweep();
    assert.equal(sink.sweep(), sweep, "maintenance coalesces while queued");
    await sweep;
    assert.deepEqual(await readdir(f.directory), [], "idle sweep prunes without a new tunnel");
    assert.equal(f.errors(), 0);
  }

  // Size eviction is oldest-first across all minute files, and forever disables age only.
  const sizing = await fixture({ SHADE_TREE_DESTINATION_LOG_RETENTION: "forever" });
  let sink = await sizing.start();
  sink.write(record);
  await sink.flush();
  const lineBytes = await usage(sizing.directory);
  await sink.close();
  sizing.env.SHADE_TREE_DESTINATION_LOG_MAX_BYTES = String(lineBytes * 2);
  sink = await sizing.start();
  const first = (await readdir(sizing.directory))[0];
  sizing.advance(MINUTE);
  sink.write(record);
  await sink.flush();
  const second = (await readdir(sizing.directory)).find((name) => name !== first);
  sizing.advance(MINUTE);
  sink.write(record);
  await sink.flush();
  assert.equal(await usage(sizing.directory), lineBytes * 2);
  assert.ok(!(await readdir(sizing.directory)).includes(first), "oldest removed, not newest");
  assert.ok((await readdir(sizing.directory)).includes(second));
  sizing.advance(5000 * 24 * 60 * MINUTE);
  await sink.sweep();
  assert.equal(await usage(sizing.directory), lineBytes * 2, "forever retains old records under cap");
  await sink.close();
  sizing.env.SHADE_TREE_DESTINATION_LOG_MAX_BYTES = String(lineBytes);
  sink = await sizing.start();
  assert.equal(await usage(sizing.directory), lineBytes, "startup enforces reduced global cap");
  assert.ok(!(await readdir(sizing.directory)).includes(second));
  for (let i = 0; i < 10; i++) sink.write({ ...record, durationMs: i });
  await sink.flush();
  assert.equal(await usage(sizing.directory), lineBytes, "same-minute rollover evicts rather than stops recording");
  assert.equal(sizing.errors(), 0);
  const survivors = await readdir(sizing.directory);
  assert.equal(survivors.length, 1);
  assert.equal(JSON.parse(await readFile(join(sizing.directory, survivors[0]), "utf8")).durationMs, 9);

  // Eight-MiB segments rotate even within one minute. Existing sizes are recovered on restart.
  const rotation = await fixture({ SHADE_TREE_DESTINATION_LOG_RETENTION: "forever" });
  const large = `destination-${Math.floor(rotation.clock() / MINUTE)}-1.jsonl`;
  await writeFile(join(rotation.directory, large), "", { mode: 0o600 });
  await truncate(join(rotation.directory, large), 8 * 1024 * 1024);
  sink = await rotation.start();
  sink.write(record);
  await sink.flush();
  assert.equal((await readdir(rotation.directory)).length, 2);
  assert.equal((await stat(join(rotation.directory, large))).size, 8 * 1024 * 1024);
  assert.equal(await usage(rotation.directory), 8 * 1024 * 1024 + lineBytes);

  const tiny = await fixture({ SHADE_TREE_DESTINATION_LOG_MAX_BYTES: "1" });
  sink = await tiny.start();
  sink.write(record);
  await sink.flush();
  assert.deepEqual(await readdir(tiny.directory), [], "oversize record dropped, no empty file");
  assert.equal(tiny.errors(), 1);

  const throwing = await fixture({ SHADE_TREE_DESTINATION_LOG_MAX_BYTES: "1" });
  sink = await throwing.start({ onError() { throw new Error("callback unavailable"); } });
  sink.write(record);
  await sink.flush();
  await sink.sweep();
  await sink.close();
  assert.equal(throwing.errors(), 1, "throwing error callback is invoked and isolated");
  assert.deepEqual(await readdir(throwing.directory), []);

  const startup = await fixture({ SHADE_TREE_DESTINATION_LOG_RETENTION: "30m" });
  sink = await startup.start();
  sink.write(record);
  await sink.flush();
  await sink.close();
  startup.advance(31 * MINUTE);
  await startup.start();
  assert.deepEqual(await readdir(startup.directory), [], "restart removes expired records");

  // Queued records cannot resurrect expired buckets. Queue overflow and error callbacks
  // cannot reject maintenance promises or become an unbounded backlog.
  const queued = await fixture({ SHADE_TREE_DESTINATION_LOG_RETENTION: "1m" });
  sink = await queued.start();
  for (let i = 0; i < 300; i++) sink.write(record);
  queued.advance(2 * MINUTE);
  await sink.flush();
  assert.deepEqual(await readdir(queued.directory), []);
  assert.equal(queued.errors(), 1);
  await sink.sweep();
  sink.write(record);
  await sink.flush();
  assert.equal((await readdir(queued.directory)).length, 1, "queue recovers after overload");
  await sink.close();
  const closedFiles = await readdir(queued.directory);
  const closedContents = await Promise.all(closedFiles.map((name) => readFile(join(queued.directory, name), "utf8")));
  queued.advance(MINUTE);
  sink.write({ ...record, durationMs: 999 });
  await sink.flush();
  assert.deepEqual(await readdir(queued.directory), closedFiles, "closed sink cannot create files");
  assert.deepEqual(await Promise.all(closedFiles.map((name) => readFile(join(queued.directory, name), "utf8"))),
    closedContents, "closed sink cannot append records");

  const outside = join(root, "unrelated");
  await writeFile(outside, "unchanged", { mode: 0o600 });
  for (const kind of ["symlink", "hardlink", "mode", "directory"]) {
    const unsafe = await fixture();
    const target = join(unsafe.directory, `destination-${Math.floor(unsafe.clock() / MINUTE)}-1.jsonl`);
    if (kind === "symlink") await symlink(outside, target);
    if (kind === "hardlink") await link(outside, target);
    if (kind === "mode") { await writeFile(target, ""); await chmod(target, 0o644); }
    if (kind === "directory") await mkdir(target);
    await assert.rejects(unsafe.start(), /unsafe destination log file/, kind);
    await rm(target, { recursive: true });
  }
  assert.equal(await readFile(outside, "utf8"), "unchanged");
  const linked = join(root, "linked-directory");
  await symlink(invalid.directory, linked);
  await assert.rejects(makeDestinationLog({ env: { ...invalid.env, SHADE_TREE_DESTINATION_LOG_DIR: linked } }), /0700/);

  await chmod(invalid.directory, 0o755);
  await assert.rejects(makeDestinationLog({ env: invalid.env }), /0700/);

  const failure = await fixture({ SHADE_TREE_DESTINATION_LOG_RETENTION: "1m" });
  sink = await failure.start();
  sink.write(record);
  await sink.flush();
  const target = join(failure.directory, (await readdir(failure.directory))[0]);
  await chmod(target, 0o644);
  sink.write(record);
  await sink.flush();
  assert.equal((await stat(target)).size, lineBytes, "unsafe file is not appended");
  failure.advance(2 * MINUTE);
  await sink.sweep();
  assert.equal((await stat(target)).size, lineBytes, "expired unsafe file is not deleted");
  assert.equal(failure.errors(), 1, "unsafe post-start file failure warns once");
  const io = await fixture();
  sink = await io.start();
  assert.equal(io.errors(), 0);
  await rm(io.directory, { recursive: true });
  sink.write(record);
  await sink.flush();
  await sink.sweep();
  assert.equal(io.errors(), 1, "healthy sink reports I/O failure");
  sink.write(record);
  await sink.flush();
  await sink.sweep();
  assert.equal(io.errors(), 1, "repeated I/O failures warn once");
  console.log("PASS: configurable 7d/30m/6h/1m/2d retention, bucket boundaries, manual idle sweeps, forever, oldest-first global cap, rotation, restart, queue bounds and unsafe/I/O isolation");
} catch (error) {
  failed = true;
  throw error;
} finally {
  const cleanup = await Promise.allSettled(sinks.map((sink) => sink.close()));
  await rm(root, { recursive: true, force: true });
  if (!failed) for (const result of cleanup) assert.equal(result.status, "fulfilled", String(result.reason));
}
