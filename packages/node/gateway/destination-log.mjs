// Independent local-only destination log. Never use the general logger/telemetry transport.
import { constants } from "node:fs";
import { lstat, open, readdir, unlink } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";

const MINUTE = 60 * 1000;
const FILE = /^destination-(\d+)-(\d+)\.jsonl$/;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PENDING = 256;
const REASONS = new Set(["idle-timeout", "payload-limit", "upstream-error", "peer-close"]);

function retentionMs(value) {
  if (value === "forever") return Infinity;
  const match = /^([1-9]\d*)([mhd])$/.exec(value);
  const ms = match && Number(match[1]) * { m: MINUTE, h: 60 * MINUTE, d: 24 * 60 * MINUTE }[match[2]];
  if (!Number.isSafeInteger(ms) || ms <= 0) throw new Error("destination log retention must be a positive integer with m/h/d, or forever");
  return ms;
}
function safeFile(stat) {
  // Refuse links and shared files rather than following an attacker-controlled sink.
  if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o600) {
    throw new Error("unsafe destination log file");
  }
}
function safeDirectory(stat) {
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o7777) !== 0o700) {
    throw new Error("destination log directory must be owned by the service uid with mode 0700");
  }
}

export async function makeDestinationLog({ env = process.env, now = Date.now, onError = () => {} } = {}) {
  if (env.SHADE_TREE_DESTINATION_LOG !== "1") return null;
  const age = retentionMs(env.SHADE_TREE_DESTINATION_LOG_RETENTION ?? "7d");
  const capValue = env.SHADE_TREE_DESTINATION_LOG_MAX_BYTES ?? "50331648";
  const maxBytes = Number(capValue);
  if (!/^[1-9]\d*$/.test(capValue) || !Number.isSafeInteger(maxBytes)) {
    throw new Error("destination log max bytes must be a positive safe integer");
  }
  const directory = env.SHADE_TREE_DESTINATION_LOG_DIR;
  // Require an unambiguous final component: trailing slash/dot can make lstat follow a link.
  // Pre-provision a dedicated directory; never fall back to stdout or a shared sink.
  if (typeof directory !== "string" || !isAbsolute(directory) || directory === "/" || resolve(directory) !== directory) {
    throw new Error("destination log requires an absolute private directory with canonical path spelling");
  }
  const stat = await lstat(directory);
  safeDirectory(stat);
  const files = new Map();
  let total = 0;
  let sequence = 0;
  let needsScan = false;
  const bucket = () => Math.floor(now() / MINUTE);
  const expired = (stamp) => (stamp + 1) * MINUTE <= now() - age;
  const oldest = () => [...files.values()].sort((a, b) => a.stamp - b.stamp || a.sequence - b.sequence);
  const remove = async (entry) => {
    try { await unlink(join(directory, entry.name)); } catch (error) { if (error.code !== "ENOENT") throw error; }
    files.delete(entry.name);
    total -= entry.size;
  };
  const scan = async () => {
    const current = await lstat(directory);
    safeDirectory(current);
    if (current.dev !== stat.dev || current.ino !== stat.ino) throw new Error("destination log directory changed externally");
    const scanned = new Map();
    let scannedTotal = 0;
    let scannedSequence = sequence;
    for (const name of await readdir(directory)) {
      const match = FILE.exec(name);
      if (!match) continue;
      const stamp = Number(match[1]);
      const seq = Number(match[2]);
      if (!Number.isSafeInteger(stamp) || !Number.isSafeInteger(seq)) throw new Error("unsafe destination log filename");
      const st = await lstat(join(directory, name));
      safeFile(st);
      const previous = files.get(name);
      // Only reuse a complete segment written by this instance. Restart/crash tails and
      // externally changed files stay sealed without reading their contents on the hot path.
      const appendable = previous?.appendable === true && previous.size === st.size
        && previous.dev === st.dev && previous.ino === st.ino;
      scanned.set(name, { name, stamp, sequence: seq, size: st.size, dev: st.dev, ino: st.ino, appendable });
      scannedSequence = Math.max(scannedSequence, seq);
      scannedTotal += st.size;
    }
    // Keep the previous accounting and sequence intact if validation fails mid-scan.
    files.clear();
    for (const [name, entry] of scanned) files.set(name, entry);
    total = scannedTotal;
    sequence = scannedSequence;
    needsScan = false;
  };
  const prune = async () => {
    await scan();
    for (const entry of oldest()) {
      if (expired(entry.stamp) || total > maxBytes) await remove(entry);
    }
  };
  // Startup validates existing files and enforces both bounds before accepting records.
  await prune();
  let tail = Promise.resolve();
  let pending = 0;
  let warned = false;
  let closed = false;
  let sweeping = false;
  const report = () => {
    if (!warned) { warned = true; try { onError(); } catch { /* no effect on relay */ } }
  };
  const enqueue = (task) => {
    if (closed || pending >= MAX_PENDING) { report(); return false; }
    pending += 1;
    tail = tail.then(task).catch(() => { needsScan = true; report(); }).finally(() => { pending -= 1; });
    return true;
  };
  return {
    // Called by the gateway's existing epoch sweep, not a timer or per-request prune.
    // Coalescing prevents slow storage from accumulating maintenance work.
    sweep() {
      if (closed) return tail;
      if (!sweeping) {
        sweeping = true;
        if (!enqueue(async () => { try { await prune(); } finally { sweeping = false; } })) sweeping = false;
      }
      return tail;
    },
    write(record) {
      if (closed || pending >= MAX_PENDING) { report(); return; }
      let line, bytes, stamp;
      try {
        // Snapshot a closed primitive-only allowlist; never invoke field toJSON methods.
        const closeReason = record.closeReason;
        const metadata = {
          event: "destination.tunnel.closed",
          host: record.host,
          ip: record.ip,
          port: record.port,
          openedAt: record.openedAt,
          durationMs: record.durationMs,
          agentToDestinationBytes: record.agentToDestinationBytes,
          destinationToAgentBytes: record.destinationToAgentBytes,
          closeReason: REASONS.has(closeReason) ? closeReason : "peer-close",
        };
        for (const key of ["host", "ip", "openedAt"]) {
          if (typeof metadata[key] !== "string") throw new Error("invalid destination log metadata");
        }
        for (const key of ["port", "durationMs", "agentToDestinationBytes", "destinationToAgentBytes"]) {
          if (typeof metadata[key] !== "number" || !Number.isFinite(metadata[key]) || metadata[key] < 0) {
            throw new Error("invalid destination log metadata");
          }
        }
        line = JSON.stringify(metadata) + "\n";
        bytes = Buffer.byteLength(line);
        stamp = bucket();
        if (!Number.isSafeInteger(stamp) || stamp < 0) throw new Error("invalid destination log clock");
      } catch { report(); return; }
      enqueue(async () => {
        // A queued record that ages out cannot recreate an expired file.
        if (expired(stamp)) return;
        if (bytes > Math.min(MAX_FILE_BYTES, maxBytes)) { report(); return; }
        // Only failures trigger an extra scan; healthy closes retain incremental accounting.
        if (needsScan) await scan();
        // Evict before append, even in forever mode; disk usage never exceeds the global cap.
        for (const entry of oldest()) {
          if (total + bytes <= maxBytes) break;
          await remove(entry);
        }
        // Never backfill a smaller record into an older, already-rotated segment.
        let entry = oldest().reverse().find((f) => f.stamp === stamp);
        if (entry && (!entry.appendable || entry.size + bytes > MAX_FILE_BYTES)) entry = undefined;
        const fresh = !entry;
        if (fresh) {
          const seq = sequence + 1;
          if (!Number.isSafeInteger(seq)) throw new Error("destination log sequence exhausted");
          sequence = seq;
          entry = { name: `destination-${stamp}-${seq}.jsonl`, stamp, sequence: seq, size: 0, appendable: false };
        }
        let file;
        try {
          file = await open(join(directory, entry.name),
            constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW | constants.O_NONBLOCK
              | (fresh ? constants.O_CREAT | constants.O_EXCL : 0), 0o600);
          const st = await file.stat();
          safeFile(st);
          // Only this process may write the private directory. Refuse unexpected mutation.
          if (st.size !== entry.size || (!fresh && (st.dev !== entry.dev || st.ino !== entry.ino))) {
            throw new Error("destination log file changed externally");
          }
          if (fresh) {
            entry.dev = st.dev; entry.ino = st.ino;
            files.set(entry.name, entry);
          }
          try {
            try { await file.writeFile(line); } catch (error) {
              // Restore the last complete JSONL boundary. If rollback fails, leave this
              // segment sealed and rescan before any further byte-cap decision.
              await file.truncate(entry.size);
              throw error;
            }
          } finally {
            const actual = (await file.stat()).size;
            total += actual - entry.size;
            entry.size = actual;
          }
          entry.appendable = true;
        } catch (error) {
          entry.appendable = false;
          throw error;
        } finally { if (file) await file.close(); }
      });
    },
    async flush() { await tail; },
    async close() { closed = true; await tail; },
  };
}
