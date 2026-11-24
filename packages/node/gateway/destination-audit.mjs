// Independent local-only destination audit. Never use the general logger/telemetry transport.
import { constants } from "node:fs";
import { lstat, open, readdir, unlink } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

const MINUTE = 60 * 1000;
const FILE = /^destination-(\d+)-(\d+)\.jsonl$/;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_PENDING = 256;
const REASONS = new Set(["idle-timeout", "payload-limit", "upstream-error", "peer-close"]);

function retentionMs(value) {
  if (value === "forever") return Infinity;
  const match = /^([1-9]\d*)([mhd])$/.exec(value);
  const ms = match && Number(match[1]) * { m: MINUTE, h: 60 * MINUTE, d: 24 * 60 * MINUTE }[match[2]];
  if (!Number.isSafeInteger(ms) || ms <= 0) throw new Error("destination audit retention must be a positive integer with m/h/d, or forever");
  return ms;
}
function safeFile(stat) {
  // Refuse links and shared files rather than following an attacker-controlled sink.
  if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600) {
    throw new Error("unsafe destination audit file");
  }
}

export async function makeDestinationAudit({ env = process.env, now = Date.now, onError = () => {} } = {}) {
  if (env.SHADE_TREE_DESTINATION_AUDIT !== "1") return null;
  const age = retentionMs(env.SHADE_TREE_DESTINATION_AUDIT_RETENTION ?? "7d");
  const capValue = env.SHADE_TREE_DESTINATION_AUDIT_MAX_BYTES ?? "50331648";
  const maxBytes = Number(capValue);
  if (!/^[1-9]\d*$/.test(capValue) || !Number.isSafeInteger(maxBytes)) {
    throw new Error("destination audit max bytes must be a positive safe integer");
  }
  const directory = env.SHADE_TREE_DESTINATION_AUDIT_DIR;
  // Pre-provision a dedicated directory; do not silently fall back to stdout or a shared sink.
  if (!directory || !isAbsolute(directory)) throw new Error("destination audit requires an absolute private directory");
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o700) {
    throw new Error("destination audit directory must be owned by the service uid with mode 0700");
  }
  const files = new Map();
  let total = 0;
  let sequence = 0;
  const bucket = () => Math.floor(now() / MINUTE);
  const expired = (stamp) => (stamp + 1) * MINUTE <= now() - age;
  const oldest = () => [...files.values()].sort((a, b) => a.stamp - b.stamp || a.sequence - b.sequence);
  const remove = async (entry) => {
    try { await unlink(join(directory, entry.name)); } catch (error) { if (error.code !== "ENOENT") throw error; }
    files.delete(entry.name);
    total -= entry.size;
  };
  const scan = async () => {
    const scanned = new Map();
    let scannedTotal = 0;
    for (const name of await readdir(directory)) {
      const match = FILE.exec(name);
      if (!match) continue;
      const stamp = Number(match[1]);
      const seq = Number(match[2]);
      if (!Number.isSafeInteger(stamp) || !Number.isSafeInteger(seq)) throw new Error("unsafe destination audit filename");
      const st = await lstat(join(directory, name));
      safeFile(st);
      scanned.set(name, { name, stamp, sequence: seq, size: st.size });
      sequence = Math.max(sequence, seq);
      scannedTotal += st.size;
    }
    // Keep the previous accounting intact if any lstat or validation fails mid-scan.
    files.clear();
    for (const [name, entry] of scanned) files.set(name, entry);
    total = scannedTotal;
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
    tail = tail.then(task).catch(report).finally(() => { pending -= 1; });
    return true;
  };
  return {
    // Called by the gateway's existing epoch sweep, not a timer or per-request prune.
    // Coalescing prevents slow storage from accumulating maintenance work.
    sweep() {
      if (!sweeping) {
        sweeping = true;
        if (!enqueue(async () => { try { await prune(); } finally { sweeping = false; } })) sweeping = false;
      }
      return tail;
    },
    write(record) {
      // Closed allowlist: neither caller objects nor error messages are serialized wholesale.
      const line = JSON.stringify({
        event: "destination.tunnel.closed",
        host: record.host,
        ip: record.ip,
        port: record.port,
        openedAt: record.openedAt,
        durationMs: record.durationMs,
        agentToDestinationBytes: record.agentToDestinationBytes,
        destinationToAgentBytes: record.destinationToAgentBytes,
        closeReason: REASONS.has(record.closeReason) ? record.closeReason : "peer-close",
      }) + "\n";
      const bytes = Buffer.byteLength(line);
      const stamp = bucket();
      enqueue(async () => {
        // A queued record that ages out cannot recreate an expired file.
        if (expired(stamp)) return;
        if (bytes > Math.min(MAX_FILE_BYTES, maxBytes)) { report(); return; }
        // Size enforcement is incremental, not a directory scan or age-prune on every close.
        // Evict before append, even in forever mode; disk usage never exceeds the global cap.
        for (const entry of oldest()) {
          if (total + bytes <= maxBytes) break;
          await remove(entry);
        }
        let entry = oldest().reverse().find((f) => f.stamp === stamp && f.size + bytes <= MAX_FILE_BYTES);
        const fresh = !entry;
        if (fresh) {
          const seq = ++sequence;
          entry = { name: `destination-${stamp}-${seq}.jsonl`, stamp, sequence: seq, size: 0 };
        }
        const file = await open(join(directory, entry.name),
          constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW | constants.O_NONBLOCK
            | (fresh ? constants.O_CREAT | constants.O_EXCL : 0), 0o600);
        try {
          const st = await file.stat();
          safeFile(st);
          // Only this process may write the private directory. Refuse unexpected mutation.
          if (st.size !== entry.size) throw new Error("destination audit file changed externally");
          if (fresh) files.set(entry.name, entry);
          try { await file.writeFile(line); } finally {
            // Account for a partial write even if the filesystem reports an error.
            const actual = (await file.stat()).size;
            total += actual - entry.size;
            entry.size = actual;
          }
        } finally { await file.close(); }
      });
    },
    async flush() { await tail; },
    async close() { closed = true; await tail; },
  };
}
