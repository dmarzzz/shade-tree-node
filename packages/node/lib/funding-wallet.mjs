// funding-wallet: the keyless funding path of `shade-tree register-member`, the way the Rust
// client's `shadenet register-member` does it (crates/shadenet/src/member.rs `funding_quote`).
// When no funding key is given on a remote RPC, the command pays from a wallet of its own: an
// owner-only key file it creates once, whose address and required amount it prints, waiting for
// the balance to cover the tier's bond plus a gas reserve before it stakes.
//
// This module holds the pure parts (quote arithmetic, rounding, formatting, the key file, the
// wait loop with injectable clock/sleep) so they are testable without a chain; the CLI in
// group/register-onchain.mjs wires them to ethers.

import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

/// Gas reserved for registerIdentity when quoting a wallet that cannot be estimated against
/// (an unfunded sender). Live registrations used 1 317 674 and 1 471 267 gas (docs/ECONOMICS.md,
/// CHANGELOG.md); the signer later uses the real estimate plus 20 % (about 1.77M), and this
/// ceiling covers that.
export const REGISTER_GAS_CEILING = 1_800_000n;
/// The least fee per gas a quote prices at: 1 gwei. Sepolia idles at a few wei and then spends a
/// week near 1 gwei; a wallet funded at the idle price would be short once the ETH arrived.
export const QUOTE_MIN_FEE_PER_GAS = 1_000_000_000n;
/// The amount to send is rounded up to 0.0001 ETH so it reads and types well.
export const SEND_GRANULARITY_WEI = 100_000_000_000_000n;
export const DEFAULT_FUNDING_POLL_MS = 15_000;
export const DEFAULT_WAIT_TIMEOUT_SECS = 3600;
/// Exit code when the wallet was not funded within the deadline.
export const EXIT_NOT_FUNDED = 4;

const KEY_RE = /^0x[0-9a-fA-F]{64}$/;

/// Where the funding wallet lives by default: the user's shade-tree config directory, so the same
/// wallet is found from any working directory (`$XDG_CONFIG_HOME/shade-tree/funding.key`,
/// `%APPDATA%\shade-tree\funding.key` on Windows, else `~/.config/shade-tree/funding.key`).
export function defaultFundingKeyPath(env = process.env) {
  if (env.XDG_CONFIG_HOME) return join(env.XDG_CONFIG_HOME, "shade-tree", "funding.key");
  if (process.platform === "win32" && env.APPDATA) return join(env.APPDATA, "shade-tree", "funding.key");
  return join(env.HOME || homedir(), ".config", "shade-tree", "funding.key");
}

function toBigInt(value, label) {
  try {
    const out = BigInt(value);
    if (out < 0n) throw new Error("negative");
    return out;
  } catch {
    throw new Error(`${label} is not a non-negative integer`);
  }
}

/// bond + REGISTER_GAS_CEILING * max(maxFeePerGas, QUOTE_MIN_FEE_PER_GAS), against `balance`.
export function quoteFunding({ bond, maxFeePerGas, balance, chainId }) {
  const bondWei = toBigInt(bond, "bond");
  if (bondWei === 0n) throw new Error("bond is zero; the tier is not admitted");
  const fee = toBigInt(maxFeePerGas, "maxFeePerGas");
  const held = toBigInt(balance, "balance");
  const priced = fee > QUOTE_MIN_FEE_PER_GAS ? fee : QUOTE_MIN_FEE_PER_GAS;
  const gasReserve = REGISTER_GAS_CEILING * priced;
  const required = bondWei + gasReserve;
  const shortfall = held >= required ? 0n : required - held;
  return { chainId: Number(chainId), bond: bondWei, gasReserve, required, balance: held, shortfall, funded: shortfall === 0n };
}

/// `wei` rounded up to the next multiple of SEND_GRANULARITY_WEI.
export function roundUpToSend(wei) {
  const value = toBigInt(wei, "amount");
  return ((value + SEND_GRANULARITY_WEI - 1n) / SEND_GRANULARITY_WEI) * SEND_GRANULARITY_WEI;
}

/// `0.0116 Sepolia ETH`: trailing zeros trimmed, the chain's ether named.
export function formatEth(wei, chainId) {
  const value = toBigInt(wei, "amount");
  const whole = value / 10n ** 18n;
  const frac = (value % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  const unit = Number(chainId) === 11155111 ? "Sepolia ETH" : "ETH";
  return `${whole}${frac ? `.${frac}` : ""} ${unit}`;
}

export function chainLabel(chainId) {
  switch (Number(chainId)) {
    case 1: return "Ethereum mainnet";
    case 11155111: return "Sepolia";
    case 17000: return "Holesky";
    default: return "this chain";
  }
}

/// Read an existing owner-only key file (refusing one readable by group/others on Unix), or
/// create it with a fresh 32-byte key. Returns `{ key, created }`; the key is never logged by
/// callers, only its address.
export function loadOrCreateFundingWallet(path, { generate = defaultGenerate } = {}) {
  let stat = null;
  try { stat = statSync(path); } catch (e) { if (e.code !== "ENOENT") throw new Error(`funding wallet ${path}: ${e.message}`); }
  if (stat) {
    if (!stat.isFile()) throw new Error(`funding wallet ${path} is not a file`);
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
      throw new Error(`funding wallet ${path} must be owner-only (chmod 600; current mode ${(stat.mode & 0o777).toString(8)})`);
    }
    const key = readFileSync(path, "utf8").trim();
    if (!KEY_RE.test(key)) throw new Error(`funding wallet ${path} is not a 32-byte hex private key (value not shown)`);
    return { key, created: false };
  }
  const key = generate();
  if (!KEY_RE.test(key)) throw new Error("generated funding key has the wrong shape (value not shown)");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  // `wx`: never overwrite a key that appeared in the meantime. A write that fails midway
  // (disk full) must not leave a truncated file that every later run refuses as malformed.
  try {
    writeFileSync(path, `${key}\n`, { flag: "wx", mode: 0o600 });
  } catch (e) {
    if (e.code !== "EEXIST") { try { rmSync(path, { force: true }); } catch { /* nothing to clean */ } }
    throw new Error(`write ${path}: ${e.message}`);
  }
  return { key, created: true };
}

function defaultGenerate() {
  return `0x${randomBytes(32).toString("hex")}`;
}

/// Poll `getQuote()` (→ `null` when the leaf is already staked, else a quoteFunding() result)
/// until it is funded or `timeoutMs` passes. `report(event)` receives `{ kind: "quote" | "progress" | "funded" | "rpc-error", ... }`.
/// Resolves to the funded quote, `null` for an already-staked leaf, and throws `{ code: EXIT_NOT_FUNDED }`
/// with the shortfall at the deadline. An RPC error after the first quote is retried on the next poll.
export async function waitForFunding({ getQuote, timeoutMs, pollMs = DEFAULT_FUNDING_POLL_MS, now = Date.now, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), report = () => {} }) {
  const started = now();
  let last = null;
  for (;;) {
    let quote;
    try {
      quote = await getQuote();
    } catch (e) {
      if (last && now() - started < timeoutMs) {
        report({ kind: "rpc-error", error: e, pollMs });
        await sleep(pollMs);
        continue;
      }
      throw e;
    }
    if (quote === null) return null;
    if (!last) report({ kind: "quote", quote, pollMs, timeoutMs });
    if (quote.funded) {
      report({ kind: "funded", quote });
      return quote;
    }
    const mark = `${quote.balance}/${quote.shortfall}`;
    if (last !== mark) {
      report({ kind: "progress", quote, first: last === null, send: roundUpToSend(quote.shortfall) });
      last = mark;
    }
    if (now() - started >= timeoutMs) {
      const error = new Error(`funding wallet holds ${formatEth(quote.balance, quote.chainId)}, ${formatEth(quote.shortfall, quote.chainId)} short of the ${formatEth(quote.required, quote.chainId)} this registration needs; send the rest and run the same command again`);
      error.code = EXIT_NOT_FUNDED;
      error.quote = quote;
      throw error;
    }
    await sleep(pollMs);
  }
}
