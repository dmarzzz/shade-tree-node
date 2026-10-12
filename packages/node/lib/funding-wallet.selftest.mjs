import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EXIT_NOT_FUNDED,
  QUOTE_MIN_FEE_PER_GAS,
  REGISTER_GAS_CEILING,
  SEND_GRANULARITY_WEI,
  chainLabel,
  defaultFundingKeyPath,
  formatEth,
  loadOrCreateFundingWallet,
  quoteFunding,
  roundUpToSend,
  waitForFunding,
} from "./funding-wallet.mjs";

const BOND = 10n ** 16n; // 0.01 ETH
const GWEI = 1_000_000_000n;

// ---- quote arithmetic
{
  const q = quoteFunding({ bond: BOND, maxFeePerGas: 3n * GWEI, balance: 0n, chainId: 11155111 });
  assert.equal(q.gasReserve, REGISTER_GAS_CEILING * 3n * GWEI);
  assert.equal(q.required, BOND + q.gasReserve);
  assert.equal(q.shortfall, q.required);
  assert.equal(q.funded, false);
  assert.equal(q.chainId, 11155111);

  const idle = quoteFunding({ bond: BOND, maxFeePerGas: 3n, balance: "0", chainId: "11155111" });
  assert.equal(idle.gasReserve, REGISTER_GAS_CEILING * QUOTE_MIN_FEE_PER_GAS, "a 3 wei fee is priced at the 1 gwei floor");
  assert.equal(formatEth(idle.required, 11155111), "0.0118 Sepolia ETH");

  const funded = quoteFunding({ bond: BOND, maxFeePerGas: GWEI, balance: idle.required, chainId: 1 });
  assert.equal(funded.funded, true);
  assert.equal(funded.shortfall, 0n);
  const over = quoteFunding({ bond: BOND, maxFeePerGas: GWEI, balance: idle.required + 1n, chainId: 1 });
  assert.equal(over.funded, true);

  assert.throws(() => quoteFunding({ bond: 0n, maxFeePerGas: GWEI, balance: 0n, chainId: 1 }), /not admitted/);
  assert.throws(() => quoteFunding({ bond: "lots", maxFeePerGas: GWEI, balance: 0n, chainId: 1 }), /bond is not/);
  assert.throws(() => quoteFunding({ bond: BOND, maxFeePerGas: -1n, balance: 0n, chainId: 1 }), /maxFeePerGas/);
  assert.throws(() => quoteFunding({ bond: BOND, maxFeePerGas: GWEI, balance: null, chainId: 1 }), /balance/);
}

// ---- rounding and formatting
{
  assert.equal(roundUpToSend(0n), 0n);
  assert.equal(roundUpToSend(1n), SEND_GRANULARITY_WEI);
  assert.equal(roundUpToSend(SEND_GRANULARITY_WEI), SEND_GRANULARITY_WEI);
  assert.equal(roundUpToSend(14_800_000_000_000_000n), 14_800_000_000_000_000n);
  assert.equal(roundUpToSend(14_800_000_000_000_001n), 14_900_000_000_000_000n);
  assert.throws(() => roundUpToSend("x"), /amount/);
  assert.equal(formatEth(10n ** 18n, 1), "1 ETH");
  assert.equal(formatEth(1n, 1), "0.000000000000000001 ETH");
  assert.equal(formatEth(0n, 11155111), "0 Sepolia ETH");
  assert.equal(formatEth(1_600_000_000_000_000n, 11155111), "0.0016 Sepolia ETH");
  assert.equal(chainLabel(11155111), "Sepolia");
  assert.equal(chainLabel(42), "this chain");
}

// ---- key file: created once, owner-only, reused, never overwritten, hostile files refused
{
  const dir = mkdtempSync(join(tmpdir(), "shade-tree-funding-"));
  try {
    const path = join(dir, "nested", "funding.key");
    const first = loadOrCreateFundingWallet(path);
    assert.equal(first.created, true);
    assert.match(first.key, /^0x[0-9a-f]{64}$/);
    assert.equal(readFileSync(path, "utf8"), `${first.key}\n`);
    if (process.platform !== "win32") assert.equal(statSync(path).mode & 0o777, 0o600);
    const again = loadOrCreateFundingWallet(path, { generate: () => { throw new Error("must not generate when the file exists"); } });
    assert.equal(again.created, false);
    assert.equal(again.key, first.key);

    const bad = join(dir, "bad.key");
    writeFileSync(bad, "not a key\n", { mode: 0o600 });
    assert.throws(() => loadOrCreateFundingWallet(bad), (e) => /not a 32-byte hex/.test(e.message) && !e.message.includes("not a key"));
    writeFileSync(bad, `0x${"ab".repeat(32)}\n`, { mode: 0o600 });
    if (process.platform !== "win32") {
      chmodSync(bad, 0o644);
      assert.throws(() => loadOrCreateFundingWallet(bad), /chmod 600/);
    }
    assert.throws(() => loadOrCreateFundingWallet(dir), /not a file/);
    // The key path is taken by a directory: the create fails with a plain "write" error, the
    // directory is left alone, and no stray file appears.
    const taken = join(dir, "taken.key");
    mkdirSync(taken);
    assert.throws(() => loadOrCreateFundingWallet(taken, { generate: () => `0x${"cd".repeat(32)}` }), /not a file/);
    const underTaken = join(taken, "deeper", "k.key");
    writeFileSync(join(taken, "deeper"), "a file where a directory is needed");
    assert.throws(() => loadOrCreateFundingWallet(underTaken, { generate: () => `0x${"cd".repeat(32)}` }), /ENOTDIR|write|mkdir/);
    assert.equal(statSync(join(taken, "deeper")).isFile(), true);
    // default location follows XDG, then HOME
    assert.equal(defaultFundingKeyPath({ XDG_CONFIG_HOME: "/x" }), join("/x", "shade-tree", "funding.key"));
    assert.equal(defaultFundingKeyPath({ HOME: "/home/h" }), join("/home/h", ".config", "shade-tree", "funding.key"));
    assert.throws(() => loadOrCreateFundingWallet(join(dir, "short.key"), { generate: () => "0x1234" }), /wrong shape/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---- wait loop: reports once, follows partial payments, retries rpc errors, exits 4 at the deadline
{
  let t = 0;
  const now = () => t;
  const sleep = async (ms) => { t += ms; };
  const events = [];
  const report = (e) => events.push(e.kind + (e.send !== undefined ? `:${e.send}` : ""));
  const balances = [0n, 0n, 5n * 10n ** 15n, "boom", 11_800_000_000_000_000n];
  const getQuote = async () => {
    const b = balances.shift();
    if (b === "boom") throw new Error("rpc down");
    return quoteFunding({ bond: BOND, maxFeePerGas: GWEI, balance: b, chainId: 11155111 });
  };
  const quote = await waitForFunding({ getQuote, timeoutMs: 60_000, pollMs: 10_000, now, sleep, report });
  assert.equal(quote.funded, true);
  assert.deepEqual(events, [
    "quote",
    "progress:11800000000000000",
    "progress:6800000000000000",
    "rpc-error",
    "funded",
  ]);

  // already staked: null, no quote printed
  const none = await waitForFunding({ getQuote: async () => null, timeoutMs: 1, now, sleep, report: () => assert.fail("no report for a staked leaf") });
  assert.equal(none, null);

  // deadline: exit code 4 carries the shortfall
  t = 0;
  await assert.rejects(
    waitForFunding({ getQuote: async () => quoteFunding({ bond: BOND, maxFeePerGas: GWEI, balance: 0n, chainId: 11155111 }), timeoutMs: 0, pollMs: 1, now, sleep }),
    (e) => e.code === EXIT_NOT_FUNDED && /0.0118 Sepolia ETH short/.test(e.message),
  );

  // the first quote failing is not retried
  await assert.rejects(waitForFunding({ getQuote: async () => { throw new Error("wrong chain"); }, timeoutMs: 60_000, now, sleep }), /wrong chain/);
}

console.log("PASS: funding-wallet selftest");
