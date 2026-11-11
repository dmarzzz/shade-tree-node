import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EXIT_NOT_FUNDED,
  FUNDING_PRIVACY,
  GAS_RESERVE_STEP_WEI,
  REGISTER_GAS_CEILING,
  SEND_GRANULARITY_WEI,
  chainLabel,
  defaultFundingKeyPath,
  formatEth,
  leftoverAtBlock,
  loadOrCreateFundingWallet,
  gasReserveFor,
  quoteFunding,
  roundUpToSend,
  waitForFunding,
} from "./funding-wallet.mjs";

const BOND = 10n ** 16n; // 0.01 ETH
const GWEI = 1_000_000_000n;

// ---- quote arithmetic
{
  const q = quoteFunding({ bond: BOND, maxFeePerGas: 3n * GWEI, balance: 0n, chainId: 11155111 });
  // 1.8M gas at 3 gwei is 0.0054 ETH: the 0.008 ETH rung.
  assert.equal(q.gasReserve, 4n * GAS_RESERVE_STEP_WEI);
  assert.equal(q.required, BOND + q.gasReserve);
  assert.equal(q.shortfall, q.required);
  assert.equal(q.funded, false);
  assert.equal(q.chainId, 11155111);

  const idle = quoteFunding({ bond: BOND, maxFeePerGas: 3n, balance: "0", chainId: "11155111" });
  assert.equal(idle.gasReserve, GAS_RESERVE_STEP_WEI, "a 3 wei fee asks for the lowest rung");
  assert.equal(formatEth(idle.required, 11155111), "0.012 Sepolia ETH");

  // The ladder: 0.002, 0.004, 0.008 ... ETH, always covering the ceiling at the fee.
  assert.equal(gasReserveFor(0n), GAS_RESERVE_STEP_WEI);
  assert.equal(gasReserveFor(11n * GWEI / 10n), GAS_RESERVE_STEP_WEI);
  assert.equal(gasReserveFor(12n * GWEI / 10n), 2n * GAS_RESERVE_STEP_WEI);
  assert.equal(gasReserveFor(50n * GWEI), 64n * GAS_RESERVE_STEP_WEI);
  for (const tenths of [1n, 7n, 11n, 12n, 25n, 90n, 333n, 2000n]) {
    const fee = tenths * GWEI / 10n;
    assert.ok(REGISTER_GAS_CEILING * fee <= gasReserveFor(fee));
  }
  assert.match(FUNDING_PRIVACY, /shared pool/);
  assert.match(FUNDING_PRIVACY, /exactly this\namount/);

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
  const balances = [0n, 0n, 5n * 10n ** 15n, "boom", 12_000_000_000_000_000n];
  const getQuote = async () => {
    const b = balances.shift();
    if (b === "boom") throw new Error("rpc down");
    return quoteFunding({ bond: BOND, maxFeePerGas: GWEI, balance: b, chainId: 11155111 });
  };
  const quote = await waitForFunding({ getQuote, timeoutMs: 60_000, pollMs: 10_000, now, sleep, report });
  assert.equal(quote.funded, true);
  assert.deepEqual(events, [
    "quote",
    "progress:12000000000000000",
    "progress:7000000000000000",
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
    (e) => e.code === EXIT_NOT_FUNDED && /0.012 Sepolia ETH short/.test(e.message),
  );

  // the first quote failing is not retried
  await assert.rejects(waitForFunding({ getQuote: async () => { throw new Error("wrong chain"); }, timeoutMs: 60_000, now, sleep }), /wrong chain/);
}

// ---- leftover note: read at the stake's block, retry a lagging replica, print nothing on failure
{
  const slept = [];
  const sleep = async (ms) => { slept.push(ms); };
  const LEFT = 1_999_700_000_000_000n; // the live 2026-10-20 figure: 0.0019997 ETH

  // The block is pinned (as a number ethers turns into a hex quantity), never `latest`.
  const tags = [];
  const left = await leftoverAtBlock({ getBalance: async (tag) => { tags.push(tag); return LEFT; }, block: 11959428n, sleep });
  assert.equal(left, LEFT);
  assert.deepEqual(tags, [11959428]);
  assert.deepEqual(slept, [], "a first read that succeeds does not wait");

  // A replica that lacks the block errors; the read is retried and the later answer wins.
  slept.length = 0;
  let calls = 0;
  const retried = await leftoverAtBlock({
    getBalance: async () => { calls++; if (calls < 3) throw new Error("header not found"); return LEFT; },
    block: 42, delayMs: 7, sleep,
  });
  assert.equal(retried, LEFT);
  assert.equal(calls, 3);
  assert.deepEqual(slept, [7, 7]);

  // Every read fails: null (the caller prints no figure), after exactly `attempts` reads.
  slept.length = 0;
  calls = 0;
  const none = await leftoverAtBlock({ getBalance: async () => { calls++; throw new Error("down"); }, block: 42, attempts: 4, delayMs: 1, sleep });
  assert.equal(none, null);
  assert.equal(calls, 4);
  assert.equal(slept.length, 3);

  // A malformed balance is not a figure either.
  assert.equal(await leftoverAtBlock({ getBalance: async () => "lots", block: 42, attempts: 2, sleep }), null);
  assert.equal(await leftoverAtBlock({ getBalance: async () => -1n, block: 42, attempts: 2, sleep }), null);
  // An empty wallet is a real zero, not a failure.
  assert.equal(await leftoverAtBlock({ getBalance: async () => 0n, block: 42, sleep }), 0n);
  // No usable block number: nothing is read, nothing is printed.
  for (const block of [null, undefined, "latest", -1, 2n ** 64n]) {
    assert.equal(await leftoverAtBlock({ getBalance: async () => assert.fail("must not read without a block"), block, sleep }), null, String(block));
  }
}

console.log("PASS: funding-wallet selftest");
