/* global document */

import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";
import { AbiCoder, Interface, solidityPackedKeccak256 } from "ethers";
import { groth16 } from "snarkjs";

async function openHomepage(page) {
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(page.locator("#grove-stage")).toHaveClass(/is-live/);
  await expect(page.locator("#grove-canvas")).toHaveCSS("opacity", "1");
}

test("homepage remains usable, quiet, and accessible", async ({ page }) => {
  const pageErrors = [];
  page.on("console", (message) => {
    if (message.type() === "error") pageErrors.push(message.text());
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));

  await openHomepage(page);

  await expect(page.getByRole("link", { name: "Lab", exact: true })).toBeHidden();
  await expect(page.locator(".forest-fallback")).toHaveCSS("opacity", "0");
  await expect(page.getByRole("heading", { name: "Cover for local agents." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Get started" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "How it works" })).toBeVisible();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  );
  expect(hasHorizontalOverflow).toBe(false);

  const installCopy = page.getByRole("button", { name: "Copy v0.6.0 live binary installation command" });
  await installCopy.click();
  await expect(installCopy).toHaveText("copied");

  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
  expect(pageErrors).toEqual([]);
});

test("signature sections match their approved visual baselines", async ({ page }, testInfo) => {
  test.slow();
  await openHomepage(page);

  const hero = page.locator(".home-hero");
  await expect(hero).toHaveScreenshot("home-hero.png", { timeout: 30_000 });

  const getStarted = page.locator(".glyph-grove");
  await getStarted.scrollIntoViewIfNeeded();
  await expect(getStarted).toHaveScreenshot("get-started.png", { timeout: 30_000 });

  const how = page.locator(".how-panel");
  await how.scrollIntoViewIfNeeded();
  // Linux and macOS Chromium round one responsive text row in opposite
  // directions. Keep reviewed baselines for both instead of letting a one-pixel
  // platform difference make local approval overwrite the canonical CI image.
  const howSnapshot = process.platform === "darwin" ? "how-it-works-macos.png" : "how-it-works.png";
  await expect(how).toHaveScreenshot(howSnapshot, { timeout: 30_000 });

  await testInfo.attach("viewport", {
    body: JSON.stringify(testInfo.project.use.viewport),
    contentType: "application/json",
  });
});

test("primary static routes and the branded 404 resolve", async ({ page }) => {
  for (const [path, heading] of [
    ["/research/", /Access-gated onion egress for local AI/i],
    ["/agent/", /agent/i],
    ["/operator/", /operator|node/i],
    ["/stake/", /Stake without giving us an identity/i],
    ["/canopy/", /ShadeNet/i],
  ]) {
    const response = await page.goto(path, { waitUntil: "domcontentloaded" });
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
  }

  const missing = await page.goto("/__shade_tree_missing_page__", { waitUntil: "domcontentloaded" });
  expect(missing?.status()).toBe(404);
  await expect(page.getByRole("heading", { name: /This path leaves the canopy/i })).toBeVisible();
});

const ACCOUNT = "0x1000000000000000000000000000000000000001";
const TX_HASH = `0x${"ab".repeat(32)}`;

// A scripted EIP-1193 wallet. `overrides` swaps single methods to drive error paths.
async function mockWallet(page, overrides = {}) {
  await page.addInitScript(({ account, hash, overrides }) => {
    const calls = [];
    window.__walletCalls = calls;
    const fixed = {
      eth_requestAccounts: [account],
      wallet_switchEthereumChain: null,
      eth_chainId: "0xaa36a7",
      eth_getCode: "0x60006000",
      eth_getBalance: "0x1bc16d674ec80000",
      eth_estimateGas: "0x100000",
      eth_gasPrice: "0x3b9aca00",
      eth_sendTransaction: hash,
      eth_getTransactionReceipt: { status: "0x1", transactionHash: hash, blockNumber: "0x100" },
      eth_getBlockByNumber: { number: "0xf0" },
      ...overrides,
    };
    window.ethereum = {
      on() {},
      async request({ method, params = [] }) {
        calls.push({ method, params });
        if (method in fixed) return fixed[method];
        if (method === "eth_getLogs") return [];
        if (method === "eth_call") {
          const data = params[0]?.data || "";
          const state = window.__memberState || {};
          if (data.startsWith("0x82afd23b") && state.active) return `0x${"0".repeat(63)}1`;
          if (data.startsWith("0xd57b50e7") && state.limit) return `0x${BigInt(state.limit).toString(16).padStart(64, "0")}`;
          if (data.startsWith("0xde259775")) return `0x${BigInt(state.withdrawableAt || 0).toString(16).padStart(64, "0")}`;
          if (data.startsWith("0xe0b91f92")) {
            const limit = BigInt(`0x${data.slice(10)}`);
            return `0x${(limit * 100000000000000000n).toString(16).padStart(64, "0")}`;
          }
          if (data.startsWith("0x82afd23b") || data.startsWith("0xd57b50e7")) return `0x${"0".repeat(64)}`;
          return "0x";
        }
        throw new Error(`unexpected wallet method ${method}`);
      },
    };
  }, { account: ACCOUNT, hash: TX_HASH, overrides });
}

async function createAndSave(page) {
  await page.getByRole("button", { name: "create identity" }).click();
  await expect(page.locator("[data-leaf]")).toHaveText(/^\d{70,80}$/);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "download identity.json" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^shadenet-identity-[0-9]{8}\.json$/);
  // Downloading is not proof of saving: the confirmation stays a deliberate click.
  await expect(page.locator("[data-recovery-check]")).not.toBeChecked();
  await page.locator("[data-recovery-check]").check();
}

test("Get access creates a compatible identity, stakes the pinned transaction, and counts down finality", async ({ page }) => {
  await mockWallet(page);
  await page.goto("/stake/", { waitUntil: "networkidle" });
  await expect(page.locator("[data-live-members]")).toHaveText("3");
  await expect(page.locator("[data-live-set]")).toHaveText(/3 staked members today/);
  await createAndSave(page);

  await page.getByRole("button", { name: "connect wallet" }).first().click();
  const stakeButton = page.getByRole("button", { name: /^stake 0\.1 Sepolia ETH$/ });
  await expect(stakeButton).toBeEnabled();
  await stakeButton.click();
  await expect(page.locator("[data-status]")).toHaveText(/Stake confirmed/);
  await expect(page.locator("[data-finality]")).toHaveText(/Finalized|finality/);

  const sent = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_sendTransaction"));
  expect(sent.params[0].to.toLowerCase()).toBe("0xeb67abf066c11d78856bccc63476ed14d51e4275");
  expect(sent.params[0].value).toBe("0x16345785d8a0000");
  // The bundled record decides the ABI: ShadeNet sets (registerInput "identityCommitment") take
  // registerIdentity(idc, limit) and derive the leaf (launch audit 2.1.4); the v4 set takes
  // register(leaf, limit). Either way the page sends the value it shows.
  const record = JSON.parse(readFileSync(new URL("../../network/sepolia/deployment.json", import.meta.url), "utf8"));
  const shadenet = record.admission.roots.staked.registerInput === "identityCommitment";
  expect(sent.params[0].data).toMatch(shadenet ? /^0x9b7b5b80/ : /^0xd66d6c10/);
  const shown = BigInt((await page.locator("[data-leaf]").textContent()).trim());
  expect(BigInt(`0x${sent.params[0].data.slice(10, 74)}`)).toBe(shown);
  expect(BigInt(`0x${sent.params[0].data.slice(74, 138)}`)).toBe(1n);

  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
});

test("Get access stakes the chosen higher tier at its own bond", async ({ page }) => {
  await mockWallet(page);
  await page.goto("/stake/", { waitUntil: "networkidle" });
  await page.getByRole("radio", { name: /tier 8/ }).first().check();
  await createAndSave(page);
  await page.getByRole("button", { name: "connect wallet" }).first().click();
  await page.getByRole("button", { name: /^stake 0\.8 Sepolia ETH$/ }).click();
  await expect(page.locator("[data-status]")).toHaveText(/Stake confirmed/);
  const sent = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_sendTransaction"));
  expect(BigInt(sent.params[0].value)).toBe(800000000000000000n);
});

test("Get access error paths are announced as alerts and send nothing", async ({ page }) => {
  await mockWallet(page, { eth_chainId: "0x1" });
  await page.goto("/stake/", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "connect wallet" }).first().click();
  await expect(page.getByRole("alert")).toHaveText(/Sepolia \(11155111\) is required/);

  await page.locator("[data-identity-file]").setInputFiles({ name: "bad.json", mimeType: "application/json", buffer: Buffer.from('{"identitySecret":"1","leaf":"1","limit":3}') });
  await expect(page.getByRole("alert")).toHaveText(/offers tiers/);

  await page.getByRole("button", { name: "I’m sponsoring" }).click();
  await page.locator("[data-sponsor-leaf]").fill("0123");
  await expect(page.getByRole("button", { name: /stake .* for this commitment/ })).toBeDisabled();
  const sent = await page.evaluate(() => window.__walletCalls.some((call) => call.method === "eth_sendTransaction"));
  expect(sent).toBe(false);
});

test("Get access reports a reverted stake without claiming admission", async ({ page }) => {
  await mockWallet(page, { eth_getTransactionReceipt: { status: "0x0", transactionHash: TX_HASH, blockNumber: "0x100" } });
  await page.goto("/stake/", { waitUntil: "networkidle" });
  await createAndSave(page);
  await page.getByRole("button", { name: "connect wallet" }).first().click();
  await page.getByRole("button", { name: /^stake 0\.1 Sepolia ETH$/ }).click();
  await expect(page.getByRole("alert")).toHaveText(/reverted/);
  await expect(page.locator("[data-finality]")).toBeHidden();
});

test("an imported identity can check status but cannot stake again", async ({ page }) => {
  await mockWallet(page);
  await page.goto("/stake/", { waitUntil: "networkidle" });
  const identity = {
    identitySecret: "619880168657502627082950702222527535803368023538932999730878823680368560389",
    leaf: "15422591461559048085568001683323977812416390282127809084852072421595506429792",
    limit: 1,
  };
  await page.locator("[data-identity-file]").setInputFiles({ name: "identity.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(identity)) });
  await page.getByRole("button", { name: "connect wallet" }).first().click();
  await expect(page.getByRole("button", { name: /^stake 0\.1 Sepolia ETH$/ })).toBeDisabled();
  await page.getByRole("button", { name: "check status through my wallet" }).click();
  await expect(page.locator("[data-member-state]")).toHaveText(/Not registered/);
});

const VECTOR_IDENTITY = {
  identitySecret: "619880168657502627082950702222527535803368023538932999730878823680368560389",
  leaf: "15422591461559048085568001683323977812416390282127809084852072421595506429792",
  limit: 1,
};

for (const [action, memberState, button, selector] of [
  ["exit", { active: true, limit: 1 }, "start exit", "0x63199902"],
  ["withdraw", { active: false, limit: 1, withdrawableAt: 1 }, "withdraw bond", "0x62b2b5f0"],
]) {
  test(`Get access proves ${action} in the tab and sends it`, async ({ page }) => {
    test.slow();
    await mockWallet(page);
    await page.addInitScript((state) => { window.__memberState = state; }, memberState);
    await page.goto("/stake/", { waitUntil: "networkidle" });
    await page.locator("[data-identity-file]").setInputFiles({ name: "identity.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(VECTOR_IDENTITY)) });
    await page.getByRole("button", { name: "connect wallet" }).first().click();
    if (action === "withdraw") await page.locator("[data-withdraw-to]").fill("0x2000000000000000000000000000000000000002");
    await page.getByRole("button", { name: button }).click();
    await expect(page.locator("[data-status]")).toHaveText(action === "exit" ? /Exit started/ : /Withdrawn/, { timeout: 90_000 });
    const sent = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_sendTransaction"));
    expect(sent.params[0].data.startsWith(selector)).toBe(true);
    expect(sent.params[0].value).toBe("0x0");
    // The bytes the contract would see must verify under the withdraw verification key.
    const iface = new Interface(["function initiateExit(uint256 commitment, bytes proof)", "function withdraw(uint256 commitment, address recipient, bytes proof)"]);
    const args = iface.parseTransaction({ data: sent.params[0].data }).args;
    const [a, b, c, idc] = AbiCoder.defaultAbiCoder().decode(["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256"], args.proof);
    const context = action === "exit"
      ? solidityPackedKeccak256(["string", "uint256"], ["SHADE_TREE_EXIT", BigInt(VECTOR_IDENTITY.leaf)])
      : solidityPackedKeccak256(["string", "uint256", "address"], ["SHADE_TREE_WITHDRAW", BigInt(VECTOR_IDENTITY.leaf), args.recipient]);
    const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const vkey = JSON.parse(readFileSync(new URL("../../circuits/rln/withdraw_verification_key.json", import.meta.url), "utf8"));
    const proof = {
      pi_a: [a[0].toString(), a[1].toString(), "1"],
      pi_b: [[b[0][1].toString(), b[0][0].toString()], [b[1][1].toString(), b[1][0].toString()], ["1", "0"]],
      pi_c: [c[0].toString(), c[1].toString(), "1"],
      protocol: "groth16",
      curve: "bn128",
    };
    expect(await groth16.verify(vkey, [idc.toString(), (BigInt(context) % FIELD).toString()], proof)).toBe(true);
  });
}

test("Get access sections match their approved visual baselines", async ({ page }) => {
  await page.goto("/stake/", { waitUntil: "networkidle" });
  await expect(page.locator(".stake-intro")).toHaveScreenshot("stake-intro.png", { timeout: 30_000 });
  const tiers = page.locator(".tier-table");
  await tiers.scrollIntoViewIfNeeded();
  await expect(tiers).toHaveScreenshot("stake-tiers.png", { timeout: 30_000 });
  const trail = page.locator("[data-member-steps]");
  await trail.scrollIntoViewIfNeeded();
  await expect(trail).toHaveScreenshot("stake-steps.png", { timeout: 30_000 });
});
