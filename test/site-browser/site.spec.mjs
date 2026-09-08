/* global document */

import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

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
  ]) {
    const response = await page.goto(path, { waitUntil: "domcontentloaded" });
    expect(response?.status()).toBe(200);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
  }

  const missing = await page.goto("/__shade_tree_missing_page__", { waitUntil: "domcontentloaded" });
  expect(missing?.status()).toBe(404);
  await expect(page.getByRole("heading", { name: /This path leaves the grove/i })).toBeVisible();
});

test("private staking creates a compatible identity and preflights the pinned transaction", async ({ page }) => {
  const account = "0x1000000000000000000000000000000000000001";
  const hash = `0x${"ab".repeat(32)}`;
  await page.addInitScript(({ account, hash }) => {
    const calls = [];
    window.__walletCalls = calls;
    window.ethereum = {
      on() {},
      async request({ method, params = [] }) {
        calls.push({ method, params });
        if (method === "eth_requestAccounts") return [account];
        if (method === "wallet_switchEthereumChain") return null;
        if (method === "eth_chainId") return "0xaa36a7";
        if (method === "eth_getCode") return "0x60006000";
        if (method === "eth_getBalance") return "0x1bc16d674ec80000";
        if (method === "eth_estimateGas") return "0x100000";
        if (method === "eth_gasPrice") return "0x3b9aca00";
        if (method === "eth_sendTransaction") return hash;
        if (method === "eth_getTransactionReceipt") return { status: "0x1", transactionHash: hash };
        if (method === "eth_call") {
          const data = params[0]?.data || "";
          if (data.startsWith("0xe0b91f92")) return `0x${BigInt("100000000000000000").toString(16).padStart(64, "0")}`;
          if (data.startsWith("0x82afd23b")) return `0x${"0".repeat(64)}`;
          if (data.startsWith("0xd57b50e7")) return `0x${"0".repeat(64)}`;
          return "0x";
        }
        throw new Error(`unexpected wallet method ${method}`);
      },
    };
  }, { account, hash });

  await page.goto("/stake/", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "create identity" }).click();
  const leaf = page.locator("[data-leaf]");
  await expect(leaf).toHaveText(/^\d{70,80}$/);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "download identity.json" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^shade-tree-identity-[0-9]{8}\.json$/);
  await expect(page.locator("[data-recovery-check]" )).toBeChecked();

  await page.getByRole("button", { name: "connect wallet" }).first().click();
  const stakeButton = page.getByRole("button", { name: "stake 0.1 Sepolia ETH" });
  await expect(stakeButton).toBeEnabled();
  await stakeButton.click();
  await expect(page.locator("[data-status]")).toHaveText(/Stake confirmed/);

  const sent = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_sendTransaction"));
  expect(sent.params[0].to.toLowerCase()).toBe("0xeb67abf066c11d78856bccc63476ed14d51e4275");
  expect(sent.params[0].value).toBe("0x16345785d8a0000");
  expect(sent.params[0].data).toMatch(/^0xd66d6c10/);

  const accessibility = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(accessibility.violations).toEqual([]);
});
