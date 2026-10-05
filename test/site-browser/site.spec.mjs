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

  await expect(page.getByRole("link", { name: "Lab", exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Network", exact: true })).toHaveAttribute("href", "./canopy/");
  await expect(page.locator(".forest-fallback")).toHaveCSS("opacity", "0");
  await expect(page.getByRole("heading", { name: "Cover for local agents." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Get started" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "How it works" })).toBeVisible();

  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
  );
  expect(hasHorizontalOverflow).toBe(false);

  const installCopy = page.getByRole("button", { name: "Copy v0.7.1 live binary installation command" });
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
    ["/stake/", /Get access/i],
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
