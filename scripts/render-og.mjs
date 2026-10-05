// Render the link-preview card (docs/post/fig/shade-tree-og.png, 1200x630) from the current
// landing page, so it always carries the live nav ("Network", not "Canopy") and the current
// hero copy. Run with the site served locally:
//   node scripts/serve-site.mjs &   node scripts/render-og.mjs
// Override the origin with SITE_BASE_URL. Task 42 in ~/shadenet-launch/PRE-POST-TASKS.md.

import { chromium } from "@playwright/test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const base = process.env.SITE_BASE_URL || "http://127.0.0.1:4173";
const out = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "post", "fig", "shade-tree-og.png");

const browser = await chromium.launch({
  args: ["--enable-webgl", "--ignore-gpu-blocklist", "--use-angle=swiftshader"],
});
const context = await browser.newContext({
  viewport: { width: 1200, height: 630 },
  deviceScaleFactor: 1,
  colorScheme: "dark",
  reducedMotion: "reduce",
});
const page = await context.newPage();
await page.goto(base + "/", { waitUntil: "load" });
// Let the grove light up so the card shows the live hero, not the fallback.
await page.locator("#grove-stage.is-live").waitFor({ timeout: 15000 }).catch(() => {});
await page.waitForTimeout(1500);
await page.screenshot({ path: out, clip: { x: 0, y: 0, width: 1200, height: 630 } });
await browser.close();
console.log("wrote", out);
