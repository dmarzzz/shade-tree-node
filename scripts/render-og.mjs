// Render the link-preview card (docs/post/fig/shade-tree-og.png, 1200x630) from the current
// landing page, so it always carries the live nav ("Network", not "Canopy") and the current
// hero copy. Run with the site served locally:
//   node scripts/serve-site.mjs &   node scripts/render-og.mjs
// Override the origin with SITE_BASE_URL. Task 42 in ~/shadenet-launch/PRE-POST-TASKS.md.
//
// `--readme-banner` renders the README banner instead (assets/shade-tree-readme-banner.webp,
// 1731x909): the same live hero, composed like a poster (see BANNER_CSS), encoded with `cwebp`
// (brew install webp):
//   SITE_BASE_URL=https://shadenet.xyz node scripts/render-og.mjs --readme-banner

import { chromium } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const base = process.env.SITE_BASE_URL || "http://127.0.0.1:4173";
const banner = process.argv.includes("--readme-banner");
const { width, height } = banner ? { width: 1731, height: 909 } : { width: 1200, height: 630 };
const out = banner
  ? join(root, "assets", "shade-tree-readme-banner.webp")
  : join(root, "docs", "post", "fig", "shade-tree-og.png");

const browser = await chromium.launch({
  args: ["--enable-webgl", "--ignore-gpu-blocklist", "--use-angle=swiftshader"],
});
const context = await browser.newContext({
  viewport: { width, height },
  // The banner renders at 2x and is downscaled on encode, so the scaled grove stays sharp.
  deviceScaleFactor: banner ? 2 : 1,
  colorScheme: "dark",
  reducedMotion: "reduce",
});
// The README banner is a composition, not a page screenshot: wordmark top-left, headline left,
// grove right, nothing else (the nav links, preview strip and calls to action are hidden), with the
// hero filling the frame. Injected at document start so the grove lays out at the final size.
const BANNER_CSS = `
  .nav-links, .preview-flag, .hero-actions { display: none !important; }
  .home-hero { min-height: 100vh !important; height: 100vh !important; }
  .home-hero .site-nav { width: auto !important; padding: 2.2rem 62px 0 !important; border-bottom: 0 !important; }
  .home-hero .wordmark { zoom: 1.7; }
  .home-copy { left: 62px !important; top: 50% !important; transform: translateY(-46%) !important; zoom: 1.14; }
  .grove-stage canvas { transform: scale(1.12); transform-origin: 72% 52%; }
`;
if (banner) {
  await context.addInitScript((css) => {
    const add = () => { const style = document.createElement("style"); style.textContent = css; document.head.append(style); };
    if (document.head) add(); else document.addEventListener("DOMContentLoaded", add, { once: true });
  }, BANNER_CSS);
}
const page = await context.newPage();
await page.goto(base + "/", { waitUntil: "load" });
// Let the grove light up so the image shows the live hero, not the fallback.
await page.locator("#grove-stage.is-live").waitFor({ timeout: 15000 }).catch(() => {});
await page.waitForTimeout(1500);
const clip = { x: 0, y: 0, width, height };
if (banner) {
  const tmp = mkdtempSync(join(tmpdir(), "readme-banner-"));
  const png = join(tmp, "banner.png");
  await page.screenshot({ path: png, clip });
  execFileSync("cwebp", ["-quiet", "-q", "82", "-m", "6", "-resize", String(width), String(height), png, "-o", out]);
  rmSync(tmp, { recursive: true, force: true });
} else {
  await page.screenshot({ path: out, clip });
}
await browser.close();
console.log("wrote", out);
