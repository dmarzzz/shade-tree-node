/* global document, getComputedStyle, Image, window */

// A page must not keep a second picture behind itself.
//
// Whatever is painted behind the page box shows as soon as the page stops covering the window:
// trackpad and touch scrolling on macOS and Android pull the document away from the top and bottom
// edge. The secondary pages used to carry the Research page's banner on a fixed layer behind an
// opaque body, so the banner showed in that gap and nowhere else. These tests walk the tabs the
// report named (Get access, Research, then another tab, by click and by browser back) and hold
// every stop to a clean load of the same page, with nothing but the root background behind it.

import { expect, test } from "@playwright/test";

// The pull is emulated by moving the page box down. This many CSS pixels of backdrop are read.
const GAP = 160;
const STRIP = 120;

async function settle(page) {
  await page.waitForLoadState("load");
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
}

// What a clean load and a walked load must agree on.
function describePage(page) {
  return page.evaluate(() => {
    const behind = [];
    for (const element of document.querySelectorAll("*")) {
      for (const pseudo of ["", "::before", "::after"]) {
        const style = getComputedStyle(element, pseudo || null);
        if (pseudo && (style.content === "none" || style.content === "normal")) continue;
        if (style.display === "none" || style.position !== "fixed") continue;
        if (Number.parseInt(style.zIndex, 10) < 0) behind.push(`${element.tagName.toLowerCase()}${pseudo}`);
      }
    }
    const root = document.documentElement;
    return {
      path: window.location.pathname,
      scrollHeight: root.scrollHeight,
      scrollWidth: root.scrollWidth,
      bodyClass: document.body.className,
      rootBackground: getComputedStyle(root).backgroundColor,
      stylesheets: [...document.styleSheets].map((sheet) => (sheet.href ? new URL(sheet.href).pathname : "inline")),
      fixedLayersBehindThePage: behind,
    };
  });
}

// A blank tab that decodes screenshots, so the checks read pixels instead of trusting the DOM.
async function openPixelReader(page) {
  const reader = await page.context().newPage();
  await page.bringToFront();
  return reader;
}

// Share of the backdrop strip that is not the root background colour.
async function backdropLeak(page, reader) {
  const { rootColour, restingTop } = await page.evaluate((gap) => {
    const restingTop = document.body.getBoundingClientRect().top;
    // The reduced-motion rule gives every property a (near zero) transition; the move must not ride one.
    document.body.style.setProperty("transition", "none", "important");
    document.body.style.marginTop = `${gap}px`;
    const rootColour = getComputedStyle(document.documentElement).backgroundColor.match(/\d+/g).slice(0, 3).map(Number);
    return { rootColour, restingTop };
  }, GAP);
  await page.waitForFunction((gap) => window.scrollY === 0 && document.body.getBoundingClientRect().top >= gap, GAP);
  const width = page.viewportSize().width;
  const strip = await page.screenshot({ clip: { x: 0, y: 0, width, height: STRIP }, scale: "css" });
  await page.evaluate(() => { document.body.style.marginTop = ""; });
  await page.waitForFunction((top) => document.body.getBoundingClientRect().top === top, restingTop);
  await page.evaluate(() => { document.body.style.removeProperty("transition"); });

  return reader.evaluate(async ([png, colour]) => {
    const image = new Image();
    await new Promise((resolve, reject) => {
      image.onload = resolve;
      image.onerror = reject;
      image.src = `data:image/png;base64,${png}`;
    });
    const canvas = document.createElement("canvas");
    canvas.width = image.width;
    canvas.height = image.height;
    const context = canvas.getContext("2d");
    context.drawImage(image, 0, 0);
    const { data } = context.getImageData(0, 0, image.width, image.height);
    let foreign = 0;
    for (let i = 0; i < data.length; i += 4) {
      if (Math.abs(data[i] - colour[0]) > 2 || Math.abs(data[i + 1] - colour[1]) > 2 || Math.abs(data[i + 2] - colour[2]) > 2) foreign += 1;
    }
    return foreign / (data.length / 4);
  }, [strip.toString("base64"), rootColour]);
}

// Share of pixels that differ between two screenshots of the same viewport.
function differingShare(reader, first, second) {
  return reader.evaluate(async ([a, b]) => {
    const pixels = async (png) => {
      const image = new Image();
      await new Promise((resolve, reject) => {
        image.onload = resolve;
        image.onerror = reject;
        image.src = `data:image/png;base64,${png}`;
      });
      const canvas = document.createElement("canvas");
      canvas.width = image.width;
      canvas.height = image.height;
      const context = canvas.getContext("2d");
      context.drawImage(image, 0, 0);
      return context.getImageData(0, 0, image.width, image.height);
    };
    const [one, two] = [await pixels(a), await pixels(b)];
    if (one.width !== two.width || one.height !== two.height) return 1;
    let different = 0;
    for (let i = 0; i < one.data.length; i += 4) {
      const distance = Math.abs(one.data[i] - two.data[i]) + Math.abs(one.data[i + 1] - two.data[i + 1]) + Math.abs(one.data[i + 2] - two.data[i + 2]);
      if (distance > 12) different += 1;
    }
    return different / (one.data.length / 4);
  }, [first.toString("base64"), second.toString("base64")]);
}

async function cleanLoad(page, path) {
  await page.goto(path, { waitUntil: "load" });
  await settle(page);
  // Pages that read live counts settle a moment after load; two equal readings in a row are the page at rest.
  let description = await describePage(page);
  await expect.poll(async () => {
    const previous = description;
    await page.waitForTimeout(250);
    description = await describePage(page);
    return JSON.stringify(description) === JSON.stringify(previous);
  }).toBe(true);
  return { description, screenshot: await page.screenshot({ scale: "css" }) };
}

async function expectCleanPage(page, reader, clean, { pixels = true } = {}) {
  await settle(page);
  await expect.poll(() => describePage(page)).toEqual(clean.description);
  expect(clean.description.fixedLayersBehindThePage).toEqual([]);
  if (pixels) {
    await expect.poll(async () => differingShare(reader, clean.screenshot, await page.screenshot({ scale: "css" }))).toBeLessThan(0.01);
  }
  expect(await backdropLeak(page, reader)).toBe(0);
}

async function follow(page, selector, path) {
  await page.locator(selector).first().click();
  await page.waitForURL((url) => url.pathname === path);
}

async function history(page, direction, path) {
  // "commit", because a page restored from the back/forward cache never fires load again.
  if (direction === "back") await page.goBack({ waitUntil: "commit" });
  else await page.goForward({ waitUntil: "commit" });
  await page.waitForURL((url) => url.pathname === path);
}

test("only the root background sits behind each page", async ({ page }) => {
  const reader = await openPixelReader(page);
  for (const path of ["/", "/stake/", "/canopy/", "/research/", "/__shade_tree_missing_page__"]) {
    await page.goto(path, { waitUntil: "load" });
    await settle(page);
    const description = await describePage(page);
    expect(description.fixedLayersBehindThePage, `fixed layers behind ${path}`).toEqual([]);
    expect(await backdropLeak(page, reader), `backdrop of ${path} that is not the root background`).toBe(0);
  }
});

test("Get access, then another tab, matches a clean load", async ({ page }) => {
  test.slow();
  const reader = await openPixelReader(page);
  const stake = await cleanLoad(page, "/stake/");
  const research = await cleanLoad(page, "/research/");

  await page.goto("/", { waitUntil: "load" });
  await follow(page, '.nav-links a[href$="stake/"]', "/stake/");
  await expectCleanPage(page, reader, stake);

  // Leave from partway down the page, the way a reader does.
  await page.evaluate(() => window.scrollTo({ top: 900, behavior: "instant" }));
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  await follow(page, '.nav-links a[href$="research/"]', "/research/");
  await expectCleanPage(page, reader, research);

  await history(page, "back", "/stake/");
  await expectCleanPage(page, reader, stake);
  await history(page, "forward", "/research/");
  await expectCleanPage(page, reader, research);
});

test("Research, then another tab, matches a clean load", async ({ page }) => {
  test.slow();
  const reader = await openPixelReader(page);
  const research = await cleanLoad(page, "/research/");
  const canopy = await cleanLoad(page, "/canopy/");
  const home = await cleanLoad(page, "/");

  await page.goto("/", { waitUntil: "load" });
  await follow(page, '.nav-links a[href$="research/"]', "/research/");
  await expectCleanPage(page, reader, research);

  await page.evaluate(() => window.scrollTo({ top: 1200, behavior: "instant" }));
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: "instant" }));
  // The canopy page runs a live WebGL globe, so it is held to its structure and its backdrop.
  await follow(page, '.nav-links a[href$="canopy/"]', "/canopy/");
  await expectCleanPage(page, reader, canopy, { pixels: false });

  await history(page, "back", "/research/");
  await expectCleanPage(page, reader, research);
  // The landing page's hero is a live WebGL scene, so it is held to its structure and its backdrop.
  await history(page, "back", "/");
  await expectCleanPage(page, reader, home, { pixels: false });

  await history(page, "forward", "/research/");
  await history(page, "forward", "/canopy/");
  await expectCleanPage(page, reader, canopy, { pixels: false });
});
