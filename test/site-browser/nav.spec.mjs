/* global document, getComputedStyle */

// One nav on every page: same items, same destinations, same type, same box, same place on screen.
// Each page is measured against the Get access page in both viewport projects, so a page that draws
// the nav a few pixels off, in another face, or with another label fails here by name.

import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { NAV_ITEMS, NAV_PAGES } from "../../site-src/site-nav.mjs";

const REFERENCE = NAV_PAGES.find((entry) => entry.file === "stake/index.html");
const MISSING_ROUTE = "/__shade_tree_missing_page__";
const routeOf = (entry) => (entry.file === "404.html" ? MISSING_ROUTE : entry.route);

// Pages whose comparison is parked, with the reason. Remove an entry when its page matches.
const PARKED = new Map([]);

async function measure(page, entry) {
  const response = await page.goto(routeOf(entry), { waitUntil: "load" });
  expect(response?.status(), `${routeOf(entry)} status`).toBe(entry.file === "404.html" ? 404 : 200);
  await expect(page.locator("nav.site-nav")).toHaveCount(1);

  return page.evaluate(() => {
    const round = (value) => Math.round(value * 100) / 100;
    const box = (element) => {
      const rect = element.getBoundingClientRect();
      return { x: round(rect.x), y: round(rect.y), width: round(rect.width), height: round(rect.height) };
    };
    const type = (element) => {
      const style = getComputedStyle(element);
      return {
        family: style.fontFamily,
        size: style.fontSize,
        style: style.fontStyle,
        letterSpacing: style.letterSpacing,
        lineHeight: style.lineHeight,
        transform: style.textTransform,
      };
    };
    // Weight, colour and decoration are where a page may mark its own tab, so they are reported
    // apart from the rest of the type and only compared between links that are not current.
    const paint = (element) => {
      const style = getComputedStyle(element);
      return { weight: style.fontWeight, color: style.color, decoration: style.textDecorationLine };
    };
    // Where a link leads, whichever of the three written forms the page uses: /stake/, ./stake/
    // and ../stake/index.html are one page, and the canopy page's own file lives at /grove/.
    const destination = (anchor) => {
      const url = new URL(anchor.href);
      if (url.origin !== document.location.origin) return url.href;
      return url.pathname.replace(/index\.html$/, "").replace(/^\/grove\//, "/canopy/") + url.hash;
    };

    const nav = document.querySelector("nav.site-nav");
    const wordmark = nav.querySelector(".wordmark");
    const strip = nav.querySelector(".nav-links");
    const navStyle = getComputedStyle(nav);
    const links = [...strip.querySelectorAll("a")];
    const atRest = links.map((anchor) => ({
      label: anchor.textContent.trim(),
      destination: destination(anchor),
      current: anchor.getAttribute("aria-current"),
      box: box(anchor),
      type: type(anchor),
      paint: paint(anchor),
    }));
    strip.scrollLeft = strip.scrollWidth;
    const last = links.at(-1).getBoundingClientRect();
    const stripRect = strip.getBoundingClientRect();
    const scrolledToEnd = { lastLinkInsideStrip: last.right <= stripRect.right + 0.5 && last.left >= stripRect.left - 0.5 };
    strip.scrollLeft = 0;

    return {
      nav: {
        label: nav.getAttribute("aria-label"),
        box: box(nav),
        ruleWidth: navStyle.borderBottomWidth,
        ruleStyle: navStyle.borderBottomStyle,
        items: nav.children.length,
      },
      wordmark: {
        text: wordmark.textContent.trim(),
        label: wordmark.getAttribute("aria-label"),
        destination: destination(wordmark),
        box: box(wordmark),
        type: type(wordmark),
        weight: getComputedStyle(wordmark).fontWeight,
        color: getComputedStyle(wordmark).color,
        mark: box(wordmark.querySelector(".tree-mark")),
        name: box(wordmark.querySelector("span:last-child")),
      },
      strip: { box: box(strip), scrollable: strip.scrollWidth > strip.clientWidth + 1 },
      links: atRest,
      scrolledToEnd,
      page: {
        width: document.documentElement.clientWidth,
        overflowsSideways: document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
      },
    };
  });
}

// What two pages must share. A page's own colours stay out of it: the research article is on
// paper, so its nav is drawn in that page's ink, and the current tab may be marked.
function comparable(measured) {
  return {
    nav: measured.nav,
    wordmark: { ...measured.wordmark, color: null },
    strip: measured.strip,
    links: measured.links.map(({ label, destination, box, type }) => ({ label, destination, box, type })),
    scrolledToEnd: measured.scrolledToEnd,
  };
}

// The colour and weight of the wordmark and of every link that neither page marks as current.
function restingPaint(measured, marked) {
  return {
    wordmark: measured.wordmark.color,
    links: measured.links.filter((_, index) => !marked.has(NAV_ITEMS[index].id)).map(({ label, paint }) => ({ label, paint })),
  };
}

for (const entry of NAV_PAGES) {
  const route = routeOf(entry);
  const run = PARKED.has(entry.file) ? test.fixme : test;

  run(`the nav on ${route} is the generated one, drawn where the Get access page draws it`, async ({ page }, testInfo) => {
    const phone = testInfo.project.use.viewport.width <= 600;
    const reference = await measure(page, REFERENCE);
    const measured = entry === REFERENCE ? reference : await measure(page, entry);

    // The items are the generator's, in its order, each leading to the same place.
    expect(measured.links.map((link) => link.label)).toEqual(NAV_ITEMS.map((item) => item.label));
    expect(measured.links.map((link) => link.destination)).toEqual(NAV_ITEMS.map((item) => item.href));
    expect(measured.links.map((link) => link.current)).toEqual(NAV_ITEMS.map((item) => (item.id === entry.current ? "page" : null)));
    expect(measured.wordmark.destination).toBe("/");
    expect(measured.wordmark.text).toBe("ShadeNet");

    // Same box, same wordmark, same type and the same x and y for every link.
    expect(measured.nav.box.y, "the nav starts at the top of the page").toBe(0);
    expect(comparable(measured)).toEqual(comparable(reference));

    // Pages on the dark ground also share the nav's colours and weights (the current tab aside).
    if (!entry.inlineCss) {
      const marked = new Set([entry.current, REFERENCE.current]);
      expect(restingPaint(measured, marked)).toEqual(restingPaint(reference, marked));
    }

    // One row; nothing pushes the page sideways; every link is a full-height target with air
    // around it and can be brought into view.
    expect(measured.page.overflowsSideways).toBe(false);
    expect(new Set(measured.links.map((link) => link.box.y)).size, "links share one row").toBe(1);
    // On a phone the row wraps: the wordmark sits on its own line above the links.
    if (!phone) expect(measured.wordmark.box.y).toBe(measured.links[0].box.y);
    for (const [index, link] of measured.links.entries()) {
      expect(link.box.height, `${link.label} target height`).toBeGreaterThanOrEqual(44);
      if (index > 0) {
        const previous = measured.links[index - 1].box;
        expect(link.box.x - (previous.x + previous.width), `gap before ${link.label}`).toBeGreaterThanOrEqual(11.99);
      }
    }
    if (!phone) expect(measured.links[0].box.x - (measured.wordmark.box.x + measured.wordmark.box.width), "gap after the wordmark").toBeGreaterThanOrEqual(11.99);
    expect(measured.scrolledToEnd.lastLinkInsideStrip).toBe(true);
    if (!phone) {
      expect(measured.strip.scrollable, "the desktop nav shows every link at once").toBe(false);
      const lastLink = measured.links.at(-1).box;
      expect(lastLink.x + lastLink.width).toBeLessThanOrEqual(measured.nav.box.x + measured.nav.box.width + 0.01);
    }

    const accessibility = await new AxeBuilder({ page })
      .include("nav.site-nav")
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(accessibility.violations).toEqual([]);
  });
}
