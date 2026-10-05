/* global document */

// No page may scroll sideways. Every public page is loaded at a phone width (390px) and a wide
// desktop width (1440px); the document must not overflow horizontally and the <body> must keep its
// sideways overflow clipped. This is the durable guard for task 45's phone-width pass: a future
// element that reaches past the viewport fails here by page and width.

import { expect, test } from "@playwright/test";
import { NAV_PAGES } from "../../site-src/site-nav.mjs";

// 404.html is served at a missing route so the server returns its branded 404.
const MISSING_ROUTE = "/__shade_tree_missing_page__";
const routeOf = (entry) => (entry.file === "404.html" ? MISSING_ROUTE : entry.route);

for (const width of [390, 1440]) {
  for (const entry of NAV_PAGES) {
    test(`${entry.route} does not overflow sideways at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      // The Network page polls and never reaches networkidle; "load" is enough to lay it out.
      const response = await page.goto(routeOf(entry), { waitUntil: "load" });
      expect(response?.status(), `${routeOf(entry)} status`).toBe(entry.file === "404.html" ? 404 : 200);

      const report = await page.evaluate(() => {
        const de = document.documentElement;
        return {
          docOverflow: de.scrollWidth - de.clientWidth,
          bodyOverflowX: getComputedStyle(document.body).overflowX,
        };
      });

      expect(report.docOverflow, "document scrollWidth minus clientWidth").toBeLessThanOrEqual(1);
      expect(report.bodyOverflowX, "body overflow-x is clipped").toMatch(/hidden|clip/);
    });
  }
}
