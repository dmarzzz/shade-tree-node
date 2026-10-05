// One primary navigation for every page of the site. scripts/build-stake-site.mjs writes siteNav()
// into each page of NAV_PAGES (the Get access page renders it itself) and copies the nav's CSS into
// the research article; test/site.selftest.mjs fails if a page drifts, and
// test/site-browser/nav.spec.mjs fails if two pages draw it differently.
// `file` is the same target as a relative path, for pages that must also open as direct-file
// previews (the canopy page).
export const NAV_ITEMS = Object.freeze([
  { id: "agent", href: "/agent/", file: "../agent/index.html", label: "Agents" },
  { id: "operator", href: "/operator/", file: "../operator/index.html", label: "Operators" },
  { id: "stake", href: "/stake/", file: "../stake/index.html", label: "Get access" },
  { id: "canopy", href: "/canopy/", file: "../grove/index.html", label: "Network" },
  { id: "research", href: "/research/", file: "../research/index.html", label: "Research" },
  { id: "source", href: "https://github.com/dmarzzz/shade-tree-node", file: "https://github.com/dmarzzz/shade-tree-node", label: "Source" },
]);

// The three ways a page writes the same destinations:
//   root     /agent/               pages that are only ever served by the site
//   landing  ./agent/              the landing page, whose routes must also resolve when opened directly
//   file     ../agent/index.html   the canopy page, which opens as a direct-file preview
const HOME = Object.freeze({ root: "/", landing: "./", file: "../index.html" });

// Every page that carries the nav: its file under docs/post/, the route it is served at, the item
// it marks as current, and how it writes its links. A page with `rendered` builds its own HTML from
// siteNav(); the build writes the nav into all the others. A page with `inlineCss` does not load
// site.css and carries a generated copy of the nav's rules instead.
export const NAV_PAGES = Object.freeze([
  { file: "index.html", route: "/", current: null, links: "landing" },
  { file: "agent/index.html", route: "/agent/", current: "agent", links: "root" },
  { file: "operator/index.html", route: "/operator/", current: "operator", links: "root" },
  { file: "stake/index.html", route: "/stake/", current: "stake", links: "root", rendered: "site-src/stake-page.mjs" },
  { file: "grove/index.html", route: "/canopy/", current: "canopy", links: "file" },
  { file: "research/index.html", route: "/research/", current: "research", links: "root", inlineCss: true },
  { file: "404.html", route: "/404", current: null, links: "root" },
]);

function hrefFor(item, links) {
  if (!item.href.startsWith("/")) return item.href;
  if (links === "file") return item.file;
  return links === "landing" ? `.${item.href}` : item.href;
}

export function navLinks(current, indent = "", { links = "root" } = {}) {
  const lines = NAV_ITEMS.map((item) => {
    const here = item.id === current ? ' aria-current="page"' : "";
    return `${indent}  <a href="${hrefFor(item, links)}"${here}>${item.label}</a>`;
  });
  return `${indent}<div class="nav-links">\n${lines.join("\n")}\n${indent}</div>`;
}

export function siteNav(current, { indent = "", links = "root" } = {}) {
  if (!(links in HOME)) throw new Error(`unknown nav link form: ${links}`);
  return `${indent}<nav class="site-nav" aria-label="Primary navigation">
${indent}  <a class="wordmark" href="${HOME[links]}" aria-label="ShadeNet home">
${indent}    <span class="tree-mark" aria-hidden="true"><i></i><i></i><i></i></span>
${indent}    <span>ShadeNet</span>
${indent}  </a>
${navLinks(current, `${indent}  `, { links })}
${indent}</nav>`;
}

// The page with its nav block replaced by the generator's, at the block's own indentation.
const NAV_BLOCK = /^([ \t]*)<nav class="site-nav"[^>]*>[\s\S]*?\n\1<\/nav>/m;

export function navBlock(html) {
  return html.match(NAV_BLOCK)?.[0] ?? null;
}

export function withSiteNav(html, { current, links }) {
  const match = html.match(NAV_BLOCK);
  if (!match) throw new Error("page has no site-nav block");
  return html.replace(match[0], () => siteNav(current, { indent: match[1], links }));
}

// The nav's CSS lives in docs/post/site.css between these two markers, complete on its own. The
// research article does not load site.css, so the build copies the block into the article's head,
// with the two font tokens the block reads from site.css's :root.
export const NAV_CSS_START = "/* site-nav:start";
export const NAV_CSS_END = "/* site-nav:end */";
const NAV_CSS_TOKENS = ["--display", "--sans"];
const NAV_STYLE = /^([ \t]*)<style id="site-nav-css">[\s\S]*?<\/style>/m;

export function navCss(siteCss) {
  const start = siteCss.indexOf(NAV_CSS_START);
  const end = siteCss.indexOf(NAV_CSS_END);
  if (start < 0 || end < start) throw new Error("site.css has no site-nav block");
  const tokens = NAV_CSS_TOKENS.map((name) => {
    const value = siteCss.match(new RegExp(`^\\s*${name}:\\s*([^;]+);`, "m"))?.[1];
    if (!value) throw new Error(`site.css :root has no ${name}`);
    return `  ${name}: ${value};`;
  });
  const block = siteCss.slice(siteCss.indexOf("*/", start) + 2, end).trim();
  return `.site-nav {\n${tokens.join("\n")}\n}\n\n${block}`;
}

export function navStyle(siteCss, indent = "") {
  const body = navCss(siteCss).split("\n").map((line) => (line ? `${indent}  ${line}` : line)).join("\n");
  return `${indent}<style id="site-nav-css">
${indent}  /* Generated by scripts/build-stake-site.mjs from the site-nav block of docs/post/site.css. Do not edit. */
${body}
${indent}</style>`;
}

export function withNavStyle(html, siteCss) {
  const match = html.match(NAV_STYLE);
  if (!match) throw new Error("page has no site-nav-css style element");
  return html.replace(match[0], () => navStyle(siteCss, match[1]));
}
