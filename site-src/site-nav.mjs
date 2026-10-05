// One primary navigation for every secondary page. scripts/build-stake-site.mjs writes it into each
// page's nav-links block; test/stake-site.selftest.mjs fails if a page drifts.
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

export function navLinks(current, indent = "", { relative = false } = {}) {
  const lines = NAV_ITEMS.map((item) => {
    const here = item.id === current ? ' aria-current="page"' : "";
    return `${indent}  <a href="${relative ? item.file : item.href}"${here}>${item.label}</a>`;
  });
  return `${indent}<div class="nav-links">\n${lines.join("\n")}\n${indent}</div>`;
}

export function siteNav(current, { indent = "" } = {}) {
  return `${indent}<nav class="site-nav" aria-label="Primary navigation">
${indent}  <a class="wordmark" href="/" aria-label="ShadeNet home">
${indent}    <span class="tree-mark" aria-hidden="true"><i></i><i></i><i></i></span>
${indent}    <span>ShadeNet</span>
${indent}  </a>
${navLinks(current, `${indent}  `)}
${indent}</nav>`;
}
