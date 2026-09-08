#!/usr/bin/env node
// docs-site/build.mjs
// Zero-dependency static docs site generator for Shade Tree Grove.
//
// Reads the repo's markdown (README + SECURITY + CONTRIBUTING + docs/**/*.md
// + specs/**/*.md),
// converts it to self-contained HTML with a categorized nav, and writes
// docs-site/out/*.html. No npm dependencies, no network, works offline.
//
//   node docs-site/build.mjs
//
// Output: docs-site/out/ (already covered by the `out/` .gitignore pattern).

import { copyFileSync, readFileSync, writeFileSync, readdirSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve, relative, posix } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const OUT_DIR = join(__dirname, 'out');

// ---------------------------------------------------------------------------
// 1. Collect source docs (grounded in the actual filesystem).
// ---------------------------------------------------------------------------

function walkMarkdown(dir, acc) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkMarkdown(full, acc);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
      acc.push(full);
    }
  }
  return acc;
}

// Scope: root README/SECURITY/CONTRIBUTING + everything under docs/ and specs/.
const sourceAbs = [];
for (const name of ['README.md', 'SECURITY.md', 'CONTRIBUTING.md']) {
  const p = join(REPO_ROOT, name);
  try { if (statSync(p).isFile()) sourceAbs.push(p); } catch { /* absent, skip */ }
}
walkMarkdown(join(REPO_ROOT, 'docs'), sourceAbs);
walkMarkdown(join(REPO_ROOT, 'specs'), sourceAbs);

// relpath (posix, repo-root-relative) -> record
const docs = new Map();
function slugFor(relPath) {
  return relPath.replace(/\.md$/i, '').replace(/[\/]/g, '__') + '.html';
}
for (const abs of sourceAbs) {
  const rel = relative(REPO_ROOT, abs).split(/[\\/]/).join('/');
  docs.set(rel, { abs, rel, out: slugFor(rel) });
}

// Non-Markdown specification artifacts linked from the generated pages.
const assets = new Map();
for (const rel of ['specs/data-api.openapi.yaml']) {
  const abs = join(REPO_ROOT, rel);
  try {
    if (statSync(abs).isFile()) assets.set(rel, { abs, rel, out: rel.replace(/[\\/]/g, '__') });
  } catch { /* absent, skip */ }
}

// Render compatibility stubs so old links resolve, but keep those stubs out of
// navigation so only the canonical specs are listed.
const NAV_EXCLUDED = new Set(['docs/PROTOCOL.md', 'docs/PUBLIC-GROVE.md', 'docs/PROTOCOL-API.md', 'docs/PROTOCOL-VERSIONING.md']);

// ---------------------------------------------------------------------------
// 2. Categorization. Mapping is explicit for known docs; anything not listed
//    (e.g. a doc added later) falls back to "Reference" so the build never
//    drops or crashes on an unmapped file.
// ---------------------------------------------------------------------------

const CATEGORIES = [
  ['Getting Started', [
    'README.md', 'docs/README.md', 'docs/OVERVIEW.md', 'docs/QUICKSTART.md', 'docs/CLI.md', 'docs/CONFIG.md',
    'docs/JOIN.md', 'docs/post/JOIN.md', 'docs/post/RUN-A-GATEWAY.md',
    'CONTRIBUTING.md',
  ]],
  ['Operate', [
    'docs/OPERATOR.md', 'docs/BOOTNODE.md', 'docs/INCIDENT.md', 'docs/SLO.md',
    'docs/DEPLOY.md', 'docs/DEPLOYMENT.md', 'docs/FLEET.md',
    'docs/CLIENTS.md', 'docs/LIGHT-CLIENT.md', 'specs/data-api.md',
  ]],
  ['Security & Audit', [
    'SECURITY.md', 'docs/AUDIT.md', 'docs/CONTRACTS-AUDIT.md',
    'docs/TOR-HARDENING.md', 'docs/adversarial-review.md',
  ]],
  ['Design', [
    'specs/README.md', 'specs/protocol.md', 'docs/WIRE-SPEC.md', 'docs/VERSIONING.md', 'docs/ONCHAIN.md',
    'docs/PAYMENTS.md', 'docs/ROADMAP.md', 'docs/NEXT-VERSION.md',
    'docs/RLN-MIGRATION.md', 'docs/ADAPTERS.md', 'docs/SDK.md',
    'docs/adr/README.md', 'docs/adr/0001-client-language.md',
    'docs/adr/0002-onion-never-on-chain.md',
    'docs/adr/0003-bootnode-is-a-cache-not-a-trust-root.md',
    'docs/adr/0004-rln-over-slot-scheme.md',
    'docs/adr/0005-governed-gateway-slash.md',
  ]],
  ['Reference', [
    'docs/STATUS.md', 'docs/REPORT.md', 'docs/exit-blocking-benchmark.md',
    'docs/residential-proxies.md', 'docs/residential-proxy-providers.md',
    'docs/SHIP-PLAN.md',
  ]],
];
const FALLBACK_CATEGORY = 'Reference';

// Assign each doc to a category, preserving the mapping order.
const catOf = new Map();
const orderIn = new Map();
for (const [cat, list] of CATEGORIES) {
  list.forEach((rel, i) => {
    if (docs.has(rel)) { catOf.set(rel, cat); orderIn.set(rel, i); }
  });
}
for (const rel of docs.keys()) {
  if (!catOf.has(rel)) { catOf.set(rel, FALLBACK_CATEGORY); orderIn.set(rel, 999); }
}

// ---------------------------------------------------------------------------
// 3. Minimal, correct-enough Markdown -> HTML converter.
//    Handles: fenced code (escaped), headings, ordered/unordered/task lists
//    (nested by indent), GFM tables, blockquotes, hr, paragraphs, and inline
//    code / bold / italic / links / images. HTML is escaped everywhere text
//    is rendered; code content is never re-interpreted as markup.
// ---------------------------------------------------------------------------

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Resolve/rewrite a link target: .md links to a known source become the
// generated .html, and allowlisted spec assets become copied output files.
// Anchors are preserved. Other non-.md and external links pass through unchanged.
function rewriteLink(href, fromRel) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('#') || href.startsWith('//')) {
    return href; // external, mailto, protocol-relative, or pure anchor
  }
  const hashIdx = href.indexOf('#');
  const path = hashIdx >= 0 ? href.slice(0, hashIdx) : href;
  const hash = hashIdx >= 0 ? href.slice(hashIdx) : '';
  // Resolve relative to the source doc's directory, normalize, repo-relative.
  const fromDir = posix.dirname(fromRel);
  const resolved = posix.normalize(posix.join(fromDir, path));
  const asset = assets.get(resolved);
  if (asset) return asset.out + hash;
  if (!/\.md$/i.test(path)) return href;
  const target = docs.get(resolved);
  if (target) return target.out + hash;
  // Unknown .md target: best-effort swap to .html so it is at least consistent.
  return path.replace(/\.md$/i, '.html') + hash;
}

function inline(text, fromRel, tokens = []) {
  const stash = (html) => {
    tokens.push(html);
    return `\u0000${tokens.length - 1}\u0000`;
  };
  // 1. inline code spans (escaped, no further processing)
  text = text.replace(/`([^`]+)`/g, (_, c) => stash(`<code>${escapeHtml(c)}</code>`));
  // 2. images  ![alt](src)
  text = text.replace(/!\[([^\]]*)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g,
    (_, alt, src) => stash(`<img alt="${escapeHtml(alt)}" src="${escapeHtml(src)}">`));
  // 3. links  [text](href)
  text = text.replace(/\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g,
    (_, label, href) => stash(`<a href="${escapeHtml(rewriteLink(href, fromRel))}">${inline(label, fromRel, tokens)}</a>`));
  // 4. escape everything else
  text = escapeHtml(text);
  // 5. emphasis (bold before italic)
  text = text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
             .replace(/__(.+?)__/g, '<strong>$1</strong>')
             .replace(/(^|[^\*])\*(?!\s)([^*]+?)\*/g, '$1<em>$2</em>')
             .replace(/(^|[^_\w])_(?!\s)([^_]+?)_(?![\w])/g, '$1<em>$2</em>');
  // 6. restore stashed tokens
  text = text.replace(/\u0000(\d+)\u0000/g, (_, i) => tokens[Number(i)]);
  return text;
}

function slugAnchor(s) {
  return s.toLowerCase().trim()
    .replace(/[^\w\s-]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-');
}

function renderMarkdown(md, fromRel) {
  const lines = md.replace(/\r\n?/g, '\n').split('\n');
  const out = [];
  let i = 0;
  let firstH1 = null;

  const isBlank = (l) => l.trim() === '';

  while (i < lines.length) {
    let line = lines[i];

    // Fenced code block
    const fence = line.match(/^(\s*)(`{3,}|~{3,})(.*)$/);
    if (fence) {
      const marker = fence[2][0];
      const lang = fence[3].trim().split(/\s+/)[0] || '';
      const body = [];
      i++;
      while (i < lines.length && !new RegExp(`^\\s*${marker}{3,}\\s*$`).test(lines[i])) {
        body.push(lines[i]); i++;
      }
      i++; // consume closing fence
      const cls = lang ? ` class="language-${escapeHtml(lang)}"` : '';
      out.push(`<pre><code${cls}>${escapeHtml(body.join('\n'))}\n</code></pre>`);
      continue;
    }

    // Blank line
    if (isBlank(line)) { i++; continue; }

    // Heading
    const h = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (h) {
      const level = h[1].length;
      const raw = h[2];
      const anchor = slugAnchor(raw);
      if (level === 1 && firstH1 === null) firstH1 = raw;
      out.push(`<h${level} id="${anchor}">${inline(raw, fromRel)}</h${level}>`);
      i++;
      continue;
    }

    // Horizontal rule
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { out.push('<hr>'); i++; continue; }

    // GFM table: header row followed by a separator row
    if (/^\s*\|?.*\|.*$/.test(line) && i + 1 < lines.length &&
        /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/.test(lines[i + 1]) && lines[i + 1].includes('-')) {
      const splitRow = (r) => {
        let s = r.trim();
        if (s.startsWith('|')) s = s.slice(1);
        if (s.endsWith('|')) s = s.slice(0, -1);
        // split on unescaped pipes
        return s.split(/(?<!\\)\|/).map((c) => c.replace(/\\\|/g, '|').trim());
      };
      const headers = splitRow(lines[i]);
      const aligns = splitRow(lines[i + 1]).map((c) => {
        const l = c.startsWith(':'), r = c.endsWith(':');
        return l && r ? 'center' : r ? 'right' : l ? 'left' : '';
      });
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes('|') && !isBlank(lines[i])) {
        rows.push(splitRow(lines[i])); i++;
      }
      const th = headers.map((c, j) => {
        const a = aligns[j] ? ` style="text-align:${aligns[j]}"` : '';
        return `<th${a}>${inline(c, fromRel)}</th>`;
      }).join('');
      const body = rows.map((cells) =>
        '<tr>' + cells.map((c, j) => {
          const a = aligns[j] ? ` style="text-align:${aligns[j]}"` : '';
          return `<td${a}>${inline(c, fromRel)}</td>`;
        }).join('') + '</tr>').join('\n');
      out.push(`<table>\n<thead><tr>${th}</tr></thead>\n<tbody>\n${body}\n</tbody>\n</table>`);
      continue;
    }

    // Blockquote (contiguous > lines)
    if (/^\s*>/.test(line)) {
      const buf = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*>\s?/, '')); i++;
      }
      out.push(`<blockquote>\n${renderMarkdown(buf.join('\n'), fromRel)}\n</blockquote>`);
      continue;
    }

    // Lists (unordered / ordered / task), nested by indentation
    if (/^\s*([-*+]|\d+[.)])\s+/.test(line)) {
      const consumed = [];
      while (i < lines.length &&
             (/^\s*([-*+]|\d+[.)])\s+/.test(lines[i]) ||
              (/^\s+\S/.test(lines[i]) && consumed.length))) {
        consumed.push(lines[i]); i++;
      }
      out.push(renderList(consumed, fromRel));
      continue;
    }

    // Paragraph: gather until blank / block starter
    const para = [];
    while (i < lines.length && !isBlank(lines[i]) &&
           !/^(\s*)(`{3,}|~{3,})/.test(lines[i]) &&
           !/^#{1,6}\s/.test(lines[i]) &&
           !/^\s*>/.test(lines[i]) &&
           !/^\s*([-*+]|\d+[.)])\s+/.test(lines[i]) &&
           !/^\s*([-*_])(\s*\1){2,}\s*$/.test(lines[i])) {
      para.push(lines[i]); i++;
    }
    if (para.length) out.push(`<p>${inline(para.join('\n').trim(), fromRel)}</p>`);
    else i++;
  }

  return out.join('\n');
}

// Render a flat block of list lines into (possibly nested) <ul>/<ol>.
function renderList(lines, fromRel) {
  // Determine base indentation of this level.
  const items = [];
  let cur = null;
  const baseIndent = lines[0].match(/^(\s*)/)[1].length;
  let ordered = /^\s*\d+[.)]\s+/.test(lines[0]);

  for (const raw of lines) {
    const m = raw.match(/^(\s*)([-*+]|\d+[.)])\s+(.*)$/);
    if (m && m[1].length <= baseIndent) {
      if (cur) items.push(cur);
      cur = { text: m[3], children: [] };
    } else {
      // continuation or nested content of the current item
      if (cur) cur.children.push(raw.slice(Math.min(baseIndent + 2, raw.length - raw.trimStart().length + baseIndent)) === '' ? raw.trim() : raw);
    }
  }
  if (cur) items.push(cur);

  const renderItem = (it) => {
    let text = it.text;
    let taskPrefix = '';
    const task = text.match(/^\[([ xX])\]\s+(.*)$/);
    if (task) {
      const checked = task[1].toLowerCase() === 'x';
      taskPrefix = `<input type="checkbox" disabled${checked ? ' checked' : ''}> `;
      text = task[2];
    }
    let inner = taskPrefix + inline(text, fromRel);
    if (it.children.length) {
      // Re-dedent children and recurse for nested lists / block content.
      const dedented = it.children.map((c) => c.replace(new RegExp(`^\\s{0,${baseIndent + 2}}`), ''));
      if (dedented.some((c) => /^\s*([-*+]|\d+[.)])\s+/.test(c))) {
        inner += '\n' + renderList(dedented.filter((c) => c.trim() !== ''), fromRel);
      } else {
        inner += ' ' + inline(dedented.join(' ').trim(), fromRel);
      }
    }
    const cls = task ? ' class="task"' : '';
    return `<li${cls}>${inner}</li>`;
  };

  const body = items.map(renderItem).join('\n');
  return ordered ? `<ol>\n${body}\n</ol>` : `<ul>\n${body}\n</ul>`;
}

// Extract a human title: first H1, else prettified filename.
function titleOf(md, rel) {
  const m = md.match(/^\s*#\s+(.+?)\s*#*\s*$/m);
  if (m) {
    // strip inline markup for a clean <title>/nav label
    return m[1].replace(/[`*_]/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1').trim();
  }
  const base = rel.split('/').pop().replace(/\.md$/i, '');
  return base;
}

// ---------------------------------------------------------------------------
// 4. Page template + navigation.
// ---------------------------------------------------------------------------

const CSS = `
:root{
  --bg:#fbfbfa; --fg:#1a1a1a; --muted:#666; --line:#e5e3df;
  --accent:#6a4bd6; --code-bg:#f3f1ee; --code-fg:#1a1a1a;
  --side-bg:#f6f5f2; --side-active:#efe9ff; --tbl-head:#f0eee9;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#16161a; --fg:#e6e6e6; --muted:#9a9a9a; --line:#2c2c33;
    --accent:#a98bff; --code-bg:#1f1f26; --code-fg:#e6e6e6;
    --side-bg:#1b1b21; --side-active:#2a2440; --tbl-head:#222229;
  }
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--fg);
  font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased}
.layout{display:flex;min-height:100vh}
.sidebar{width:280px;flex:0 0 280px;background:var(--side-bg);
  border-right:1px solid var(--line);padding:24px 16px;overflow-y:auto;
  position:sticky;top:0;height:100vh}
.sidebar .brand{font-weight:700;font-size:15px;letter-spacing:-.01em;
  display:block;margin:0 8px 18px;color:var(--fg);text-decoration:none}
.sidebar .brand small{display:block;font-weight:400;color:var(--muted);font-size:12px;margin-top:2px}
.sidebar h3{font-size:11px;text-transform:uppercase;letter-spacing:.08em;
  color:var(--muted);margin:18px 8px 6px}
.sidebar a{display:block;padding:5px 8px;border-radius:6px;color:var(--fg);
  text-decoration:none;font-size:14px}
.sidebar a:hover{background:var(--side-active)}
.sidebar a.active{background:var(--side-active);color:var(--accent);font-weight:600}
.content{flex:1;min-width:0;padding:40px min(6vw,64px);max-width:920px}
.content a{color:var(--accent)}
h1,h2,h3,h4,h5,h6{line-height:1.25;margin:1.6em 0 .6em;font-weight:650}
h1{font-size:2rem;margin-top:0;letter-spacing:-.02em}
h2{font-size:1.5rem;border-bottom:1px solid var(--line);padding-bottom:.3em}
h3{font-size:1.2rem}
p{margin:.7em 0}
code{background:var(--code-bg);color:var(--code-fg);padding:.15em .4em;
  border-radius:4px;font:13.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:var(--code-bg);border:1px solid var(--line);border-radius:8px;
  padding:14px 16px;overflow-x:auto;margin:1em 0}
pre code{background:none;padding:0;font-size:13px;color:var(--code-fg)}
blockquote{margin:1em 0;padding:.2em 1em;border-left:3px solid var(--accent);
  color:var(--muted);background:var(--code-bg);border-radius:0 6px 6px 0}
table{border-collapse:collapse;margin:1em 0;display:block;overflow-x:auto;max-width:100%}
th,td{border:1px solid var(--line);padding:7px 12px;text-align:left}
th{background:var(--tbl-head);font-weight:600}
hr{border:none;border-top:1px solid var(--line);margin:2em 0}
ul,ol{padding-left:1.5em;margin:.6em 0}
li{margin:.25em 0}
li.task{list-style:none;margin-left:-1.2em}
li.task input{margin-right:.5em}
img{max-width:100%;height:auto}
.index-hero{margin-bottom:8px}
.index-hero p{color:var(--muted);max-width:60ch}
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:18px;margin-top:24px}
.cat-card{border:1px solid var(--line);border-radius:10px;padding:16px 18px;background:var(--side-bg)}
.cat-card h3{margin:0 0 10px;font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.cat-card ul{list-style:none;padding:0;margin:0}
.cat-card li{margin:2px 0}
.cat-card a{color:var(--fg);text-decoration:none;font-size:14.5px}
.cat-card a:hover{color:var(--accent)}
.footer{margin-top:48px;padding-top:16px;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px}
@media (max-width:820px){
  .layout{flex-direction:column}
  .sidebar{width:100%;flex:none;height:auto;position:static;
    border-right:none;border-bottom:1px solid var(--line)}
  .content{padding:28px 20px}
}
`;

function navHtml(activeRel) {
  let s = `<a class="brand" href="index.html">Shade Tree Grove<small>documentation</small></a>`;
  for (const [cat] of CATEGORIES) {
    const inCat = [...docs.values()]
      .filter((d) => catOf.get(d.rel) === cat && !NAV_EXCLUDED.has(d.rel))
      .sort((a, b) => (orderIn.get(a.rel) - orderIn.get(b.rel)) || a.rel.localeCompare(b.rel));
    if (!inCat.length) continue;
    s += `\n<h3>${escapeHtml(cat)}</h3>`;
    for (const d of inCat) {
      const cls = d.rel === activeRel ? ' class="active"' : '';
      s += `\n<a${cls} href="${d.out}">${escapeHtml(d.title)}</a>`;
    }
  }
  return s;
}

function page(title, activeRel, bodyHtml) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${CSS}</style>
</head>
<body>
<div class="layout">
<nav class="sidebar">${navHtml(activeRel)}</nav>
<main class="content">
${bodyHtml}
<div class="footer">Generated by <code>docs-site/build.mjs</code> · zero dependencies, offline-ready.</div>
</main>
</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// 5. Build.
// ---------------------------------------------------------------------------

rmSync(OUT_DIR, { recursive: true, force: true });
mkdirSync(OUT_DIR, { recursive: true });

const failures = [];
let rendered = 0;

// Preload titles so nav is complete before rendering bodies.
for (const d of docs.values()) {
  const md = readFileSync(d.abs, 'utf8');
  d.md = md;
  d.title = titleOf(md, d.rel);
}

let copied = 0;
for (const asset of assets.values()) {
  try {
    copyFileSync(asset.abs, join(OUT_DIR, asset.out));
    copied++;
  } catch (err) {
    failures.push({ rel: asset.rel, error: err.message });
  }
}

for (const d of docs.values()) {
  try {
    const body = renderMarkdown(d.md, d.rel);
    writeFileSync(join(OUT_DIR, d.out), page(d.title, d.rel, body));
    rendered++;
  } catch (err) {
    failures.push({ rel: d.rel, error: err.message });
  }
}

// Index page.
let indexBody = `<div class="index-hero">
<h1>Documentation</h1>
<p>Browsable index of the <strong>Shade Tree Grove</strong> docs.
Rendered from the repository's markdown by a dependency-free generator.</p>
</div>
<div class="cat-grid">`;
for (const [cat] of CATEGORIES) {
  const inCat = [...docs.values()]
    .filter((d) => catOf.get(d.rel) === cat && !NAV_EXCLUDED.has(d.rel))
    .sort((a, b) => (orderIn.get(a.rel) - orderIn.get(b.rel)) || a.rel.localeCompare(b.rel));
  if (!inCat.length) continue;
  indexBody += `\n<div class="cat-card"><h3>${escapeHtml(cat)}</h3><ul>`;
  for (const d of inCat) {
    indexBody += `\n<li><a href="${d.out}">${escapeHtml(d.title)}</a></li>`;
  }
  indexBody += `\n</ul></div>`;
}
indexBody += `\n</div>`;
writeFileSync(join(OUT_DIR, 'index.html'), page('Documentation', null, indexBody));

// ---------------------------------------------------------------------------
// 6. Report.
// ---------------------------------------------------------------------------

console.log(`docs-site: rendered ${rendered} doc page(s) + index.html and copied ${copied} spec asset(s) -> ${relative(REPO_ROOT, OUT_DIR)}/`);
const catCounts = {};
for (const d of docs.values()) {
  if (!NAV_EXCLUDED.has(d.rel)) catCounts[catOf.get(d.rel)] = (catCounts[catOf.get(d.rel)] || 0) + 1;
}
for (const [cat] of CATEGORIES) {
  if (catCounts[cat]) console.log(`  ${cat}: ${catCounts[cat]}`);
}
if (failures.length) {
  console.log(`\n${failures.length} doc(s) FAILED:`);
  for (const f of failures) console.log(`  ${f.rel}: ${f.error}`);
  process.exitCode = 1;
} else {
  console.log('  all docs converted without error');
}
