// Every relative link in tracked Markdown resolves to a tracked file (and, for #anchors into
// Markdown, to a heading that exists). External links are not fetched. Guards docs moves.
//   node test/docs-links.selftest.mjs
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const tracked = new Set(execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean));
const markdown = [...tracked].filter((f) => f.endsWith(".md") && !f.includes("node_modules/"));

// GitHub's heading slug: lowercase, drop punctuation except - and _, spaces to -.
const slug = (text) => text.trim().toLowerCase().replace(/<\/?[a-z][^>]*>/gi, "").replace(/[`*_]/g, (c) => (c === "_" ? "_" : ""))
  .replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
const anchorCache = new Map();
function anchors(file) {
  if (!anchorCache.has(file)) {
    const seen = new Map();
    const out = new Set();
    let fenced = false;
    for (const line of readFileSync(join(ROOT, file), "utf8").split("\n")) {
      if (/^\s*```/.test(line)) fenced = !fenced;
      const m = !fenced && line.match(/^#{1,6}\s+(.*?)\s*#*\s*$/);
      if (!m) continue;
      const base = slug(m[1]);
      const n = seen.get(base) || 0;
      seen.set(base, n + 1);
      out.add(n ? `${base}-${n}` : base);
    }
    for (const m of readFileSync(join(ROOT, file), "utf8").matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) out.add(m[1]);
    anchorCache.set(file, out);
  }
  return anchorCache.get(file);
}

const broken = [];
let checked = 0;
for (const file of markdown) {
  const text = readFileSync(join(ROOT, file), "utf8").replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "");
  const links = [...text.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g), ...text.matchAll(/^\[[^\]]+\]:\s*<?(\S+?)>?\s*$/gm)].map((m) => m[1]);
  for (const raw of links) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(raw) || raw.startsWith("//")) continue;
    const [pathPart, anchor] = raw.split("#");
    const target = pathPart ? normalize(join(dirname(file), decodeURI(pathPart))).replace(/\/$/, "") : file;
    checked++;
    if (target.startsWith("..")) { broken.push(`${file}: ${raw} (leaves the repository)`); continue; }
    const isDir = [...tracked].some((t) => t.startsWith(`${target}/`));
    if (!tracked.has(target) && !isDir && !(target === "" || existsSync(join(ROOT, target)) && isDir)) {
      broken.push(`${file}: ${raw}`);
      continue;
    }
    if (anchor && target.endsWith(".md") && tracked.has(target) && !/^L\d+/.test(anchor) && !anchors(target).has(anchor.toLowerCase())) {
      broken.push(`${file}: ${raw} (no heading #${anchor} in ${relative(ROOT, join(ROOT, target))})`);
    }
  }
}
if (broken.length) {
  console.log(`FAIL: ${broken.length} broken relative link(s):\n  ${broken.join("\n  ")}`);
  process.exit(1);
}
console.log(`PASS: docs links (${checked} relative links in ${markdown.length} Markdown files)`);
