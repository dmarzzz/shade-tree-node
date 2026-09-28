import { createReadStream } from "node:fs";
import { access, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "docs", "post");
const HOST = process.env.SITE_HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || process.env.SITE_PORT || 4173);

const CONTENT_TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".txt", "text/plain; charset=utf-8"],
  [".webp", "image/webp"],
  [".xml", "application/xml; charset=utf-8"],
]);

const REWRITES = new Map([
  ["/lab.css", "lab/lab.css"],
  ["/lab.js", "lab/lab.js"],
  ["/api/v2/openapi.json", "openapi-v2.json"],
  // Local stand-ins for the aggregate APIs the Get access page reads (Vercel functions in production).
  ["/api/v1/data/grove/sepolia/head", "grove/network.fallback.json"],
]);
const FIXTURES = new Map([
  ["/api/v1/data/stake/sepolia/head", resolve(dirname(fileURLToPath(import.meta.url)), "..", "test", "fixtures", "stake-head.json")],
]);

function safePath(relativePath) {
  const candidate = resolve(ROOT, normalize(relativePath));
  return candidate === ROOT || candidate.startsWith(`${ROOT}${sep}`) ? candidate : null;
}

async function existingFile(path) {
  if (!path) return null;
  try {
    await access(path);
    return (await stat(path)).isFile() ? path : null;
  } catch {
    return null;
  }
}

async function resolveRequest(pathname) {
  const fixture = FIXTURES.get(pathname);
  if (fixture) return { file: await existingFile(fixture), status: 200 };
  if (pathname === "/canopy" || pathname.startsWith("/canopy/")) pathname = `/grove${pathname.slice("/canopy".length) || "/"}`;
  const rewritten = REWRITES.get(pathname);
  if (rewritten) return { file: await existingFile(safePath(rewritten)), status: 200 };

  const decoded = decodeURIComponent(pathname);
  const relativePath = decoded.replace(/^\/+/, "");
  const candidates = [];

  if (!relativePath || decoded.endsWith("/")) candidates.push(join(relativePath, "index.html"));
  else if (extname(relativePath)) candidates.push(relativePath);
  else candidates.push(`${relativePath}.html`, join(relativePath, "index.html"));

  for (const candidate of candidates) {
    const file = await existingFile(safePath(candidate));
    if (file) return { file, status: 200 };
  }

  return { file: await existingFile(safePath("404.html")), status: 404 };
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://${request.headers.host || `${HOST}:${PORT}`}`);
    const { file, status } = await resolveRequest(url.pathname);

    if (!file) {
      response.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
      response.end("Not found\n");
      return;
    }

    const metadata = await stat(file);
    response.writeHead(status, {
      "Cache-Control": "no-store",
      "Content-Length": metadata.size,
      "Content-Type": CONTENT_TYPES.get(extname(file).toLowerCase()) || "application/octet-stream",
      "X-Content-Type-Options": "nosniff",
    });

    if (request.method === "HEAD") response.end();
    else createReadStream(file).pipe(response);
  } catch (error) {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
    response.end(`Bad request: ${error.message}\n`);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Shade Tree site ready at http://${HOST}:${PORT}`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
