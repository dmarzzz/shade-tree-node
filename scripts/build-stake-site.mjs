import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

await build({
  entryPoints: [join(root, "site-src", "stake.mjs")],
  outfile: join(root, "docs", "post", "stake", "stake.js"),
  bundle: true,
  format: "esm",
  minify: true,
  legalComments: "eof",
  sourcemap: false,
  target: ["chrome109", "firefox115", "safari16.4"],
});
