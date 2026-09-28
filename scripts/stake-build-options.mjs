// The one esbuild configuration for the /stake page, shared by scripts/build-stake-site.mjs and
// test/stake-site.selftest.mjs (which rebuilds and compares every output byte for byte).
// Code splitting keeps snarkjs (exit and withdraw proofs) in a lazy chunk, so staking loads
// only the SDK's identity and staking code (STAKE-14).
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const STAKE_OUT = join(ROOT, "docs", "post", "stake");

export const stakeBuildOptions = {
  entryPoints: { stake: join(ROOT, "site-src", "stake.mjs") },
  outdir: STAKE_OUT,
  chunkNames: "chunks/[name]-[hash]",
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "browser",
  minify: true,
  legalComments: "eof",
  sourcemap: false,
  target: ["chrome109", "firefox115", "safari16.4"],
  absWorkingDir: ROOT,
};
