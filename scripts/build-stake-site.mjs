import { rmSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";
import { stakeBuildOptions, STAKE_OUT } from "./stake-build-options.mjs";

rmSync(join(STAKE_OUT, "chunks"), { recursive: true, force: true });
const { metafile } = await build({ ...stakeBuildOptions, metafile: true });
for (const [file, out] of Object.entries(metafile.outputs)) {
  console.log(`${(out.bytes / 1024).toFixed(1).padStart(7)} KiB  ${file}`);
}
