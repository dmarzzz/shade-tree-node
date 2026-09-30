#!/usr/bin/env node
// Compatibility shim (one minor release): this file moved to packages/node/client/shim.mjs. Re-points
// process.argv[1] first so the moved entry point still runs its main() when invoked here.
import "../packages/node/lib/entry-shim.mjs";
export * from "../packages/node/client/shim.mjs";
