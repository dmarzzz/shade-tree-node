// Flat ESLint config (ESM). Pragmatic ruleset: catch real bugs, not style.
//
//   npm run lint        (eslint .)
//
// Rationale: this lint is a bug net, not a formatter. It flags undefined
// references, unreachable code, duplicate object keys, and constant conditions
// -- classes of mistake that break the egress proxy at runtime -- while leaving
// style untouched so the existing tree passes clean today. Generated / vendored
// / non-JS trees are ignored.

import globals from "globals";

export default [
  {
    // Directories that are generated, vendored, or not first-party Node source.
    ignores: [
      "node_modules/**",
      "out/**",
      "coverage/**",
      "cache/**",
      ".stryker-tmp/**",
      "reports/**",
      "rust/target/**",
      "experiments/**",
      "demo/**",
      "contracts/**",
      "testdata/**",
      "docs/post/stake/stake.js",
      "**/*.min.*",
    ],
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.node,
      },
    },
    rules: {
      // Real-bug net.
      "no-undef": "error",
      "no-unused-vars": ["warn", { args: "none", varsIgnorePattern: "^_" }],
      "no-unreachable": "error",
      "no-constant-condition": ["warn", { checkLoops: false }],
      "no-dupe-keys": "error",
      "no-dupe-args": "error",
      "no-dupe-else-if": "error",
      "no-func-assign": "error",
      "no-cond-assign": ["error", "except-parens"],
      "use-isnan": "error",
      "valid-typeof": "error",
      // Style is intentionally NOT enforced (no semi/quotes/indent/eqeqeq).
      eqeqeq: "off",
    },
  },
  {
    files: ["site-src/**/*.{js,mjs}", "test/site-browser/**/*.{js,mjs}"],
    languageOptions: {
      globals: {
        ...globals.node,
        ...globals.browser,
      },
    },
  },
];
