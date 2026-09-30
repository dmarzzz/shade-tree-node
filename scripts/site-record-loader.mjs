// Node module-customization hook for scripts/build-stake-site.mjs: the site sources import the
// bundled record through site-src/record.mjs (network/<default>/deployment.json); with
// SHADENET_SITE_NETWORK set to another record name, that import resolves to
// network/<name>/deployment.json instead, so a page for another record renders without touching
// the sources.
let from = null;
let to = null;

export function initialize(data) {
  from = data?.from || null;
  to = data?.to || null;
}

export async function resolve(specifier, context, nextResolve) {
  if (from && to && from !== to && new RegExp(`(^|/)network/${from}/deployment\\.json$`).test(specifier)) {
    specifier = specifier.replace(new RegExp(`network/${from}/deployment\\.json$`), `network/${to}/deployment.json`);
  }
  return nextResolve(specifier, context);
}
