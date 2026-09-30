// Node module-customization hook for scripts/build-stake-site.mjs: the site sources import the
// bundled record as ../network/sepolia/deployment.json; with SHADENET_SITE_NETWORK set to another
// record name (sepolia-staging), that import resolves to network/<name>/deployment.json instead,
// so a staging page renders from the staging record without touching the sources.
let network = "sepolia";

export function initialize(data) {
  network = data?.network || "sepolia";
}

export async function resolve(specifier, context, nextResolve) {
  if (network !== "sepolia" && /(^|\/)network\/sepolia\/deployment\.json$/.test(specifier)) {
    specifier = specifier.replace(/network\/sepolia\/deployment\.json$/, `network/${network}/deployment.json`);
  }
  return nextResolve(specifier, context);
}
