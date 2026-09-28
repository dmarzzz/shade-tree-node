// Live, identity-free numbers for the Get access page: staked set size and announced nodes.
// Both come from same-origin aggregate endpoints (the CSP allows only 'self'). Nothing about the
// visitor's identity, commitment or wallet is read or sent here; see test/stake-site.selftest.mjs.
export const STAKE_HEAD_URL = "/api/v1/data/stake/sepolia/head";
export const CANOPY_HEAD_URL = "/api/v1/data/grove/sepolia/head";

async function getJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" }, cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error(`${url} ${response.status}`);
  return response.json();
}

export function describeSetSize(activeCount) {
  const n = Number(activeCount);
  if (!Number.isSafeInteger(n) || n < 0) return null;
  if (n === 0) return "0 staked members today. The first stakers are easy to single out; a launch cohort is being seeded.";
  if (n < 20) return `${n} staked members today. A proof hides you among ${n}, so timing and tier can still single you out.`;
  return `${n} staked members today. A proof hides you among them.`;
}

function fill(selector, text) {
  for (const node of document.querySelectorAll(selector)) node.textContent = text;
}

export async function loadLive() {
  const [stake, canopy] = await Promise.allSettled([getJson(STAKE_HEAD_URL), getJson(CANOPY_HEAD_URL)]);
  if (stake.status === "fulfilled") {
    const size = describeSetSize(stake.value.activeCount);
    if (size) {
      fill("[data-live-members]", String(stake.value.activeCount));
      fill("[data-live-set]", size);
    }
  }
  if (canopy.status === "fulfilled" && Number.isSafeInteger(canopy.value?.nodes?.announced)) {
    fill("[data-live-nodes]", String(canopy.value.nodes.announced));
  }
}

if (typeof document !== "undefined" && document.querySelector("[data-live-members]")) loadLive().catch(() => {});
