// The one live number on the Get access page: how many members are staked, which is how large
// the set a proof hides in is. It comes from a same-origin aggregate endpoint (the CSP allows
// only 'self'). Nothing the visitor typed or connected is read or sent here; see
// test/stake-site.selftest.mjs.
export const STAKE_HEAD_URL = "/api/v1/data/stake/sepolia/head";

async function getJson(url) {
  const response = await fetch(url, { headers: { accept: "application/json" }, cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error(`${url} ${response.status}`);
  return response.json();
}

// `tierCount` is how many tiers the set offers: with more than one, the tier narrows the set too.
export function describeSetSize(activeCount, tierCount = 1) {
  const n = Number(activeCount);
  if (!Number.isSafeInteger(n) || n < 0) return null;
  const tell = tierCount > 1 ? "timing and tier" : "timing";
  if (n === 0) return "0 staked members today. The first stakers are easy to single out.";
  if (n < 20) return `${n} staked ${n === 1 ? "member" : "members"} today. A proof hides you among ${n}, so ${tell} can still single you out.`;
  return `${n} staked members today. A proof hides you among them.`;
}

export async function loadLive() {
  const head = await getJson(STAKE_HEAD_URL);
  const size = describeSetSize(head.activeCount, Array.isArray(head.tiers) ? head.tiers.length : 1);
  if (size) for (const node of document.querySelectorAll("[data-live-set]")) node.textContent = size;
}

if (typeof document !== "undefined" && document.querySelector("[data-live-set]")) loadLive().catch(() => {});
