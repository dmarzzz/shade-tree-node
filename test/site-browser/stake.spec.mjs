/* global document, getComputedStyle, navigator, window */

// The Get access page: three steps, one on screen at a time, each inside the viewport, on a
// desktop and on a phone (both Playwright projects run every test here). The wallet is a scripted
// EIP-1193 provider; nothing is sent to a chain.

import { existsSync, readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { identityCommitmentOf, leafFromIdentityCommitment } from "../../packages/node/lib/identity-core.mjs";

// The record the page under test was built from (site-src/record.mjs decides).
const { SITE_NETWORK } = await import("../../site-src/record.mjs");
const RECORD = JSON.parse(readFileSync(new URL(`../../network/${SITE_NETWORK}/deployment.json`, import.meta.url), "utf8"));
const STAKED = RECORD.admission.roots.staked;
const TIERS = STAKED.tiers;
const DEFAULT = TIERS.find((t) => t.limit === STAKED.defaultLimit) || TIERS[0];
// With one tier the page does not name it in status lines.
const atTier = TIERS.length > 1 ? ` at tier ${DEFAULT.limit}` : "";
const tierNote = TIERS.length > 1 ? `: a tier ${DEFAULT.limit} identity` : "";
const BONDS = Object.fromEntries(TIERS.map((t) => [t.limit, t.bondWei]));
const eth = (wei) => { const v = BigInt(wei); const whole = v / 10n ** 18n; const frac = (v % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, ""); return frac ? `${whole}.${frac}` : `${whole}`; };
const stakeName = (tier) => new RegExp(`^Stake ${eth(tier.bondWei).replace(".", "\\.")} Sepolia ETH$`);

// The shared Rust and Semaphore-v3 vector: a secret, its public identity commitment, its leaves.
const SECRET = "619880168657502627082950702222527535803368023538932999730878823680368560389";
const IDC = identityCommitmentOf(SECRET).toString();
const leafAt = (limit) => leafFromIdentityCommitment(IDC, limit).toString();
const ACCOUNT = "0x1000000000000000000000000000000000000001";
const TX_HASH = `0x${"ab".repeat(32)}`;

// A scripted wallet. `overrides` swaps single methods; `member` is what the contract says about
// the commitment; window.__member, __reject and __answer change it while a test runs.
async function mockWallet(page, { overrides = {}, member = {} } = {}) {
  await page.addInitScript(({ account, hash, overrides, bonds, member }) => {
    const calls = (window.__walletCalls = []);
    window.__member = member;
    const fixed = {
      eth_requestAccounts: [account],
      wallet_switchEthereumChain: null,
      eth_chainId: "0xaa36a7",
      eth_getCode: "0x60006000",
      eth_getBalance: "0x1bc16d674ec80000",
      eth_estimateGas: "0x100000",
      eth_gasPrice: "0x3b9aca00",
      eth_sendTransaction: hash,
      eth_getTransactionReceipt: { status: "0x1", transactionHash: hash, blockNumber: "0x100" },
      eth_getBlockByNumber: { number: "0xf0" },
      ...overrides,
    };
    const word = (value) => `0x${BigInt(value).toString(16).padStart(64, "0")}`;
    window.ethereum = {
      on() {},
      async request({ method, params = [] }) {
        calls.push({ method, params });
        const rejection = window.__reject?.[method];
        if (rejection) { const error = new Error(rejection.message); error.code = rejection.code; throw error; }
        if (window.__answer && method in window.__answer) return window.__answer[method];
        if (method in fixed) return fixed[method];
        const state = window.__member || {};
        if (method === "eth_getLogs") return state.finalized ? [{}] : [];
        if (method === "eth_call") {
          const data = params[0]?.data || "";
          if (data.startsWith("0x82afd23b")) return word(state.active ? 1 : 0); // isActive
          if (data.startsWith("0xd57b50e7")) return word(state.limit || 0); // limitOf
          if (data.startsWith("0xde259775")) return word(state.withdrawableAt || 0); // withdrawableAt
          if (data.startsWith("0xe0b91f92")) return word(bonds[Number(BigInt(`0x${data.slice(10)}`))] || 0); // bondFor
          return "0x";
        }
        throw new Error(`unexpected wallet method ${method}`);
      },
    };
  }, { account: ACCOUNT, hash: TX_HASH, overrides, bonds: BONDS, member });
}

const panel = (page, name) => page.locator(`[data-panel="${name}"]`);
const field = (page) => page.locator("[data-commitment]");
const message = (page) => page.locator("[data-commitment-message]");
const primary = (page) => page.locator("[data-primary]");

async function open(page, hash = "") {
  await page.goto(`/stake/${hash}`, { waitUntil: "networkidle" });
  await expect(page.locator("html")).toHaveAttribute("data-access", "ready");
}

async function enterFlow(page) {
  if (await panel(page, "setup").isVisible().catch(() => false)) return;
  await page.locator(".access-paths").getByRole("link", { name: "Start" }).click();
  await expect(panel(page, "setup")).toBeVisible();
}

async function toStake(page) {
  await enterFlow(page);
  await field(page).fill(IDC);
  await panel(page, "setup").getByRole("link", { name: "Next" }).click();
  await expect(panel(page, "stake")).toBeVisible();
}

async function connect(page) {
  await toStake(page);
  await primary(page).click();
  await expect(primary(page)).toHaveText(stakeName(DEFAULT));
}

// The whole document is inside the viewport: nothing to scroll, down or sideways.
async function expectFits(page, what) {
  const size = await page.evaluate(() => ({
    height: document.documentElement.scrollHeight, viewport: window.innerHeight,
    width: document.documentElement.scrollWidth, client: document.documentElement.clientWidth,
    used: Math.ceil(document.querySelector(".panel[data-current]").getBoundingClientRect().bottom),
  }));
  expect(size.height, `${what}: page height`).toBeLessThanOrEqual(size.viewport);
  expect(size.used, `${what}: the step's own bottom edge`).toBeLessThanOrEqual(size.viewport);
  expect(size.width, `${what}: page width`).toBeLessThanOrEqual(size.client + 1);
}

async function expectAccessible(page) {
  const result = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  expect(result.violations).toEqual([]);
}

test("each step shows alone, fits the viewport, and is accessible", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (entry) => { if (entry.type() === "error") errors.push(entry.text()); });
  await mockWallet(page);
  await open(page);

  await expect(page.getByRole("heading", { level: 1, name: "Get Access" })).toBeVisible();
  // First screen: the chooser shows both paths; the steps stay hidden until you start.
  for (const name of ["setup", "stake", "start", "details"]) await expect(panel(page, name)).toBeHidden();
  await expect(page.getByRole("heading", { level: 3, name: "For agents" })).toBeVisible();
  await expect(page.getByRole("heading", { level: 3, name: "For humans" })).toBeVisible();
  await expect(page.locator(".access-paths [data-copy-brief]")).toBeVisible();
  await expectFits(page, "the chooser");
  await expectAccessible(page);

  // The agent's whole brief copies from the first screen (shown as its first sentence, copied in full).
  await page.locator(".access-paths").getByRole("button", { name: "copy agent brief" }).click();
  const copiedBrief = await page.evaluate(() => navigator.clipboard.readText());
  const landingHtml = readFileSync(new URL("../../docs/post/index.html", import.meta.url), "utf8");
  const briefSource = landingHtml.match(/<code id="agent-setup-task"[^>]*>([\s\S]*?)<\/code>/)[1].trim().replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
  expect(copiedBrief).toBe(briefSource);

  await page.locator(".access-paths").getByRole("link", { name: "Start" }).click();
  await expect(panel(page, "setup")).toBeVisible();
  for (const name of ["choose", "stake", "start", "details"]) await expect(panel(page, name)).toBeHidden();
  await expect(page.locator('[data-step-link="setup"]')).toHaveAttribute("aria-current", "step");
  await expect(page.getByText("Run these on the machine where your agent runs.")).toBeVisible();
  await expectFits(page, "step 1, empty");
  await expectAccessible(page);

  // An error message takes room too.
  await field(page).fill(`leaf ${leafAt(DEFAULT.limit)}`);
  await expect(message(page)).toHaveText(/That is the leaf/);
  await expectFits(page, "step 1, invalid");

  await toStake(page);
  await expect(panel(page, "setup")).toBeHidden();
  await expect(page.locator('[data-step-link="stake"]')).toHaveAttribute("aria-current", "step");
  await expect(page.locator('[data-step-link="setup"]')).not.toHaveAttribute("aria-current", "step");
  await expect(page.locator("#stake-title")).toBeFocused();
  await expectFits(page, "step 2, no wallet connected");
  await expectAccessible(page);

  await primary(page).click();
  await expect(primary(page)).toHaveText(stakeName(DEFAULT));
  await expect(page.locator("[data-preview-statement]")).toBeVisible();
  await expectFits(page, "step 2, wallet connected");
  await expectAccessible(page);

  await panel(page, "stake").getByRole("link", { name: "Next" }).click();
  await expect(page.locator('[data-step-link="start"]')).toHaveAttribute("aria-current", "step");
  await expect(page.getByRole("tabpanel", { name: "Human" })).toBeVisible();
  await expectFits(page, "step 3, Human");
  await expectAccessible(page);
  await page.getByRole("tab", { name: "Agent" }).click();
  await expectFits(page, "step 3, Agent");
  await expectAccessible(page);

  await panel(page, "start").getByRole("link", { name: "Leave and details" }).click();
  await expect(page.getByRole("heading", { name: "Leave and details" })).toBeVisible();
  await expect(page.locator("[data-stepper]")).toBeHidden();
  for (const summary of await page.locator("#details summary").all()) {
    await summary.click();
    await expectFits(page, `details: ${(await summary.textContent()).trim()}`);
  }
  await expect(page.locator("#details details[open]")).toHaveCount(1);
  await expect(page.locator("[data-live-set]")).toHaveText(/3 staked members today/);
  await expectAccessible(page);
  await page.getByRole("link", { name: "Back to the steps" }).click();
  await expect(panel(page, "start")).toBeVisible();

  // The browser's own back button walks the steps too.
  await page.goBack();
  await expect(panel(page, "details")).toBeVisible();
  await page.goBack();
  await expect(panel(page, "start")).toBeVisible();
  await page.goBack();
  await expect(panel(page, "stake")).toBeVisible();
  expect(errors).toEqual([]);
});

test("controls are at least 44 px tall and commands scroll in place where they do not fit", async ({ page }) => {
  await open(page);
  await enterFlow(page);
  const targets = page.locator(".stepper a, .panel[data-current] .cmd button, .panel[data-current] .panel-nav a");
  for (const target of await targets.all()) {
    const box = await target.boundingBox();
    expect(box.height, await target.textContent()).toBeGreaterThanOrEqual(44);
  }
  // The install line is never wrapped inside a flag: it keeps its lines and scrolls inside its plate.
  const install = panel(page, "setup").locator(".cmd pre").first();
  await expect(install).toHaveCSS("white-space", "pre");
  const scroll = await install.evaluate((node) => ({ scroll: node.scrollWidth, client: node.clientWidth, more: node.hasAttribute("data-more") }));
  expect(scroll.more).toBe(scroll.scroll - scroll.client > 2);
  await panel(page, "setup").getByRole("button", { name: "Copy: Install the ShadeNet client" }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied.replace(/\s*\\\n\s*/g, " ")).toMatch(/^curl -fsSL --proto '=https' --proto-redir '=https' https:\/\/raw\.githubusercontent\.com\/dmarzzz\/shade-tree-node\/main\/scripts\/install\.sh \| SHADENET_VERSION=v\d+\.\d+\.\d+ sh$/);
});

test("the shared nav on Get access is the one every page has", async ({ page }) => {
  const measure = () => page.evaluate(() => {
    const type = (node) => { const s = getComputedStyle(node); return { family: s.fontFamily, size: s.fontSize, weight: s.fontWeight, spacing: s.letterSpacing, color: s.color }; };
    const box = (node) => { const r = node.getBoundingClientRect(); return { x: Math.round(r.x * 10) / 10, y: Math.round(r.y * 10) / 10, width: Math.round(r.width * 10) / 10, height: Math.round(r.height * 10) / 10 }; };
    const nav = document.querySelector(".site-nav");
    const links = [...document.querySelectorAll(".nav-links a")];
    return {
      nav: box(nav),
      wordmark: { ...type(document.querySelector(".wordmark")), ...box(document.querySelector(".wordmark")) },
      firstLink: type(links[0]),
      // The current page's link carries the site's own "you are here" colour; the rest must match.
      links: links.map((link) => ({ label: link.textContent, ...box(link), family: getComputedStyle(link).fontFamily, size: getComputedStyle(link).fontSize, weight: getComputedStyle(link).fontWeight })),
    };
  });
  await page.goto("/canopy/", { waitUntil: "load" });
  const reference = await measure();
  await open(page);
  const stake = await measure();
  expect(stake.wordmark).toEqual(reference.wordmark);
  expect(stake.firstLink.family).toBe(reference.firstLink.family);
  expect(stake.firstLink.size).toBe(reference.firstLink.size);
  expect(stake.firstLink.weight).toBe(reference.firstLink.weight);
  expect(stake.firstLink.spacing).toBe(reference.firstLink.spacing);
  expect(stake.links).toEqual(reference.links);
  expect(stake.nav).toEqual(reference.nav);
});

test("the pasted value is checked and each mistake is named", async ({ page }) => {
  await open(page);
  await enterFlow(page);
  const next = panel(page, "setup").getByRole("link", { name: "Next" });

  await next.click();
  await expect(message(page)).toHaveText("Paste the identity commitment that shadenet init prints.");
  await expect(field(page)).toHaveAttribute("aria-invalid", "true");
  await expect(field(page)).toBeFocused();
  await expect(panel(page, "stake")).toBeHidden();

  for (const [text, reason] of [
    [IDC.slice(0, 40), /That is 40 digits\. The identity commitment has about 77/],
    [`0x${BigInt(IDC).toString(16)}`, /decimal number shadenet init prints, without 0x/],
    [`${IDC}abc`, /other characters/],
    [`${IDC}${IDC}`, /too large/],
    [`  leaf ${leafAt(DEFAULT.limit)}`, /That is the leaf\. Paste the identity commitment, which is a different number\./],
  ]) {
    await field(page).fill(text);
    await expect(message(page)).toHaveText(reason);
    await expect(field(page)).toHaveAttribute("aria-invalid", "true");
    await next.click();
    await expect(panel(page, "stake")).toBeHidden();
  }

  await field(page).fill(IDC);
  await expect(message(page)).toHaveText(/digits, ending 128114\.$/);
  await expect(field(page)).not.toHaveAttribute("aria-invalid", "true");

  // The lines the CLI prints, pasted whole: the number is taken out and checked against its leaf.
  await field(page).fill(`  identity commitment ${IDC}\n  leaf ${leafAt(DEFAULT.limit)}`);
  await expect(field(page)).toHaveValue(IDC);
  await expect(message(page)).toHaveText(`Checked against its leaf${tierNote}.`);
  await field(page).press("Enter");
  await expect(panel(page, "stake")).toBeVisible();
  await expect(page.locator("[data-commitment-shown]")).toHaveText(`${IDC.slice(0, 10)}…${IDC.slice(-8)}`);
});

test("a link's fragment fills the commitment and opens the stake step", async ({ page }) => {
  await mockWallet(page);
  const requests = [];
  page.on("request", (request) => requests.push(request.url()));
  await open(page, `#c=${IDC}&limit=${DEFAULT.limit}&leaf=${leafAt(DEFAULT.limit)}`);
  await expect(panel(page, "stake")).toBeVisible();
  await expect(page.locator("[data-commitment-shown]")).toHaveText(`${IDC.slice(0, 10)}…${IDC.slice(-8)}`);
  await expect(page.locator('[data-step-link="setup"]')).toHaveAttribute("data-done", "");
  // A fragment never leaves the browser, and the page sends the value to no server of its own.
  expect(requests.filter((url) => url.includes(IDC) || url.includes("c="))).toEqual([]);
  if (TIERS.length > 1) {
    await expect(page.locator("[data-tier-hint]")).toHaveText(`Tier ${DEFAULT.limit}, checked against the identity's leaf.`);
    await expect(page.locator(".tier-pick")).toBeHidden();
  }
  await page.getByRole("button", { name: "copy link" }).click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toMatch(new RegExp(`/stake/#c=${IDC}&limit=${DEFAULT.limit}&leaf=${leafAt(DEFAULT.limit)}$`));
  await panel(page, "stake").getByRole("link", { name: "Back", exact: true }).click();
  await expect(field(page)).toHaveValue(IDC);
  await expect(message(page)).toHaveText(`From your link. Checked against its leaf${tierNote}.`);

  // The bare form works too, and a link that cannot be right stays on step 1 and says why.
  await page.goto("about:blank");
  await open(page, `#c=${IDC}`);
  await expect(panel(page, "stake")).toBeVisible();
  await page.goto("about:blank");
  await open(page, `#c=${IDC}&leaf=${IDC}`);
  await expect(panel(page, "setup")).toBeVisible();
  await expect(message(page)).toHaveText(/^The link is not usable\. The leaf does not match this identity commitment/);
  await page.goto("about:blank");
  await open(page, `#c=${IDC.slice(0, 20)}`);
  await expect(panel(page, "setup")).toBeVisible();
  await expect(message(page)).toHaveText(/^The link is not usable\. That is 20 digits/);
});

test("a reload keeps the step and the pasted commitment, and stores nothing else", async ({ page }) => {
  await open(page);
  await toStake(page);
  await page.reload({ waitUntil: "networkidle" });
  await expect(panel(page, "stake")).toBeVisible();
  await expect(page.locator("[data-commitment-shown]")).toHaveText(`${IDC.slice(0, 10)}…${IDC.slice(-8)}`);
  await panel(page, "stake").getByRole("link", { name: "Next" }).click();
  await page.reload({ waitUntil: "networkidle" });
  await expect(panel(page, "start")).toBeVisible();
  const stored = await page.evaluate(() => ({ session: { ...window.sessionStorage }, local: { ...window.localStorage } }));
  expect(Object.keys(stored.local)).toEqual([]);
  expect(Object.keys(stored.session)).toEqual(["shadenet.access.v1"]);
  expect(JSON.parse(stored.session["shadenet.access.v1"])).toEqual({ panel: "start", input: IDC, tx: null, limit: DEFAULT.limit });
});

test("Get access stakes the pinned transaction for the pasted commitment and follows finality to admitted", async ({ page }) => {
  await mockWallet(page);
  await open(page);
  await toStake(page);
  await expect(page.locator("[data-privacy-note]")).toContainText("Staking links your wallet to this membership on chain, permanently.");
  await expect(page.locator("[data-privacy-note]").getByRole("link", { name: "Railgun" })).toHaveAttribute("href", "https://www.railgun.org/");
  await expect(page.locator("[data-privacy-note]").getByRole("link", { name: "agent-boost" })).toHaveAttribute("href", "https://github.com/dmarzzz/agent-boost");
  await primary(page).click();
  // The wallet's balance is judged before any stake: the mock holds 2 ETH.
  await expect(page.locator("[data-balance]")).toHaveText("2 Sepolia ETH, enough for the bond and gas.");
  await expect(page.locator("[data-preview-statement]")).toContainText("ShadeNet is a research preview on Sepolia.");
  await expect(primary(page)).toHaveText(stakeName(DEFAULT));

  // Finality is still behind the stake's block (0x100): the bar waits, the page does not claim admission.
  await page.evaluate(() => { window.__answer = { eth_getBlockByNumber: { number: "0xe0" } }; });
  await primary(page).click();
  await expect(page.locator("[data-status]")).toHaveText("Stake confirmed.");
  await expect(page.locator("[data-finality]")).toHaveText(/^\d+ blocks? to Sepolia finality, about \d+ min\. You can go on to step 3 meanwhile\.$/);
  await expect(page.locator("[data-member-state]")).toBeHidden();
  await expect(primary(page)).toBeHidden();
  await expect(page.locator("[data-before-stake]")).toBeHidden();
  await expect(page.locator("[data-receipt-link]")).toHaveAttribute("href", `https://sepolia.etherscan.io/tx/${TX_HASH}`);
  await expect(page.locator('[data-step-link="stake"]')).toHaveAttribute("aria-current", "step");
  await expect(page.locator("[data-next-start]")).toHaveClass(/solid-action/);
  await expectFits(page, "step 2, waiting for finality");

  const sent = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_sendTransaction"));
  expect(sent.params[0].to.toLowerCase()).toBe(STAKED.contract.toLowerCase());
  expect(BigInt(sent.params[0].value)).toBe(BigInt(DEFAULT.bondWei));
  // registerIdentity(identityCommitment, limit): the page sends exactly the value that was pasted.
  expect(sent.params[0].data).toMatch(/^0x9b7b5b80/);
  expect(BigInt(`0x${sent.params[0].data.slice(10, 74)}`)).toBe(BigInt(IDC));
  expect(BigInt(`0x${sent.params[0].data.slice(74, 138)}`)).toBe(BigInt(DEFAULT.limit));
  // Status is read for the leaf the contract derives from that commitment at that tier.
  const statusCall = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_call" && call.params[0].data.startsWith("0x82afd23b")));
  expect(BigInt(`0x${statusCall.params[0].data.slice(10)}`)).toBe(BigInt(leafAt(DEFAULT.limit)));

  // The chain finalizes the block and the contract shows the member: admitted.
  await page.evaluate((limit) => { window.__answer = { eth_getBlockByNumber: { number: "0x101" } }; window.__member = { active: true, limit, finalized: true }; }, DEFAULT.limit);
  await expect(page.locator("[data-member-state]")).toHaveText(`Admitted${atTier}. The stake is final and nodes accept this identity.`, { timeout: 20_000 });
  await expect(page.locator("[data-finality-panel]")).toBeHidden();
  await expectFits(page, "step 2, admitted");
  await expectAccessible(page);
  await panel(page, "stake").getByRole("link", { name: "Next" }).click();
  await expect(page.locator("[data-start-state]")).toHaveText("Admitted. Nodes accept this identity.");
  expect(await page.evaluate(() => window.__walletCalls.filter((call) => call.method === "eth_sendTransaction").length)).toBe(1);

  // After a reload the stake is still shown; reconnecting reads the real state and sends nothing.
  await page.reload({ waitUntil: "networkidle" });
  await panel(page, "start").getByRole("link", { name: "Back", exact: true }).click();
  await expect(page.locator("[data-status]")).toHaveText(/Connect the wallet again to follow finality here/);
  await expect(page.locator("[data-receipt-link]")).toBeVisible();
});

test("a commitment that is already staked goes straight to its state and nothing is sent", async ({ page }) => {
  await mockWallet(page, { member: { active: true, limit: DEFAULT.limit, finalized: true } });
  await open(page);
  await toStake(page);
  await primary(page).click();
  await expect(page.locator("[data-member-state]")).toHaveText(/^Admitted[ .]/);
  await expect(primary(page)).toBeHidden();
  expect(await page.evaluate(() => window.__walletCalls.some((call) => call.method === "eth_sendTransaction"))).toBe(false);
});

test("with several tiers the chosen tier is staked at its own bond", async ({ page }) => {
  test.skip(TIERS.length < 2, "the record has one tier: the page offers no choice");
  const other = TIERS.find((t) => t.limit !== DEFAULT.limit);
  await mockWallet(page);
  await open(page);
  await toStake(page);
  await page.getByRole("radio", { name: `tier ${other.limit}` }).check();
  await expect(page.locator("[data-bond]")).toHaveText(`${eth(other.bondWei)} Sepolia ETH`);
  await primary(page).click();
  await expect(primary(page)).toHaveText(stakeName(other));
  await primary(page).click();
  await expect(page.locator("[data-status]")).toHaveText("Stake confirmed.");
  const sent = await page.evaluate(() => window.__walletCalls.find((call) => call.method === "eth_sendTransaction"));
  expect(BigInt(sent.params[0].value)).toBe(BigInt(other.bondWei));
  expect(BigInt(`0x${sent.params[0].data.slice(74, 138)}`)).toBe(BigInt(other.limit));
});

test("with one tier there is no tier choice at all", async ({ page }) => {
  test.skip(TIERS.length !== 1, "the record has several tiers");
  await open(page);
  await expect(page.getByRole("radio")).toHaveCount(0);
});

test("stake step errors are announced as alerts, fit the screen and send nothing", async ({ page }) => {
  await mockWallet(page, { overrides: { eth_chainId: "0x1" } });
  await open(page);
  await toStake(page);
  await primary(page).click();
  await expect(page.getByRole("alert")).toHaveText("The wallet is not on Sepolia. Switch its network to Sepolia and connect again.");
  await expect(primary(page)).toHaveText("Connect wallet");
  await expectFits(page, "step 2, wrong network");

  // Back on Sepolia with an empty wallet: told how much it is short before anything is sent.
  await page.evaluate(() => { window.__answer = { eth_chainId: "0xaa36a7", eth_getBalance: "0x1" }; });
  await primary(page).click();
  await expect(page.locator("[data-balance]")).toHaveText(/^under 0\.000001 Sepolia ETH\. The bond and gas come to about [\d.]+ ETH, so this wallet needs about [\d.]+ ETH more\.$/);
  await primary(page).click();
  await expect(page.getByRole("alert")).toHaveText("Not enough Sepolia ETH in this wallet. Faucets are under Leave and details. Someone else can stake for you: copy the link and send it to them.");
  await expectFits(page, "step 2, not enough ETH");

  // Funded, then the visitor cancels in the wallet.
  await page.evaluate(() => { window.__answer = { eth_chainId: "0xaa36a7" }; window.__reject = { eth_sendTransaction: { code: 4001, message: "User rejected the request." } }; });
  await page.getByRole("button", { name: "change" }).click();
  await expect(page.locator("[data-balance]")).toHaveText(/enough for the bond and gas/);
  await primary(page).click();
  await expect(page.getByRole("alert")).toHaveText("You cancelled in the wallet. Nothing was sent. Press the button again when you are ready.");
  await expectFits(page, "step 2, cancelled");
  expect(await page.evaluate(() => window.__walletCalls.some((call) => call.method === "eth_sendTransaction" && !window.__reject))).toBe(false);

  // A reverted transaction is reported and never shown as a stake.
  await page.evaluate((hash) => { window.__reject = null; window.__answer = { eth_chainId: "0xaa36a7", eth_getTransactionReceipt: { status: "0x0", transactionHash: hash, blockNumber: "0x100" } }; }, TX_HASH);
  await primary(page).click();
  await expect(page.getByRole("alert")).toHaveText(/^Sepolia rejected the transaction/);
  await expect(page.locator("[data-finality-panel]")).toBeHidden();
  await expect(page.locator("[data-member-state]")).toBeHidden();
  await expect(primary(page)).toHaveText(stakeName(DEFAULT));
});

test("without a browser wallet the step says so and offers the terminal command", async ({ page }) => {
  await open(page);
  await toStake(page);
  await expect(page.locator("[data-terminal-text]")).toHaveText(/^No wallet in this browser\. On a phone, open this page inside your wallet app\./);
  await primary(page).click();
  await expect(page.getByRole("alert")).toHaveText("No wallet was found in this browser.");
  await panel(page, "stake").getByRole("button", { name: "Copy: Stake from the terminal" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("shadenet register-member --identity ~/.config/shadenet/identity.json --key-file funded.key");
  await expectFits(page, "step 2, no wallet");
});

test("Start has a Human and an Agent tab, by click and by arrow keys, and the commands copy", async ({ page }) => {
  await open(page);
  await page.locator('[data-step-link="start"]').click();
  const tabs = page.getByRole("tab");
  await expect(tabs).toHaveCount(2);
  await expect(page.getByRole("tabpanel", { name: "Human" })).toBeVisible();
  await expect(page.getByRole("tabpanel", { name: "Agent" })).toBeHidden();
  for (const [label, command] of [
    ["Wait until the identity is admitted", "shadenet status --wait"],
    ["Start the proxy", "shadenet proxy"],
    ["Run your agent through the proxy", "shadenet run --no-proxy api.openai.com -- your-agent"],
  ]) {
    const button = page.getByRole("button", { name: `Copy: ${label}` });
    await button.click();
    await expect(button).toHaveText("copied");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(command);
  }
  await tabs.first().focus();
  await tabs.first().press("ArrowRight");
  await expect(page.getByRole("tabpanel", { name: "Agent" })).toBeVisible();
  await expect(page.getByRole("tabpanel", { name: "Human" })).toBeHidden();
  await expect(tabs.nth(1)).toBeFocused();
  await page.getByRole("button", { name: "Copy: Serve the ShadeNet MCP tools" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("shadenet mcp");
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("the page is a readable document: every step in order, the commands, no dead controls", async ({ page }) => {
    await page.goto("/stake/", { waitUntil: "load" });
    await expect(page.getByRole("heading", { level: 1, name: "Get Access" })).toBeVisible();
    const tops = [];
    for (const name of ["setup", "stake", "start", "details"]) {
      await expect(panel(page, name)).toBeVisible();
      tops.push((await panel(page, name).boundingBox()).y);
    }
    expect([...tops].sort((a, b) => a - b)).toEqual(tops);
    for (const text of ["shadenet init", "shadenet status --wait", "shadenet proxy", "shadenet mcp"]) {
      await expect(page.locator("pre code").filter({ hasText: new RegExp(`^${text}$`) })).toBeVisible();
    }
    await expect(page.locator("pre code").filter({ hasText: "shadenet register-member" })).toBeVisible();
    await expect(page.locator("pre code").filter({ hasText: "shadenet exit-member" })).toBeVisible();
    await expect(page.locator("[data-privacy-note]")).toBeVisible();
    await expect(page.locator("[data-preview-statement]")).toBeVisible();
    await expect(page.locator("noscript p")).toHaveText(/^Staking from a browser wallet needs JavaScript\./);
    // Nothing that needs a script is offered.
    await expect(page.locator(".needs-script:visible")).toHaveCount(0);
    await expect(page.getByRole("tablist")).toBeHidden();
    await expect(page.getByRole("heading", { level: 3, name: "Human", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { level: 3, name: "Agent", exact: true })).toBeVisible();
    // The step links are plain anchors and still move through the document.
    await page.locator('[data-step-link="start"]').click();
    await expect(page).toHaveURL(/#start$/);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
    expect(overflow).toBe(false);
  });
});

test("Get access steps match their approved visual baselines", async ({ page }, testInfo) => {
  // Mono and sans system fonts differ between macOS and Linux Chromium; one reviewed baseline per
  // platform. A platform whose baselines have not been reviewed in yet is skipped, not guessed.
  const os = process.platform === "darwin" ? "-macos" : "";
  const names = ["stake-setup", "stake-stake", "stake-start"].map((name) => `${name}${os}.png`);
  test.skip(!testInfo.config.updateSnapshots.match(/all|changed/) && names.some((name) => !existsSync(testInfo.snapshotPath(name))), `no reviewed ${process.platform} baselines for the Get access steps yet`);
  await mockWallet(page);
  await open(page);
  // The canopy grove is a live, animated canvas; masking it keeps the baseline on the chrome
  // (type, hairlines, rows, the one amber action) deterministic while the grove drifts behind.
  const mask = [page.locator(".canopy")];
  await expect(page.locator(".access")).toHaveScreenshot(names[0], { timeout: 30_000, mask });
  await connect(page);
  await expect(page.locator(".access")).toHaveScreenshot(names[1], { timeout: 30_000, mask });
  await panel(page, "stake").getByRole("link", { name: "Next" }).click();
  await expect(page.locator(".access")).toHaveScreenshot(names[2], { timeout: 30_000, mask });
});
