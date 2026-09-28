/* global document, IntersectionObserver, navigator, window */

const ARTICLE_ANCHORS = new Set([
  "title-block-header",
  "TOC",
  "access-gated-onion-egress",
  "tor-exit-ips-are-a-public-blocklist",
  "gating-on-membership-not-identity",
  "an-onion-service-instead-of-an-exit-node",
  "a-membership-proof-rate-limited-with-rln",
  "the-wire-protocol",
  "deployment-and-results",
  "discussion",
  "the-design-space",
  "topology",
  "payment",
  "addendum-zk-payment-channels",
  "how-it-would-work",
  "what-it-costs",
  "references",
  "further-reading",
]);

function forwardArticleBookmark() {
  let articleAnchor = "";
  try {
    articleAnchor = decodeURIComponent(window.location.hash.slice(1));
  } catch {
    // A malformed escape sequence is not an article bookmark. Leave it alone.
  }

  if (ARTICLE_ANCHORS.has(articleAnchor)) {
    window.location.replace(`/research/#${encodeURIComponent(articleAnchor)}`);
  }
}

forwardArticleBookmark();
window.addEventListener("hashchange", forwardArticleBookmark);

const copyButtons = [...document.querySelectorAll("[data-copy]")];
const copyStatus = document.createElement("span");
copyStatus.className = "sr-only";
copyStatus.setAttribute("role", "status");
copyStatus.setAttribute("aria-live", "polite");
if (copyButtons.length) document.body.append(copyStatus);

for (const button of copyButtons) {
  button.addEventListener("click", async () => {
    const command = button.dataset.copy;
    if (!command) return;

    const idleLabel = button.textContent;
    const copyNoun = button.dataset.copyNoun || "Command";
    let resetDelay = 1800;
    let restoreCodeTabIndex = null;
    try {
      await navigator.clipboard.writeText(command);
      button.textContent = "copied";
      copyStatus.textContent = `${copyNoun} copied to clipboard.`;
    } catch {
      const copyTarget = button.dataset.copyTarget
        ? document.getElementById(button.dataset.copyTarget)
        : null;
      const visibleCode = copyTarget || button.closest(".command")?.querySelector("code");
      const helper = document.createElement("textarea");
      helper.value = command;
      helper.readOnly = true;
      helper.style.position = "fixed";
      helper.style.left = "-9999px";
      document.body.append(helper);
      let legacyCopied = false;

      try {
        helper.focus();
        helper.select();
        legacyCopied = Boolean(document.execCommand?.("copy"));
      } catch {
        legacyCopied = false;
      } finally {
        helper.remove();
      }

      if (legacyCopied) {
        button.textContent = "copied";
        copyStatus.textContent = `${copyNoun} copied to clipboard.`;
      } else if (visibleCode) {
        const wasHidden = visibleCode.hidden;
        visibleCode.hidden = false;
        visibleCode.closest("details")?.setAttribute("open", "");
        const previousTabIndex = visibleCode.getAttribute("tabindex");
        visibleCode.setAttribute("tabindex", "-1");
        visibleCode.focus();

        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(visibleCode);
        selection?.removeAllRanges();
        selection?.addRange(range);

        restoreCodeTabIndex = () => {
          if (previousTabIndex === null) visibleCode.removeAttribute("tabindex");
          else visibleCode.setAttribute("tabindex", previousTabIndex);
          if (wasHidden) visibleCode.hidden = true;
        };
        button.textContent = "selected";
        copyStatus.textContent = `${copyNoun} selected. Press Control+C or Command+C to copy.`;
        resetDelay = 6000;
      } else {
        button.textContent = "copy manually";
        copyStatus.textContent = `Automatic copy failed. Select the ${copyNoun.toLowerCase()} and copy it.`;
        resetDelay = 6000;
      }
    }

    window.setTimeout(() => {
      restoreCodeTabIndex?.();
      button.textContent = idleLabel;
      copyStatus.textContent = "";
    }, resetDelay);
  });
}

const stage = document.querySelector("#grove-stage");
const canvas = document.querySelector("#grove-canvas");
const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function supportsWebGL2() {
  const probe = document.createElement("canvas");
  let context = null;

  try {
    context = probe.getContext("webgl2", {
      failIfMajorPerformanceCaveat: true,
      powerPreference: "default",
    });
  } catch {
    return false;
  }

  if (!context) return false;
  context.getExtension("WEBGL_lose_context")?.loseContext();
  return true;
}

async function loadGrove() {
  if (!stage || !canvas) return;

  if (connection?.saveData || !supportsWebGL2()) {
    stage.classList.add("use-fallback");
    return;
  }

  try {
    const { mountGrove } = await import("./grove.js");
    mountGrove({ stage, canvas, reducedMotion });
  } catch (error) {
    stage.classList.remove("is-live");
    stage.classList.add("use-fallback");
    console.warn("ShadeNet fell back to its still image.", error);
  }
}

if (stage && "IntersectionObserver" in window) {
  const loader = new IntersectionObserver((entries) => {
    if (!entries.some((entry) => entry.isIntersecting)) return;
    loader.disconnect();
    loadGrove();
  }, { rootMargin: "160px" });
  loader.observe(stage);
} else {
  loadGrove();
}
