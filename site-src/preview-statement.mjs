// The research preview statement, defined once and reused everywhere. One text in two lengths:
// the long form opens with the short form. The wording is owner-approved and must stay identical
// across every surface (the site, the README warning box, SECURITY.md, the installer, the docs).
// test/site.selftest.mjs pins the on-site copy against these constants so it cannot drift.
//
// Sources for every claim are in ~/shadenet-launch/COPY-OPTIONS.md section 2.

export const PREVIEW_STATEMENT_SHORT =
  "ShadeNet is a research preview on Sepolia. The code is unaudited, the proof keys come from a trusted setup, and it should not be considered secure against a motivated actor: do not use it for real funds or sensitive traffic.";

export const PREVIEW_STATEMENT_CEREMONY =
  "The proof keys are the output of the RLN trusted setup ceremony that Privacy & Scaling Explorations (PSE) ran in 2023. ShadeNet did not run the ceremony. This project adopted its output and re-verified it from public inputs, and no outside verifier has confirmed that check yet. The keys are sound if at least one contributor to each was honest (60 contributed to the membership key, 62 to the withdrawal key). If all of them colluded, proofs could be forged.";

export const PREVIEW_STATEMENT_REASONS_LEAD =
  "Reasons it should not be considered secure against a motivated actor:";

export const PREVIEW_STATEMENT_REASONS = Object.freeze([
  "One operator runs every Shade Tree node and both Elder Trees, so one party sees the destination and timing of every tunnel.",
  "Every Shade Tree node is hosted at one provider.",
  "The member set is small, so each member hides among few others.",
  "The Elder Trees' signers choose the node list a client sees, and can omit nodes or add their own.",
  "Rate limits are enforced per node. Replay protection across nodes is best effort and fails open.",
  "A wallet that stakes is linked to its member commitment on chain, publicly and permanently.",
  "The node that serves a tunnel sees the destination hostname, the timing and the byte counts.",
  "Tor does not stop an observer who watches both ends of a tunnel from correlating timing.",
]);

// The short launch banner, option 2. The site strip and the README note both read this line.
export const PREVIEW_BANNER_LINE =
  "Research preview launched: Sepolia testnet, unaudited, trusted setup.";
export const PREVIEW_BANNER_LINK_LABEL = "What that means";

// The long form as Markdown (README warning box, SECURITY.md, docs).
export function previewStatementMarkdown() {
  const reasons = PREVIEW_STATEMENT_REASONS.map((reason) => `- ${reason}`).join("\n");
  return [
    PREVIEW_STATEMENT_SHORT,
    PREVIEW_STATEMENT_CEREMONY,
    PREVIEW_STATEMENT_REASONS_LEAD,
    reasons,
  ].join("\n\n");
}

function escapeHtml(text) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// The long form as an HTML block for the on-site statement home (the research note). Plainly
// styled: a paragraph, the ceremony paragraph, a lead line and a list, inside one <section>.
export function previewStatementBlock(indent = "") {
  const reasons = PREVIEW_STATEMENT_REASONS.map(
    (reason) => `${indent}  <li>${escapeHtml(reason)}</li>`,
  ).join("\n");
  return `${indent}<section id="research-preview" class="preview-statement" aria-label="Research preview">
${indent}<h2>Research preview</h2>
${indent}<p>${escapeHtml(PREVIEW_STATEMENT_SHORT)}</p>
${indent}<p>${escapeHtml(PREVIEW_STATEMENT_CEREMONY)}</p>
${indent}<p>${escapeHtml(PREVIEW_STATEMENT_REASONS_LEAD)}</p>
${indent}<ul>
${reasons}
${indent}</ul>
${indent}</section>`;
}
