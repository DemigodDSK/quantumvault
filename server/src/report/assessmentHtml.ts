import type { Severity } from "../types.js";
import type { AssessmentReport } from "./assessment.js";

/**
 * Render a Quantum Readiness Assessment as a self-contained, print-ready HTML
 * document — open in a browser and "Save as PDF" to deliver. This is a pure view
 * over the {@link AssessmentReport} model: every number traces to real scan data.
 */

function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const TAG_CLASS: Record<Severity, string> = {
  critical: "t-crit",
  high: "t-high",
  medium: "t-med",
  low: "t-low",
};

// Labels mirror the compliance report renderer (compliance/export.ts) so the
// same client never receives two QuantumVault reports that disagree on what a
// "fail" status is called. Red for fail, amber for partial, green for pass.
const STATUS_LABEL = { pass: "No gaps found", gap: "Partial", fail: "Fail" } as const;
const STATUS_CLASS = { pass: "t-low", gap: "t-med", fail: "t-crit" } as const;

function fmtDate(iso: string): string {
  // Stable, locale-independent date (avoids per-environment formatting drift in
  // a document that is often regenerated and diffed).
  return esc(iso.slice(0, 10));
}

export function renderAssessmentHtml(r: AssessmentReport): string {
  const inventoryRows = r.inventory
    .map(
      (row) => `
      <tr><td>${esc(row.label)}</td><td class="num">${row.count}</td><td class="num">${row.sharePct}%</td>
      <td>${esc(row.quantumImpact)}</td><td>${esc(row.nistReplacement)}</td></tr>`,
    )
    .join("");

  const priorityRows = r.priority
    .map(
      (row) => `
      <tr><td><span class="tag ${TAG_CLASS[row.priority]}">${row.priority}</span></td>
      <td class="num">${row.count}</td><td>${esc(row.meaning)}</td></tr>`,
    )
    .join("");

  const findingRows = r.topFindings.length
    ? r.topFindings
        .map(
          (f) => `
      <tr><td>${esc(f.algorithm)}</td><td class="mono">${esc(f.file)}:${f.line}</td>
      <td><span class="tag ${TAG_CLASS[f.priority]}">${f.priority}</span></td></tr>`,
        )
        .join("")
    : `<tr><td colspan="3" class="small">No quantum-vulnerable findings in scope.</td></tr>`;

  const complianceRows = r.compliance.length
    ? r.compliance
        .map(
          (c) => `
      <tr><td>${esc(c.framework)}</td><td>${esc(c.controlArea)}</td>
      <td><span class="tag ${STATUS_CLASS[c.status]}">${STATUS_LABEL[c.status]}</span></td>
      <td class="num">${c.scorePct}%</td><td>${esc(c.gap)}</td></tr>`,
        )
        .join("")
    : `<tr><td colspan="5" class="small">No compliance frameworks evaluated.</td></tr>`;

  const roadmap = r.roadmap
    .map(
      (p) => `
    <div class="phase"><b>${esc(p.title)} (${esc(p.horizon)})</b>${renderInline(p.body)}</div>`,
    )
    .join("");

  const scannedAt = r.scope.scannedAt ? fmtDate(r.scope.scannedAt) : "—";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Quantum Readiness Assessment — ${esc(r.orgName)}</title>
<style>
  :root{
    --ink:#15151f; --muted:#55556a; --faint:#8a8a9c; --line:#e2e2ec;
    --accent:#7c3aed; --accent-soft:#f3efff; --ok:#15803d; --warn:#b45309; --crit:#b91c1c;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  body{margin:0;background:#f4f4f8;color:var(--ink);font-family:var(--sans);line-height:1.55;font-size:14px}
  .page{background:#fff;max-width:820px;margin:24px auto;padding:54px 60px;box-shadow:0 2px 18px rgba(0,0,0,.08);position:relative}
  h1,h2,h3{line-height:1.2;letter-spacing:-.01em}
  h2{font-size:21px;margin:0 0 4px;padding-top:8px}
  h3{font-size:15px;margin:22px 0 6px;color:var(--ink)}
  p{margin:0 0 12px;color:var(--muted)}
  .accent{color:var(--accent)}
  .mono{font-family:var(--mono)}
  .small{font-size:12px;color:var(--faint)}
  table{width:100%;border-collapse:collapse;margin:10px 0 18px;font-size:13px}
  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--faint)}
  td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
  .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:capitalize}
  .t-crit{background:#fee2e2;color:var(--crit)} .t-high{background:#ffedd5;color:var(--warn)}
  .t-med{background:#fef9c3;color:#854d0e} .t-low{background:#dcfce7;color:var(--ok)}
  .rule{border:0;border-top:2px solid var(--ink);margin:0 0 6px}
  .brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:17px}
  .brand .dot{width:20px;height:20px;border-radius:6px;background:linear-gradient(135deg,#a78bfa,#7c3aed)}
  .cover{min-height:920px;display:flex;flex-direction:column}
  .cover .top{flex:1}
  .cover h1{font-size:40px;margin:120px 0 10px;letter-spacing:-.02em}
  .cover .sub{font-size:17px;color:var(--muted)}
  .cover .meta{margin-top:40px;border-top:1px solid var(--line);padding-top:20px;font-size:13px}
  .cover .meta div{margin-bottom:4px}
  .conf{position:absolute;bottom:54px;left:60px;right:60px;font-size:11px;color:var(--faint);border-top:1px solid var(--line);padding-top:12px}
  .grade-wrap{display:flex;gap:24px;align-items:center;background:var(--accent-soft);border:1px solid #e6ddff;border-radius:14px;padding:22px 26px;margin:14px 0 20px}
  .grade{font-size:54px;font-weight:800;color:var(--accent);line-height:1}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:14px 0 8px}
  .kpi{border:1px solid var(--line);border-radius:10px;padding:14px}
  .kpi .n{font-size:24px;font-weight:800}
  .kpi .l{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.05em}
  .phase{border-left:3px solid var(--accent);padding:2px 0 2px 16px;margin:0 0 16px;color:var(--muted)}
  .phase b{display:block;color:var(--ink)}
  @media print{
    body{background:#fff}
    .page{box-shadow:none;margin:0;max-width:none;padding:40px 48px}
    .page-break{page-break-before:always}
    @page{margin:14mm}
  }
</style></head>
<body>

<section class="page cover">
  <div class="top">
    <div class="brand"><span class="dot"></span> UniQueS</div>
    <h1>Quantum Readiness<br>Assessment</h1>
    <div class="sub">Cryptographic asset inventory, post-quantum risk ranking, and compliance gap analysis.</div>
    <div class="meta">
      <div><b>Prepared for:</b> ${esc(r.orgName)}</div>
      <div><b>Scope:</b> ${esc(r.scope.target)} · ${r.scope.filesScanned} files scanned</div>
      <div><b>Scan date:</b> ${scannedAt}</div>
      <div><b>Report generated:</b> ${fmtDate(r.generatedAt)}</div>
    </div>
  </div>
  <div class="conf">CONFIDENTIAL — Prepared for ${esc(r.orgName)}. Contains sensitive cryptographic
    posture information. Do not distribute.</div>
</section>

<section class="page page-break">
  <hr class="rule"><h2>Executive Summary</h2>
  <div class="grade-wrap">
    <div><div class="grade" style="color:${esc(r.posture.color)}">${esc(r.posture.grade)}</div><div class="small">Quantum-posture grade</div></div>
    <div><p style="margin:0;color:var(--ink)">${renderInline(r.executiveSummary)}</p></div>
  </div>
  <div class="kpis">
    <div class="kpi"><div class="n">${r.kpis.vulnerableAssets}</div><div class="l">Vulnerable assets</div></div>
    <div class="kpi"><div class="n accent">${r.kpis.highPriority}</div><div class="l">High priority</div></div>
    <div class="kpi"><div class="n">${r.kpis.filesScanned}</div><div class="l">Files scanned</div></div>
    <div class="kpi"><div class="n">~${r.kpis.estMigrationDays}</div><div class="l">Est. migration days</div></div>
  </div>
  <h3>Posture</h3>
  <p>${renderInline(r.posture.narrative)}</p>
</section>

<section class="page page-break">
  <hr class="rule"><h2>Cryptographic Inventory</h2>
  <p>Findings by algorithm family. Shor-broken asymmetric crypto is the priority — a
     cryptographically-relevant quantum computer breaks it outright. AES-128 is only
     Grover-weakened (security margin reduced, not broken): migrate to AES-256 on your
     normal upgrade cycle. DES/3DES and MD5/SHA-1 are classically weak already.</p>
  <table>
    <thead><tr><th>Family</th><th>Assets</th><th>Share</th><th>Quantum impact</th><th>NIST replacement</th></tr></thead>
    <tbody>${inventoryRows || `<tr><td colspan="5" class="small">No cryptographic assets discovered.</td></tr>`}</tbody>
  </table>
  <h3>Priority distribution</h3>
  <table>
    <thead><tr><th>Priority</th><th>Assets</th><th>Meaning</th></tr></thead>
    <tbody>${priorityRows}</tbody>
  </table>
  <p class="small">${r.totals.productionAssets} of ${r.totals.totalAssets} assets are on production
     paths; the remainder are test/example or vendored code, de-prioritized for migration.</p>
  <h3>Selected high-priority findings</h3>
  <table>
    <thead><tr><th>Algorithm</th><th>Location</th><th>Priority</th></tr></thead>
    <tbody>${findingRows}</tbody>
  </table>
  <p class="small">Full inventory delivered as CycloneDX 1.6 CBOM + CSV.</p>
</section>

<section class="page page-break">
  <hr class="rule"><h2>Compliance Gap Analysis</h2>
  <p>Mapped against the frameworks in scope. Status reflects cryptographic-control
     readiness for post-quantum requirements.</p>
  <table>
    <thead><tr><th>Framework</th><th>Relevant control area</th><th>Status</th><th>Coverage</th><th>Headline gap</th></tr></thead>
    <tbody>${complianceRows}</tbody>
  </table>
  <p class="small">Auditor-ready evidence (JSON system-of-record + per-framework reports) accompanies this assessment.</p>
</section>

<section class="page page-break">
  <hr class="rule"><h2>Recommended Migration Roadmap</h2>
  ${roadmap}
  <hr class="rule" style="margin-top:30px"><h3>Methodology &amp; caveats</h3>
  <p class="small">Findings were produced by the open-source UniQueS scanner v${esc(r.toolVersion)}
     (pattern-based detection across 25+ file types) over the scope above. Detection identifies <i>uses</i> of
     quantum-vulnerable cryptography, not exploitable vulnerabilities. Risk scores are a transparent,
     tunable 5-factor heuristic calibrated by deployment context — a prioritization aid, not a
     guarantee. Full raw output (CBOM, SARIF, CSV) accompanies this report.</p>
  <div class="brand" style="margin-top:24px;font-size:14px"><span class="dot"></span> Generated by UniQueS v${esc(r.toolVersion)}</div>
  <p class="small" style="margin-top:6px">github.com/uni-que-s/uniques</p>
</section>

</body></html>`;
}

/**
 * Render a trusted, model-authored string that may contain backtick-delimited
 * `code` spans into safe HTML. The input comes only from this module's own
 * templates (never user data), but we still escape first, then re-introduce the
 * single intended bit of markup, so a future change can't inject markup.
 */
function renderInline(s: string): string {
  return esc(s).replace(/`([^`]+)`/g, (_m, code) => `<span class="mono">${code}</span>`);
}
