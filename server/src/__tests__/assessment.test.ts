import { test } from "node:test";
import assert from "node:assert/strict";

import { buildAssessment } from "../report/assessment.js";
import { renderAssessmentHtml } from "../report/assessmentHtml.js";
import { VERSION } from "../version.js";
import { computePosture } from "../report/posture.js";
import { generateReport, FRAMEWORKS } from "../compliance/reporter.js";
import type { CryptoAsset, CryptoFamily, RiskScore, Severity } from "../types.js";

/** Build a scored CryptoAsset for assessment tests. */
function asset(
  partial: Partial<CryptoAsset> & { family: CryptoFamily; priority: Severity },
): CryptoAsset {
  const { priority, ...rest } = partial;
  const risk: RiskScore = {
    score: priority === "critical" ? 90 : priority === "high" ? 70 : priority === "medium" ? 50 : 20,
    priority,
    factors: { dataSensitivity: 50, retentionExposure: 50, hndlExposure: 50, complianceImpact: 50, businessImpact: 50 },
    recommendation: "Migrate",
    migrationEffortDays: 8,
    contextMultiplier: rest.file?.includes("test") ? 0.55 : 1,
    deploymentContext: rest.file?.includes("test") ? "test/example code" : "production code",
    ...((rest.risk as Partial<RiskScore>) ?? {}),
  };
  return {
    id: rest.id ?? `a_${Math.round(risk.score)}_${rest.family}`,
    scanId: "s1",
    file: rest.file ?? "src/app.ts",
    line: rest.line ?? 1,
    family: partial.family,
    algorithm: rest.algorithm ?? partial.family,
    keyBits: rest.keyBits ?? null,
    language: rest.language ?? "typescript",
    snippet: rest.snippet ?? "",
    patternId: rest.patternId ?? "p",
    quantumVulnerable: rest.quantumVulnerable ?? true,
    confidence: rest.confidence ?? "high",
    pqcReplacement: rest.pqcReplacement ?? "ML-KEM",
    status: rest.status ?? "open",
    risk,
  };
}

function sampleAssets(): CryptoAsset[] {
  return [
    asset({ id: "rsa1", family: "RSA", priority: "critical", file: "auth/signing.pem", algorithm: "RSA private key" }),
    asset({ id: "ecc1", family: "ECC", priority: "high", file: "gateway/tls.go", algorithm: "ECDSA", line: 88 }),
    asset({ id: "ecc2", family: "ECC", priority: "high", file: "api/jwt.ts", algorithm: "ECDSA (JWT ES)", line: 24 }),
    asset({ id: "dh1", family: "DH", priority: "medium", file: "vpn/handshake.ts", algorithm: "Diffie-Hellman" }),
    asset({ id: "md5", family: "HashLegacy", priority: "medium", file: "util/hash.ts", algorithm: "MD5" }),
    asset({ id: "tst", family: "RSA", priority: "low", file: "tests/fixtures/key.test.ts", algorithm: "RSA" }),
  ];
}

function build(assets: CryptoAsset[]) {
  const reports = FRAMEWORKS.map((fw) => generateReport(fw, assets, "scan-1"));
  return buildAssessment({
    orgName: "Acme Corp",
    generatedAt: "2026-06-20T12:00:00.000Z",
    scan: { target: "acme/monorepo", filesScanned: 1200, finishedAt: "2026-06-20T11:59:00.000Z" },
    assets,
    reports,
  });
}

// ----------------------------------------------------------------- posture
test("posture: server model matches the dashboard's documented thresholds", () => {
  // No assets -> perfect A.
  assert.equal(computePosture({ totalAssets: 0, quantumVulnerable: 0, byPriority: {}, avgCompliancePct: 0, migrationProgressPct: 0 }).grade, "A");
  // Heavy critical exposure with no remediation -> F.
  const bad = computePosture({ totalAssets: 50, quantumVulnerable: 50, byPriority: { critical: 10, high: 10 }, avgCompliancePct: 20, migrationProgressPct: 0 });
  assert.equal(bad.grade, "F");
  assert.ok(bad.score >= 0 && bad.score <= 100);
  // Score is a pinned function of inputs (guards against silent drift from web).
  const mid = computePosture({ totalAssets: 10, quantumVulnerable: 10, byPriority: { critical: 0, high: 2 }, avgCompliancePct: 80, migrationProgressPct: 50 });
  // 0.45*80 + 0.3*50 + 0.25*(100-8) = 36 + 15 + 23 = 74 -> C
  assert.equal(mid.score, 74);
  assert.equal(mid.grade, "C");
});

// ------------------------------------------------------------ inventory + shares
test("assessment: inventory aggregates by family and shares are sane", () => {
  const a = build(sampleAssets());
  assert.equal(a.totals.totalAssets, 6);
  assert.equal(a.totals.quantumVulnerable, 6);

  // Families present, sorted by count descending.
  const fams = a.inventory.map((r) => r.family);
  assert.deepEqual([...fams].sort(), ["DH", "ECC", "HashLegacy", "RSA"].sort());
  for (let i = 1; i < a.inventory.length; i++) {
    assert.ok(a.inventory[i - 1].count >= a.inventory[i].count, "inventory not sorted by count desc");
  }
  // RSA appears twice (one prod, one test) -> count 2.
  assert.equal(a.inventory.find((r) => r.family === "RSA")?.count, 2);
  // Each share is a bounded integer percentage.
  for (const row of a.inventory) {
    assert.ok(Number.isInteger(row.sharePct) && row.sharePct >= 0 && row.sharePct <= 100);
  }
  // Quantum-impact classification (⚑4 honest tiers): asymmetric is Shor-broken;
  // MD5/SHA-1 is classically weak (collision-broken without a quantum computer).
  assert.equal(a.inventory.find((r) => r.family === "ECC")?.quantumImpact, "Broken (Shor)");
  assert.equal(a.inventory.find((r) => r.family === "HashLegacy")?.quantumImpact, "Classically weak");
});

test("assessment: SymmetricLegacy impact is derived from the findings present (⚑4)", () => {
  // AES-128 alone → Grover-weakened, never lumped with the Shor-broken tier.
  const aesOnly = build([
    asset({ id: "aes", family: "SymmetricLegacy", priority: "medium", algorithm: "AES-128", patternId: "sym-aes128" }),
  ]);
  assert.equal(aesOnly.inventory.find((r) => r.family === "SymmetricLegacy")?.quantumImpact, "Weakened (Grover)");

  // 3DES alone → classically weak (broken-tier for classical reasons, not Grover).
  const desOnly = build([
    asset({ id: "des", family: "SymmetricLegacy", priority: "high", algorithm: "DES/3DES", patternId: "sym-des-3des" }),
  ]);
  assert.equal(desOnly.inventory.find((r) => r.family === "SymmetricLegacy")?.quantumImpact, "Classically weak");

  // Mixed AES-128 + 3DES → the row says so instead of overstating either.
  const mixed = build([
    asset({ id: "aes", family: "SymmetricLegacy", priority: "medium", algorithm: "AES-128", patternId: "sym-aes128" }),
    asset({ id: "des", family: "SymmetricLegacy", priority: "high", algorithm: "DES/3DES", patternId: "sym-des-3des" }),
  ]);
  assert.equal(mixed.inventory.find((r) => r.family === "SymmetricLegacy")?.quantumImpact, "Grover / classically weak");

  // A parsed PQC certificate row is quantum-SAFE — it must never read as Grover-affected.
  const pqc = build([
    asset({ id: "pqc", family: "PQC", priority: "low", algorithm: "ML-DSA-65", patternId: "x509-certificate", quantumVulnerable: false }),
  ]);
  assert.equal(pqc.inventory.find((r) => r.family === "PQC")?.quantumImpact, "None (post-quantum)");
});

// ------------------------------------------------------------ priority + KPIs
test("assessment: priority distribution and KPIs reflect real counts", () => {
  const a = build(sampleAssets());
  const byP = Object.fromEntries(a.priority.map((p) => [p.priority, p.count]));
  assert.equal(byP.critical, 1);
  assert.equal(byP.high, 2);
  assert.equal(byP.medium, 2);
  assert.equal(byP.low, 1);
  // All four tiers are always represented (even at 0) for a stable table.
  assert.equal(a.priority.length, 4);

  // High-priority KPI counts only production critical/high (excludes the test RSA, which is low anyway).
  assert.equal(a.kpis.highPriority, 3);
  assert.equal(a.kpis.vulnerableAssets, 6);
  assert.equal(a.kpis.filesScanned, 1200);
  // Est. migration days = sum of unresolved effort (all open here): 6 * 8 = 48.
  assert.equal(a.kpis.estMigrationDays, 48);
});

// ------------------------------------------------------------ top findings ordering
test("assessment: top findings put production paths first, then by score, and respect the limit", () => {
  const a = buildAssessment({
    orgName: "Acme",
    generatedAt: "2026-06-20T12:00:00.000Z",
    scan: { target: "t", filesScanned: 10, finishedAt: "2026-06-20T11:00:00.000Z" },
    assets: sampleAssets(),
    reports: [],
    topFindingsLimit: 3,
  });
  assert.equal(a.topFindings.length, 3);
  // First finding is the critical production RSA key.
  assert.equal(a.topFindings[0].priority, "critical");
  assert.ok(a.topFindings[0].file.includes("signing.pem"));
  // The de-prioritized test asset must not crowd out production findings.
  assert.ok(!a.topFindings.some((f) => f.file.includes("tests/")));
});

// ------------------------------------------------------------ roadmap derivation
test("assessment: roadmap phases quantify the real worklist", () => {
  const a = build(sampleAssets());
  assert.equal(a.roadmap.length, 3);
  // Phase 1 references the 3 critical+high assets (1 critical + 2 high).
  assert.match(a.roadmap[0].body, /\b3 critical\/high-priority assets\b/);
  // Phase 2 references the 2 medium findings.
  assert.match(a.roadmap[1].body, /\b2 medium-priority findings\b/);
});

// ------------------------------------------------------------ compliance matrix
test("assessment: compliance matrix maps from the supplied reports", () => {
  const a = build(sampleAssets());
  assert.equal(a.compliance.length, FRAMEWORKS.length);
  for (const row of a.compliance) {
    assert.ok(FRAMEWORKS.includes(row.framework as (typeof FRAMEWORKS)[number]));
    assert.ok(["pass", "gap", "fail"].includes(row.status));
    assert.ok(row.scorePct >= 0 && row.scorePct <= 100);
    assert.ok(row.controlArea.length > 0);
    assert.ok(row.gap.length > 0);
  }
});

// ------------------------------------------------------------ exec-summary accuracy
test("assessment: executive-summary share is over the vulnerable population, not the whole estate", () => {
  // 6 vulnerable RSA + 4 non-vulnerable AES: 100% of the *vulnerable* assets are
  // Shor-broken, even though Shor-broken is only 60% of the *total* estate. The
  // sentence is about the vulnerable assets, so it must read 100%, not 60%.
  const assets: CryptoAsset[] = [
    ...Array.from({ length: 6 }, (_, i) => asset({ id: `rsa${i}`, family: "RSA", priority: "high", file: `svc/auth${i}.ts` })),
    ...Array.from({ length: 4 }, (_, i) =>
      asset({ id: `aes${i}`, family: "SymmetricLegacy", priority: "low", algorithm: "AES-256-GCM", quantumVulnerable: false }),
    ),
  ];
  const a = build(assets);
  assert.equal(a.totals.totalAssets, 10);
  assert.equal(a.totals.quantumVulnerable, 6);
  assert.match(a.executiveSummary, /\(100%\)/, "share must be 100% of vulnerable assets");
  assert.doesNotMatch(a.executiveSummary, /\b60%/, "must not use the total-estate denominator");
  // The label must name the families it counts, not only RSA/ECC.
  assert.match(a.executiveSummary, /Shor-vulnerable public-key cryptography/);
  assert.doesNotMatch(a.executiveSummary, /rely on RSA or elliptic-curve cryptography/);
});

test("assessment: a DSA/DH-heavy estate is not mislabeled as RSA/elliptic-curve", () => {
  const assets: CryptoAsset[] = [
    asset({ id: "dsa1", family: "DSA", priority: "high", algorithm: "DSA" }),
    asset({ id: "dh1", family: "DH", priority: "high", algorithm: "Diffie-Hellman" }),
  ];
  const a = build(assets);
  // 100% Shor-broken (DSA + DH), correctly described without claiming RSA/ECC.
  assert.match(a.executiveSummary, /Shor-vulnerable public-key cryptography/);
  assert.doesNotMatch(a.executiveSummary, /rely on RSA or elliptic-curve cryptography/);
});

// ------------------------------------------------------------ empty estate
test("assessment: a clean estate produces a no-exposure A report", () => {
  const a = build([]);
  assert.equal(a.totals.totalAssets, 0);
  assert.equal(a.posture.grade, "A");
  assert.match(a.executiveSummary, /no quantum-vulnerable/i);
  assert.equal(a.topFindings.length, 0);
  // HTML still renders without throwing.
  const html = renderAssessmentHtml(a);
  assert.ok(html.includes("Quantum Readiness"));
});

// ------------------------------------------------------------ HTML rendering + escaping
test("assessment HTML: contains all sections and is print-ready", () => {
  const html = renderAssessmentHtml(build(sampleAssets()));
  for (const section of [
    "Executive Summary",
    "Cryptographic Inventory",
    "Priority distribution",
    "Compliance Gap Analysis",
    "Recommended Migration Roadmap",
    "Methodology",
  ]) {
    assert.ok(html.includes(section), `missing section: ${section}`);
  }
  assert.ok(html.includes("@media print"), "report should be print-styled");
  assert.ok(html.includes("Generated by UniQueS"));
  // A failing framework status renders as "Fail" (matching the compliance export),
  // never the milder "Gap" tag that would contradict the other report.
  assert.ok(!html.includes(">Gap</span>"), "fail status must render as 'Fail', not 'Gap'");
  // The OSS-generated report must NOT carry the analyst's pricing/sales table.
  assert.ok(!/Investment|Retainer|\/ mo\b/.test(html), "OSS report must not include the sales/pricing table");
});

test("assessment: report carries tool-version provenance, stamped into the rendered HTML", () => {
  const a = build(sampleAssets());
  assert.equal(a.toolVersion, VERSION, "the report model must record the producing build version");
  const html = renderAssessmentHtml(a);
  assert.ok(html.includes(`Generated by UniQueS v${VERSION}`), "the report footer must stamp the version for audit provenance");
});

test("assessment HTML: escapes a hostile organization name (no markup injection)", () => {
  const a = buildAssessment({
    orgName: '<script>alert(1)</script>',
    generatedAt: "2026-06-20T12:00:00.000Z",
    scan: { target: "<img src=x onerror=alert(1)>", filesScanned: 1, finishedAt: "2026-06-20T11:00:00.000Z" },
    assets: sampleAssets(),
    reports: [],
  });
  const html = renderAssessmentHtml(a);
  assert.ok(!html.includes("<script>alert(1)</script>"), "unescaped script tag leaked into the report");
  assert.ok(html.includes("&lt;script&gt;"), "org name should be HTML-escaped");
  assert.ok(!html.includes("<img src=x"), "unescaped attribute-injection vector leaked");
});
