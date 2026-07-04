import type { CryptoAsset, CryptoFamily, ComplianceReport, Severity } from "../types.js";
import { RESOLVED_STATUSES } from "../types.js";
import { VERSION } from "../version.js";
import { computePosture, type Posture } from "./posture.js";

/**
 * Quantum Readiness Assessment — the structured model behind QuantumVault's
 * flagship report. It turns the raw output of a scan (scored assets + compliance
 * reports) into the executive-ready narrative an organization needs to brief a
 * CISO and plan a post-quantum migration: an at-a-glance posture grade, a
 * cryptographic inventory, a prioritized worklist, the real top findings, a
 * compliance gap matrix, and a phased roadmap.
 *
 * Everything here is computed from real scan data — there is no sample/fiction.
 * The renderer (`assessmentHtml.ts`) is a pure view over this model, so the same
 * assessment can be emitted as HTML (print-to-PDF) or JSON (system of record).
 */

/** Quantum impact class for an algorithm family. */
type QuantumImpact = "Broken (Shor)" | "Weakened (Grover)";

// Asymmetric public-key crypto is broken outright by Shor's algorithm; legacy
// symmetric/hash primitives are only weakened by Grover (a quadratic, not
// exponential, speedup) — a distinction that drives migration urgency.
const SHOR_BROKEN: CryptoFamily[] = ["RSA", "ECC", "DSA", "DH", "Asymmetric"];

const FAMILY_LABEL: Record<CryptoFamily, string> = {
  RSA: "RSA",
  ECC: "ECC (elliptic curve)",
  DSA: "DSA",
  DH: "Diffie-Hellman",
  Asymmetric: "Asymmetric (PKCS#8, unspecified)",
  SymmetricLegacy: "Symmetric (legacy)",
  HashLegacy: "Legacy hash (MD5/SHA-1)",
  PQC: "Post-quantum (safe)",
};

const FAMILY_REPLACEMENT: Record<CryptoFamily, string> = {
  RSA: "ML-KEM / ML-DSA",
  ECC: "ML-KEM / ML-DSA",
  DSA: "ML-DSA",
  DH: "ML-KEM",
  Asymmetric: "Identify & replace",
  SymmetricLegacy: "AES-256",
  HashLegacy: "SHA-256 / SHA-3",
  PQC: "None — already post-quantum",
};

const PRIORITY_MEANING: Record<Severity, string> = {
  critical: "Production secrets on sensitive paths — migrate immediately",
  high: "Production crypto — prioritize",
  medium: "Plan migration",
  low: "Test/vendored or low-exposure — de-prioritized",
};

const COMPLIANCE_AREA: Record<string, string> = {
  FISMA: "SC-13 cryptographic protection (OMB M-23-02 inventory)",
  CISA: "PQC inventory & prioritized migration plan",
  FedRAMP: "SC-8/SC-13 transmission & use of cryptography",
  SOC2: "CC6.1 logical access — encryption of data",
  "PCI-DSS": "Req. 3/4 — strong cryptography at rest & in transit",
};

export interface InventoryRow {
  family: CryptoFamily;
  label: string;
  count: number;
  sharePct: number;
  quantumImpact: QuantumImpact;
  nistReplacement: string;
}

export interface PriorityRow {
  priority: Severity;
  count: number;
  meaning: string;
}

export interface FindingRow {
  algorithm: string;
  file: string;
  line: number;
  priority: Severity;
  deploymentContext: string;
}

export interface ComplianceRow {
  framework: string;
  controlArea: string;
  status: ComplianceReport["overallStatus"];
  scorePct: number;
  gap: string;
}

export interface RoadmapPhase {
  title: string;
  horizon: string;
  body: string;
}

export interface AssessmentReport {
  orgName: string;
  generatedAt: string;
  /** Version of the QuantumVault scanner that produced this report — audit
   *  provenance, so a reviewer knows exactly which build generated the findings. */
  toolVersion: string;
  scope: { target: string; filesScanned: number; scannedAt: string | null };
  posture: Posture;
  kpis: {
    vulnerableAssets: number;
    highPriority: number; // critical + high on production paths
    filesScanned: number;
    estMigrationDays: number;
  };
  executiveSummary: string;
  inventory: InventoryRow[];
  priority: PriorityRow[];
  topFindings: FindingRow[];
  compliance: ComplianceRow[];
  roadmap: RoadmapPhase[];
  totals: { totalAssets: number; quantumVulnerable: number; productionAssets: number };
}

export interface AssessmentInput {
  orgName: string;
  generatedAt: string;
  scan: { target: string; filesScanned: number; finishedAt: string } | null;
  assets: CryptoAsset[];
  reports: ComplianceReport[];
  /** How many top findings to surface in the report. */
  topFindingsLimit?: number;
}

const PRIORITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

function priorityOf(a: CryptoAsset): Severity {
  return a.risk?.priority ?? "low";
}

function isProduction(a: CryptoAsset): boolean {
  // The risk scorer labels deployment context; "production code" runs at full
  // weight (multiplier 1.0). Treat anything not explicitly de-prioritized as
  // production so we never *under*-count exposure.
  const m = a.risk?.contextMultiplier;
  return m === undefined || m >= 1;
}

function gapText(report: ComplianceReport): string {
  if (report.overallStatus === "pass") return "All in-scope cryptographic controls satisfied";
  // Surface the most material failing/partial control as the headline gap.
  const failing = report.controls.filter((c) => c.status === "fail");
  const partial = report.controls.filter((c) => c.status === "gap");
  const worst = failing[0] ?? partial[0];
  if (!worst) return "Remediation plan required";
  return `${worst.title}: ${worst.remediation}`;
}

export function buildAssessment(input: AssessmentInput): AssessmentReport {
  const { orgName, generatedAt, scan, assets, reports } = input;
  const total = assets.length;
  // Low-confidence findings are possible mentions — excluded from the grade,
  // priority distribution, and migration math, consistent with the dashboard.
  const actionable = assets.filter((a) => a.confidence !== "low");
  const possibleMentions = total - actionable.length;
  const vulnerable = actionable.filter((a) => a.quantumVulnerable).length;

  // ---- inventory by family (sorted by count desc) -------------------------
  const familyCounts = new Map<CryptoFamily, number>();
  for (const a of assets) familyCounts.set(a.family, (familyCounts.get(a.family) ?? 0) + 1);
  const inventory: InventoryRow[] = [...familyCounts.entries()]
    .map(([family, count]) => ({
      family,
      label: FAMILY_LABEL[family] ?? family,
      count,
      sharePct: total ? Math.round((count / total) * 100) : 0,
      quantumImpact: (SHOR_BROKEN.includes(family) ? "Broken (Shor)" : "Weakened (Grover)") as QuantumImpact,
      nistReplacement: FAMILY_REPLACEMENT[family] ?? "NIST PQC",
    }))
    .sort((a, b) => b.count - a.count);

  // ---- priority distribution ---------------------------------------------
  const priorityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of actionable) priorityCounts[priorityOf(a)] += 1;
  const priority: PriorityRow[] = PRIORITY_ORDER.map((p) => ({
    priority: p,
    count: priorityCounts[p],
    meaning: PRIORITY_MEANING[p],
  }));

  // ---- migration progress & effort (for posture + KPIs) ------------------
  const resolved = actionable.filter((a) => RESOLVED_STATUSES.includes(a.status)).length;
  const migrationProgressPct = actionable.length ? Math.round((resolved / actionable.length) * 100) : 0;
  const estMigrationDays = actionable
    .filter((a) => !RESOLVED_STATUSES.includes(a.status))
    .reduce((s, a) => s + (a.risk?.migrationEffortDays ?? 0), 0);

  // ---- compliance gap matrix ---------------------------------------------
  const avgCompliancePct = reports.length
    ? Math.round(reports.reduce((s, r) => s + r.scorePct, 0) / reports.length)
    : 0;
  const compliance: ComplianceRow[] = reports.map((r) => ({
    framework: r.framework,
    controlArea: COMPLIANCE_AREA[r.framework] ?? "Cryptographic controls",
    status: r.overallStatus,
    scorePct: r.scorePct,
    gap: gapText(r),
  }));

  // ---- posture grade (same model as the live dashboard) ------------------
  const posture = computePosture({
    totalAssets: total,
    quantumVulnerable: vulnerable,
    possibleMentions,
    byPriority: { critical: priorityCounts.critical, high: priorityCounts.high },
    avgCompliancePct,
    migrationProgressPct,
  });

  // ---- KPIs ---------------------------------------------------------------
  const productionAssets = assets.filter(isProduction).length;
  const prodHighPriority = assets.filter(
    (a) => isProduction(a) && (priorityOf(a) === "critical" || priorityOf(a) === "high"),
  ).length;

  // ---- top findings (real, by risk score; production paths first) --------
  const limit = input.topFindingsLimit ?? 12;
  const topFindings: FindingRow[] = [...assets]
    .sort((a, b) => {
      // production before de-prioritized, then by score
      const pa = isProduction(a) ? 1 : 0;
      const pb = isProduction(b) ? 1 : 0;
      if (pa !== pb) return pb - pa;
      return (b.risk?.score ?? 0) - (a.risk?.score ?? 0);
    })
    .slice(0, limit)
    .map((a) => ({
      algorithm: a.algorithm,
      file: a.file,
      line: a.line,
      priority: priorityOf(a),
      deploymentContext: a.risk?.deploymentContext ?? "production code",
    }));

  // ---- executive summary (computed, honest) ------------------------------
  // Share of the *vulnerable* population that is Shor-broken public-key crypto.
  // The denominator is `vulnerable` (not `total`) so the percentage matches the
  // sentence, which is about the quantum-vulnerable assets just stated. Counts
  // every Shor-broken family (RSA/ECC/DSA/DH/Asymmetric), so the prose names them
  // accurately rather than implying only RSA/ECC.
  const shorVulnerable = assets.filter(
    (a) => a.quantumVulnerable && SHOR_BROKEN.includes(a.family),
  ).length;
  const shorSharePct = vulnerable ? Math.round((shorVulnerable / vulnerable) * 100) : 0;
  const executiveSummary = buildExecutiveSummary({
    orgName,
    posture,
    vulnerable,
    filesScanned: scan?.filesScanned ?? 0,
    shorSharePct,
    prodHighPriority,
  });

  // ---- phased roadmap (derived from the actual worklist) -----------------
  const roadmap = buildRoadmap(priorityCounts.critical, priorityCounts.high, priorityCounts.medium);

  return {
    orgName,
    generatedAt,
    toolVersion: VERSION,
    scope: {
      target: scan?.target ?? "—",
      filesScanned: scan?.filesScanned ?? 0,
      scannedAt: scan?.finishedAt ?? null,
    },
    posture,
    kpis: {
      vulnerableAssets: vulnerable,
      highPriority: prodHighPriority,
      filesScanned: scan?.filesScanned ?? 0,
      estMigrationDays,
    },
    executiveSummary,
    inventory,
    priority,
    topFindings,
    compliance,
    roadmap,
    totals: { totalAssets: total, quantumVulnerable: vulnerable, productionAssets },
  };
}

function buildExecutiveSummary(o: {
  orgName: string;
  posture: Posture;
  vulnerable: number;
  filesScanned: number;
  shorSharePct: number;
  prodHighPriority: number;
}): string {
  if (o.vulnerable === 0) {
    // Only claim "all clear" when the grade actually backs it; a clean scan can
    // still grade low on outstanding remediation or thin compliance coverage.
    if (o.posture.grade === "A" || o.posture.grade === "B") {
      return `${o.orgName}'s scanned estate shows no quantum-vulnerable cryptography. Posture grade ${o.posture.grade} (${o.posture.label}). Maintain continuous monitoring so newly-introduced quantum-vulnerable crypto is caught in CI before it reaches production.`;
    }
    return `${o.orgName}'s scan surfaced no quantum-vulnerable cryptography, but the posture grade is ${o.posture.grade} (${o.posture.label}) due to outstanding remediation or limited compliance coverage — see the gap analysis below.`;
  }
  // "Shor-vulnerable public-key cryptography" accurately covers every counted
  // family (RSA, ECC, DSA, Diffie-Hellman, and unspecified PKCS#8 keys); the
  // percentage is a share of the just-stated vulnerable assets.
  const families = "Shor-vulnerable public-key cryptography (RSA, ECC, DSA, Diffie-Hellman)";
  const exposure =
    o.shorSharePct >= 50
      ? `The majority (${o.shorSharePct}%) rely on ${families}`
      : `${o.shorSharePct}% rely on ${families}`;
  const priorityClause = o.prodHighPriority
    ? ` ${o.prodHighPriority} sit on production data-protection paths that warrant priority migration.`
    : " None currently sit on production data-protection paths flagged critical/high, but the inventory should still be migrated on a schedule.";
  return (
    `${o.orgName}'s estate is materially exposed to "harvest-now, decrypt-later." ` +
    `We inventoried ${o.vulnerable} quantum-vulnerable cryptographic assets across ${o.filesScanned} files. ` +
    `${exposure} — algorithms a cryptographically-relevant quantum computer breaks outright.${priorityClause} ` +
    `Overall quantum-posture grade: ${o.posture.grade} (${o.posture.label}).`
  );
}

function buildRoadmap(critical: number, high: number, medium: number): RoadmapPhase[] {
  const p1 = critical + high;
  return [
    {
      title: "Stop the bleeding",
      horizon: "0–3 months",
      body:
        `Migrate the ${p1} critical/high-priority asset${p1 === 1 ? "" : "s"} to hybrid PQC (ML-KEM for key ` +
        `exchange, ML-DSA for signing). Add UniQueS to CI with \`--fail-on high\` so no new ` +
        `quantum-vulnerable crypto merges.`,
    },
    {
      title: "Systematic migration",
      horizon: "3–12 months",
      body:
        `Work the ${medium} medium-priority finding${medium === 1 ? "" : "s"} by service, re-issue certificates ` +
        `as hybrid X.509, and track progress to completion. Re-scan to measure drift.`,
    },
    {
      title: "Continuous assurance",
      horizon: "ongoing",
      body:
        "Stand up continuous monitoring and scheduled compliance evidence. Maintain the CBOM as a living " +
        "system of record for auditors and regulators.",
    },
  ];
}
