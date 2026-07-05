export type CryptoFamily =
  | "RSA"
  | "ECC"
  | "DSA"
  | "DH"
  // A PKCS#8 `BEGIN PRIVATE KEY` block whose algorithm can't be determined from
  // the header alone (may be RSA, EC, Ed25519, …). Still quantum-vulnerable, but
  // we don't assert a specific algorithm we can't see.
  | "Asymmetric"
  | "SymmetricLegacy"
  | "HashLegacy"
  // A NIST post-quantum algorithm (ML-DSA / ML-KEM / SLH-DSA), recognized so a
  // PQC X.509 certificate is inventoried as SAFE (quantumVulnerable: false)
  // rather than flagged. Only parsed-certificate assets carry this family —
  // no regex pattern emits it.
  | "PQC";

export type Severity = "critical" | "high" | "medium" | "low";

/** How strongly a detection implies actual cryptographic USAGE versus a mere
 *  mention (a name in a string, enum, doc, or config token). Regex can't see
 *  call-sites, so name/enum matches are down-ranked. "low" = possible mention:
 *  surfaced for review, but excluded from the posture grade and the headline
 *  quantum-vulnerable count. (The full fix is AST/semantic detection.) */
export type Confidence = "high" | "medium" | "low";

/** Remediation lifecycle for a discovered asset. */
export type AssetStatus = "open" | "in_progress" | "migrated" | "accepted";

export const ASSET_STATUSES: AssetStatus[] = ["open", "in_progress", "migrated", "accepted"];

/** Statuses that count as "resolved" for migration-progress reporting. */
export const RESOLVED_STATUSES: AssetStatus[] = ["migrated", "accepted"];

export interface CryptoPattern {
  id: string;
  family: CryptoFamily;
  algorithm: string;
  /** Human description of what this pattern detects. */
  description: string;
  /** Regex applied per-line against source text. */
  regex: RegExp;
  /** True if broken by a sufficiently large quantum computer (Shor/Grover). */
  quantumVulnerable: boolean;
  /** Baseline severity before risk scoring context is applied. */
  baseSeverity: Severity;
  /** Languages / file kinds this pattern is meaningful for. */
  languages: string[];
  /** NIST-recommended post-quantum replacement. */
  pqcReplacement: string;
}

export interface CryptoAsset {
  id: string;
  scanId: string;
  file: string;
  line: number;
  family: CryptoFamily;
  algorithm: string;
  keyBits: number | null;
  language: string;
  snippet: string;
  patternId: string;
  quantumVulnerable: boolean;
  /** Detection confidence — how strongly the match implies real usage vs a mention. */
  confidence: Confidence;
  /** Machine-readable reason a finding was demoted to the informational tier
   *  ("low"), e.g. "import-declaration" for a bare Go import line. Demoted
   *  findings are re-tiered, never hidden — they remain in every output. Absent
   *  when the finding sits at its pattern's earned confidence. */
  demotionReason?: string;
  pqcReplacement: string;
  /** Remediation status, defaults to "open" when an asset is first discovered. */
  status: AssetStatus;
  /** Filled in by the risk scoring service. */
  risk?: RiskScore;
  // ── X.509 certificate metadata (ENG-02) — present only on parsed-certificate
  //    assets; optional and additive so existing consumers are untouched. ──
  certSubject?: string;
  certIssuer?: string;
  /** ISO-8601 validity bounds, when the certificate's Time fields parsed. */
  certNotBefore?: string;
  certNotAfter?: string;
  certExpired?: boolean;
  certKeyAlgorithm?: string;
  certSignatureAlgorithm?: string;
}

export interface RiskFactorBreakdown {
  dataSensitivity: number;
  retentionExposure: number;
  hndlExposure: number;
  complianceImpact: number;
  businessImpact: number;
}

export interface RiskScore {
  score: number; // 0-100
  priority: Severity;
  factors: RiskFactorBreakdown;
  recommendation: string;
  migrationEffortDays: number;
  /** Deployment-context discount applied to the factors (1.0 = production code,
   *  <1.0 = test/example or vendored code that protects no production data). */
  contextMultiplier?: number;
  /** Human label for the deployment context, e.g. "production code". */
  deploymentContext?: string;
}

export interface ScanJob {
  id: string;
  target: string;
  startedAt: string;
  finishedAt: string;
  filesScanned: number;
  durationMs: number;
  assetCount: number;
  status: "completed" | "running" | "failed";
}

/** A target that QuantumVault re-scans automatically on a schedule — the core
 *  of continuous monitoring / "crypto-agility as a standing capability". */
export interface MonitorTarget {
  id: string;
  orgId: string;
  name: string;
  /** "git" clones a repo URL each run; "path" re-scans a local directory. */
  kind: "git" | "path";
  target: string;
  intervalMinutes: number;
  enabled: boolean;
  createdAt: string;
  lastRunAt: string | null;
  nextRunAt: string;
  lastScanId: string | null;
  lastStatus: "ok" | "failed" | null;
  lastError: string | null;
  runCount: number;
}

export type ComplianceStatus = "pass" | "gap" | "fail";

export interface ComplianceControl {
  id: string;
  title: string;
  description: string;
  status: ComplianceStatus;
  affectedAssets: number;
  remediation: string;
}

export interface ComplianceReport {
  framework: "FISMA" | "CISA" | "FedRAMP" | "SOC2" | "PCI-DSS" | "CNSA-2.0" | "NIST-CSF-2.0";
  generatedAt: string;
  scanId: string;
  overallStatus: ComplianceStatus;
  scorePct: number;
  controls: ComplianceControl[];
  summary: string;
}
