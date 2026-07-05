import type { CryptoAsset, RiskScore, RiskFactorBreakdown, Severity } from "../types.js";
import { quantumExposure } from "../discovery/cryptoRef.js";

/**
 * 5-factor weighted risk model.
 *
 * Each factor is scored 0-100, then combined with the weights below. The result
 * prioritizes assets for post-quantum migration. Weights sum to 1.0 and reflect
 * that "harvest-now-decrypt-later" (HNDL) exposure and data sensitivity dominate
 * the urgency of migration for long-lived secrets.
 *
 * Weights are tunable per deployment via the QV_RISK_WEIGHTS environment
 * variable (a JSON object of any subset of these keys); provided values are
 * merged over the defaults and normalized to sum to 1.0, so a sector can
 * calibrate the model to its risk appetite without code changes.
 */
export interface RiskWeights {
  dataSensitivity: number;
  retentionExposure: number;
  hndlExposure: number;
  complianceImpact: number;
  businessImpact: number;
}

export const DEFAULT_WEIGHTS: RiskWeights = {
  dataSensitivity: 0.25,
  retentionExposure: 0.2,
  hndlExposure: 0.25,
  complianceImpact: 0.2,
  businessImpact: 0.1,
};

let cacheKey: string | undefined;
let cached: RiskWeights = DEFAULT_WEIGHTS;

function parseWeights(raw: string): RiskWeights {
  try {
    const obj = JSON.parse(raw) as Partial<Record<keyof RiskWeights, unknown>>;
    const merged: RiskWeights = { ...DEFAULT_WEIGHTS };
    for (const k of Object.keys(DEFAULT_WEIGHTS) as (keyof RiskWeights)[]) {
      const v = obj[k];
      if (typeof v === "number" && Number.isFinite(v) && v >= 0) merged[k] = v;
    }
    const sum = Object.values(merged).reduce((a, b) => a + b, 0);
    if (sum <= 0) return DEFAULT_WEIGHTS;
    for (const k of Object.keys(merged) as (keyof RiskWeights)[]) merged[k] = merged[k] / sum;
    return merged;
  } catch {
    return DEFAULT_WEIGHTS;
  }
}

/**
 * Active risk weights: the defaults, optionally overridden by QV_RISK_WEIGHTS
 * (JSON) and normalized to sum to 1.0. Invalid input falls back to the defaults.
 */
export function getRiskWeights(): RiskWeights {
  const raw = process.env.QV_RISK_WEIGHTS;
  if (!raw) return DEFAULT_WEIGHTS;
  if (raw !== cacheKey) {
    cacheKey = raw;
    cached = parseWeights(raw);
  }
  return cached;
}

// Signals derived from where an asset lives. A real deployment enriches these
// from data-classification metadata; here we infer from path + algorithm.
const SENSITIVE_HINTS = ["auth", "payment", "billing", "key", "secret", "token", "settlement", "card", "ssn", "pii"];
const PARTNER_HINTS = ["partner", "gateway", "transport", "vpn", "tls", "edge", "external", "exchange"];

// Vendored / third-party dependency code — not the first thing *you* migrate.
const VENDOR_PATH =
  /(^|\/)(node_modules|vendor|third[_-]?party|site-packages|\.venv|venv|bower_components|\.tox|dist|build|target)(\/|$)/;
// Test / fixture / example / sample code — protects no production data.
const TEST_PATH = /(^|\/)(tests?|__tests__|testdata|specs?|fixtures?|mocks?|examples?|samples?|e2e|demos?|benchmarks?)(\/|$)/;
// Test FILE conventions: foo.test.ts, foo.spec.js, foo_test.go, test_foo.py
const TEST_FILE = /(?:[._-](?:test|tests|spec)\.[a-z0-9]+|_test\.[a-z0-9]+|(?:^|\/)test_[^/]*\.[a-z0-9]+)$/;

/**
 * Deployment context inferred from an asset's path. Test/example and vendored
 * code is de-prioritized for migration because it doesn't protect production
 * data — without this, every asymmetric finding floors at "high" and the
 * inventory becomes a wall of alerts instead of a worklist. Returns a multiplier
 * applied uniformly to the factor scores (so `score` stays the weighted sum of
 * the reported factors) plus a human label for auditability.
 */
function deploymentContext(file: string): { multiplier: number; label: string } {
  const f = file.toLowerCase();
  if (VENDOR_PATH.test(f)) return { multiplier: 0.4, label: "vendored dependency" };
  if (TEST_PATH.test(f) || TEST_FILE.test(f)) return { multiplier: 0.55, label: "test/example code" };
  return { multiplier: 1, label: "production code" };
}

function pathSignal(file: string, hints: string[]): number {
  const lower = file.toLowerCase();
  let hits = 0;
  for (const h of hints) if (lower.includes(h)) hits += 1;
  return Math.min(hits, 3);
}

/** Asymmetric crypto (RSA/ECC/DSA/DH) is fully broken by Shor — max HNDL weight.
 * "Asymmetric" (an unspecified PKCS#8 private key) is one of these too. */
function isShorBroken(asset: CryptoAsset): boolean {
  return ["RSA", "ECC", "DSA", "DH", "Asymmetric"].includes(asset.family);
}

function dataSensitivityScore(asset: CryptoAsset): number {
  const base = pathSignal(asset.file, SENSITIVE_HINTS) * 25;
  const pemBoost = asset.patternId.includes("pem") ? 30 : 0;
  return clamp(40 + base + pemBoost);
}

function retentionScore(asset: CryptoAsset): number {
  // Signing keys and certificates protect data with long retention windows.
  if (asset.family === "RSA" || asset.family === "DSA") return 85;
  if (asset.patternId.includes("cert") || asset.patternId.includes("pem")) return 90;
  if (asset.family === "ECC") return 70;
  return 45;
}

function hndlScore(asset: CryptoAsset): number {
  // Harvest-now-decrypt-later: key-exchange + transport crypto on partner paths
  // is the highest-urgency category — captured traffic can be decrypted later.
  //
  // Grover-weakened symmetric crypto (AES-128) has NO practical HNDL path:
  // harvested AES-128 ciphertext still costs ~2^64 quantum operations under
  // Grover, with serial-depth requirements widely considered impractical at
  // scale. It scores below the classically-weak ciphers (DES/3DES/RC4), whose
  // harvested traffic is attackable with CLASSICAL compute alone (⚑4).
  if (quantumExposure(asset) === "grover-weakened") return 20;
  if (!isShorBroken(asset)) return 35;
  const partner = pathSignal(asset.file, PARTNER_HINTS) * 20;
  const keyExchangeBoost = asset.family === "DH" || asset.family === "ECC" ? 25 : 10;
  return clamp(45 + partner + keyExchangeBoost);
}

function complianceScore(asset: CryptoAsset): number {
  // Weak hashes/ciphers and RSA certs are explicit findings under FISMA/FedRAMP.
  if (asset.family === "HashLegacy") return 75;
  if (asset.patternId.includes("cert") || asset.patternId.includes("tls")) return 80;
  if (isShorBroken(asset)) return 70;
  return 50;
}

function businessImpactScore(asset: CryptoAsset): number {
  const base = pathSignal(asset.file, SENSITIVE_HINTS) * 20;
  const keyBoost = asset.keyBits && asset.keyBits <= 1024 ? 25 : 0;
  return clamp(40 + base + keyBoost);
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)));
}

function priorityFor(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function effortFor(asset: CryptoAsset, priority: Severity): number {
  const families: Record<string, number> = {
    RSA: 8,
    ECC: 6,
    DSA: 7,
    DH: 5,
    SymmetricLegacy: 3,
    HashLegacy: 2,
  };
  const base = families[asset.family] ?? 4;
  const urgencyMultiplier = priority === "critical" ? 1.5 : priority === "high" ? 1.2 : 1;
  return Math.round(base * urgencyMultiplier);
}

function recommendationFor(asset: CryptoAsset, priority: Severity): string {
  // Grover-weakened symmetric crypto (AES-128) is margin reduction, not a
  // break — the honest recommendation is a scheduled key-length upgrade, never
  // the "migrate immediately" language reserved for Shor-broken crypto (⚑4).
  if (quantumExposure(asset) === "grover-weakened") {
    return (
      `Migrate ${asset.algorithm} at ${asset.file}:${asset.line} to ${asset.pqcReplacement} ` +
      `on your normal upgrade cycle — Grover only halves the effective security margin ` +
      `(~2^64, widely considered impractical at scale); this is not a crypto emergency.`
    );
  }
  const verb = priority === "critical" ? "Immediately migrate" : priority === "high" ? "Prioritize migration of" : "Plan migration of";
  return `${verb} ${asset.algorithm} at ${asset.file}:${asset.line} to ${asset.pqcReplacement}.`;
}

export function scoreAsset(asset: CryptoAsset): RiskScore {
  const ctx = deploymentContext(asset.file);
  // A quantum-SAFE asset (e.g. a parsed ML-DSA certificate) is inventory, not
  // exposure — zero risk, no migration effort, and it must never gate a build.
  if (!asset.quantumVulnerable) {
    return {
      score: 0,
      priority: "low",
      factors: { dataSensitivity: 0, retentionExposure: 0, hndlExposure: 0, complianceImpact: 0, businessImpact: 0 },
      recommendation: `${asset.algorithm} at ${asset.file}:${asset.line} is already post-quantum — no migration required.`,
      migrationEffortDays: 0,
      contextMultiplier: ctx.multiplier,
      deploymentContext: ctx.label,
    };
  }
  // An INFORMATIONAL finding (confidence "low" — a demoted Go import
  // declaration, or a possible mention: a crypto name in a string/enum/doc) is
  // visibility, not exposure. It stays in every output, but it must not earn a
  // migration plan of its own: the actionable exposure lives on the corroborated
  // call-site findings, which are scored normally. Without this, a demoted
  // finding still exported at priority "medium" / 8 effort-days through CSV,
  // SARIF, and the API — the tier existed only in the JSON confidence field.
  if (asset.confidence === "low") {
    return {
      score: 0,
      priority: "low",
      factors: { dataSensitivity: 0, retentionExposure: 0, hndlExposure: 0, complianceImpact: 0, businessImpact: 0 },
      recommendation:
        `${asset.algorithm} at ${asset.file}:${asset.line} is informational` +
        `${asset.demotionReason ? ` (${asset.demotionReason})` : " (possible mention)"} — ` +
        `verify usage; actionable exposure is tracked at call-site findings.`,
      migrationEffortDays: 0,
      contextMultiplier: ctx.multiplier,
      deploymentContext: ctx.label,
    };
  }
  // Apply the deployment-context discount to each factor so the reported
  // factors remain consistent with the final score (score = weighted sum).
  const factors: RiskFactorBreakdown = {
    dataSensitivity: clamp(dataSensitivityScore(asset) * ctx.multiplier),
    retentionExposure: clamp(retentionScore(asset) * ctx.multiplier),
    hndlExposure: clamp(hndlScore(asset) * ctx.multiplier),
    complianceImpact: clamp(complianceScore(asset) * ctx.multiplier),
    businessImpact: clamp(businessImpactScore(asset) * ctx.multiplier),
  };

  const W = getRiskWeights();
  const score = clamp(
    factors.dataSensitivity * W.dataSensitivity +
      factors.retentionExposure * W.retentionExposure +
      factors.hndlExposure * W.hndlExposure +
      factors.complianceImpact * W.complianceImpact +
      factors.businessImpact * W.businessImpact,
  );

  const priority = priorityFor(score);
  const baseRec = recommendationFor(asset, priority);
  return {
    score,
    priority,
    factors,
    recommendation: ctx.multiplier < 1 ? `${baseRec} (de-prioritized — ${ctx.label})` : baseRec,
    migrationEffortDays: effortFor(asset, priority),
    contextMultiplier: ctx.multiplier,
    deploymentContext: ctx.label,
  };
}

/** Attach risk scores to a batch of assets (mutates and returns them). */
export function scoreAssets(assets: CryptoAsset[]): CryptoAsset[] {
  for (const a of assets) a.risk = scoreAsset(a);
  return assets;
}
