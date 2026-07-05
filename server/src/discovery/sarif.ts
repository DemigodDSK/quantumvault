import type { CryptoAsset } from "../types.js";
import { PATTERNS } from "./patterns.js";
import { quantumExposure } from "./cryptoRef.js";
import { VERSION } from "../version.js";

const PATTERN_BY_ID = new Map(PATTERNS.map((p) => [p.id, p]));
const INFO_URI = "https://github.com/uni-que-s/uniques";

/** SARIF result level from the finding's tier + risk priority. An informational
 *  finding (confidence "low" — a demoted import declaration or a possible
 *  mention) is always `note`, regardless of what the risk model would say:
 *  the informational tier must survive into SARIF consumers (GitHub
 *  code-scanning), not just the JSON export. */
function levelFor(asset: CryptoAsset): "error" | "warning" | "note" {
  if (asset.confidence === "low") return "note";
  const p = asset.risk?.priority;
  if (p === "critical" || p === "high") return "error";
  if (p === "medium") return "warning";
  return "note";
}

export interface SarifMeta {
  toolVersion?: string;
}

/**
 * Serialize discovered crypto assets to a SARIF 2.1.0 log so findings can be
 * uploaded to GitHub code-scanning (and other SARIF consumers) and surfaced as
 * PR annotations in the Security tab. Risk priority maps to SARIF level and to
 * GitHub's `security-severity` (0–10).
 */
export function assetsToSarif(assets: CryptoAsset[], meta: SarifMeta = {}): Record<string, unknown> {
  const ruleIds = [...new Set(assets.map((a) => a.patternId))];
  const rules = ruleIds.map((id) => {
    const p = PATTERN_BY_ID.get(id);
    const desc = p?.description ?? `Quantum-vulnerable cryptography (${id})`;
    return {
      id,
      name: id,
      shortDescription: { text: desc },
      fullDescription: { text: p ? `${desc}. Migrate to: ${p.pqcReplacement}` : desc },
      helpUri: INFO_URI,
      defaultConfiguration: { level: "warning" },
      properties: { family: p?.family, tags: ["cryptography", "post-quantum", "security"] },
    };
  });

  const results = assets.map((a) => {
    const score = a.risk?.score ?? 0;
    const exposure = quantumExposure(a);
    // Honest per-tier copy (⚑4): calling AES-128 "quantum-vulnerable" would
    // put a margin reduction in the same words as a Shor break.
    const bits = a.keyBits ? ` (${a.keyBits}-bit)` : "";
    const messageText =
      exposure === "grover-weakened"
        ? `${a.algorithm}${bits} is Grover-weakened: security margin reduced (~2^64 effective), not broken. Migrate to ${a.pqcReplacement} on your normal upgrade cycle — not a crypto emergency.`
        : `${a.algorithm} is quantum-vulnerable${bits}. Replace with ${a.pqcReplacement}.`;
    return {
      ruleId: a.patternId,
      level: levelFor(a),
      message: {
        text: messageText,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: a.file },
            region: { startLine: Math.max(1, a.line) },
          },
        },
      ],
      properties: {
        family: a.family,
        confidence: a.confidence,
        quantumExposure: exposure,
        ...(a.demotionReason ? { demotionReason: a.demotionReason } : {}),
        // An informational finding carries no security severity — it would
        // otherwise land in the GitHub Security tab at the same severity as an
        // actionable finding, erasing the tier.
        "security-severity": a.confidence === "low" ? "0.0" : (score / 10).toFixed(1),
        riskScore: score,
        remediationStatus: a.status,
      },
    };
  });

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "UniQueS",
            informationUri: INFO_URI,
            version: meta.toolVersion ?? VERSION,
            rules,
          },
        },
        results,
      },
    ],
  };
}
