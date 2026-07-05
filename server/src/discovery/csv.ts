import type { CryptoAsset } from "../types.js";
import { quantumExposure } from "./cryptoRef.js";

/** RFC-4180 field escaping: quote fields containing comma, quote, or newline. */
function csvField(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

const COLUMNS: { header: string; get: (a: CryptoAsset) => unknown }[] = [
  { header: "file", get: (a) => a.file },
  { header: "line", get: (a) => a.line },
  { header: "family", get: (a) => a.family },
  { header: "algorithm", get: (a) => a.algorithm },
  { header: "key_bits", get: (a) => a.keyBits ?? "" },
  { header: "language", get: (a) => a.language },
  { header: "pattern_id", get: (a) => a.patternId },
  // Tier columns: without these, a demoted (informational) finding is
  // indistinguishable from an actionable one in a spreadsheet.
  { header: "confidence", get: (a) => a.confidence },
  { header: "demotion_reason", get: (a) => a.demotionReason ?? "" },
  // Honest exposure tier (⚑4): shor-broken vs grover-weakened (AES-128) vs
  // classically-weak — so a spreadsheet can tell a crypto emergency from a
  // scheduled key-length upgrade.
  { header: "quantum_exposure", get: (a) => quantumExposure(a) },
  { header: "risk_score", get: (a) => a.risk?.score ?? "" },
  { header: "priority", get: (a) => a.risk?.priority ?? "" },
  { header: "migration_effort_days", get: (a) => a.risk?.migrationEffortDays ?? "" },
  { header: "status", get: (a) => a.status },
  { header: "pqc_replacement", get: (a) => a.pqcReplacement },
  { header: "recommendation", get: (a) => a.risk?.recommendation ?? "" },
  { header: "snippet", get: (a) => a.snippet },
];

/** Serialize an asset inventory to a CSV document (with a header row, CRLF lines). */
export function assetsToCsv(assets: CryptoAsset[]): string {
  const rows = [COLUMNS.map((c) => c.header).join(",")];
  for (const a of assets) {
    rows.push(COLUMNS.map((c) => csvField(c.get(a))).join(","));
  }
  return rows.join("\r\n") + "\r\n";
}
