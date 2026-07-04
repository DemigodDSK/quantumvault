#!/usr/bin/env node
import { resolve } from "node:path";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { CryptoAsset, ScanJob, Severity } from "./types.js";
import { VERSION } from "./version.js";
import { scanDirectory } from "./discovery/scanner.js";
import { scoreAssets } from "./risk/scorer.js";
import { assetsToCbom } from "./discovery/cbom.js";
import { assetsToSarif } from "./discovery/sarif.js";
import { assetsToCsv } from "./discovery/csv.js";
import { buildBaseline, loadBaselineSet, partitionByBaseline } from "./discovery/baseline.js";
import { generateReport, FRAMEWORKS } from "./compliance/reporter.js";
import { buildAssessment } from "./report/assessment.js";
import { renderAssessmentHtml } from "./report/assessmentHtml.js";

type Format = "table" | "json" | "sarif" | "cbom" | "csv" | "assessment";

interface Args {
  path?: string;
  format: Format;
  failOn?: string;
  org?: string;
  baseline?: string;
  writeBaseline?: string;
  help: boolean;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const HELP = `UniQueS — universal quantum scanner (finds quantum-vulnerable cryptography)

Usage: quantumvault <path> [options]

Scans a directory for quantum-vulnerable cryptographic assets (RSA, ECC, DSA,
Diffie-Hellman, legacy symmetric/hashes, key material) and reports risk-scored
findings. Reuses the same engine as the UniQueS platform.

Options:
  --json            Output findings as JSON
  --sarif           Output SARIF 2.1.0 (for GitHub code-scanning)
  --cbom            Output a CycloneDX 1.6 CBOM
  --csv             Output a CSV inventory
  --assessment      Output a branded Quantum Readiness Assessment (print-to-PDF HTML)
  --org <name>      Organization name for the assessment report header
  --fail-on <sev>   Exit 1 if a gated finding is at or above <sev>
                    (critical | high | medium | low) — for CI gating.
                    Low-confidence "possible mentions" are never gated.
  --baseline <file> Compare against an accepted baseline; only NEW findings (not
                    in the baseline) are gated by --fail-on. Adopt in CI without
                    failing on pre-existing crypto.
  --write-baseline <file>
                    Write the current findings as the accepted baseline and exit.
                    Run once to adopt, and again to accept new findings.
  -h, --help        Show this help

Examples:
  quantumvault ./src
  quantumvault . --sarif > quantumvault.sarif
  quantumvault . --assessment --org "Acme Corp" > assessment.html
  quantumvault . --fail-on high
  quantumvault . --write-baseline quantumvault-baseline.json
  quantumvault . --baseline quantumvault-baseline.json --fail-on high
`;

function parseArgs(argv: string[]): Args {
  const args: Args = { format: "table", help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") args.help = true;
    else if (a === "--json") args.format = "json";
    else if (a === "--sarif") args.format = "sarif";
    else if (a === "--cbom") args.format = "cbom";
    else if (a === "--csv") args.format = "csv";
    else if (a === "--assessment") args.format = "assessment";
    else if (a === "--org") args.org = argv[++i];
    else if (a === "--fail-on") args.failOn = argv[++i];
    else if (a === "--baseline") args.baseline = argv[++i];
    else if (a === "--write-baseline") args.writeBaseline = argv[++i];
    else if (!a.startsWith("-")) args.path = a;
  }
  return args;
}

function printTable(job: ScanJob, assets: CryptoAsset[]): void {
  // Low-confidence findings are possible mentions (a crypto name in a string,
  // enum, or doc) — reported separately, not counted as hard exposure. A
  // quantum-SAFE asset (a parsed PQC certificate) is inventory, not exposure,
  // so it never inflates the headline vulnerable count.
  const confident = assets.filter((a) => a.confidence !== "low");
  const mentions = assets.length - confident.length;
  const actionable = confident.filter((a) => a.quantumVulnerable);
  const safeAssets = confident.length - actionable.length;
  const byPriority: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of actionable) byPriority[a.risk?.priority ?? "low"] += 1;

  process.stdout.write(
    `\nUniQueS — ${job.filesScanned} files scanned, ${actionable.length} quantum-vulnerable assets` +
      (safeAssets ? ` · ${safeAssets} post-quantum (safe)` : "") +
      (mentions ? ` · ${mentions} possible mention${mentions === 1 ? "" : "s"} (low confidence)` : "") +
      ` (${job.durationMs}ms)\n`,
  );
  process.stdout.write(
    `  critical ${byPriority.critical}   high ${byPriority.high}   medium ${byPriority.medium}   low ${byPriority.low}\n\n`,
  );

  const top = [...actionable].sort((a, b) => (b.risk?.score ?? 0) - (a.risk?.score ?? 0)).slice(0, 25);
  for (const a of top) {
    const pri = (a.risk?.priority ?? "low").padEnd(8);
    const conf = a.confidence.padEnd(6);
    process.stdout.write(`  [${pri}] [${conf}] ${a.algorithm}  —  ${a.file}:${a.line}\n`);
  }
  if (actionable.length > top.length) {
    process.stdout.write(`  … and ${actionable.length - top.length} more\n`);
  }
  if (mentions) {
    process.stdout.write(`  ${mentions} possible mention${mentions === 1 ? "" : "s"} (low confidence) — review, not counted as exposure\n`);
  }
  process.stdout.write("\n");
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.path) {
    process.stdout.write(HELP);
    process.exit(args.help ? 0 : 2);
  }

  const target = resolve(args.path);
  if (!existsSync(target)) {
    process.stderr.write(`error: path does not exist: ${target}\n`);
    process.exit(2);
  }

  const { job, assets } = scanDirectory(target, "cli");
  scoreAssets(assets);

  // Write an accepted baseline and exit — the one-time "adopt in CI" action.
  if (args.writeBaseline) {
    const baseline = buildBaseline(assets, { version: VERSION, generatedAt: new Date().toISOString() });
    writeFileSync(args.writeBaseline, JSON.stringify(baseline, null, 2) + "\n");
    const n = baseline.fingerprints.length;
    process.stdout.write(`Wrote ${n} baselined finding${n === 1 ? "" : "s"} to ${args.writeBaseline}\n`);
    process.exit(0);
  }

  switch (args.format) {
    case "json":
      process.stdout.write(JSON.stringify({ job, assets }, null, 2) + "\n");
      break;
    case "sarif":
      process.stdout.write(JSON.stringify(assetsToSarif(assets), null, 2) + "\n");
      break;
    case "cbom":
      process.stdout.write(JSON.stringify(assetsToCbom(assets, { target }), null, 2) + "\n");
      break;
    case "csv":
      process.stdout.write(assetsToCsv(assets));
      break;
    case "assessment": {
      const reports = FRAMEWORKS.map((fw) => generateReport(fw, assets, job.id));
      const assessment = buildAssessment({
        orgName: args.org?.trim() || "Your Organization",
        generatedAt: new Date().toISOString(),
        scan: { target: job.target, filesScanned: job.filesScanned, finishedAt: job.finishedAt },
        assets,
        reports,
      });
      process.stdout.write(renderAssessmentHtml(assessment) + "\n");
      break;
    }
    default:
      printTable(job, assets);
  }

  // Gating operates on actionable findings — low-confidence "possible mentions"
  // are never exposure and never fail a build, and neither is a quantum-SAFE
  // asset (a parsed PQC certificate is inventory, not exposure). With
  // --baseline, only findings that are NEW since the accepted baseline are gated.
  let gated = assets.filter((a) => a.confidence !== "low" && a.quantumVulnerable);
  if (args.baseline) {
    if (!existsSync(args.baseline)) {
      process.stderr.write(`error: baseline not found: ${args.baseline} (create it with --write-baseline)\n`);
      process.exit(2);
    }
    const accepted = loadBaselineSet(readFileSync(args.baseline, "utf8"));
    const { fresh, baselined } = partitionByBaseline(gated, accepted);
    gated = fresh;
    process.stderr.write(
      `\nBaseline: ${fresh.length} new finding${fresh.length === 1 ? "" : "s"} since baseline (${baselined.length} accepted).\n`,
    );
  }

  if (args.failOn) {
    const threshold = SEVERITY_RANK[args.failOn as Severity];
    if (!threshold) {
      process.stderr.write(`error: --fail-on must be one of critical | high | medium | low\n`);
      process.exit(2);
    }
    const worst = Math.max(0, ...gated.map((a) => SEVERITY_RANK[a.risk?.priority ?? "low"]));
    if (worst >= threshold) {
      process.stderr.write(`FAIL: ${args.baseline ? "new findings" : "findings"} at or above "${args.failOn}" severity.\n`);
      process.exit(1);
    }
  }
}

main();
