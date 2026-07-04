import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { scanDirectory } from "../discovery/scanner.js";
import { QBENCH, KNOWN_GAPS, type QCase } from "./qbench.fixtures.js";

/**
 * qbench harness — scores detection precision/recall over the labeled corpus and
 * gates regressions. "Actionable" = confidence high or medium (the exposure a
 * buyer sees); low-confidence "possible mentions" are excluded by design, so the
 * metric measures exactly the "doesn't cry wolf" claim.
 *
 *   precision = TP / (TP + FP)   — of what we flagged as exposure, how much is real
 *   recall    = TP / (TP + FN)   — of the real crypto, how much we caught
 *
 * The gated corpus must score a perfect 1.0 / 1.0 — any drop is a precision (FP)
 * or recall (FN) regression and fails the build. New precision work adds cases.
 */

/** Scan every case (each as its own file) and return actionable patternIds per case. */
function runCorpus(cases: QCase[]): Map<string, string[]> {
  const dir = mkdtempSync(join(tmpdir(), "qv-qbench-"));
  try {
    const fileOf = new Map<QCase, string>();
    for (const c of cases) {
      const file = `${c.id}.${c.ext}`;
      writeFileSync(join(dir, file), c.code);
      fileOf.set(c, file);
    }
    const { assets } = scanDirectory(dir, "qbench");
    const actionableByFile = new Map<string, string[]>();
    for (const a of assets) {
      if (a.confidence === "low") continue; // possible mentions are not exposure
      if (!a.quantumVulnerable) continue; // quantum-SAFE inventory (a parsed PQC cert) is not exposure
      const list = actionableByFile.get(a.file) ?? [];
      list.push(a.patternId);
      actionableByFile.set(a.file, list);
    }
    const out = new Map<string, string[]>();
    for (const c of cases) out.set(c.id, actionableByFile.get(fileOf.get(c)!) ?? []);
    return out;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function multiset(xs: string[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
  return m;
}

interface Score {
  tp: number;
  fp: number;
  fn: number;
  precision: number;
  recall: number;
  fps: string[]; // "<case>: unexpected Nx <patternId>"
  fns: string[]; // "<case>: missing Nx <patternId>"
}

function score(cases: QCase[], actual: Map<string, string[]>): Score {
  let tp = 0, fp = 0, fn = 0;
  const fps: string[] = [];
  const fns: string[] = [];
  for (const c of cases) {
    const exp = multiset(c.expect);
    const act = multiset(actual.get(c.id) ?? []);
    const ids = new Set([...exp.keys(), ...act.keys()]);
    for (const id of ids) {
      const e = exp.get(id) ?? 0;
      const a = act.get(id) ?? 0;
      tp += Math.min(e, a);
      if (a > e) { fp += a - e; fps.push(`${c.id}: unexpected ${a - e}x ${id}`); }
      if (e > a) { fn += e - a; fns.push(`${c.id}: missing ${e - a}x ${id}`); }
    }
  }
  return {
    tp, fp, fn,
    precision: tp + fp === 0 ? 1 : tp / (tp + fp),
    recall: tp + fn === 0 ? 1 : tp / (tp + fn),
    fps, fns,
  };
}

test("qbench: detection precision & recall hold at 1.0 over the labeled corpus", () => {
  const s = score(QBENCH, runCorpus(QBENCH));
  const pct = (n: number) => (n * 100).toFixed(1);
  process.stdout.write(
    `\n  qbench — ${QBENCH.length} cases · TP ${s.tp} · FP ${s.fp} · FN ${s.fn}` +
      ` · precision ${pct(s.precision)}% · recall ${pct(s.recall)}%\n`,
  );
  // Recall is sacred for a security scanner — never silently miss real crypto.
  assert.equal(s.recall, 1, `recall regression (missed real crypto):\n  ${s.fns.join("\n  ")}`);
  // Precision: no trap may count as exposure.
  assert.equal(s.precision, 1, `precision regression (false positives):\n  ${s.fps.join("\n  ")}`);
});

test("qbench-gaps: report the precision worklist (informational — not gated)", () => {
  const actual = runCorpus(KNOWN_GAPS);
  const resolved: string[] = [];
  const open: string[] = [];
  for (const c of KNOWN_GAPS) {
    const act = actual.get(c.id) ?? [];
    // fp gap resolved = no actionable finding; fn gap resolved = something fires.
    const isResolved = c.gapKind === "fn" ? act.length > 0 : act.length === 0;
    (isResolved ? resolved : open).push(c.id);
  }
  process.stdout.write(
    `\n  qbench-gaps — ${open.length} open, ${resolved.length} resolved (of ${KNOWN_GAPS.length}).` +
      (open.length ? `\n    open (precision worklist — see each fixture's note for the fix path): ${open.join(", ")}` : "") +
      (resolved.length ? `\n    ✓ RESOLVED — promote into QBENCH: ${resolved.join(", ")}` : "") +
      "\n",
  );
  // Informational only — no assertion. A resolved gap should be moved into the
  // gated QBENCH corpus; this surfaces the worklist without failing the build.
});
