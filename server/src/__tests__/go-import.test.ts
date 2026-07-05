import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanDirectory } from "../discovery/scanner.js";
import { isGoImportDeclAt } from "../discovery/context.js";
import { scoreAssets } from "../risk/scorer.js";
import { assetsToSarif } from "../discovery/sarif.js";
import { assetsToCsv } from "../discovery/csv.js";
import type { CryptoAsset } from "../types.js";

// ── Go-import precision slice ────────────────────────────────────────────────
// A bare Go import line (`import "crypto/ecdsa"`, or a grouped-block member) is
// a package dependency declaration, not a crypto operation. Such findings are
// DEMOTED to the informational tier (confidence "low", demotionReason
// "import-declaration"), never hidden: they must remain visible in output. Go
// files only. NOTE: the 20-repo benchmark's published labels adjudicated an
// uncorroborated import as FP and a call-site-corroborated import as TP; this
// demotion re-tiers BOTH classes (the call-site stays actionable) — the
// benchmark impact, including the labeled-TP shrink, is disclosed in
// bench/REPORT.md.

function scanGo(source: string): CryptoAsset[] {
  const dir = mkdtempSync(join(tmpdir(), "qv-goimp-"));
  try {
    writeFileSync(join(dir, "main.go"), source);
    return scanDirectory(dir, "goimp").assets;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("go import: single-line import is demoted to informational, not hidden", () => {
  const assets = scanGo('package main\n\nimport "crypto/ecdsa"\n');
  const hit = assets.find((a) => a.patternId === "go-ecdsa");
  assert.ok(hit, "the import finding must remain visible in output");
  assert.equal(hit.confidence, "low", "a bare import declaration is informational");
  assert.equal(hit.demotionReason, "import-declaration");
});

test("go import: grouped block members (plain, aliased, underscore) are all demoted", () => {
  const assets = scanGo(
    "package main\n\nimport (\n" +
      '\t"crypto/rsa"\n' +
      '\tecdsakey "crypto/ecdsa"\n' +
      '\t_ "crypto/dsa"\n' +
      ")\n",
  );
  for (const id of ["go-crypto-rsa", "go-ecdsa", "go-dsa"]) {
    const hit = assets.find((a) => a.patternId === id);
    assert.ok(hit, `${id} must remain visible in output`);
    assert.equal(hit.confidence, "low", `${id} on an import block member must be informational`);
    assert.equal(hit.demotionReason, "import-declaration", `${id} must carry the demotion reason`);
  }
});

test("go import: commented-out import yields no finding at all (comment mask)", () => {
  const assets = scanGo('package main\n\n// import "crypto/ecdsa"\nvar x = 1\n');
  assert.equal(
    assets.length, 0,
    `a commented import is a masked mention, got: ${assets.map((a) => a.patternId).join(", ")}`,
  );
});

test("go import: a REAL usage call keeps full confidence and no demotion reason", () => {
  const assets = scanGo(
    "package main\n\n" +
      'import (\n\t"crypto/ecdsa"\n\t"crypto/elliptic"\n\t"crypto/rand"\n)\n\n' +
      "func gen() {\n" +
      "\tkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)\n" +
      "\t_ = key\n" +
      "}\n",
  );
  const usage = assets.find((a) => a.patternId === "go-ecdsa" && a.snippet.includes("GenerateKey"));
  assert.ok(usage, "the ecdsa.GenerateKey call-site must fire");
  assert.equal(usage.confidence, "high", "a real key generation is actionable, never demoted");
  assert.equal(usage.demotionReason, undefined);
  // …while the import line in the SAME file stays visible at the informational tier.
  const imp = assets.find((a) => a.patternId === "go-ecdsa" && a.demotionReason === "import-declaration");
  assert.ok(imp, "the import finding is kept (demoted, visible) alongside the usage");
  assert.equal(imp.confidence, "low");
});

test("go import: a usage line whose string merely contains the word import is NOT demoted", () => {
  const assets = scanGo(
    "package main\n\n" +
      "func gen() {\n" +
      '\tkey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // note\n' +
      '\tlog("import complete")\n' +
      "\t_ = key\n" +
      "}\n",
  );
  const usage = assets.find((a) => a.patternId === "go-ecdsa");
  assert.ok(usage, "the ecdsa.GenerateKey call-site must fire");
  assert.notEqual(usage.confidence, "low", "a real usage near the word import stays actionable");
  assert.equal(usage.demotionReason, undefined);
});

test("go import: a bare quoted path in a composite literal is not an import member", () => {
  // Same string shape as an import member, but inside a []string literal — the
  // backward scan never reaches an `import (` opener (the literal's own lines
  // carry trailing commas, which fail the member shape).
  const src =
    "package main\n\n" +
    "var deps = []string{\n" +
    '\t"crypto/ecdsa",\n' +
    '\t"crypto/rsa",\n' +
    "}\n";
  const assets = scanGo(src);
  for (const a of assets.filter((x) => x.patternId === "go-ecdsa" || x.patternId === "go-crypto-rsa")) {
    assert.equal(a.demotionReason, undefined, `${a.patternId} in a composite literal must not be tagged import-declaration`);
  }
  // Direct helper check on the trailing-comma line shape:
  const off = src.indexOf('\t"crypto/ecdsa",');
  assert.equal(isGoImportDeclAt(src, off), false, "a comma-terminated literal element is not an import member");
});

test("go import: an import-shaped line inside a backtick raw string is NOT stamped import-declaration", () => {
  // Codegen-template fixture: the line is string CONTENT, not an import
  // declaration. The mention machinery already keeps it low; the machine-
  // readable reason must not mislabel it.
  const src =
    "package main\n\n" +
    "var tmpl = `package out\n" +
    'import "crypto/rsa"\n' +
    "`\n";
  const assets = scanGo(src);
  for (const a of assets.filter((x) => x.patternId === "go-crypto-rsa")) {
    assert.equal(a.demotionReason, undefined, "raw-string content must not carry import-declaration");
  }
});

test("go import: the informational tier survives into risk, SARIF, and CSV — not just JSON", () => {
  const assets = scanGo('package main\n\nimport "crypto/rsa"\n');
  const imp = assets.find((a) => a.demotionReason === "import-declaration");
  assert.ok(imp, "demoted import finding present");
  scoreAssets(assets);

  // Risk model honors the tier: no migration plan for an informational finding.
  assert.equal(imp.risk!.priority, "low", "informational must not earn an actionable priority");
  assert.equal(imp.risk!.migrationEffortDays, 0, "informational carries no migration effort");
  assert.match(imp.risk!.recommendation, /informational/i);

  // SARIF: level note, zero security-severity, machine-readable reason.
  const sarif = assetsToSarif(assets) as any;
  const res = sarif.runs[0].results.find((r: any) => r.properties.demotionReason === "import-declaration");
  assert.ok(res, "demoted finding must remain in SARIF output");
  assert.equal(res.level, "note", "informational tier maps to SARIF note, never warning/error");
  assert.equal(res.properties.confidence, "low");
  assert.equal(res.properties["security-severity"], "0.0");

  // CSV: confidence + demotion_reason columns make the tier visible per row.
  const csv = assetsToCsv(assets);
  const header = csv.split("\r\n")[0].split(",");
  assert.ok(header.includes("confidence") && header.includes("demotion_reason"), header.join(","));
  const row = csv.split("\r\n").find((l) => l.includes("import-declaration"));
  assert.ok(row, "demoted finding must remain in CSV output, tagged with its reason");
  assert.ok(row!.includes("low"), "CSV row must carry the informational tier");
});

test("go import: scope is Go only — a Python crypto import is untouched by this slice", () => {
  const dir = mkdtempSync(join(tmpdir(), "qv-goimp-py-"));
  try {
    writeFileSync(join(dir, "keys.py"),
      "from cryptography.hazmat.primitives.asymmetric import ec\n" +
      "priv = ec.generate_private_key(ec.SECP256R1())\n");
    const assets = scanDirectory(dir, "goimp-py").assets;
    const hit = assets.find((a) => a.patternId === "ecc-python");
    assert.ok(hit, "the Python EC keygen must fire");
    assert.equal(hit.demotionReason, undefined, "no Python finding may carry the Go import demotion");
    assert.equal(hit.confidence, "high");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
