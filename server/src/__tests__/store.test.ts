import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the SQLite database to a temp file BEFORE importing the store, so this
// test never touches a real/seeded database. node:test runs each test file in
// its own process, so this env var is picked up cleanly at module init.
const dbDir = mkdtempSync(join(tmpdir(), "qv-store-db-"));
process.env.QV_DB_PATH = join(dbDir, "test.db");

const { store } = await import("../store/store.js");
const { runDueMonitors, runMonitorOnce } = await import("../monitor/scheduler.js");

test("store: status updates drive migration progress and are org-scoped", () => {
  const org = "org_test";
  const src = mkdtempSync(join(tmpdir(), "qv-store-src-"));
  try {
    // A source tree with a few quantum-vulnerable assets.
    writeFileSync(
      join(src, "app.ts"),
      [
        "const k = generateKeyPairSync('rsa', { modulusLength: 2048 });",
        "// uses ECDSA on prime256v1",
        "createDiffieHellman(2048);",
      ].join("\n"),
    );

    store.runScan(src, undefined, org);
    const assets = store.getAssets(undefined, org);
    assert.ok(assets.length >= 2, `expected >=2 assets, got ${assets.length}`);
    assert.ok(assets.every((a) => a.status === "open"), "new assets must start 'open'");

    // The worklist / migration math is over ACTIONABLE findings only — low-confidence
    // "possible mentions" are excluded (a clean design choice, surfaced separately).
    const actionable = assets.filter((a) => a.confidence !== "low");

    // Baseline: nothing resolved.
    let dash = store.dashboard(org);
    assert.equal(dash.migrationProgressPct, 0);
    assert.equal(dash.byStatus.open, actionable.length);
    const totalEffort = dash.migrationEffortDays;
    assert.equal(dash.remainingEffortDays, totalEffort);

    // Resolve one actionable asset -> progress and remaining effort move.
    const first = actionable[0];
    const updated = store.updateAssetStatus(first.id, "migrated", org);
    assert.equal(updated?.status, "migrated");

    dash = store.dashboard(org);
    assert.equal(dash.byStatus.migrated, 1);
    assert.equal(dash.migrationProgressPct, Math.round((1 / actionable.length) * 100));
    assert.ok(dash.remainingEffortDays <= totalEffort);

    // Invalid status is rejected.
    assert.throws(() => store.updateAssetStatus(first.id, "bogus" as never, org), /invalid status/);

    // Unknown id -> undefined (no throw).
    assert.equal(store.updateAssetStatus("nope", "migrated", org), undefined);

    // Org isolation: another org can't mutate this org's asset.
    assert.equal(store.updateAssetStatus(first.id, "accepted", "org_other"), undefined);
    assert.equal(store.getAsset(first.id, org)?.status, "migrated");
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("store: remediation status carries forward across re-scans", () => {
  const org = "org_rescan";
  const src = mkdtempSync(join(tmpdir(), "qv-rescan-src-"));
  try {
    writeFileSync(
      join(src, "app.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "createDiffieHellman(2048);"].join("\n"),
    );

    // First scan, then resolve one finding.
    store.runScan(src, undefined, org);
    const before = store.getAssets(undefined, org);
    // Resolve an ACTIONABLE finding (low-confidence "mentions" are excluded from
    // the dashboard worklist), so byStatus reflects the migration below.
    const target = before.find((a) => a.confidence !== "low") ?? before[0];
    store.updateAssetStatus(target.id, "migrated", org);

    // Re-scan the same (unchanged) source — a brand new scan with new asset ids.
    store.runScan(src, undefined, org);
    const after = store.getAssets(undefined, org);

    // New scan => different asset ids, but the resolved finding stays "migrated".
    assert.ok(!after.some((a) => a.id === target.id), "re-scan should produce fresh asset ids");
    const carried = after.find((a) => a.patternId === target.patternId && a.file === target.file);
    assert.equal(carried?.status, "migrated", "status should carry across re-scan");

    // Other findings remain open, and progress reflects exactly one carried asset.
    const dash = store.dashboard(org);
    assert.equal(dash.byStatus.migrated, 1);
    assert.ok(dash.byStatus.open >= 1);
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("store: scan delta reports new and removed findings vs the previous scan", () => {
  const org = "org_delta";
  const src = mkdtempSync(join(tmpdir(), "qv-delta-src-"));
  try {
    // Scan 1: one RSA finding + one DH finding.
    writeFileSync(
      join(src, "app.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "createDiffieHellman(2048);"].join("\n"),
    );
    store.runScan(src, undefined, org);
    assert.equal(store.dashboard(org).delta.hasPrevious, false, "first scan has no previous");

    // Scan 2: remove the DH line, add a DES line -> 1 new, 1 removed.
    writeFileSync(
      join(src, "app.ts"),
      ["const k = generateKeyPairSync('rsa', { modulusLength: 2048 });", "const c = createCipheriv('des-ede3', k, iv);"].join("\n"),
    );
    store.runScan(src, undefined, org);

    const delta = store.dashboard(org).delta;
    assert.equal(delta.hasPrevious, true);
    assert.ok(delta.newFindings >= 1, `expected >=1 new, got ${delta.newFindings}`);
    assert.ok(delta.removedFindings >= 1, `expected >=1 removed, got ${delta.removedFindings}`);
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("store: scan-time confidence and demotionReason survive persistence (server/dashboard path)", () => {
  // A demoted Go import must come back from the DB at its DEMOTED tier with its
  // machine-readable reason — not recomputed to the pattern's base tier. This is
  // the surface enterprise buyers consume (API + dashboard), so the informational
  // tier has to be real here, not only in the CLI's in-memory output.
  const org = "org_demotion";
  const src = mkdtempSync(join(tmpdir(), "qv-demote-src-"));
  try {
    writeFileSync(join(src, "wrapper.go"), 'package main\n\nimport "crypto/rsa"\n');
    store.runScan(src, undefined, org);
    const assets = store.getAssets(undefined, org);
    const imp = assets.find((a) => a.patternId === "go-crypto-rsa");
    assert.ok(imp, "the demoted import finding must remain visible via the store");
    assert.equal(imp.confidence, "low", "persisted confidence must be the scan-time (demoted) tier");
    assert.equal(imp.demotionReason, "import-declaration", "demotionReason must survive the DB round-trip");
    assert.equal(imp.risk?.priority, "low", "informational findings carry no actionable priority");
    assert.equal(imp.risk?.migrationEffortDays, 0, "informational findings carry no migration effort");
    assert.equal(store.getAsset(imp.id, org)?.demotionReason, "import-declaration");
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- continuous monitoring
test("monitor: create exposes defaults and is due immediately", () => {
  const org = "org_mon1";
  const m = store.createMonitor({ name: "demo", kind: "path", target: "/tmp/qv-nope", intervalMinutes: 30 }, org);
  assert.equal(m.enabled, true);
  assert.equal(m.runCount, 0);
  assert.equal(m.intervalMinutes, 30);
  assert.ok(store.dueMonitors(new Date(Date.now() + 1000)).some((d) => d.id === m.id), "new monitor is due");
  assert.ok(store.listMonitors(org).some((x) => x.id === m.id));
  assert.equal(store.getMonitor(m.id, org)?.kind, "path");
});

test("monitor: scheduler runs a due path monitor and records a tagged scan", async () => {
  const org = "org_mon2";
  const src = mkdtempSync(join(tmpdir(), "qv-mon-src-"));
  try {
    writeFileSync(join(src, "app.ts"), "const k = generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    const m = store.createMonitor({ name: "repo", kind: "path", target: src, intervalMinutes: 60 }, org);

    const ran = await runDueMonitors(new Date(Date.now() + 1000));
    assert.ok(ran >= 1, "at least one monitor ran");
    const fresh = store.getMonitor(m.id, org)!;
    assert.equal(fresh.lastStatus, "ok");
    assert.equal(fresh.runCount, 1);
    assert.ok(fresh.lastScanId, "a scan id was recorded");
    assert.ok(new Date(fresh.nextRunAt).getTime() > Date.now(), "next run scheduled in the future");
    assert.equal(store.monitorScans(m.id, org).length, 1, "exactly one scan tagged to the monitor");
    assert.equal(store.monitorDrift(m.id, org).hasPrevious, false);
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("monitor: a second run surfaces drift between the monitor's scans", async () => {
  const org = "org_mon_drift";
  const src = mkdtempSync(join(tmpdir(), "qv-mon-drift-"));
  try {
    writeFileSync(join(src, "app.ts"), "const k = generateKeyPairSync('rsa', { modulusLength: 2048 });\n");
    const m = store.createMonitor({ name: "drift", kind: "path", target: src, intervalMinutes: 60 }, org);
    await runMonitorOnce(store.getMonitor(m.id, org)!);

    // Replace the RSA usage with a legacy cipher -> 1 new, 1 removed.
    writeFileSync(join(src, "app.ts"), "const c = createCipheriv('des-ede3', k, iv);\n");
    await runMonitorOnce(store.getMonitor(m.id, org)!);

    assert.ok(store.monitorScans(m.id, org).length >= 2, "two monitor scans recorded");
    const drift = store.monitorDrift(m.id, org);
    assert.equal(drift.hasPrevious, true);
    assert.ok(drift.newFindings >= 1, `expected new findings, got ${drift.newFindings}`);
    assert.ok(drift.removedFindings >= 1, `expected removed findings, got ${drift.removedFindings}`);
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
});

test("monitor: a failed run is recorded without throwing", async () => {
  const org = "org_mon_fail";
  const m = store.createMonitor({ name: "bad", kind: "path", target: "/tmp/qv-does-not-exist-xyz", intervalMinutes: 60 }, org);
  await runMonitorOnce(store.getMonitor(m.id, org)!);
  const fresh = store.getMonitor(m.id, org)!;
  assert.equal(fresh.lastStatus, "failed");
  assert.ok(fresh.lastError && fresh.lastError.length > 0, "error message captured");
  assert.equal(fresh.lastScanId, null);
});

test("monitor: disabled monitors are not due; recordRun schedules by interval; delete works", () => {
  const org = "org_mon5";
  const m = store.createMonitor({ name: "iv", kind: "path", target: "/tmp/qv-z", intervalMinutes: 15 }, org);

  store.setMonitorEnabled(m.id, false, org);
  assert.ok(!store.dueMonitors(new Date(Date.now() + 60_000)).some((d) => d.id === m.id), "disabled is not due");

  store.setMonitorEnabled(m.id, true, org);
  store.recordMonitorRun(m.id, { scanId: "scan_x", status: "ok", ranAt: new Date("2030-01-01T00:00:00.000Z") });
  const fresh = store.getMonitor(m.id, org)!;
  assert.equal(new Date(fresh.nextRunAt).toISOString(), "2030-01-01T00:15:00.000Z", "next run = ranAt + interval");
  assert.ok(!store.dueMonitors(new Date()).some((d) => d.id === m.id), "not due until 2030");

  assert.equal(store.deleteMonitor(m.id, org), true);
  assert.equal(store.getMonitor(m.id, org), undefined);
});

test.after(() => rmSync(dbDir, { recursive: true, force: true }));
