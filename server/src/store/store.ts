import { randomUUID } from "node:crypto";
import type { AssetStatus, Confidence, CryptoAsset, ComplianceReport, MonitorTarget, RiskScore, ScanJob } from "../types.js";
import { ASSET_STATUSES, RESOLVED_STATUSES } from "../types.js";
import { scanDirectory } from "../discovery/scanner.js";
import { confidenceFor } from "../discovery/patterns.js";
import { scoreAssets } from "../risk/scorer.js";
import { generateReport, FRAMEWORKS } from "../compliance/reporter.js";
import { db, DEFAULT_ORG_ID } from "./db.js";

interface AssetRow {
  id: string;
  scan_id: string;
  file: string;
  line: number;
  family: string;
  algorithm: string;
  key_bits: number | null;
  language: string;
  snippet: string;
  pattern_id: string;
  quantum_vulnerable: number;
  confidence: string | null;
  demotion_reason: string | null;
  pqc_replacement: string;
  risk_json: string | null;
  status: string;
}

interface ScanRow {
  id: string;
  target: string;
  started_at: string;
  finished_at: string;
  files_scanned: number;
  duration_ms: number;
  asset_count: number;
  status: string;
}

interface ReportRow {
  framework: string;
  scan_id: string;
  generated_at: string;
  overall_status: string;
  score_pct: number;
  summary: string;
  controls_json: string;
}

function rowToAsset(r: AssetRow): CryptoAsset {
  return {
    id: r.id,
    scanId: r.scan_id,
    file: r.file,
    line: r.line,
    family: r.family as CryptoAsset["family"],
    algorithm: r.algorithm,
    keyBits: r.key_bits,
    language: r.language,
    snippet: r.snippet,
    patternId: r.pattern_id,
    quantumVulnerable: !!r.quantum_vulnerable,
    // The scan-time confidence is authoritative: it carries per-finding context
    // demotions (mention/import-declaration/…) that the pattern's base tier does
    // not. confidenceFor() is only the fallback for rows persisted before the
    // confidence column existed.
    confidence: (r.confidence as Confidence | null) ?? confidenceFor(r.pattern_id),
    ...(r.demotion_reason ? { demotionReason: r.demotion_reason } : {}),
    pqcReplacement: r.pqc_replacement,
    status: (r.status as AssetStatus) ?? "open",
    risk: r.risk_json ? (JSON.parse(r.risk_json) as RiskScore) : undefined,
  };
}

function rowToScan(r: ScanRow): ScanJob {
  return {
    id: r.id,
    target: r.target,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    filesScanned: r.files_scanned,
    durationMs: r.duration_ms,
    assetCount: r.asset_count,
    status: r.status as ScanJob["status"],
  };
}

function rowToReport(r: ReportRow): ComplianceReport {
  return {
    framework: r.framework as ComplianceReport["framework"],
    scanId: r.scan_id,
    generatedAt: r.generated_at,
    overallStatus: r.overall_status as ComplianceReport["overallStatus"],
    scorePct: r.score_pct,
    summary: r.summary,
    controls: JSON.parse(r.controls_json),
  };
}

interface MonitorRow {
  id: string;
  org_id: string;
  name: string;
  kind: string;
  target: string;
  interval_minutes: number;
  enabled: number;
  created_at: string;
  last_run_at: string | null;
  next_run_at: string;
  last_scan_id: string | null;
  last_status: string | null;
  last_error: string | null;
  run_count: number;
}

function rowToMonitor(r: MonitorRow): MonitorTarget {
  return {
    id: r.id,
    orgId: r.org_id,
    name: r.name,
    kind: r.kind as MonitorTarget["kind"],
    target: r.target,
    intervalMinutes: r.interval_minutes,
    enabled: !!r.enabled,
    createdAt: r.created_at,
    lastRunAt: r.last_run_at,
    nextRunAt: r.next_run_at,
    lastScanId: r.last_scan_id,
    lastStatus: (r.last_status as MonitorTarget["lastStatus"]) ?? null,
    lastError: r.last_error,
    runCount: r.run_count,
  };
}

class Store {
  private insertScan = db.prepare(
    `INSERT INTO scans (id, org_id, target, started_at, finished_at, files_scanned, duration_ms, asset_count, status, is_latest, monitor_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
  );
  private clearLatest = db.prepare(`UPDATE scans SET is_latest = 0 WHERE org_id = ?`);
  private insertAsset = db.prepare(
    `INSERT INTO assets (id, scan_id, org_id, file, line, family, algorithm, key_bits, language, snippet, pattern_id, quantum_vulnerable, confidence, demotion_reason, pqc_replacement, risk_score, risk_priority, risk_json, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  private updateStatus = db.prepare(
    `UPDATE assets SET status = ? WHERE id = ? AND org_id = ?`,
  );
  private insertReport = db.prepare(
    `INSERT OR REPLACE INTO reports (framework, scan_id, org_id, generated_at, overall_status, score_pct, summary, controls_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );

  newScanId(): string {
    return `scan_${randomUUID().slice(0, 8)}`;
  }

  /**
   * Stable identity for a finding across re-scans: same file, same detection
   * pattern, same matched line text. Line numbers shift as code changes, so they
   * are deliberately excluded from the key.
   */
  private static carryKey(file: string, patternId: string, snippet: string): string {
    return `${file}\x1f${patternId}\x1f${snippet}`;
  }

  /**
   * Build a map of remediation statuses to carry forward from a prior scan, so a
   * finding marked migrated/in_progress/accepted stays that way when the codebase
   * is re-scanned. Only non-"open" statuses are carried.
   */
  private carryStatuses(orgId: string, prevScanId: string | null): Map<string, AssetStatus> {
    const map = new Map<string, AssetStatus>();
    if (!prevScanId) return map;
    const rows = db
      .prepare(
        `SELECT file, pattern_id, snippet, status FROM assets
         WHERE org_id = ? AND scan_id = ? AND status != 'open'`,
      )
      .all(orgId, prevScanId) as unknown as {
      file: string;
      pattern_id: string;
      snippet: string;
      status: string;
    }[];
    for (const r of rows) {
      map.set(Store.carryKey(r.file, r.pattern_id, r.snippet), r.status as AssetStatus);
    }
    return map;
  }

  /** Run discovery → risk scoring → compliance for a target dir, persist results. */
  runScan(
    target: string,
    displayTarget?: string,
    orgId = DEFAULT_ORG_ID,
    monitorId: string | null = null,
  ): { job: ScanJob; assetCount: number } {
    const scanId = this.newScanId();
    const { job, assets } = scanDirectory(target, scanId);
    if (displayTarget) job.target = displayTarget;
    scoreAssets(assets);

    // Capture prior remediation statuses before this scan becomes the latest.
    const carry = this.carryStatuses(orgId, this.latestScanId(orgId));

    db.exec("BEGIN");
    try {
      this.clearLatest.run(orgId);
      this.insertScan.run(
        job.id,
        orgId,
        job.target,
        job.startedAt,
        job.finishedAt,
        job.filesScanned,
        job.durationMs,
        job.assetCount,
        job.status,
        monitorId,
      );
      for (const a of assets) {
        // Carry forward a prior remediation status for the same finding.
        a.status = carry.get(Store.carryKey(a.file, a.patternId, a.snippet)) ?? a.status;
        this.insertAsset.run(
          a.id,
          a.scanId,
          orgId,
          a.file,
          a.line,
          a.family,
          a.algorithm,
          a.keyBits,
          a.language,
          a.snippet,
          a.patternId,
          a.quantumVulnerable ? 1 : 0,
          a.confidence,
          a.demotionReason ?? null,
          a.pqcReplacement,
          a.risk?.score ?? null,
          a.risk?.priority ?? null,
          a.risk ? JSON.stringify(a.risk) : null,
          a.status,
        );
      }
      for (const fw of FRAMEWORKS) {
        const report = generateReport(fw, assets, scanId);
        this.insertReport.run(
          report.framework,
          report.scanId,
          orgId,
          report.generatedAt,
          report.overallStatus,
          report.scorePct,
          report.summary,
          JSON.stringify(report.controls),
        );
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }

    return { job, assetCount: assets.length };
  }

  private latestScanId(orgId: string): string | null {
    const row = db
      .prepare(`SELECT id FROM scans WHERE org_id = ? AND is_latest = 1 LIMIT 1`)
      .get(orgId) as { id: string } | undefined;
    return row?.id ?? null;
  }

  /** Set of finding-identity keys for a given scan. */
  private scanKeys(orgId: string, scanId: string): Set<string> {
    const rows = db
      .prepare(`SELECT file, pattern_id, snippet FROM assets WHERE org_id = ? AND scan_id = ?`)
      .all(orgId, scanId) as unknown as { file: string; pattern_id: string; snippet: string }[];
    return new Set(rows.map((r) => Store.carryKey(r.file, r.pattern_id, r.snippet)));
  }

  /**
   * Drift between the latest scan and the one before it: how many findings were
   * newly introduced and how many disappeared (fixed or code removed). Identity
   * matches the carry-over key (file + pattern + matched line).
   */
  scanDelta(orgId = DEFAULT_ORG_ID): { hasPrevious: boolean; newFindings: number; removedFindings: number } {
    const ids = db
      .prepare(`SELECT id FROM scans WHERE org_id = ? ORDER BY started_at DESC LIMIT 2`)
      .all(orgId) as unknown as { id: string }[];
    if (ids.length < 2) return { hasPrevious: false, newFindings: 0, removedFindings: 0 };

    const latest = this.scanKeys(orgId, ids[0].id);
    const prev = this.scanKeys(orgId, ids[1].id);
    let newFindings = 0;
    let removedFindings = 0;
    for (const k of latest) if (!prev.has(k)) newFindings += 1;
    for (const k of prev) if (!latest.has(k)) removedFindings += 1;
    return { hasPrevious: true, newFindings, removedFindings };
  }

  getScans(orgId = DEFAULT_ORG_ID): ScanJob[] {
    const rows = db
      .prepare(`SELECT * FROM scans WHERE org_id = ? ORDER BY started_at DESC`)
      .all(orgId) as unknown as ScanRow[];
    return rows.map(rowToScan);
  }

  getAssets(filter?: { family?: string; priority?: string; q?: string }, orgId = DEFAULT_ORG_ID): CryptoAsset[] {
    const sid = this.latestScanId(orgId);
    if (!sid) return [];
    const clauses = ["scan_id = ?"];
    const params: (string | number)[] = [sid];
    if (filter?.family) {
      clauses.push("family = ?");
      params.push(filter.family);
    }
    if (filter?.priority) {
      clauses.push("risk_priority = ?");
      params.push(filter.priority);
    }
    if (filter?.q) {
      clauses.push("(lower(file) LIKE ? OR lower(algorithm) LIKE ? OR lower(snippet) LIKE ?)");
      const like = `%${filter.q.toLowerCase()}%`;
      params.push(like, like, like);
    }
    const rows = db
      .prepare(`SELECT * FROM assets WHERE ${clauses.join(" AND ")} ORDER BY risk_score DESC`)
      .all(...params) as unknown as AssetRow[];
    return rows.map(rowToAsset);
  }

  getAsset(id: string, orgId = DEFAULT_ORG_ID): CryptoAsset | undefined {
    const row = db
      .prepare(`SELECT * FROM assets WHERE id = ? AND org_id = ?`)
      .get(id, orgId) as AssetRow | undefined;
    return row ? rowToAsset(row) : undefined;
  }

  /**
   * Update an asset's remediation status. Scoped to the org so one tenant can't
   * mutate another's assets. Returns the updated asset, or undefined if no asset
   * with that id exists for the org.
   */
  updateAssetStatus(id: string, status: AssetStatus, orgId = DEFAULT_ORG_ID): CryptoAsset | undefined {
    if (!ASSET_STATUSES.includes(status)) {
      throw new Error(`invalid status: ${status}`);
    }
    const res = this.updateStatus.run(status, id, orgId);
    if (res.changes === 0) return undefined;
    return this.getAsset(id, orgId);
  }

  getReports(scanId?: string, orgId = DEFAULT_ORG_ID): ComplianceReport[] {
    const sid = scanId ?? this.latestScanId(orgId);
    if (!sid) return [];
    const rows = db
      .prepare(`SELECT * FROM reports WHERE scan_id = ? AND org_id = ?`)
      .all(sid, orgId) as unknown as ReportRow[];
    return rows.map(rowToReport);
  }

  getReport(framework: string, scanId?: string, orgId = DEFAULT_ORG_ID): ComplianceReport | undefined {
    const sid = scanId ?? this.latestScanId(orgId);
    if (!sid) return undefined;
    const row = db
      .prepare(`SELECT * FROM reports WHERE framework = ? AND scan_id = ? AND org_id = ?`)
      .get(framework, sid, orgId) as ReportRow | undefined;
    return row ? rowToReport(row) : undefined;
  }

  hasAnyScan(orgId = DEFAULT_ORG_ID): boolean {
    return this.latestScanId(orgId) !== null;
  }

  dashboard(orgId = DEFAULT_ORG_ID) {
    const assets = this.getAssets(undefined, orgId);
    const byFamily: Record<string, number> = {};
    const byPriority: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const byStatus: Record<AssetStatus, number> = { open: 0, in_progress: 0, migrated: 0, accepted: 0 };
    let migrationEffortDays = 0;
    let remainingEffortDays = 0;
    let quantumVulnerable = 0;
    let possibleMentions = 0;

    for (const a of assets) {
      // Low-confidence findings are possible mentions (a crypto name in a string,
      // enum, or doc). Surface them separately and exclude them from every
      // grade-driving aggregate so they can't tank the posture or pad the worklist.
      if (a.confidence === "low") {
        possibleMentions += 1;
        continue;
      }
      if (a.quantumVulnerable) quantumVulnerable += 1;
      byFamily[a.family] = (byFamily[a.family] ?? 0) + 1;
      const p = a.risk?.priority ?? "low";
      byPriority[p] += 1;
      byStatus[a.status] += 1;
      const effort = a.risk?.migrationEffortDays ?? 0;
      migrationEffortDays += effort;
      if (!RESOLVED_STATUSES.includes(a.status)) remainingEffortDays += effort;
    }

    const actionable = assets.length - possibleMentions;
    const resolved = byStatus.migrated + byStatus.accepted;
    const migrationProgressPct = actionable ? Math.round((resolved / actionable) * 100) : 0;

    const reports = this.getReports(undefined, orgId);
    const avgCompliance = reports.length
      ? Math.round(reports.reduce((s, r) => s + r.scorePct, 0) / reports.length)
      : 0;
    const sid = this.latestScanId(orgId);
    const latest = sid ? this.getScans(orgId).find((s) => s.id === sid) : undefined;

    return {
      totalAssets: assets.length,
      quantumVulnerable,
      possibleMentions,
      byFamily,
      byPriority,
      byStatus,
      migrationProgressPct,
      migrationEffortDays,
      remainingEffortDays,
      delta: this.scanDelta(orgId),
      avgCompliancePct: avgCompliance,
      frameworks: reports.map((r) => ({
        framework: r.framework,
        scorePct: r.scorePct,
        status: r.overallStatus,
      })),
      lastScan: latest
        ? {
            id: latest.id,
            filesScanned: latest.filesScanned,
            durationMs: latest.durationMs,
            finishedAt: latest.finishedAt,
          }
        : null,
    };
  }

  // ----------------------------------------------------------- continuous monitoring
  private insertMonitor = db.prepare(
    `INSERT INTO monitors (id, org_id, name, kind, target, interval_minutes, enabled, created_at, next_run_at, run_count)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, 0)`,
  );

  createMonitor(
    input: { name: string; kind: "git" | "path"; target: string; intervalMinutes: number },
    orgId = DEFAULT_ORG_ID,
  ): MonitorTarget {
    const id = `mon_${randomUUID().slice(0, 8)}`;
    const createdAt = new Date().toISOString();
    const interval = Math.max(1, Math.floor(input.intervalMinutes));
    // next_run_at = now → due on the very next scheduler tick.
    this.insertMonitor.run(id, orgId, input.name, input.kind, input.target, interval, createdAt, createdAt);
    return this.getMonitor(id, orgId)!;
  }

  listMonitors(orgId = DEFAULT_ORG_ID): MonitorTarget[] {
    const rows = db
      .prepare(`SELECT * FROM monitors WHERE org_id = ? ORDER BY created_at DESC`)
      .all(orgId) as unknown as MonitorRow[];
    return rows.map(rowToMonitor);
  }

  getMonitor(id: string, orgId = DEFAULT_ORG_ID): MonitorTarget | undefined {
    const row = db
      .prepare(`SELECT * FROM monitors WHERE id = ? AND org_id = ?`)
      .get(id, orgId) as MonitorRow | undefined;
    return row ? rowToMonitor(row) : undefined;
  }

  deleteMonitor(id: string, orgId = DEFAULT_ORG_ID): boolean {
    return db.prepare(`DELETE FROM monitors WHERE id = ? AND org_id = ?`).run(id, orgId).changes > 0;
  }

  setMonitorEnabled(id: string, enabled: boolean, orgId = DEFAULT_ORG_ID): MonitorTarget | undefined {
    const res = db
      .prepare(`UPDATE monitors SET enabled = ? WHERE id = ? AND org_id = ?`)
      .run(enabled ? 1 : 0, id, orgId);
    return res.changes === 0 ? undefined : this.getMonitor(id, orgId);
  }

  /** Enabled monitors whose next_run_at is at or before `now` — due to run.
   *  Spans all orgs because the scheduler is global. */
  dueMonitors(now = new Date()): MonitorTarget[] {
    const rows = db
      .prepare(`SELECT * FROM monitors WHERE enabled = 1 AND next_run_at <= ? ORDER BY next_run_at ASC`)
      .all(now.toISOString()) as unknown as MonitorRow[];
    return rows.map(rowToMonitor);
  }

  /** Record a monitor run's outcome and schedule the next run (ranAt + interval). */
  recordMonitorRun(
    id: string,
    outcome: { scanId: string | null; status: "ok" | "failed"; error?: string | null; ranAt?: Date },
  ): void {
    const mon = db
      .prepare(`SELECT interval_minutes FROM monitors WHERE id = ?`)
      .get(id) as { interval_minutes: number } | undefined;
    if (!mon) return;
    const ranAt = outcome.ranAt ?? new Date();
    const nextRunAt = new Date(ranAt.getTime() + mon.interval_minutes * 60_000).toISOString();
    db.prepare(
      `UPDATE monitors
         SET last_run_at = ?, next_run_at = ?, last_scan_id = ?, last_status = ?, last_error = ?, run_count = run_count + 1
       WHERE id = ?`,
    ).run(ranAt.toISOString(), nextRunAt, outcome.scanId, outcome.status, outcome.error ?? null, id);
  }

  /** Scans produced by a given monitor, newest first. */
  monitorScans(monitorId: string, orgId = DEFAULT_ORG_ID): ScanJob[] {
    const rows = db
      .prepare(`SELECT * FROM scans WHERE monitor_id = ? AND org_id = ? ORDER BY started_at DESC`)
      .all(monitorId, orgId) as unknown as ScanRow[];
    return rows.map(rowToScan);
  }

  /** Drift between a monitor's two most recent scans (new vs removed findings). */
  monitorDrift(
    monitorId: string,
    orgId = DEFAULT_ORG_ID,
  ): { hasPrevious: boolean; newFindings: number; removedFindings: number } {
    const ids = db
      .prepare(`SELECT id FROM scans WHERE monitor_id = ? AND org_id = ? ORDER BY started_at DESC LIMIT 2`)
      .all(monitorId, orgId) as unknown as { id: string }[];
    if (ids.length < 2) return { hasPrevious: false, newFindings: 0, removedFindings: 0 };
    const latest = this.scanKeys(orgId, ids[0].id);
    const prev = this.scanKeys(orgId, ids[1].id);
    let newFindings = 0;
    let removedFindings = 0;
    for (const k of latest) if (!prev.has(k)) newFindings += 1;
    for (const k of prev) if (!latest.has(k)) removedFindings += 1;
    return { hasPrevious: true, newFindings, removedFindings };
  }
}

export const store = new Store();
