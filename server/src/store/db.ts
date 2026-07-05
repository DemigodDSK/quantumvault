import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DB_PATH = process.env.QV_DB_PATH ?? resolve(__dirname, "..", "..", "data", "quantumvault.db");

mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS organizations (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES organizations(id),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    target        TEXT NOT NULL,
    started_at    TEXT NOT NULL,
    finished_at   TEXT NOT NULL,
    files_scanned INTEGER NOT NULL,
    duration_ms   INTEGER NOT NULL,
    asset_count   INTEGER NOT NULL,
    status        TEXT NOT NULL,
    is_latest     INTEGER NOT NULL DEFAULT 0,
    monitor_id    TEXT
  );

  CREATE TABLE IF NOT EXISTS assets (
    id                 TEXT PRIMARY KEY,
    scan_id            TEXT NOT NULL,
    org_id             TEXT NOT NULL,
    file               TEXT NOT NULL,
    line               INTEGER NOT NULL,
    family             TEXT NOT NULL,
    algorithm          TEXT NOT NULL,
    key_bits           INTEGER,
    language           TEXT NOT NULL,
    snippet            TEXT NOT NULL,
    pattern_id         TEXT NOT NULL,
    quantum_vulnerable INTEGER NOT NULL,
    confidence         TEXT,
    demotion_reason    TEXT,
    pqc_replacement    TEXT NOT NULL,
    risk_score         INTEGER,
    risk_priority      TEXT,
    risk_json          TEXT,
    status             TEXT NOT NULL DEFAULT 'open'
  );

  CREATE TABLE IF NOT EXISTS reports (
    framework      TEXT NOT NULL,
    scan_id        TEXT NOT NULL,
    org_id         TEXT NOT NULL,
    generated_at   TEXT NOT NULL,
    overall_status TEXT NOT NULL,
    score_pct      INTEGER NOT NULL,
    summary        TEXT NOT NULL,
    controls_json  TEXT NOT NULL,
    PRIMARY KEY (framework, scan_id)
  );

  CREATE TABLE IF NOT EXISTS monitors (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    target           TEXT NOT NULL,
    interval_minutes INTEGER NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    last_run_at      TEXT,
    next_run_at      TEXT NOT NULL,
    last_scan_id     TEXT,
    last_status      TEXT,
    last_error       TEXT,
    run_count        INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS app_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
  CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);
  CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id);
  CREATE INDEX IF NOT EXISTS idx_monitors_org ON monitors(org_id);
`);

// Lightweight, idempotent migrations for databases created before a column
// existed. CREATE TABLE IF NOT EXISTS does not alter existing tables, so add
// new columns here; the ALTER throws (and is ignored) once the column exists.
for (const stmt of [
  `ALTER TABLE assets ADD COLUMN status TEXT NOT NULL DEFAULT 'open'`,
  `ALTER TABLE scans ADD COLUMN monitor_id TEXT`,
  // Per-finding confidence + demotion reason (Go-import precision slice). NULL on
  // rows written before these columns existed — readers fall back to the
  // pattern's base tier for those legacy rows only.
  `ALTER TABLE assets ADD COLUMN confidence TEXT`,
  `ALTER TABLE assets ADD COLUMN demotion_reason TEXT`,
]) {
  try {
    db.exec(stmt);
  } catch {
    /* column already present — nothing to do */
  }
}

// Created after the migration so the column is guaranteed to exist on old DBs.
db.exec(`CREATE INDEX IF NOT EXISTS idx_scans_monitor ON scans(monitor_id)`);

export const DEFAULT_ORG_ID = "org_default";
/** Display name for the public demo org — the single source of truth shared by
 *  the seed row and the unauthenticated display-name fallback (e.g. report headers). */
export const DEFAULT_ORG_NAME = "Demo Organization";

// Ensure a default organization exists for unauthenticated / seed usage.
db.prepare(
  `INSERT OR IGNORE INTO organizations (id, name, created_at) VALUES (?, ?, ?)`,
).run(DEFAULT_ORG_ID, DEFAULT_ORG_NAME, new Date().toISOString());
