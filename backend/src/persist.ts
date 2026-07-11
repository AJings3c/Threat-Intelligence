import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { errorMessage } from './util.js';
import type { AuditEvent, CveItem, DetectionArtifact, InvestigationHistoryEntry, ThreatIndicator } from './types.js';

// Lightweight, OPT-IN persistence layer backed by Node's built-in SQLite (node:sqlite,
// Node >= 22). It is enabled only when DATA_DIR is set; otherwise everything is a no-op
// and the platform runs purely in-memory exactly as before. If node:sqlite is unavailable
// (e.g. Node 20) or the DB can't be opened, we log and fall back to in-memory.

export interface GeoRow {
  country?: string;
  countryCode?: string;
  lat?: number;
  lon?: number;
}

export interface TrendPoint {
  ts: number;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export type PushEventStatus = 'success' | 'failed';

export interface PushEventInput {
  itemId: string;
  channel: string;
  status: PushEventStatus;
  title: string;
  error?: string;
}

export interface SourceHealthHistoryPoint {
  ts: number;
  source: string;
  ok: boolean;
  stale: boolean;
  count: number;
  error: string | null;
}

export interface PersistedStixObject {
  type: string;
  id: string;
  spec_version?: string;
  created?: string;
  modified?: string;
  [key: string]: unknown;
}

interface Statement {
  all(...params: unknown[]): unknown[];
  get(...params: unknown[]): unknown;
  run(...params: unknown[]): unknown;
}

interface Database {
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
}

let db: Database | null = null;

export function isPersistEnabled(): boolean {
  return db !== null;
}

// Open (or create) the SQLite database. Safe to call once at startup.
export function initPersistence(): void {
  const dir = process.env.DATA_DIR?.trim();
  if (!dir) return; // opt-in: no DATA_DIR => in-memory only
  try {
    fs.mkdirSync(dir, { recursive: true });
    const require = createRequire(import.meta.url);
    const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');
    db = new DatabaseSync(path.join(dir, 'threat-intel.db')) as unknown as Database;
    db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
    db.exec(`
      CREATE TABLE IF NOT EXISTS geo_cache (
        ip TEXT PRIMARY KEY, country TEXT, country_code TEXT, lat REAL, lon REAL
      );
      CREATE TABLE IF NOT EXISTS indicator_seen (
        key TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS threat_indicators (
        object_key TEXT PRIMARY KEY,
        id TEXT NOT NULL,
        source TEXT NOT NULL,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        first_persisted_at INTEGER NOT NULL,
        last_persisted_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_threat_indicators_active_type
        ON threat_indicators(active, indicator_type);
      CREATE INDEX IF NOT EXISTS idx_threat_indicators_active_severity
        ON threat_indicators(active, severity);
      CREATE TABLE IF NOT EXISTS indicator_observations (
        object_key TEXT NOT NULL,
        source TEXT NOT NULL,
        first_observed_at INTEGER NOT NULL,
        last_observed_at INTEGER NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (object_key, source)
      );
      CREATE INDEX IF NOT EXISTS idx_indicator_observations_source_last
        ON indicator_observations(source, last_observed_at);
      CREATE TABLE IF NOT EXISTS cve_objects (
        cve_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        severity TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        first_persisted_at INTEGER NOT NULL,
        last_persisted_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cve_objects_active_severity
        ON cve_objects(active, severity);
      CREATE TABLE IF NOT EXISTS intel_snapshot_meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        saved_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS connector_state (
        connector TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS imported_stix_objects (
        object_id TEXT NOT NULL,
        version TEXT NOT NULL,
        object_type TEXT NOT NULL,
        connector TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        first_imported_at INTEGER NOT NULL,
        last_imported_at INTEGER NOT NULL,
        PRIMARY KEY (object_id, version)
      );
      CREATE INDEX IF NOT EXISTS idx_imported_stix_type
        ON imported_stix_objects(object_type, last_imported_at);
      CREATE TABLE IF NOT EXISTS detection_artifacts (
        id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        format TEXT CHECK(format IN ('sigma','yara','snort')) NOT NULL,
        payload_json TEXT NOT NULL,
        first_imported_at INTEGER NOT NULL,
        last_imported_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_detection_artifacts_format
        ON detection_artifacts(format, last_imported_at);
      CREATE TABLE IF NOT EXISTS background_jobs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT CHECK(status IN ('queued','running','succeeded','failed','dead')) NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 5,
        available_at INTEGER NOT NULL,
        lease_until INTEGER,
        locked_by TEXT,
        dedupe_key TEXT,
        last_error TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_background_jobs_claim
        ON background_jobs(status, available_at, created_at);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_background_jobs_active_dedupe
        ON background_jobs(dedupe_key) WHERE dedupe_key IS NOT NULL AND status IN ('queued','running');
      CREATE TABLE IF NOT EXISTS refresh_snapshot (
        ts INTEGER PRIMARY KEY, total INTEGER, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER
      );
      CREATE TABLE IF NOT EXISTS push_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        status TEXT NOT NULL,
        title TEXT NOT NULL,
        pushed_at TEXT NOT NULL,
        error TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_push_events_lookup
        ON push_events(item_id, channel, status);
      CREATE TABLE IF NOT EXISTS source_health_history (
        ts INTEGER NOT NULL,
        source TEXT NOT NULL,
        ok INTEGER NOT NULL,
        stale INTEGER NOT NULL,
        count INTEGER NOT NULL,
        error TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (ts, source)
      );
      CREATE INDEX IF NOT EXISTS idx_source_health_history_source_ts
        ON source_health_history(source, ts);
      CREATE TABLE IF NOT EXISTS investigation_history (
        id TEXT PRIMARY KEY,
        ts INTEGER NOT NULL,
        indicator TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        posture TEXT NOT NULL,
        exact_count INTEGER NOT NULL,
        related_count INTEGER NOT NULL,
        highest_severity TEXT NOT NULL DEFAULT '',
        confidence INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_investigation_history_ts
        ON investigation_history(ts);
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        role TEXT NOT NULL,
        principal TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL,
        path TEXT NOT NULL,
        ok INTEGER NOT NULL,
        detail TEXT NOT NULL DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_audit_events_ts
        ON audit_events(ts);

      -- Phase 1: Platform Upgrade Tables
      CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        status TEXT CHECK(status IN ('open','investigating','resolved','closed')) NOT NULL,
        severity TEXT CHECK(severity IN ('low','medium','high','critical')) NOT NULL,
        assignee TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
      CREATE INDEX IF NOT EXISTS idx_cases_assignee ON cases(assignee);

      CREATE TABLE IF NOT EXISTS case_iocs (
        case_id TEXT NOT NULL,
        ioc_id TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (case_id, ioc_id)
      );
      CREATE INDEX IF NOT EXISTS idx_case_iocs_ioc ON case_iocs(ioc_id);

      CREATE TABLE IF NOT EXISTS case_comments (
        id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        author TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_case_comments_case ON case_comments(case_id);

      CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        trigger_type TEXT CHECK(trigger_type IN ('ioc_match','threshold','schedule')) NOT NULL,
        trigger_config TEXT NOT NULL,
        actions TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

      CREATE TABLE IF NOT EXISTS rule_executions (
        id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        triggered_at INTEGER NOT NULL,
        actions_taken TEXT NOT NULL,
        success INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_rule_executions_rule ON rule_executions(rule_id);
      CREATE INDEX IF NOT EXISTS idx_rule_executions_triggered ON rule_executions(triggered_at);

      CREATE TABLE IF NOT EXISTS enrichment_cache (
        ioc_value TEXT NOT NULL,
        provider TEXT NOT NULL,
        result TEXT NOT NULL,
        cached_at INTEGER NOT NULL,
        PRIMARY KEY (ioc_value, provider)
      );
      CREATE INDEX IF NOT EXISTS idx_enrichment_cache_cached_at ON enrichment_cache(cached_at);

      CREATE TABLE IF NOT EXISTS false_positives (
        ioc_value TEXT PRIMARY KEY,
        marked_by TEXT NOT NULL,
        reason TEXT,
        marked_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS hunt_history (
        id TEXT PRIMARY KEY,
        query TEXT NOT NULL,
        results_count INTEGER NOT NULL,
        initiated_by TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_hunt_history_created ON hunt_history(created_at);

      INSERT OR IGNORE INTO schema_migrations (version, applied_at)
      VALUES (1, CURRENT_TIMESTAMP);
      INSERT OR IGNORE INTO schema_migrations (version, applied_at)
      VALUES (2, CURRENT_TIMESTAMP);
      INSERT OR IGNORE INTO schema_migrations (version, applied_at)
      VALUES (3, CURRENT_TIMESTAMP);
      INSERT OR IGNORE INTO schema_migrations (version, applied_at)
      VALUES (2, CURRENT_TIMESTAMP);
    `);
    const auditColumns = db.prepare('PRAGMA table_info(audit_events)').all() as Array<{ name: string }>;
    if (!auditColumns.some((column) => column.name === 'principal')) {
      db.exec("ALTER TABLE audit_events ADD COLUMN principal TEXT NOT NULL DEFAULT ''");
    }
    console.log(`[persist] SQLite persistence enabled at ${dir}`);
  } catch (err) {
    db = null;
    console.warn(`[persist] disabled (in-memory only): ${errorMessage(err)}`);
  }
}

export interface IntelSnapshot {
  indicators: ThreatIndicator[];
  cves: CveItem[];
  savedAt: number;
}

export type BackgroundJobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'dead';

export interface BackgroundJob {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  status: BackgroundJobStatus;
  attempts: number;
  maxAttempts: number;
  availableAt: number;
  leaseUntil: number | null;
  lockedBy: string | null;
  dedupeKey: string | null;
  lastError: string;
  createdAt: number;
  updatedAt: number;
}

interface BackgroundJobRow {
  id: string;
  type: string;
  payload_json: string;
  status: BackgroundJobStatus;
  attempts: number;
  max_attempts: number;
  available_at: number;
  lease_until: number | null;
  locked_by: string | null;
  dedupe_key: string | null;
  last_error: string;
  created_at: number;
  updated_at: number;
}

function backgroundJobFromRow(row: BackgroundJobRow): BackgroundJob {
  let payload: Record<string, unknown> = {};
  try {
    payload = JSON.parse(row.payload_json) as Record<string, unknown>;
  } catch {
    // Invalid payloads are still claimable and will fail in the typed handler.
  }
  return {
    id: row.id,
    type: row.type,
    payload,
    status: row.status,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    availableAt: row.available_at,
    leaseUntil: row.lease_until,
    lockedBy: row.locked_by,
    dedupeKey: row.dedupe_key,
    lastError: row.last_error,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function enqueueBackgroundJob(input: {
  id: string;
  type: string;
  payload?: Record<string, unknown>;
  maxAttempts?: number;
  availableAt?: number;
  dedupeKey?: string;
}): boolean {
  if (!db) return false;
  const now = Date.now();
  const result = db.prepare(
    'INSERT OR IGNORE INTO background_jobs ' +
      '(id, type, payload_json, status, attempts, max_attempts, available_at, lease_until, locked_by, dedupe_key, last_error, created_at, updated_at) ' +
      "VALUES (?, ?, ?, 'queued', 0, ?, ?, NULL, NULL, ?, '', ?, ?)",
  ).run(
    input.id,
    input.type,
    JSON.stringify(input.payload ?? {}),
    Math.min(Math.max(1, Math.floor(input.maxAttempts ?? 5)), 20),
    input.availableAt ?? now,
    input.dedupeKey ?? null,
    now,
    now,
  ) as { changes?: number };
  return (result.changes ?? 0) > 0;
}

export function claimBackgroundJob(workerId: string, now = Date.now(), leaseMs = 60_000): BackgroundJob | null {
  if (!db) return null;
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare(
      "UPDATE background_jobs SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END, " +
        "available_at = ?, lease_until = NULL, locked_by = NULL, last_error = 'worker lease expired', updated_at = ? " +
        "WHERE status = 'running' AND lease_until IS NOT NULL AND lease_until <= ?",
    ).run(now, now, now);
    const row = db.prepare(
      "SELECT * FROM background_jobs WHERE status = 'queued' AND available_at <= ? " +
        'ORDER BY available_at ASC, created_at ASC LIMIT 1',
    ).get(now) as BackgroundJobRow | undefined;
    if (!row) {
      db.exec('COMMIT');
      return null;
    }
    db.prepare(
      "UPDATE background_jobs SET status = 'running', attempts = attempts + 1, lease_until = ?, locked_by = ?, updated_at = ? " +
        "WHERE id = ? AND status = 'queued'",
    ).run(now + Math.max(1000, leaseMs), workerId, now, row.id);
    const claimed = db.prepare('SELECT * FROM background_jobs WHERE id = ?').get(row.id) as BackgroundJobRow;
    db.exec('COMMIT');
    return backgroundJobFromRow(claimed);
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Preserve the original claim error.
    }
    throw err;
  }
}

export function completeBackgroundJob(id: string, workerId: string, now = Date.now()): void {
  if (!db) return;
  db.prepare(
    "UPDATE background_jobs SET status = 'succeeded', lease_until = NULL, locked_by = NULL, updated_at = ? " +
      "WHERE id = ? AND status = 'running' AND locked_by = ?",
  ).run(now, id, workerId);
}

export function failBackgroundJob(
  id: string,
  workerId: string,
  error: string,
  now = Date.now(),
  retryDelayMs = 1000,
): void {
  if (!db) return;
  const row = db.prepare(
    "SELECT * FROM background_jobs WHERE id = ? AND status = 'running' AND locked_by = ?",
  ).get(id, workerId) as BackgroundJobRow | undefined;
  if (!row) return;
  const exhausted = row.attempts >= row.max_attempts;
  db.prepare(
    'UPDATE background_jobs SET status = ?, available_at = ?, lease_until = NULL, locked_by = NULL, ' +
      'last_error = ?, updated_at = ? WHERE id = ? AND locked_by = ?',
  ).run(exhausted ? 'dead' : 'queued', now + Math.max(0, retryDelayMs), error.slice(0, 2000), now, id, workerId);
}

export function getBackgroundJobs(limit = 100): BackgroundJob[] {
  if (!db) return [];
  const rows = db.prepare('SELECT * FROM background_jobs ORDER BY created_at DESC LIMIT ?').all(
    Math.min(Math.max(1, Math.floor(limit)), 500),
  ) as BackgroundJobRow[];
  return rows.map(backgroundJobFromRow);
}

export function getBackgroundJobCounts(): Record<BackgroundJobStatus, number> {
  const counts: Record<BackgroundJobStatus, number> = {
    queued: 0,
    running: 0,
    succeeded: 0,
    failed: 0,
    dead: 0,
  };
  if (!db) return counts;
  const rows = db.prepare('SELECT status, COUNT(*) AS count FROM background_jobs GROUP BY status').all() as Array<{
    status: BackgroundJobStatus;
    count: number;
  }>;
  for (const row of rows) {
    if (row.status in counts) counts[row.status] = row.count;
  }
  return counts;
}

export function deleteFinishedBackgroundJobs(before: number): void {
  if (!db) return;
  db.prepare("DELETE FROM background_jobs WHERE status IN ('succeeded','failed','dead') AND updated_at < ?").run(before);
}

function indicatorKey(indicator: ThreatIndicator): string {
  return `${indicator.indicatorType}:${indicator.indicator.toLowerCase()}`;
}

export function persistIntelSnapshot(indicators: ThreatIndicator[], cves: CveItem[], savedAt = Date.now()): void {
  if (!db) return;
  const upsertIndicator = db.prepare(
    'INSERT INTO threat_indicators ' +
      '(object_key, id, source, indicator, indicator_type, threat_type, severity, payload_json, active, first_persisted_at, last_persisted_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?) ' +
      'ON CONFLICT(object_key) DO UPDATE SET id = excluded.id, source = excluded.source, ' +
      'indicator = excluded.indicator, indicator_type = excluded.indicator_type, threat_type = excluded.threat_type, ' +
      'severity = excluded.severity, payload_json = excluded.payload_json, active = 1, ' +
      'last_persisted_at = excluded.last_persisted_at',
  );
  const upsertObservation = db.prepare(
    'INSERT INTO indicator_observations ' +
      '(object_key, source, first_observed_at, last_observed_at, observation_count) VALUES (?, ?, ?, ?, 1) ' +
      'ON CONFLICT(object_key, source) DO UPDATE SET last_observed_at = excluded.last_observed_at, ' +
      'observation_count = indicator_observations.observation_count + 1',
  );
  const upsertCve = db.prepare(
    'INSERT INTO cve_objects ' +
      '(cve_id, source, severity, payload_json, active, first_persisted_at, last_persisted_at) ' +
      'VALUES (?, ?, ?, ?, 1, ?, ?) ' +
      'ON CONFLICT(cve_id) DO UPDATE SET source = excluded.source, severity = excluded.severity, ' +
      'payload_json = excluded.payload_json, active = 1, last_persisted_at = excluded.last_persisted_at',
  );

  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec('UPDATE threat_indicators SET active = 0; UPDATE cve_objects SET active = 0;');
    for (const indicator of indicators) {
      const key = indicatorKey(indicator);
      upsertIndicator.run(
        key,
        indicator.id,
        indicator.source,
        indicator.indicator,
        indicator.indicatorType,
        indicator.type,
        indicator.severity,
        JSON.stringify(indicator),
        savedAt,
        savedAt,
      );
      for (const source of indicator.sources ?? [indicator.source]) {
        upsertObservation.run(key, source, savedAt, savedAt);
      }
    }
    for (const cve of cves) {
      upsertCve.run(cve.id, cve.source, cve.severity, JSON.stringify(cve), savedAt, savedAt);
    }
    db.prepare(
      'INSERT INTO intel_snapshot_meta (singleton, saved_at) VALUES (1, ?) ' +
        'ON CONFLICT(singleton) DO UPDATE SET saved_at = excluded.saved_at',
    ).run(savedAt);
    db.exec('COMMIT');
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Preserve the original persistence error.
    }
    throw err;
  }
}

export function loadIntelSnapshot(activeOnly = true): IntelSnapshot {
  if (!db) return { indicators: [], cves: [], savedAt: 0 };
  const where = activeOnly ? ' WHERE active = 1' : '';
  const indicatorRows = db
    .prepare(`SELECT payload_json FROM threat_indicators${where} ORDER BY last_persisted_at DESC`)
    .all() as Array<{ payload_json: string }>;
  const cveRows = db
    .prepare(`SELECT payload_json FROM cve_objects${where} ORDER BY last_persisted_at DESC`)
    .all() as Array<{ payload_json: string }>;
  const meta = db.prepare('SELECT saved_at FROM intel_snapshot_meta WHERE singleton = 1').get() as
    | { saved_at: number }
    | undefined;
  const parseRows = <T>(rows: Array<{ payload_json: string }>): T[] => {
    const values: T[] = [];
    for (const row of rows) {
      try {
        values.push(JSON.parse(row.payload_json) as T);
      } catch {
        // Skip corrupt rows while retaining the rest of the last-good snapshot.
      }
    }
    return values;
  };
  return {
    indicators: parseRows<ThreatIndicator>(indicatorRows),
    cves: parseRows<CveItem>(cveRows),
    savedAt: meta?.saved_at ?? 0,
  };
}

function validStixObject(value: PersistedStixObject): boolean {
  return Boolean(
    value &&
      typeof value.type === 'string' &&
      value.type.length > 0 &&
      typeof value.id === 'string' &&
      value.id.startsWith(`${value.type}--`),
  );
}

// Preserve the original STIX graph alongside normalized IOC rows. The compound
// key retains multiple STIX object versions rather than silently overwriting
// relationship, marking, actor, campaign, malware, or attack-pattern objects.
export function persistStixObjects(
  objects: PersistedStixObject[],
  connector: string,
  importedAt = Date.now(),
): number {
  if (!db) return 0;
  const upsert = db.prepare(
    'INSERT INTO imported_stix_objects ' +
      '(object_id, version, object_type, connector, payload_json, first_imported_at, last_imported_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(object_id, version) DO UPDATE SET connector = excluded.connector, ' +
      'payload_json = excluded.payload_json, last_imported_at = excluded.last_imported_at',
  );
  let persisted = 0;
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const object of objects) {
      if (!validStixObject(object)) continue;
      const payload = JSON.stringify(object);
      if (Buffer.byteLength(payload, 'utf8') > 1_000_000) continue;
      const version = object.modified ?? object.created ?? 'unversioned';
      upsert.run(object.id, version, object.type, connector, payload, importedAt, importedAt);
      persisted += 1;
    }
    db.exec('COMMIT');
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Preserve the original persistence error.
    }
    throw err;
  }
  return persisted;
}

export function loadStixObjects(connector?: string): PersistedStixObject[] {
  if (!db) return [];
  const rows = (connector
    ? db
        .prepare(
          'SELECT payload_json FROM imported_stix_objects WHERE connector = ? ORDER BY object_id, version',
        )
        .all(connector)
    : db.prepare('SELECT payload_json FROM imported_stix_objects ORDER BY object_id, version').all()) as Array<{
    payload_json: string;
  }>;
  const objects: PersistedStixObject[] = [];
  for (const row of rows) {
    try {
      const object = JSON.parse(row.payload_json) as PersistedStixObject;
      if (validStixObject(object)) objects.push(object);
    } catch {
      // Ignore one corrupt object without discarding the remaining graph.
    }
  }
  return objects;
}

export function persistDetectionArtifacts(artifacts: DetectionArtifact[], importedAt = Date.now()): number {
  if (!db) return 0;
  const upsert = db.prepare(
    'INSERT INTO detection_artifacts (id, source, format, payload_json, first_imported_at, last_imported_at) ' +
      'VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET source = excluded.source, ' +
      'format = excluded.format, payload_json = excluded.payload_json, last_imported_at = excluded.last_imported_at',
  );
  let persisted = 0;
  db.exec('BEGIN IMMEDIATE');
  try {
    for (const artifact of artifacts) {
      const payload = JSON.stringify(artifact);
      if (!artifact.id || !artifact.content || Buffer.byteLength(payload, 'utf8') > 1_000_000) continue;
      upsert.run(artifact.id, artifact.source, artifact.format, payload, importedAt, importedAt);
      persisted += 1;
    }
    db.exec('COMMIT');
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Preserve the original persistence error.
    }
    throw err;
  }
  return persisted;
}

export function getDetectionArtifacts(
  format?: DetectionArtifact['format'],
  limit = 100,
): DetectionArtifact[] {
  if (!db) return [];
  const bounded = Math.min(Math.max(1, Math.floor(limit)), 1000);
  const rows = (format
    ? db
        .prepare('SELECT payload_json FROM detection_artifacts WHERE format = ? ORDER BY last_imported_at DESC LIMIT ?')
        .all(format, bounded)
    : db.prepare('SELECT payload_json FROM detection_artifacts ORDER BY last_imported_at DESC LIMIT ?').all(bounded)) as Array<{
    payload_json: string;
  }>;
  const artifacts: DetectionArtifact[] = [];
  for (const row of rows) {
    try {
      artifacts.push(JSON.parse(row.payload_json) as DetectionArtifact);
    } catch {
      // Skip corrupt rows while retaining other detection artifacts.
    }
  }
  return artifacts;
}

export function getConnectorState(connector: string): Record<string, unknown> {
  if (!db) return {};
  const row = db.prepare('SELECT state_json FROM connector_state WHERE connector = ?').get(connector) as
    | { state_json: string }
    | undefined;
  if (!row) return {};
  try {
    return JSON.parse(row.state_json) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export function setConnectorState(connector: string, state: Record<string, unknown>, updatedAt = Date.now()): void {
  if (!db) return;
  db.prepare(
    'INSERT INTO connector_state (connector, state_json, updated_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT(connector) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at',
  ).run(connector, JSON.stringify(state), updatedAt);
}

export function recordInvestigationHistory(entry: InvestigationHistoryEntry): void {
  if (!db) return;
  db.prepare(
    'INSERT OR REPLACE INTO investigation_history ' +
      '(id, ts, indicator, indicator_type, posture, exact_count, related_count, highest_severity, confidence) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(
    entry.id,
    entry.ts,
    entry.indicator,
    entry.indicatorType,
    entry.posture,
    entry.exactCount,
    entry.relatedCount,
    entry.highestSeverity ?? '',
    entry.confidence,
  );
}

export function getInvestigationHistory(limit = 50): InvestigationHistoryEntry[] {
  if (!db) return [];
  const rows = db
    .prepare(
      'SELECT id, ts, indicator, indicator_type, posture, exact_count, related_count, highest_severity, confidence ' +
        'FROM investigation_history ORDER BY ts DESC LIMIT ?',
    )
    .all(Math.min(Math.max(1, Math.floor(limit)), 200)) as Array<{
      id: string;
      ts: number;
      indicator: string;
      indicator_type: InvestigationHistoryEntry['indicatorType'];
      posture: InvestigationHistoryEntry['posture'];
      exact_count: number;
      related_count: number;
      highest_severity: InvestigationHistoryEntry['highestSeverity'] | '';
      confidence: number;
    }>;
  return rows.map((row) => ({
    id: row.id,
    ts: row.ts,
    indicator: row.indicator,
    indicatorType: row.indicator_type,
    posture: row.posture,
    exactCount: row.exact_count,
    relatedCount: row.related_count,
    highestSeverity: row.highest_severity || null,
    confidence: row.confidence,
  }));
}

export function recordAuditEvent(event: AuditEvent): void {
  if (!db) return;
  db.prepare('INSERT INTO audit_events (ts, role, principal, action, path, ok, detail) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    event.ts,
    event.role,
    event.principal,
    event.action,
    event.path,
    event.ok ? 1 : 0,
    event.detail,
  );
}

export function getAuditEvents(limit = 100): AuditEvent[] {
  if (!db) return [];
  const rows = db
    .prepare('SELECT ts, role, principal, action, path, ok, detail FROM audit_events ORDER BY ts DESC LIMIT ?')
    .all(Math.min(Math.max(1, Math.floor(limit)), 500)) as Array<{
      ts: string;
      role: AuditEvent['role'];
      principal: string;
      action: string;
      path: string;
      ok: number;
      detail: string;
    }>;
  return rows.map((row) => ({
    ts: row.ts,
    role: row.role,
    principal: row.principal,
    action: row.action,
    path: row.path,
    ok: row.ok === 1,
    detail: row.detail,
  }));
}

// Test helper: close and reset the handle.
export function closePersistence(): void {
  if (db) {
    try {
      db.close();
    } catch {
      // ignore
    }
    db = null;
  }
}

export function loadGeoCache(): Map<string, GeoRow> {
  const map = new Map<string, GeoRow>();
  if (!db) return map;
  const rows = db.prepare('SELECT ip, country, country_code, lat, lon FROM geo_cache').all() as Array<{
    ip: string;
    country: string | null;
    country_code: string | null;
    lat: number | null;
    lon: number | null;
  }>;
  for (const r of rows) {
    map.set(r.ip, {
      country: r.country ?? undefined,
      countryCode: r.country_code ?? undefined,
      lat: r.lat ?? undefined,
      lon: r.lon ?? undefined,
    });
  }
  return map;
}

export function saveGeo(ip: string, g: GeoRow): void {
  if (!db) return;
  db.prepare(
    'INSERT OR REPLACE INTO geo_cache (ip, country, country_code, lat, lon) VALUES (?, ?, ?, ?, ?)',
  ).run(ip, g.country ?? null, g.countryCode ?? null, g.lat ?? null, g.lon ?? null);
}

// Record observation of each key, returning key -> first-ever-seen timestamp so callers
// can surface a stable firstSeen that survives restarts.
export function recordSeen(keys: string[], nowIso: string): Map<string, string> {
  const firstSeen = new Map<string, string>();
  if (!db || keys.length === 0) return firstSeen;
  const sel = db.prepare('SELECT first_seen FROM indicator_seen WHERE key = ?');
  const ins = db.prepare(
    'INSERT INTO indicator_seen (key, first_seen, last_seen) VALUES (?, ?, ?) ' +
      'ON CONFLICT(key) DO UPDATE SET last_seen = excluded.last_seen',
  );
  for (const key of keys) {
    const existing = sel.get(key) as { first_seen: string } | undefined;
    ins.run(key, existing?.first_seen ?? nowIso, nowIso);
    firstSeen.set(key, existing?.first_seen ?? nowIso);
  }
  return firstSeen;
}

export function recordSnapshot(p: TrendPoint): void {
  if (!db) return;
  db.prepare(
    'INSERT OR REPLACE INTO refresh_snapshot (ts, total, critical, high, medium, low) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(p.ts, p.total, p.critical, p.high, p.medium, p.low);
}

export function getTrend(sinceMs: number): TrendPoint[] {
  if (!db) return [];
  const rows = db
    .prepare('SELECT ts, total, critical, high, medium, low FROM refresh_snapshot WHERE ts >= ? ORDER BY ts ASC')
    .all(sinceMs) as TrendPoint[];
  return rows;
}

export function successfulPushIds(channel: string, itemIds: string[]): Set<string> {
  const found = new Set<string>();
  if (!db || itemIds.length === 0) return found;
  const placeholders = itemIds.map(() => '?').join(',');
  const rows = db
    .prepare(
      `SELECT DISTINCT item_id FROM push_events WHERE channel = ? AND status = 'success' AND item_id IN (${placeholders})`,
    )
    .all(channel, ...itemIds) as Array<{ item_id: string }>;
  for (const row of rows) found.add(row.item_id);
  return found;
}

export function recordPushEvent(event: PushEventInput): void {
  if (!db) return;
  db.prepare(
    'INSERT INTO push_events (item_id, channel, status, title, pushed_at, error) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(
    event.itemId,
    event.channel,
    event.status,
    event.title,
    new Date().toISOString(),
    event.error ?? '',
  );
}

export function recordSourceHealthHistory(points: SourceHealthHistoryPoint[]): void {
  if (!db || points.length === 0) return;
  const stmt = db.prepare(
    'INSERT OR REPLACE INTO source_health_history (ts, source, ok, stale, count, error) VALUES (?, ?, ?, ?, ?, ?)',
  );
  for (const point of points) {
    stmt.run(
      point.ts,
      point.source,
      point.ok ? 1 : 0,
      point.stale ? 1 : 0,
      point.count,
      point.error ?? '',
    );
  }
}

export function getSourceHealthHistory(sinceMs: number): SourceHealthHistoryPoint[] {
  if (!db) return [];
  const rows = db
    .prepare(
      'SELECT ts, source, ok, stale, count, error FROM source_health_history WHERE ts >= ? ORDER BY ts ASC, source ASC',
    )
    .all(sinceMs) as Array<{
      ts: number;
      source: string;
      ok: number;
      stale: number;
      count: number;
      error: string;
    }>;
  return rows.map((row) => ({
    ts: row.ts,
    source: row.source,
    ok: row.ok === 1,
    stale: row.stale === 1,
    count: row.count,
    error: row.error || null,
  }));
}

// Phase 1: Platform Upgrade - Cases Management

export function createCase(caseData: {
  id: string;
  title: string;
  status: string;
  severity: string;
  assignee?: string;
  createdAt: number;
  updatedAt: number;
}): void {
  if (!db) return;
  db.prepare(
    'INSERT INTO cases (id, title, status, severity, assignee, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(
    caseData.id,
    caseData.title,
    caseData.status,
    caseData.severity,
    caseData.assignee ?? null,
    caseData.createdAt,
    caseData.updatedAt,
  );
}

export function updateCase(id: string, updates: { status?: string; assignee?: string; updatedAt: number }): void {
  if (!db) return;
  const fields: string[] = [];
  const values: unknown[] = [];

  if (updates.status !== undefined) {
    fields.push('status = ?');
    values.push(updates.status);
  }
  if (updates.assignee !== undefined) {
    fields.push('assignee = ?');
    values.push(updates.assignee);
  }
  fields.push('updated_at = ?');
  values.push(updates.updatedAt);

  if (fields.length > 0) {
    values.push(id);
    db.prepare(`UPDATE cases SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  }
}

export function getCase(id: string): unknown {
  if (!db) return null;
  return db.prepare('SELECT * FROM cases WHERE id = ?').get(id);
}

export function getCases(filters?: { status?: string; assignee?: string }): unknown[] {
  if (!db) return [];
  let query = 'SELECT * FROM cases';
  const params: unknown[] = [];

  if (filters) {
    const conditions: string[] = [];
    if (filters.status) {
      conditions.push('status = ?');
      params.push(filters.status);
    }
    if (filters.assignee) {
      conditions.push('assignee = ?');
      params.push(filters.assignee);
    }
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
  }

  query += ' ORDER BY created_at DESC';
  return db.prepare(query).all(...params) as unknown[];
}

export function addCaseIoc(caseId: string, iocId: string, addedAt: number): void {
  if (!db) return;
  db.prepare('INSERT OR IGNORE INTO case_iocs (case_id, ioc_id, added_at) VALUES (?, ?, ?)').run(
    caseId,
    iocId,
    addedAt,
  );
}

export function getCaseIocs(caseId: string): Array<{ ioc_id: string; added_at: number }> {
  if (!db) return [];
  return db.prepare('SELECT ioc_id, added_at FROM case_iocs WHERE case_id = ? ORDER BY added_at ASC').all(caseId) as Array<{
    ioc_id: string;
    added_at: number;
  }>;
}

export function addCaseComment(comment: {
  id: string;
  caseId: string;
  author: string;
  content: string;
  createdAt: number;
}): void {
  if (!db) return;
  db.prepare('INSERT INTO case_comments (id, case_id, author, content, created_at) VALUES (?, ?, ?, ?, ?)').run(
    comment.id,
    comment.caseId,
    comment.author,
    comment.content,
    comment.createdAt,
  );
}

export function getCaseComments(caseId: string): unknown[] {
  if (!db) return [];
  return db.prepare('SELECT * FROM case_comments WHERE case_id = ? ORDER BY created_at ASC').all(caseId) as unknown[];
}

// Phase 1: Platform Upgrade - Rules Engine

export function createRule(rule: {
  id: string;
  name: string;
  triggerType: string;
  triggerConfig: string;
  actions: string;
  enabled: number;
  createdAt: number;
}): void {
  if (!db) return;
  db.prepare(
    'INSERT INTO rules (id, name, trigger_type, trigger_config, actions, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(rule.id, rule.name, rule.triggerType, rule.triggerConfig, rule.actions, rule.enabled, rule.createdAt);
}

export function updateRule(id: string, updates: { enabled?: number }): void {
  if (!db) return;
  if (updates.enabled !== undefined) {
    db.prepare('UPDATE rules SET enabled = ? WHERE id = ?').run(updates.enabled, id);
  }
}

export function getRule(id: string): unknown {
  if (!db) return null;
  return db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
}

export function getRules(enabledOnly = false): unknown[] {
  if (!db) return [];
  const query = enabledOnly
    ? 'SELECT * FROM rules WHERE enabled = 1 ORDER BY created_at DESC'
    : 'SELECT * FROM rules ORDER BY created_at DESC';
  return db.prepare(query).all() as unknown[];
}

export function recordRuleExecution(execution: {
  id: string;
  ruleId: string;
  triggeredAt: number;
  actionsTaken: string;
  success: number;
}): void {
  if (!db) return;
  db.prepare(
    'INSERT INTO rule_executions (id, rule_id, triggered_at, actions_taken, success) VALUES (?, ?, ?, ?, ?)',
  ).run(execution.id, execution.ruleId, execution.triggeredAt, execution.actionsTaken, execution.success);
}

export function getRuleExecutions(ruleId: string, limit = 50): unknown[] {
  if (!db) return [];
  return db
    .prepare('SELECT * FROM rule_executions WHERE rule_id = ? ORDER BY triggered_at DESC LIMIT ?')
    .all(ruleId, Math.min(limit, 200)) as unknown[];
}

// Phase 1: Platform Upgrade - Enrichment Cache

export function getEnrichmentCache(iocValue: string, provider: string): unknown {
  if (!db) return null;
  const row = db.prepare('SELECT * FROM enrichment_cache WHERE ioc_value = ? AND provider = ?').get(iocValue, provider);
  if (!row) return null;

  const cached = row as { cached_at: number };
  const ttl = 3600 * 1000;
  if (Date.now() - cached.cached_at > ttl) {
    db.prepare('DELETE FROM enrichment_cache WHERE ioc_value = ? AND provider = ?').run(iocValue, provider);
    return null;
  }

  return row;
}

export function setEnrichmentCache(iocValue: string, provider: string, result: string, cachedAt: number): void {
  if (!db) return;
  db.prepare(
    'INSERT OR REPLACE INTO enrichment_cache (ioc_value, provider, result, cached_at) VALUES (?, ?, ?, ?)',
  ).run(iocValue, provider, result, cachedAt);
}

export function cleanExpiredCache(ttlMs = 3600 * 1000): void {
  if (!db) return;
  const cutoff = Date.now() - ttlMs;
  db.prepare('DELETE FROM enrichment_cache WHERE cached_at < ?').run(cutoff);
}

// Phase 1: Platform Upgrade - False Positives

export function markFalsePositive(iocValue: string, markedBy: string, reason: string | null, markedAt: number): void {
  if (!db) return;
  db.prepare('INSERT OR REPLACE INTO false_positives (ioc_value, marked_by, reason, marked_at) VALUES (?, ?, ?, ?)').run(
    iocValue,
    markedBy,
    reason,
    markedAt,
  );
}

export function isFalsePositive(iocValue: string): boolean {
  if (!db) return false;
  const row = db.prepare('SELECT 1 FROM false_positives WHERE ioc_value = ?').get(iocValue);
  return row !== undefined;
}

export function getFalsePositives(): unknown[] {
  if (!db) return [];
  return db.prepare('SELECT * FROM false_positives ORDER BY marked_at DESC').all() as unknown[];
}

// Phase 1: Platform Upgrade - Hunt History

export function recordHuntHistory(hunt: {
  id: string;
  query: string;
  resultsCount: number;
  initiatedBy: string;
  createdAt: number;
}): void {
  if (!db) return;
  db.prepare('INSERT INTO hunt_history (id, query, results_count, initiated_by, created_at) VALUES (?, ?, ?, ?, ?)').run(
    hunt.id,
    hunt.query,
    hunt.resultsCount,
    hunt.initiatedBy,
    hunt.createdAt,
  );
}

export function getHuntHistory(limit = 50): unknown[] {
  if (!db) return [];
  return db
    .prepare('SELECT * FROM hunt_history ORDER BY created_at DESC LIMIT ?')
    .all(Math.min(limit, 200)) as unknown[];
}
