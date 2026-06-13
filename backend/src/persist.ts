import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { errorMessage } from './util.js';
import type { AuditEvent, InvestigationHistoryEntry } from './types.js';

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
    db.exec(`
      CREATE TABLE IF NOT EXISTS geo_cache (
        ip TEXT PRIMARY KEY, country TEXT, country_code TEXT, lat REAL, lon REAL
      );
      CREATE TABLE IF NOT EXISTS indicator_seen (
        key TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
      );
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
    `);
    console.log(`[persist] SQLite persistence enabled at ${dir}`);
  } catch (err) {
    db = null;
    console.warn(`[persist] disabled (in-memory only): ${errorMessage(err)}`);
  }
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
  db.prepare('INSERT INTO audit_events (ts, role, action, path, ok, detail) VALUES (?, ?, ?, ?, ?, ?)').run(
    event.ts,
    event.role,
    event.action,
    event.path,
    event.ok ? 1 : 0,
    event.detail,
  );
}

export function getAuditEvents(limit = 100): AuditEvent[] {
  if (!db) return [];
  const rows = db
    .prepare('SELECT ts, role, action, path, ok, detail FROM audit_events ORDER BY ts DESC LIMIT ?')
    .all(Math.min(Math.max(1, Math.floor(limit)), 500)) as Array<{
      ts: string;
      role: AuditEvent['role'];
      action: string;
      path: string;
      ok: number;
      detail: string;
    }>;
  return rows.map((row) => ({
    ts: row.ts,
    role: row.role,
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


