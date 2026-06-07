import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { errorMessage } from './util.js';

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
    `);
    console.log(`[persist] SQLite persistence enabled at ${dir}`);
  } catch (err) {
    db = null;
    console.warn(`[persist] disabled (in-memory only): ${errorMessage(err)}`);
  }
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
