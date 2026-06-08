import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  initPersistence,
  closePersistence,
  isPersistEnabled,
  saveGeo,
  loadGeoCache,
  recordSeen,
  recordSnapshot,
  getTrend,
  recordPushEvent,
  successfulPushIds,
} from '../src/persist.js';

const dir = path.join(process.cwd(), `.tmp-persist-test-${process.pid}`);

beforeAll(() => {
  process.env.DATA_DIR = dir;
  initPersistence();
});

afterAll(() => {
  closePersistence();
  delete process.env.DATA_DIR;
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('persist (node:sqlite)', () => {
  it('enables when DATA_DIR is set', () => {
    expect(isPersistEnabled()).toBe(true);
  });

  it('round-trips the geo cache', () => {
    saveGeo('8.8.8.8', { country: 'United States', countryCode: 'US', lat: 1, lon: 2 });
    const cache = loadGeoCache();
    expect(cache.get('8.8.8.8')).toEqual({ country: 'United States', countryCode: 'US', lat: 1, lon: 2 });
  });

  it('returns a stable first-seen across observations and updates last-seen', () => {
    const t1 = '2025-01-01T00:00:00.000Z';
    const t2 = '2025-02-01T00:00:00.000Z';
    const first = recordSeen(['ip:1.1.1.1'], t1);
    expect(first.get('ip:1.1.1.1')).toBe(t1);
    const second = recordSeen(['ip:1.1.1.1'], t2);
    // first-seen stays at the original observation time.
    expect(second.get('ip:1.1.1.1')).toBe(t1);
  });

  it('stores and queries trend snapshots within a time window', () => {
    const now = Date.now();
    recordSnapshot({ ts: now - 1000, total: 10, critical: 1, high: 2, medium: 3, low: 4 });
    recordSnapshot({ ts: now, total: 12, critical: 2, high: 2, medium: 4, low: 4 });
    const points = getTrend(now - 5000);
    expect(points.length).toBe(2);
    expect(points[points.length - 1].total).toBe(12);
    // Older-than-window snapshots are excluded.
    expect(getTrend(now + 1000)).toHaveLength(0);
  });

  it('tracks successful push events per channel', () => {
    recordPushEvent({
      itemId: 'kev:CVE-2026-0001',
      channel: 'telegram',
      status: 'success',
      title: 'CVE-2026-0001',
    });
    recordPushEvent({
      itemId: 'kev:CVE-2026-0002',
      channel: 'telegram',
      status: 'failed',
      title: 'CVE-2026-0002',
      error: 'timeout',
    });

    expect(successfulPushIds('telegram', ['kev:CVE-2026-0001', 'kev:CVE-2026-0002'])).toEqual(
      new Set(['kev:CVE-2026-0001']),
    );
    expect(successfulPushIds('dingtalk', ['kev:CVE-2026-0001'])).toEqual(new Set());
  });
});
