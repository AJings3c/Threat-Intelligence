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
  recordSourceHealthHistory,
  getSourceHealthHistory,
  loadIntelSnapshot,
  persistIntelSnapshot,
  claimBackgroundJob,
  completeBackgroundJob,
  enqueueBackgroundJob,
  failBackgroundJob,
  getBackgroundJobs,
  getConnectorState,
  loadStixObjects,
  persistStixObjects,
  getDetectionArtifacts,
  persistDetectionArtifacts,
  setConnectorState,
} from '../src/persist.js';
import type { CveItem, ThreatIndicator } from '../src/types.js';
import { store } from '../src/store.js';

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

  it('stores and queries source health history', () => {
    const now = Date.now();
    recordSourceHealthHistory([
      {
        ts: now - 1000,
        source: 'nvd',
        ok: false,
        stale: false,
        count: 12,
        error: 'HTTP 503',
      },
      {
        ts: now,
        source: 'feodo',
        ok: true,
        stale: true,
        count: 4,
        error: null,
      },
    ]);

    const points = getSourceHealthHistory(now - 5000);
    expect(points).toEqual(
      expect.arrayContaining([
        {
          ts: now - 1000,
          source: 'nvd',
          ok: false,
          stale: false,
          count: 12,
          error: 'HTTP 503',
        },
        {
          ts: now,
          source: 'feodo',
          ok: true,
          stale: true,
          count: 4,
          error: null,
        },
      ]),
    );
  });

  it('restores active IOC/CVE snapshots and retains inactive historical objects', () => {
    const indicator: ThreatIndicator = {
      id: 'feodo:203.0.113.10',
      source: 'feodo',
      type: 'c2_server',
      indicator: '203.0.113.10',
      indicatorType: 'ip',
      severity: 'high',
      tags: ['c2'],
      sources: ['feodo', 'threatfox'],
      confidence: 90,
    };
    const cve: CveItem = {
      id: 'CVE-2026-12345',
      source: 'nvd',
      title: 'Test vulnerability',
      description: 'Persistence round-trip fixture',
      severity: 'critical',
      reference: 'https://example.test/CVE-2026-12345',
      knownExploited: false,
    };

    persistIntelSnapshot([indicator], [cve], 1000);
    expect(loadIntelSnapshot()).toEqual({ indicators: [indicator], cves: [cve], savedAt: 1000 });

    persistIntelSnapshot([], [], 2000);
    expect(loadIntelSnapshot()).toEqual({ indicators: [], cves: [], savedAt: 2000 });
    expect(loadIntelSnapshot(false)).toMatchObject({ indicators: [indicator], cves: [cve], savedAt: 2000 });

    persistIntelSnapshot([indicator], [cve], 3000);
    store.resetForTest();
    store.hydrateFromPersistence();
    expect(store.queryThreats({}).threats).toEqual([indicator]);
    expect(store.getCves().cves).toEqual([cve]);
    expect(store.lastRefreshAt).toBe(3000);
  });

  it('claims durable jobs with deduplication, retry state, and completion', () => {
    expect(
      enqueueBackgroundJob({
        id: 'job-1',
        type: 'feed_refresh',
        payload: { reason: 'test' },
        dedupeKey: 'refresh-test',
        maxAttempts: 3,
        availableAt: 100,
      }),
    ).toBe(true);
    expect(
      enqueueBackgroundJob({ id: 'job-duplicate', type: 'feed_refresh', dedupeKey: 'refresh-test', availableAt: 100 }),
    ).toBe(false);

    const first = claimBackgroundJob('worker-1', 100, 1000);
    expect(first).toMatchObject({ id: 'job-1', status: 'running', attempts: 1, payload: { reason: 'test' } });
    failBackgroundJob('job-1', 'worker-1', 'temporary outage', 200, 0);

    const second = claimBackgroundJob('worker-2', 200, 1000);
    expect(second).toMatchObject({ id: 'job-1', status: 'running', attempts: 2 });
    completeBackgroundJob('job-1', 'worker-2', 300);
    expect(getBackgroundJobs().find((job) => job.id === 'job-1')).toMatchObject({
      status: 'succeeded',
      attempts: 2,
    });
  });

  it('round-trips durable connector checkpoints', () => {
    expect(getConnectorState('taxii-test')).toEqual({});
    setConnectorState('taxii-test', { addedAfter: '2026-07-11T00:00:00.000Z', page: 4 }, 123);
    expect(getConnectorState('taxii-test')).toEqual({ addedAfter: '2026-07-11T00:00:00.000Z', page: 4 });
  });

  it('retains imported STIX graph objects and distinct object versions', () => {
    const attackPatternId = 'attack-pattern--11111111-1111-4111-8111-111111111111';
    const relationshipId = 'relationship--22222222-2222-4222-8222-222222222222';
    expect(
      persistStixObjects(
        [
          {
            type: 'attack-pattern',
            spec_version: '2.1',
            id: attackPatternId,
            created: '2026-01-01T00:00:00.000Z',
            modified: '2026-01-01T00:00:00.000Z',
            name: 'Test technique v1',
          },
          {
            type: 'attack-pattern',
            spec_version: '2.1',
            id: attackPatternId,
            created: '2026-01-01T00:00:00.000Z',
            modified: '2026-02-01T00:00:00.000Z',
            name: 'Test technique v2',
          },
          {
            type: 'relationship',
            spec_version: '2.1',
            id: relationshipId,
            created: '2026-02-01T00:00:00.000Z',
            modified: '2026-02-01T00:00:00.000Z',
            relationship_type: 'uses',
            source_ref: 'malware--33333333-3333-4333-8333-333333333333',
            target_ref: attackPatternId,
          },
        ],
        'taxii-test',
        4000,
      ),
    ).toBe(3);

    const objects = loadStixObjects('taxii-test');
    expect(objects.filter((object) => object.id === attackPatternId)).toHaveLength(2);
    expect(objects.find((object) => object.id === relationshipId)).toMatchObject({
      type: 'relationship',
      relationship_type: 'uses',
      target_ref: attackPatternId,
    });
  });

  it('stores detection artifacts separately from executable automation rules', () => {
    expect(
      persistDetectionArtifacts(
        [
          {
            id: 'misp:rule-1:sigma',
            source: 'misp',
            format: 'sigma',
            content: 'title: Suspicious process',
            title: 'Imported Sigma',
            tags: ['misp', 'sigma'],
          },
        ],
        5000,
      ),
    ).toBe(1);
    expect(getDetectionArtifacts('sigma')).toEqual([
      expect.objectContaining({ id: 'misp:rule-1:sigma', format: 'sigma', content: 'title: Suspicious process' }),
    ]);
    expect(getDetectionArtifacts('yara')).toEqual([]);
  });
});
