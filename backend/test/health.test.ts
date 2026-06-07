import { describe, it, expect } from 'vitest';
import { reduceHealth, emptyHealthState } from '../src/notify/health.js';
import { buildSourceAlert } from '../src/notify/format.js';

const ok = (source: string) => ({ source, lastError: null });
const bad = (source: string) => ({ source, lastError: 'HTTP 503' });

describe('reduceHealth', () => {
  it('fires "down" only once the failure streak reaches the threshold', () => {
    let s = emptyHealthState();
    let r = reduceHealth(s, [bad('nvd')], 2);
    expect(r.fire).toEqual([]); // first failure, below threshold
    s = r.state;

    r = reduceHealth(s, [bad('nvd')], 2);
    expect(r.fire).toEqual([{ source: 'nvd', kind: 'down' }]);
    s = r.state;

    // Already alerted: a continued failure does not re-fire.
    r = reduceHealth(s, [bad('nvd')], 2);
    expect(r.fire).toEqual([]);
  });

  it('fires "recovered" once after a source comes back, then resets', () => {
    let s = emptyHealthState();
    s = reduceHealth(s, [bad('feodo')], 1).state; // down (threshold 1)
    let r = reduceHealth(s, [ok('feodo')], 1);
    expect(r.fire).toEqual([{ source: 'feodo', kind: 'recovered' }]);
    s = r.state;

    // Stays quiet while healthy.
    r = reduceHealth(s, [ok('feodo')], 1);
    expect(r.fire).toEqual([]);
  });

  it('does not fire for a source that is healthy from the start', () => {
    const r = reduceHealth(emptyHealthState(), [ok('cisa_kev')], 1);
    expect(r.fire).toEqual([]);
  });
});

describe('buildSourceAlert', () => {
  it('includes the error reason and cached count for a down alert', () => {
    const d = buildSourceAlert('down', { label: 'NVD CVE', lastError: 'HTTP 503', count: 42 });
    expect(d.text).toContain('NVD CVE is failing');
    expect(d.text).toContain('HTTP 503');
    expect(d.text).toContain('42 cached');
  });

  it('reports recovery', () => {
    const d = buildSourceAlert('recovered', { label: 'NVD CVE', lastError: null, count: 60 });
    expect(d.text).toContain('NVD CVE recovered');
    expect(d.text).toContain('60 indicator');
  });
});
