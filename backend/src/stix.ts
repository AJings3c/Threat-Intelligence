import { createHash } from 'node:crypto';
import type { ThreatIndicator, CveItem } from './types.js';

// Minimal STIX 2.1 shapes (only the fields we emit).
export interface StixObject {
  type: string;
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  [key: string]: unknown;
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  objects: StixObject[];
}

// Deterministic UUIDv5-style id from a seed so the same indicator maps to a stable
// STIX id across exports (useful for downstream correlation/dedup).
function deterministicUuid(seed: string): string {
  const h = createHash('sha1').update(seed).digest('hex');
  const variant = ((parseInt(h.slice(16, 18), 16) & 0x3f) | 0x80)
    .toString(16)
    .padStart(2, '0');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-${variant}${h.slice(
    18,
    20,
  )}-${h.slice(20, 32)}`;
}

function stixId(type: string, seed: string): string {
  return `${type}--${deterministicUuid(`${type}:${seed}`)}`;
}

// Escape a value for inclusion in a STIX pattern single-quoted string.
function escapePattern(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function patternFor(t: ThreatIndicator): string | null {
  switch (t.indicatorType) {
    case 'ip':
      return `[ipv4-addr:value = '${escapePattern(t.indicator)}']`;
    case 'url':
      return `[url:value = '${escapePattern(t.indicator)}']`;
    case 'domain':
      return `[domain-name:value = '${escapePattern(t.indicator)}']`;
    default:
      return null;
  }
}

function indicatorToStix(t: ThreatIndicator, now: string): StixObject {
  const created = t.firstSeen ?? now;
  const modified = t.lastSeen ?? created;
  const pattern = patternFor(t);

  // CVE-typed indicators (e.g. CISA KEV) become Vulnerability SDOs.
  if (!pattern) {
    return {
      type: 'vulnerability',
      spec_version: '2.1',
      id: stixId('vulnerability', t.id),
      created,
      modified,
      name: t.indicator,
      description: t.description,
      external_references: [{ source_name: 'cve', external_id: t.indicator }],
      labels: t.tags?.length ? t.tags : undefined,
      x_severity: t.severity,
    };
  }

  return {
    type: 'indicator',
    spec_version: '2.1',
    id: stixId('indicator', t.id),
    created,
    modified,
    name: t.title ?? t.type,
    description: t.description,
    indicator_types: ['malicious-activity'],
    pattern,
    pattern_type: 'stix',
    valid_from: created,
    labels: t.tags?.length ? t.tags : undefined,
    x_severity: t.severity,
    x_source: t.source,
  };
}

function cveToStix(c: CveItem, now: string): StixObject {
  const created = c.published ?? now;
  return {
    type: 'vulnerability',
    spec_version: '2.1',
    id: stixId('vulnerability', c.id),
    created,
    modified: c.lastModified ?? created,
    name: c.id,
    description: c.description,
    external_references: [{ source_name: 'cve', external_id: c.id }],
    x_severity: c.severity,
    x_cvss_score: c.cvssScore,
  };
}

/** Convert the current indicator + CVE snapshots into a STIX 2.1 bundle. */
export function toStixBundle(indicators: ThreatIndicator[], cves: CveItem[]): StixBundle {
  const now = new Date().toISOString();
  const objects: StixObject[] = [
    ...indicators.map((t) => indicatorToStix(t, now)),
    ...cves.map((c) => cveToStix(c, now)),
  ];
  return {
    type: 'bundle',
    id: `bundle--${deterministicUuid(`bundle:${now}`)}`,
    objects,
  };
}
