import crypto from 'node:crypto';
import type { ThreatIndicator, CveItem } from './types.js';

// Minimal STIX 2.1 export so indicators/CVEs can be shared with MISP / OpenCTI / SIEMs.
// We emit `indicator` SDOs (with STIX patterns) for network IOCs and `vulnerability`
// SDOs for CVEs, wrapped in a bundle.

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

function patternFor(t: ThreatIndicator): string | null {
  const v = t.indicator.replace(/'/g, "\\'");
  switch (t.indicatorType) {
    case 'ip':
      return `[ipv4-addr:value = '${v}']`;
    case 'domain':
      return `[domain-name:value = '${v}']`;
    case 'url':
      return `[url:value = '${v}']`;
    case 'cidr':
      return `[ipv4-addr:value ISSUBSET '${v}']`;
    case 'hash':
      if (/^[a-f0-9]{64}$/i.test(t.indicator)) return `[file:hashes.'SHA-256' = '${v}']`;
      if (/^[a-f0-9]{40}$/i.test(t.indicator)) return `[file:hashes.'SHA-1' = '${v}']`;
      if (/^[a-f0-9]{32}$/i.test(t.indicator)) return `[file:hashes.MD5 = '${v}']`;
      return null;
    default:
      return null; // 'cve' is exported as a vulnerability SDO instead
  }
}

function deterministicUuid(seed: string): string {
  const bytes = crypto.createHash('sha256').update(seed).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function stixId(prefix: 'indicator' | 'vulnerability', seed: string): string {
  return `${prefix}--${deterministicUuid(`${prefix}:${seed}`)}`;
}

function isoOr(value: string | undefined, fallback: string): string {
  if (!value) return fallback;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? fallback : parsed.toISOString();
}

function objectTimes(createdFallback: string, firstSeen?: string, lastSeen?: string): { created: string; modified: string } {
  const created = isoOr(firstSeen ?? lastSeen, createdFallback);
  const modified = isoOr(lastSeen, created);
  return { created, modified };
}

function vulnerability(
  id: string,
  created: string,
  modified: string,
  name?: string,
  description?: string,
): StixObject {
  return {
    type: 'vulnerability',
    spec_version: '2.1',
    id: stixId('vulnerability', id.toUpperCase()),
    created,
    modified,
    name: name ?? id,
    description,
    external_references: [{ source_name: 'cve', external_id: id }],
  };
}

export function buildStixBundle(
  indicators: ThreatIndicator[],
  cves: CveItem[],
  now = new Date(),
): StixBundle {
  const created = now.toISOString();
  const objects: StixObject[] = [];
  const seenVuln = new Set<string>();

  for (const t of indicators) {
    if (t.indicatorType === 'cve') {
      if (seenVuln.has(t.indicator)) continue;
      seenVuln.add(t.indicator);
      const times = objectTimes(created, t.firstSeen, t.lastSeen);
      objects.push(vulnerability(t.indicator, times.created, times.modified, t.title, t.description));
      continue;
    }
    const pattern = patternFor(t);
    if (!pattern) continue;
    const times = objectTimes(created, t.firstSeen, t.lastSeen);
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: stixId('indicator', `${t.indicatorType}:${t.indicator.toLowerCase()}`),
      created: times.created,
      modified: times.modified,
      name: t.title ?? t.indicator,
      description: t.description,
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: t.firstSeen ?? created,
      labels: t.tags.length > 0 ? t.tags : undefined,
      confidence: t.confidence,
      x_threat_intel_source_reliability: t.sourceReliability,
      x_threat_intel_tlp: t.tlp,
      external_references: t.reference ? [{ source_name: t.source, url: t.reference }] : undefined,
    });
  }

  for (const c of cves) {
    if (seenVuln.has(c.id)) continue;
    seenVuln.add(c.id);
    objects.push(
      vulnerability(
        c.id,
        isoOr(c.published, created),
        isoOr(c.lastModified ?? c.published, isoOr(c.published, created)),
        c.title,
        c.description,
      ),
    );
  }

  return { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects };
}
