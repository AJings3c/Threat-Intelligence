import crypto from 'node:crypto';
import type { ThreatIndicator, CveItem, Tlp } from './types.js';

// STIX 2.1 export for sharing with MISP / OpenCTI / SIEMs. Indicators and
// vulnerabilities are linked to source-authored Report and Identity SDOs so
// downstream graph consumers retain evidence provenance.

export interface StixObject {
  type: string;
  spec_version: '2.1';
  id: string;
  created?: string;
  modified?: string;
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

function stixId(prefix: 'indicator' | 'vulnerability' | 'identity' | 'report', seed: string): string {
  return `${prefix}--${deterministicUuid(`${prefix}:${seed}`)}`;
}

const TLP_MARKING_IDS: Record<Tlp, string> = {
  clear: 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487',
  green: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
  amber: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
  red: 'marking-definition--5e57c739-391a-4eb3-b6e7-5b9acb13fe73',
};

function tlpMarking(tlp: Tlp): StixObject {
  return {
    type: 'marking-definition',
    spec_version: '2.1',
    id: TLP_MARKING_IDS[tlp],
    created: '2017-01-20T00:00:00.000Z',
    definition_type: 'tlp',
    name: `TLP:${tlp.toUpperCase()}`,
    definition: { tlp },
  };
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
  createdByRef?: string,
  tlp?: Tlp,
): StixObject {
  return {
    type: 'vulnerability',
    spec_version: '2.1',
    id: stixId('vulnerability', id.toUpperCase()),
    created,
    modified,
    name: name ?? id,
    description,
    created_by_ref: createdByRef,
    object_marking_refs: tlp ? [TLP_MARKING_IDS[tlp]] : undefined,
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
  const usedTlp = new Set<Tlp>();
  const sourceObjectRefs = new Map<string, Set<string>>();
  const sourceTlp = new Map<string, Set<Tlp>>();
  const addSourceRefs = (sources: string[], objectId: string): void => {
    for (const source of sources) {
      const refs = sourceObjectRefs.get(source) ?? new Set<string>();
      refs.add(objectId);
      sourceObjectRefs.set(source, refs);
    }
  };
  const addTlp = (sources: string[], tlp: Tlp | undefined): void => {
    if (!tlp) return;
    usedTlp.add(tlp);
    for (const source of sources) {
      const values = sourceTlp.get(source) ?? new Set<Tlp>();
      values.add(tlp);
      sourceTlp.set(source, values);
    }
  };

  for (const t of indicators) {
    if (t.indicatorType === 'cve') {
      const objectId = stixId('vulnerability', t.indicator.toUpperCase());
      const sources = t.sources ?? [t.source];
      addSourceRefs(sources, objectId);
      addTlp(sources, t.tlp);
      if (!seenVuln.has(t.indicator)) {
        seenVuln.add(t.indicator);
        const times = objectTimes(created, t.firstSeen, t.lastSeen);
        objects.push(
          vulnerability(
            t.indicator,
            times.created,
            times.modified,
            t.title,
            t.description,
            stixId('identity', t.source),
            t.tlp,
          ),
        );
      }
      continue;
    }
    const pattern = patternFor(t);
    if (!pattern) continue;
    const times = objectTimes(created, t.firstSeen, t.lastSeen);
    const objectId = stixId('indicator', `${t.indicatorType}:${t.indicator.toLowerCase()}`);
    const sources = t.sources ?? [t.source];
    addSourceRefs(sources, objectId);
    addTlp(sources, t.tlp);
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: objectId,
      created: times.created,
      modified: times.modified,
      name: t.title ?? t.indicator,
      description: t.description,
      created_by_ref: stixId('identity', t.source),
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: t.firstSeen ?? created,
      labels: t.tags.length > 0 ? t.tags : undefined,
      confidence: t.confidence,
      x_threat_intel_source_reliability: t.sourceReliability,
      x_threat_intel_tlp: t.tlp,
      object_marking_refs: t.tlp ? [TLP_MARKING_IDS[t.tlp]] : undefined,
      x_threat_intel_sources: t.sources ?? [t.source],
      external_references: t.reference ? [{ source_name: t.source, url: t.reference }] : undefined,
    });
  }

  for (const c of cves) {
    const objectId = stixId('vulnerability', c.id.toUpperCase());
    addSourceRefs([c.source], objectId);
    addTlp([c.source], c.tlp);
    if (!seenVuln.has(c.id)) {
      seenVuln.add(c.id);
      objects.push(
        vulnerability(
          c.id,
          isoOr(c.published, created),
          isoOr(c.lastModified ?? c.published, isoOr(c.published, created)),
          c.title,
          c.description,
          stixId('identity', c.source),
          c.tlp,
        ),
      );
    }
  }

  for (const [source, refs] of Array.from(sourceObjectRefs.entries()).sort(([a], [b]) => a.localeCompare(b))) {
    const identityId = stixId('identity', source);
    const reportMarkings = Array.from(sourceTlp.get(source) ?? []).map((tlp) => TLP_MARKING_IDS[tlp]);
    objects.push({
      type: 'identity',
      spec_version: '2.1',
      id: identityId,
      created,
      modified: created,
      name: source,
      identity_class: 'organization',
      description: `Threat intelligence source represented by the ${source} adapter.`,
    });
    objects.push({
      type: 'report',
      spec_version: '2.1',
      id: stixId('report', source),
      created,
      modified: created,
      created_by_ref: identityId,
      name: `${source} normalized threat intelligence`,
      description: `Normalized objects observed through the ${source} source adapter.`,
      report_types: ['threat-report'],
      published: created,
      object_refs: Array.from(refs).sort(),
      object_marking_refs: reportMarkings.length > 0 ? reportMarkings : undefined,
    });
  }

  objects.unshift(...Array.from(usedTlp).sort().map(tlpMarking));

  return { type: 'bundle', id: `bundle--${crypto.randomUUID()}`, objects };
}
