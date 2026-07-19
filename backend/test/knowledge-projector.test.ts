import { describe, expect, it } from 'vitest';
import { projectStixObject, projectStixObjects } from '../src/knowledge/projector.js';

function id(type: string, suffix: number): string {
  return `${type}--00000000-0000-4000-8000-${String(suffix).padStart(12, '0')}`;
}

const created = '2025-01-02T03:04:05.000Z';
const modified = '2025-02-03T04:05:06.000Z';
const projectedAt = '2026-07-18T04:00:00.000Z';

function entity(type: string, suffix: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type,
    spec_version: '2.1',
    id: id(type, suffix),
    created,
    modified,
    name: `${type} ${suffix}`,
    ...extra,
  };
}

function relationship(
  suffix: number,
  sourceRef: string,
  targetRef: string,
  relationshipType: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type: 'relationship',
    spec_version: '2.1',
    id: id('relationship', suffix),
    created,
    modified,
    source_ref: sourceRef,
    target_ref: targetRef,
    relationship_type: relationshipType,
    ...extra,
  };
}

describe('STIX knowledge projector', () => {
  it('preserves sourced actor identity, version, aliases, references, markings, confidence, and validity', () => {
    const actor = entity('threat-actor', 1, {
      name: 'Midnight Example',
      description: 'A test actor maintained as sourced intelligence.',
      aliases: ['Example Bear', 'Example Bear', 'EX-29'],
      labels: ['attributed-to:example-state', 'apt'],
      created_by_ref: id('identity', 99),
      first_seen: '2022-01-01T00:00:00.000Z',
      last_seen: '2025-01-01T00:00:00.000Z',
      confidence: 87,
      object_marking_refs: ['marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
      external_references: [
        {
          source_name: 'mitre-attack',
          external_id: 'G9999',
          url: 'https://attack.example/groups/G9999',
          description: 'ATT&CK group record',
        },
      ],
    });

    const projection = projectStixObject(actor, {
      projectedAt,
      source: { name: 'enterprise-taxii', kind: 'taxii' },
    });

    expect(projection.warnings).toEqual([]);
    expect(projection.relationships).toEqual([]);
    expect(projection.entities).toHaveLength(1);
    expect(projection.entities[0]).toMatchObject({
      id: actor.id,
      type: 'threat-actor',
      name: 'Midnight Example',
      description: 'A test actor maintained as sourced intelligence.',
      aliases: ['Example Bear', 'EX-29'],
      confidence: 87,
      tlp: 'amber',
      validFrom: '2022-01-01T00:00:00.000Z',
      validUntil: '2025-01-01T00:00:00.000Z',
      stixVersion: modified,
      objectMarkingRefs: ['marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'],
      createdAt: created,
      modifiedAt: modified,
      externalReferences: [
        {
          sourceName: 'mitre-attack',
          externalId: 'G9999',
          url: 'https://attack.example/groups/G9999',
          description: 'ATT&CK group record',
        },
      ],
    });
    expect(projection.entities[0].sources.map((source) => source.name)).toEqual([
      'enterprise-taxii',
      'mitre-attack',
      id('identity', 99),
    ]);
    expect(projection.entities[0].evidence.every((item) => item.objectRefs.includes(String(actor.id)))).toBe(true);
  });

  it('projects every supported knowledge entity type without inventing confidence or TLP', () => {
    const types = [
      'threat-actor',
      'intrusion-set',
      'campaign',
      'malware',
      'tool',
      'attack-pattern',
      'identity',
      'vulnerability',
      'infrastructure',
      'indicator',
    ];
    const projection = projectStixObjects(
      types.map((type, index) => entity(type, index + 1)),
      { projectedAt },
    );

    expect(projection.entities.map((item) => item.type)).toEqual(types);
    expect(projection.entities.every((item) => item.confidence === undefined)).toBe(true);
    expect(projection.entities.every((item) => item.tlp === 'unknown')).toBe(true);
    expect(projection.warnings).toEqual([]);
  });

  it('projects only explicit, policy-valid attribution and never derives it from labels', () => {
    const intrusionSet = entity('intrusion-set', 1, { labels: ['attributed-to:test-actor'] });
    const actor = entity('threat-actor', 2);
    const explicitAttribution = relationship(1, String(intrusionSet.id), String(actor.id), 'attributed-to', {
      confidence: 76,
      start_time: '2024-01-01T00:00:00.000Z',
      stop_time: '2025-01-01T00:00:00.000Z',
      external_references: [
        { source_name: 'vendor-report', url: 'https://intel.example/reports/attribution-1' },
      ],
    });

    const projection = projectStixObjects([intrusionSet, actor, explicitAttribution], {
      projectedAt,
      source: { name: 'taxii-collection-a', kind: 'taxii' },
    });

    expect(projection.relationships).toHaveLength(1);
    expect(projection.relationships[0]).toMatchObject({
      id: explicitAttribution.id,
      relationshipType: 'attributed-to',
      sourceRef: intrusionSet.id,
      targetRef: actor.id,
      confidence: 76,
      tlp: 'unknown',
      validFrom: '2024-01-01T00:00:00.000Z',
      validUntil: '2025-01-01T00:00:00.000Z',
      stixVersion: modified,
    });
    expect(projection.warnings).toEqual([]);
  });

  it('rejects invalid attribution but retains cross-page relationships for repository validation', () => {
    const intrusionSet = entity('intrusion-set', 1);
    const actor = entity('threat-actor', 2);
    const noConfidence = relationship(1, String(intrusionSet.id), String(actor.id), 'attributed-to', {
      external_references: [{ source_name: 'vendor-report', url: 'https://intel.example/reports/weak' }],
    });
    const unavailableTarget = relationship(2, String(intrusionSet.id), id('threat-actor', 404), 'attributed-to', {
      confidence: 80,
      external_references: [{ source_name: 'vendor-report', url: 'https://intel.example/reports/missing' }],
    });

    const projection = projectStixObjects([intrusionSet, actor, noConfidence, unavailableTarget], { projectedAt });

    expect(projection.relationships).toHaveLength(1);
    expect(projection.relationships[0].id).toBe(unavailableTarget.id);
    expect(projection.warnings.filter((item) => item.code === 'unsupported-relationship')).toHaveLength(1);
    expect(projection.warnings.filter((item) => item.code === 'unresolved-reference')).toHaveLength(1);
    expect(projection.warnings[0].message).toContain('missing-confidence');
  });

  it('preserves sighting time, count, references, markings, and retained supporting object refs', () => {
    const malware = entity('malware', 1);
    const sighting = {
      type: 'sighting',
      spec_version: '2.1',
      id: id('sighting', 1),
      created,
      modified,
      sighting_of_ref: malware.id,
      first_seen: '2025-03-01T00:00:00.000Z',
      last_seen: '2025-03-02T00:00:00.000Z',
      count: 14,
      observed_data_refs: [id('observed-data', 1)],
      where_sighted_refs: [id('identity', 3)],
      confidence: 64,
      object_marking_refs: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'],
      external_references: [{ source_name: 'sensor-report', url: 'https://sensor.example/sightings/1' }],
    };

    const projection = projectStixObjects([malware, sighting], { projectedAt });

    expect(projection.warnings).toEqual([]);
    expect(projection.sightings).toHaveLength(1);
    expect(projection.sightings[0]).toMatchObject({
      id: sighting.id,
      entityRef: malware.id,
      firstSeen: '2025-03-01T00:00:00.000Z',
      lastSeen: '2025-03-02T00:00:00.000Z',
      count: 14,
      confidence: 64,
      tlp: 'green',
      stixVersion: modified,
      externalReferences: [{ sourceName: 'sensor-report', url: 'https://sensor.example/sightings/1' }],
    });
    expect(projection.sightings[0].evidence[0].objectRefs).toEqual([
      sighting.id,
      malware.id,
      id('observed-data', 1),
      id('identity', 3),
    ]);
  });

  it('keeps non-attribution facts with unresolved endpoint warnings and rejects unsupported predicates', () => {
    const actor = entity('threat-actor', 1);
    const unresolvedUses = relationship(1, String(actor.id), id('malware', 404), 'uses');
    const unsupported = relationship(2, String(actor.id), id('malware', 405), 'created-by');
    const projection = projectStixObjects([actor, unresolvedUses, unsupported, null], { projectedAt });

    expect(projection.relationships).toHaveLength(1);
    expect(projection.relationships[0].relationshipType).toBe('uses');
    expect(projection.warnings.map((item) => item.code)).toEqual([
      'unsupported-relationship',
      'invalid-object',
      'unresolved-reference',
    ]);
  });
});
