import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import type { SqliteDatabase } from '../src/persistenceDb.js';
import { applyKnowledgeSchema } from '../src/knowledge/schema.js';
import {
  backfillKnowledgeProjection,
  getKnowledgeEntity,
  getKnowledgeGraph,
  listKnowledgeEntities,
  projectAndPersistKnowledgeObjects,
} from '../src/knowledge/repository.js';

const created = '2026-01-01T00:00:00.000Z';
const modified = '2026-02-01T00:00:00.000Z';
const GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da';
const RED = 'marking-definition--5e57c739-391a-4eb3-b6e7-5b9acb13fe73';

function stixId(type: string, suffix: number): string {
  return `${type}--00000000-0000-4000-8000-${String(suffix).padStart(12, '0')}`;
}

function entity(type: string, suffix: number, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type,
    spec_version: '2.1',
    id: stixId(type, suffix),
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
    id: stixId('relationship', suffix),
    created,
    modified,
    relationship_type: relationshipType,
    source_ref: sourceRef,
    target_ref: targetRef,
    ...extra,
  };
}

function initializeBaseSchema(database: SqliteDatabase): void {
  database.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );
    CREATE TABLE imported_stix_objects (
      object_id TEXT NOT NULL,
      version TEXT NOT NULL,
      object_type TEXT NOT NULL,
      connector TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      first_imported_at INTEGER NOT NULL,
      last_imported_at INTEGER NOT NULL,
      PRIMARY KEY (object_id, version)
    );
    CREATE TABLE threat_indicators (
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
  `);
}

describe('knowledge repository', () => {
  let database: SqliteDatabase;

  beforeEach(() => {
    database = new DatabaseSync(':memory:') as unknown as SqliteDatabase;
    initializeBaseSchema(database);
  });

  afterEach(() => database.close());

  it('applies schema v6 idempotently and backfills existing connector provenance', () => {
    const actor = entity('threat-actor', 1);
    database
      .prepare(`
        INSERT INTO imported_stix_objects (
          object_id, version, object_type, connector, payload_json,
          first_imported_at, last_imported_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(actor.id, modified, actor.type, 'legacy-taxii', JSON.stringify(actor), 1, 2);

    applyKnowledgeSchema(database);
    applyKnowledgeSchema(database);

    const versions = database.prepare('SELECT version FROM schema_migrations ORDER BY version').all() as Array<{
      version: number;
    }>;
    const sources = database.prepare('SELECT connector FROM imported_stix_sources').all() as Array<{
      connector: string;
    }>;
    expect(versions).toEqual([{ version: 4 }, { version: 5 }, { version: 6 }]);
    expect(sources).toEqual([{ connector: 'legacy-taxii' }]);
  });

  it('persists searchable entities, aliases, external IDs, relationships, and graph evidence', () => {
    applyKnowledgeSchema(database);
    const intrusion = entity('intrusion-set', 1, {
      name: 'Example Cluster',
      aliases: ['Example Bear'],
      confidence: 75,
      object_marking_refs: [GREEN],
      external_references: [
        { source_name: 'mitre-attack', external_id: 'G9999', url: 'https://example.test/G9999' },
      ],
    });
    const malware = entity('malware', 2, { name: 'Example Loader', object_marking_refs: [GREEN] });
    const uses = relationship(1, String(intrusion.id), String(malware.id), 'uses', {
      confidence: 80,
      object_marking_refs: [GREEN],
      external_references: [{ source_name: 'vendor-report', url: 'https://example.test/report' }],
    });

    const result = projectAndPersistKnowledgeObjects(database, [uses, malware, intrusion], 'taxii-a', 10);
    expect(result).toMatchObject({ entities: 2, relationships: 1, skippedRelationships: 0 });
    expect(listKnowledgeEntities(database, 'viewer', { q: 'example bear' }).entities).toHaveLength(1);
    expect(listKnowledgeEntities(database, 'viewer', { q: 'g9999' }).entities[0].id).toBe(intrusion.id);
    expect(listKnowledgeEntities(database, 'viewer', { q: '%' }).total).toBe(0);
    expect(listKnowledgeEntities(database, 'viewer', { q: '_' }).total).toBe(0);
    expect(getKnowledgeEntity(database, 'viewer', String(intrusion.id))?.sources[0]).toMatchObject({
      name: 'taxii-a',
      kind: 'taxii',
    });

    const graph = getKnowledgeGraph(database, 'viewer', String(intrusion.id), 1);
    expect(graph?.entities.map((item) => item.id).sort()).toEqual([intrusion.id, malware.id].sort());
    expect(graph?.relationships).toEqual([
      expect.objectContaining({ relationshipType: 'uses', sourceRef: intrusion.id, targetRef: malware.id }),
    ]);
  });

  it('keeps unknown TLP admin-only and removes relationships with hidden endpoints', () => {
    applyKnowledgeSchema(database);
    const publicActor = entity('threat-actor', 1, { object_marking_refs: [GREEN] });
    const unknownMalware = entity('malware', 2);
    const relation = relationship(1, String(publicActor.id), String(unknownMalware.id), 'uses', {
      confidence: 70,
      object_marking_refs: [GREEN],
    });
    projectAndPersistKnowledgeObjects(database, [publicActor, unknownMalware, relation], 'taxii-a', 20);

    expect(listKnowledgeEntities(database, 'viewer').entities.map((item) => item.id)).toEqual([publicActor.id]);
    expect(listKnowledgeEntities(database, 'admin').entities).toHaveLength(2);
    expect(getKnowledgeGraph(database, 'viewer', String(publicActor.id), 1)?.relationships).toEqual([]);
    expect(getKnowledgeEntity(database, 'analyst', String(unknownMalware.id))).toBeNull();
    expect(getKnowledgeEntity(database, 'admin', String(unknownMalware.id))?.tlp).toBe('unknown');
  });

  it('rejects stored payloads whose identity or TLP disagrees with filtered SQL columns', () => {
    applyKnowledgeSchema(database);
    const actor = entity('threat-actor', 19, { object_marking_refs: [GREEN] });
    projectAndPersistKnowledgeObjects(database, [actor], 'taxii-a', 25);
    const row = database
      .prepare('SELECT payload_json FROM knowledge_entities WHERE id = ?')
      .get(actor.id) as { payload_json: string };
    const payload = JSON.parse(row.payload_json) as Record<string, unknown>;
    database
      .prepare('UPDATE knowledge_entities SET payload_json = ? WHERE id = ?')
      .run(JSON.stringify({ ...payload, tlp: 'red' }), actor.id);

    expect(getKnowledgeEntity(database, 'viewer', String(actor.id))).toBeNull();
    expect(getKnowledgeGraph(database, 'viewer', String(actor.id), 1)).toBeNull();
    expect(listKnowledgeEntities(database, 'viewer').entities).toEqual([]);
  });

  it('does not persist dangling or policy-invalid relationships', () => {
    applyKnowledgeSchema(database);
    const campaign = entity('campaign', 1, { object_marking_refs: [GREEN] });
    const dangling = relationship(1, String(campaign.id), stixId('malware', 404), 'uses', {
      object_marking_refs: [GREEN],
    });
    const identity = entity('identity', 2, { object_marking_refs: [GREEN] });
    const invalid = relationship(2, String(campaign.id), String(identity.id), 'uses', {
      object_marking_refs: [GREEN],
    });

    const result = projectAndPersistKnowledgeObjects(database, [campaign, identity, dangling, invalid], 'taxii-a', 30);
    expect(result.relationships).toBe(0);
    expect(result.skippedRelationships).toBe(2);
  });

  it('retries deferred relationships and sightings when their entities arrive later', () => {
    applyKnowledgeSchema(database);
    const campaign = entity('campaign', 20, { object_marking_refs: [GREEN] });
    const malware = entity('malware', 21, { object_marking_refs: [GREEN] });
    const uses = relationship(20, String(campaign.id), String(malware.id), 'uses', {
      object_marking_refs: [GREEN],
    });
    const unsupportedEndpoint = relationship(21, String(campaign.id), stixId('location', 21), 'related-to', {
      object_marking_refs: [GREEN],
    });
    const sighting = {
      type: 'sighting',
      spec_version: '2.1',
      id: stixId('sighting', 20),
      created,
      modified,
      sighting_of_ref: malware.id,
      count: 3,
      object_marking_refs: [GREEN],
    };

    const deferred = projectAndPersistKnowledgeObjects(database, [uses, sighting, unsupportedEndpoint], 'relations-first', 31);
    expect(deferred).toMatchObject({ relationships: 0, sightings: 0, skippedRelationships: 2, skippedSightings: 1 });
    expect(database.prepare('SELECT COUNT(*) AS count FROM knowledge_pending_facts').get()).toEqual({ count: 2 });

    projectAndPersistKnowledgeObjects(database, [campaign], 'actor-catalog', 32);
    expect(database.prepare('SELECT COUNT(*) AS count FROM knowledge_pending_facts').get()).toEqual({ count: 2 });

    const recovered = projectAndPersistKnowledgeObjects(database, [malware], 'malware-catalog', 33);
    expect(recovered).toMatchObject({ relationships: 1, sightings: 1 });
    expect(database.prepare('SELECT COUNT(*) AS count FROM knowledge_pending_facts').get()).toEqual({ count: 0 });
    expect(getKnowledgeGraph(database, 'viewer', String(campaign.id), 1)).toMatchObject({
      relationships: [expect.objectContaining({ id: uses.id })],
      sightings: [expect.objectContaining({ id: sighting.id, count: 3 })],
    });
  });

  it('merges connector provenance without merging entities by alias', () => {
    applyKnowledgeSchema(database);
    const first = entity('intrusion-set', 1, {
      name: 'Shared Name One',
      aliases: ['Ambiguous Bear'],
      object_marking_refs: [GREEN],
    });
    const second = entity('intrusion-set', 2, {
      name: 'Shared Name Two',
      aliases: ['Ambiguous Bear'],
      object_marking_refs: [GREEN],
    });
    projectAndPersistKnowledgeObjects(database, [first, second], 'taxii-a', 40);
    projectAndPersistKnowledgeObjects(database, [first], 'taxii-b', 50);

    const aliasMatches = listKnowledgeEntities(database, 'viewer', { q: 'ambiguous bear' });
    expect(aliasMatches.total).toBe(2);
    expect(getKnowledgeEntity(database, 'viewer', String(first.id))?.sources.map((source) => source.name)).toEqual([
      'taxii-a',
      'taxii-b',
    ]);
  });

  it('keeps the newest entity view while retaining evidence from older versions', () => {
    applyKnowledgeSchema(database);
    const actorId = stixId('threat-actor', 1);
    const newer = entity('threat-actor', 1, {
      id: actorId,
      name: 'Current Name',
      modified: '2026-03-01T00:00:00.000Z',
      object_marking_refs: [GREEN],
    });
    const older = entity('threat-actor', 1, {
      id: actorId,
      name: 'Old Name',
      modified: '2026-01-15T00:00:00.000Z',
      object_marking_refs: [GREEN],
    });
    projectAndPersistKnowledgeObjects(database, [newer], 'taxii-a', 60);
    projectAndPersistKnowledgeObjects(database, [older], 'taxii-a', 70);

    expect(getKnowledgeEntity(database, 'viewer', actorId)?.name).toBe('Current Name');
    const evidenceCount = database
      .prepare('SELECT COUNT(*) AS count FROM knowledge_evidence WHERE entity_id = ?')
      .get(actorId) as { count: number };
    expect(evidenceCount.count).toBe(2);
  });

  it('backfills valid stored STIX while isolating corrupt payloads', () => {
    applyKnowledgeSchema(database);
    const actor = entity('threat-actor', 1, { object_marking_refs: [GREEN] });
    const insert = database.prepare(`
      INSERT INTO imported_stix_objects (
        object_id, version, object_type, connector, payload_json,
        first_imported_at, last_imported_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    insert.run(actor.id, modified, actor.type, 'taxii-a', JSON.stringify(actor), 1, 1);
    insert.run(stixId('malware', 9), modified, 'malware', 'taxii-a', '{broken', 1, 1);

    const result = backfillKnowledgeProjection(database);
    expect(result.entities).toBe(1);
    expect(result.warnings.map((warning) => warning.code)).toContain('invalid-object');
    expect(getKnowledgeEntity(database, 'viewer', String(actor.id))?.id).toBe(actor.id);
  });

  it('never downgrades merged entity, relationship, or sighting provenance to GREEN', () => {
    applyKnowledgeSchema(database);
    const restrictedActor = entity('threat-actor', 50, {
      name: 'Restricted Actor Name',
      modified: '2026-01-10T00:00:00.000Z',
      object_marking_refs: [RED],
      external_references: [{ source_name: 'restricted-report', url: 'https://restricted.example/actor' }],
    });
    const intrusion = entity('intrusion-set', 51, { object_marking_refs: [GREEN] });
    const malware = entity('malware', 52, { object_marking_refs: [GREEN] });
    const restrictedRelationship = relationship(50, String(intrusion.id), String(malware.id), 'uses', {
      modified: '2026-01-10T00:00:00.000Z',
      object_marking_refs: [RED],
    });
    const restrictedSighting = {
      type: 'sighting',
      spec_version: '2.1',
      id: stixId('sighting', 50),
      created,
      modified: '2026-01-10T00:00:00.000Z',
      sighting_of_ref: malware.id,
      first_seen: '2026-01-05T00:00:00.000Z',
      last_seen: '2026-01-10T00:00:00.000Z',
    };
    projectAndPersistKnowledgeObjects(
      database,
      [restrictedActor, intrusion, malware, restrictedRelationship, restrictedSighting],
      'restricted-feed',
      80,
    );

    const greenActor = entity('threat-actor', 50, {
      name: 'Current Actor Name',
      modified: '2026-04-10T00:00:00.000Z',
      object_marking_refs: [GREEN],
      external_references: [{ source_name: 'public-report', url: 'https://public.example/actor' }],
    });
    const greenRelationship = relationship(50, String(intrusion.id), String(malware.id), 'uses', {
      modified: '2026-04-10T00:00:00.000Z',
      object_marking_refs: [GREEN],
    });
    const greenSighting = {
      ...restrictedSighting,
      modified: '2026-04-10T00:00:00.000Z',
      last_seen: '2026-04-10T00:00:00.000Z',
      object_marking_refs: [GREEN],
    };
    projectAndPersistKnowledgeObjects(
      database,
      [greenActor, greenRelationship, greenSighting],
      'public-feed',
      90,
    );

    expect(getKnowledgeEntity(database, 'viewer', String(restrictedActor.id))).toBeNull();
    const adminActor = getKnowledgeEntity(database, 'admin', String(restrictedActor.id));
    expect(adminActor).toMatchObject({ name: 'Current Actor Name', tlp: 'red' });
    expect(adminActor?.sources.map((item) => item.name)).toEqual(
      expect.arrayContaining(['public-feed', 'restricted-feed']),
    );
    expect(adminActor?.objectMarkingRefs).toEqual(expect.arrayContaining([GREEN, RED]));
    expect(new Set(adminActor?.evidence.map((item) => item.tlp))).toEqual(new Set(['green', 'red']));

    expect(getKnowledgeGraph(database, 'viewer', String(intrusion.id), 1)?.relationships).toEqual([]);
    expect(getKnowledgeGraph(database, 'viewer', String(malware.id), 0)?.sightings).toEqual([]);
    const adminGraph = getKnowledgeGraph(database, 'admin', String(intrusion.id), 1);
    expect(adminGraph?.relationships).toEqual([
      expect.objectContaining({ id: restrictedRelationship.id, tlp: 'red' }),
    ]);
    expect(adminGraph?.sightings).toEqual([
      expect.objectContaining({ id: restrictedSighting.id, tlp: 'unknown' }),
    ]);

    const storedMalware = database
      .prepare('SELECT payload_json FROM knowledge_entities WHERE id = ?')
      .get(malware.id) as { payload_json: string };
    const legacyPayload = JSON.parse(storedMalware.payload_json) as {
      evidence: Array<Record<string, unknown>>;
    };
    legacyPayload.evidence.push({
      ...legacyPayload.evidence[0],
      id: 'evidence--legacy-red',
      tlp: 'red',
    });
    database
      .prepare('UPDATE knowledge_entities SET payload_json = ? WHERE id = ?')
      .run(JSON.stringify(legacyPayload), malware.id);
    expect(getKnowledgeEntity(database, 'viewer', String(malware.id))?.evidence.every((item) => item.tlp === 'green')).toBe(
      true,
    );
  });

  it('does not traverse through a TLP-hidden entity at depth two', () => {
    applyKnowledgeSchema(database);
    const root = entity('campaign', 60, { object_marking_refs: [GREEN] });
    const hidden = entity('intrusion-set', 61, { object_marking_refs: [RED] });
    const leaf = entity('malware', 62, { object_marking_refs: [GREEN] });
    const rootToHidden = relationship(60, String(root.id), String(hidden.id), 'related-to', {
      object_marking_refs: [GREEN],
    });
    const hiddenToLeaf = relationship(61, String(hidden.id), String(leaf.id), 'related-to', {
      object_marking_refs: [GREEN],
    });
    projectAndPersistKnowledgeObjects(
      database,
      [root, hidden, leaf, rootToHidden, hiddenToLeaf],
      'graph-feed',
      100,
    );

    const viewerGraph = getKnowledgeGraph(database, 'viewer', String(root.id), 2);
    expect(viewerGraph?.entities.map((item) => item.id)).toEqual([root.id]);
    expect(viewerGraph?.relationships).toEqual([]);

    const adminGraph = getKnowledgeGraph(database, 'admin', String(root.id), 2);
    expect(adminGraph?.entities.map((item) => item.id).sort()).toEqual([root.id, hidden.id, leaf.id].sort());
    expect(adminGraph?.relationships).toHaveLength(2);
  });

});
