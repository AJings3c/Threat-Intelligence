import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import type { SqliteDatabase } from '../src/persistenceDb.js';
import { applyKnowledgeSchema } from '../src/knowledge/schema.js';
import {
  backfillKnowledgeProjection,
  getKnowledgeEntity,
  getKnowledgeGraph,
  listKnowledgeEntities,
} from '../src/knowledge/repository.js';

const GREEN = 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da';

function stixId(type: string, suffix: number): string {
  return `${type}--10000000-0000-4000-8000-${String(suffix).padStart(12, '0')}`;
}

function entity(
  type: string,
  suffix: number,
  modified: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type,
    spec_version: '2.1',
    id: stixId(type, suffix),
    created: '2026-01-01T00:00:00.000Z',
    modified,
    name: `${type} ${suffix}`,
    ...extra,
  };
}

function relationship(
  suffix: number,
  sourceRef: string,
  targetRef: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    type: 'relationship',
    spec_version: '2.1',
    id: stixId('relationship', suffix),
    created: '2026-01-01T00:00:00.000Z',
    modified: '2026-02-01T00:00:00.000Z',
    relationship_type: 'uses',
    source_ref: sourceRef,
    target_ref: targetRef,
    ...extra,
  };
}

function initializeV3Schema(database: SqliteDatabase): void {
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
    INSERT INTO schema_migrations (version, applied_at) VALUES
      (1, CURRENT_TIMESTAMP),
      (2, CURRENT_TIMESTAMP),
      (3, CURRENT_TIMESTAMP);
  `);
}

function insertStoredStix(
  database: SqliteDatabase,
  object: Record<string, unknown>,
  connector: string,
  importedAt: number,
): void {
  const objectId = String(object.id);
  const version = String(object.modified ?? object.created ?? 'unversioned');
  database
    .prepare(`
      INSERT INTO imported_stix_objects (
        object_id, version, object_type, connector, payload_json,
        first_imported_at, last_imported_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .run(objectId, version, String(object.type), connector, JSON.stringify(object), importedAt, importedAt);
  database
    .prepare(`
      INSERT INTO imported_stix_sources (
        object_id, version, connector, first_imported_at, last_imported_at
      ) VALUES (?, ?, ?, ?, ?)
    `)
    .run(objectId, version, connector, importedAt, importedAt);
}

function rowCount(database: SqliteDatabase, table: string): number {
  const row = database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number };
  return row.count;
}

describe('knowledge persistence integration', () => {
  let database: SqliteDatabase;

  beforeEach(() => {
    database = new DatabaseSync(':memory:') as unknown as SqliteDatabase;
    initializeV3Schema(database);
  });

  afterEach(() => database.close());

  it('migrates a v3 database to v6 once and preserves legacy STIX provenance and payload', () => {
    const actor = entity('threat-actor', 1, '2026-02-01T00:00:00.000Z');
    database
      .prepare(`
        INSERT INTO imported_stix_objects (
          object_id, version, object_type, connector, payload_json,
          first_imported_at, last_imported_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `)
      .run(actor.id, actor.modified, actor.type, 'legacy-taxii', JSON.stringify(actor), 100, 200);

    applyKnowledgeSchema(database);
    applyKnowledgeSchema(database);

    const versions = database.prepare('SELECT version FROM schema_migrations ORDER BY version').all() as Array<{
      version: number;
    }>;
    const sources = database
      .prepare(`
        SELECT connector, first_imported_at, last_imported_at
        FROM imported_stix_sources
      `)
      .all() as Array<{ connector: string; first_imported_at: number; last_imported_at: number }>;
    const payloads = database
      .prepare(`
        SELECT connector, payload_json, payload_sha256, first_imported_at, last_imported_at
        FROM imported_stix_payloads
      `)
      .all() as Array<{
      connector: string;
      payload_json: string;
      payload_sha256: string;
      first_imported_at: number;
      last_imported_at: number;
    }>;

    expect(versions).toEqual([
      { version: 1 },
      { version: 2 },
      { version: 3 },
      { version: 4 },
      { version: 5 },
      { version: 6 },
    ]);
    expect(sources).toEqual([{ connector: 'legacy-taxii', first_imported_at: 100, last_imported_at: 200 }]);
    expect(payloads).toEqual([
      {
        connector: 'legacy-taxii',
        payload_json: JSON.stringify(actor),
        payload_sha256: '',
        first_imported_at: 100,
        last_imported_at: 200,
      },
    ]);
    expect(rowCount(database, 'imported_stix_conflicts')).toBe(0);
    expect(rowCount(database, 'knowledge_entities')).toBe(0);
  });

  it('migrates v5 assessments to nullable confidence without losing supersession history', () => {
    database.exec(`
      CREATE TABLE knowledge_assessments (
        id TEXT PRIMARY KEY,
        subject_type TEXT NOT NULL CHECK(subject_type IN ('entity','relationship')),
        subject_ref TEXT NOT NULL,
        verdict TEXT NOT NULL CHECK(verdict IN ('supported','disputed','rejected','inconclusive')),
        rationale TEXT NOT NULL,
        confidence INTEGER NOT NULL CHECK(confidence >= 0 AND confidence <= 100),
        tlp TEXT NOT NULL CHECK(tlp IN ('clear','green','amber','red','unknown')),
        analyst_id TEXT NOT NULL,
        analyst_name TEXT,
        valid_from TEXT,
        valid_until TEXT,
        supersedes_id TEXT,
        created_at TEXT NOT NULL,
        modified_at TEXT NOT NULL,
        FOREIGN KEY (supersedes_id) REFERENCES knowledge_assessments(id) ON DELETE RESTRICT
      );
      CREATE INDEX idx_knowledge_assessments_subject
        ON knowledge_assessments(subject_type, subject_ref, modified_at);
      INSERT INTO knowledge_assessments (
        id, subject_type, subject_ref, verdict, rationale, confidence, tlp,
        analyst_id, created_at, modified_at
      ) VALUES (
        'assessment--old', 'relationship', 'relationship--one', 'inconclusive',
        'Initial assessment', 40, 'amber', 'analyst-one',
        '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z'
      );
      INSERT INTO knowledge_assessments (
        id, subject_type, subject_ref, verdict, rationale, confidence, tlp,
        analyst_id, supersedes_id, created_at, modified_at
      ) VALUES (
        'assessment--new', 'relationship', 'relationship--one', 'supported',
        'Follow-up assessment', 75, 'amber', 'analyst-two', 'assessment--old',
        '2026-02-01T00:00:00.000Z', '2026-02-01T00:00:00.000Z'
      );
      INSERT INTO schema_migrations (version, applied_at) VALUES
        (4, CURRENT_TIMESTAMP),
        (5, CURRENT_TIMESTAMP);
    `);

    applyKnowledgeSchema(database);

    const confidenceColumn = database
      .prepare('PRAGMA table_info(knowledge_assessments)')
      .all()
      .find((column) => (column as { name: string }).name === 'confidence') as { notnull: number };
    expect(confidenceColumn.notnull).toBe(0);
    expect(rowCount(database, 'knowledge_assessments')).toBe(2);
    expect(
      database.prepare('SELECT supersedes_id FROM knowledge_assessments WHERE id = ?').get('assessment--new'),
    ).toEqual({ supersedes_id: 'assessment--old' });
    expect(() =>
      database
        .prepare(`
          INSERT INTO knowledge_assessments (
            id, subject_type, subject_ref, verdict, rationale, confidence, tlp,
            analyst_id, created_at, modified_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .run(
          'assessment--unknown',
          'entity',
          'threat-actor--one',
          'inconclusive',
          'Confidence remains unknown',
          null,
          'amber',
          'analyst-three',
          '2026-03-01T00:00:00.000Z',
          '2026-03-01T00:00:00.000Z',
        ),
    ).not.toThrow();
  });

  it('backfills entities before cross-connector relationships and isolates dangling references', () => {
    applyKnowledgeSchema(database);
    const intrusionId = stixId('intrusion-set', 30);
    const olderIntrusion = entity('intrusion-set', 30, '2026-01-15T00:00:00.000Z', {
      id: intrusionId,
      name: 'Historical Cluster Name',
      object_marking_refs: [GREEN],
    });
    const currentIntrusion = entity('intrusion-set', 30, '2026-03-15T00:00:00.000Z', {
      id: intrusionId,
      name: 'Current Cluster Name',
    });
    const malware = entity('malware', 31, '2026-02-15T00:00:00.000Z', {
      name: 'Cross Connector Loader',
      object_marking_refs: [GREEN],
    });
    const validUses = relationship(30, intrusionId, String(malware.id), {
      object_marking_refs: [GREEN],
    });
    const danglingUses = relationship(31, intrusionId, stixId('malware', 404), {
      object_marking_refs: [GREEN],
    });

    // Relationships are imported first on purpose. Backfill must still project all
    // entity batches before evaluating relationship batches from other connectors.
    insertStoredStix(database, validUses, 'relationship-feed', 10);
    insertStoredStix(database, danglingUses, 'relationship-feed', 20);
    insertStoredStix(database, olderIntrusion, 'actor-history', 30);
    insertStoredStix(database, malware, 'malware-catalog', 40);
    insertStoredStix(database, currentIntrusion, 'actor-current', 50);

    const result = backfillKnowledgeProjection(database);

    expect(result.relationships).toBe(1);
    expect(result.skippedRelationships).toBe(1);
    expect(result.warnings.map((warning) => warning.code)).toContain('unresolved-reference');
    expect(listKnowledgeEntities(database, 'analyst').entities.map((item) => item.id)).not.toContain(intrusionId);

    const current = getKnowledgeEntity(database, 'admin', intrusionId);
    expect(current).toMatchObject({ name: 'Current Cluster Name', tlp: 'unknown' });
    expect(current?.sources.map((source) => source.name).sort()).toEqual(['actor-current', 'actor-history']);

    const graph = getKnowledgeGraph(database, 'admin', intrusionId, 1);
    expect(graph?.relationships).toEqual([
      expect.objectContaining({ id: validUses.id, sourceRef: intrusionId, targetRef: malware.id }),
    ]);
    expect(
      database.prepare('SELECT id FROM knowledge_relationships ORDER BY id').all(),
    ).toEqual([{ id: validUses.id }]);

    const evidenceVersions = database
      .prepare(`
        SELECT source_connector, source_object_version
        FROM knowledge_evidence
        WHERE entity_id = ?
        ORDER BY source_object_version
      `)
      .all(intrusionId) as Array<{ source_connector: string; source_object_version: string }>;
    expect(evidenceVersions).toEqual([
      { source_connector: 'actor-history', source_object_version: '2026-01-15T00:00:00.000Z' },
      { source_connector: 'actor-current', source_object_version: '2026-03-15T00:00:00.000Z' },
    ]);

    const countsBeforeReplay = {
      entities: rowCount(database, 'knowledge_entities'),
      relationships: rowCount(database, 'knowledge_relationships'),
      evidence: rowCount(database, 'knowledge_evidence'),
    };
    backfillKnowledgeProjection(database);
    expect({
      entities: rowCount(database, 'knowledge_entities'),
      relationships: rowCount(database, 'knowledge_relationships'),
      evidence: rowCount(database, 'knowledge_evidence'),
    }).toEqual(countsBeforeReplay);
  });
});
