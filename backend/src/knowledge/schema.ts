import type { SqliteDatabase } from '../persistenceDb.js';
import { withTransaction } from '../persistenceDb.js';

export const KNOWLEDGE_SCHEMA_VERSION = 6;

function migrationApplied(database: SqliteDatabase, version: number): boolean {
  return Boolean(database.prepare('SELECT 1 FROM schema_migrations WHERE version = ?').get(version));
}

function assessmentConfidenceWasRequired(database: SqliteDatabase): boolean {
  const columns = database.prepare('PRAGMA table_info(knowledge_assessments)').all() as Array<{
    name: string;
    notnull: number;
  }>;
  return columns.some((column) => column.name === 'confidence' && column.notnull === 1);
}

export function applyKnowledgeSchema(database: SqliteDatabase): void {
  withTransaction(database, () => {
    // Recheck after BEGIN IMMEDIATE acquires the writer lock. Another process
    // may have completed the migration between opening the database and here.
    if (migrationApplied(database, KNOWLEDGE_SCHEMA_VERSION)) return;
    const rebuildAssessments = assessmentConfidenceWasRequired(database);

    database.exec(`
      CREATE TABLE IF NOT EXISTS imported_stix_sources (
        object_id TEXT NOT NULL,
        version TEXT NOT NULL,
        connector TEXT NOT NULL,
        first_imported_at INTEGER NOT NULL,
        last_imported_at INTEGER NOT NULL,
        PRIMARY KEY (object_id, version, connector),
        FOREIGN KEY (object_id, version)
          REFERENCES imported_stix_objects(object_id, version) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_imported_stix_sources_connector
        ON imported_stix_sources(connector, last_imported_at);

      CREATE TABLE IF NOT EXISTS imported_stix_payloads (
        object_id TEXT NOT NULL,
        version TEXT NOT NULL,
        connector TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        first_imported_at INTEGER NOT NULL,
        last_imported_at INTEGER NOT NULL,
        PRIMARY KEY (object_id, version, connector),
        FOREIGN KEY (object_id, version, connector)
          REFERENCES imported_stix_sources(object_id, version, connector) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS imported_stix_conflicts (
        object_id TEXT NOT NULL,
        version TEXT NOT NULL,
        connector TEXT NOT NULL,
        payload_sha256 TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        detected_at INTEGER NOT NULL,
        PRIMARY KEY (object_id, version, connector, payload_sha256)
      );
      CREATE INDEX IF NOT EXISTS idx_imported_stix_conflicts_detected
        ON imported_stix_conflicts(detected_at);

      CREATE TABLE IF NOT EXISTS knowledge_entities (
        id TEXT PRIMARY KEY,
        entity_type TEXT NOT NULL CHECK(entity_type IN (
          'threat-actor','intrusion-set','campaign','malware','tool',
          'attack-pattern','identity','vulnerability','infrastructure','indicator'
        )),
        name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        confidence INTEGER CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
        tlp TEXT NOT NULL CHECK(tlp IN ('clear','green','amber','red','unknown')),
        valid_from TEXT,
        valid_until TEXT,
        revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
        source_object_id TEXT NOT NULL,
        source_object_version TEXT NOT NULL,
        source_connector TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        modified_at TEXT NOT NULL,
        first_projected_at INTEGER NOT NULL,
        last_projected_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_entities_type_name
        ON knowledge_entities(entity_type, normalized_name);
      CREATE INDEX IF NOT EXISTS idx_knowledge_entities_source
        ON knowledge_entities(source_object_id, source_object_version);

      CREATE TABLE IF NOT EXISTS knowledge_aliases (
        entity_id TEXT NOT NULL,
        alias TEXT NOT NULL,
        normalized_alias TEXT NOT NULL,
        source_object_id TEXT NOT NULL,
        source_object_version TEXT NOT NULL,
        source_connector TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (entity_id, normalized_alias, source_object_id, source_object_version, source_connector),
        FOREIGN KEY (entity_id) REFERENCES knowledge_entities(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_aliases_normalized
        ON knowledge_aliases(normalized_alias);

      CREATE TABLE IF NOT EXISTS knowledge_external_refs (
        entity_id TEXT NOT NULL,
        source_name TEXT NOT NULL,
        external_id TEXT NOT NULL DEFAULT '',
        url TEXT NOT NULL DEFAULT '',
        description TEXT NOT NULL DEFAULT '',
        source_object_id TEXT NOT NULL,
        source_object_version TEXT NOT NULL,
        source_connector TEXT NOT NULL,
        PRIMARY KEY (
          entity_id, source_name, external_id, url,
          source_object_id, source_object_version, source_connector
        ),
        FOREIGN KEY (entity_id) REFERENCES knowledge_entities(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_external_refs_identity
        ON knowledge_external_refs(source_name, external_id);

      CREATE TABLE IF NOT EXISTS knowledge_relationships (
        id TEXT PRIMARY KEY,
        relationship_type TEXT NOT NULL,
        source_entity_id TEXT NOT NULL,
        target_entity_id TEXT NOT NULL,
        assertion_status TEXT NOT NULL DEFAULT 'reported'
          CHECK(assertion_status IN ('reported','candidate','accepted','disputed','rejected')),
        description TEXT NOT NULL DEFAULT '',
        confidence INTEGER CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
        tlp TEXT NOT NULL CHECK(tlp IN ('clear','green','amber','red','unknown')),
        valid_from TEXT,
        valid_until TEXT,
        revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
        source_object_id TEXT NOT NULL,
        source_object_version TEXT NOT NULL,
        source_connector TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        modified_at TEXT NOT NULL,
        first_projected_at INTEGER NOT NULL,
        last_projected_at INTEGER NOT NULL,
        CHECK(source_entity_id <> target_entity_id),
        FOREIGN KEY (source_entity_id) REFERENCES knowledge_entities(id) ON DELETE RESTRICT,
        FOREIGN KEY (target_entity_id) REFERENCES knowledge_entities(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_relationships_source
        ON knowledge_relationships(source_entity_id, relationship_type);
      CREATE INDEX IF NOT EXISTS idx_knowledge_relationships_target
        ON knowledge_relationships(target_entity_id, relationship_type);

      CREATE TABLE IF NOT EXISTS knowledge_sightings (
        id TEXT PRIMARY KEY,
        entity_id TEXT NOT NULL,
        indicator_ref TEXT,
        first_seen TEXT,
        last_seen TEXT,
        observation_count INTEGER NOT NULL DEFAULT 1 CHECK(observation_count >= 0),
        confidence INTEGER CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
        tlp TEXT NOT NULL CHECK(tlp IN ('clear','green','amber','red','unknown')),
        where_sighted_refs_json TEXT NOT NULL DEFAULT '[]',
        observed_data_refs_json TEXT NOT NULL DEFAULT '[]',
        source_object_id TEXT NOT NULL,
        source_object_version TEXT NOT NULL,
        source_connector TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        modified_at TEXT NOT NULL,
        first_projected_at INTEGER NOT NULL,
        last_projected_at INTEGER NOT NULL,
        FOREIGN KEY (entity_id) REFERENCES knowledge_entities(id) ON DELETE RESTRICT
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_sightings_entity
        ON knowledge_sightings(entity_id, last_seen);
      CREATE INDEX IF NOT EXISTS idx_knowledge_sightings_indicator
        ON knowledge_sightings(indicator_ref, last_seen);

      CREATE TABLE IF NOT EXISTS knowledge_pending_facts (
        id TEXT NOT NULL,
        fact_type TEXT NOT NULL CHECK(fact_type IN ('relationship','sighting')),
        source_object_version TEXT NOT NULL,
        source_connector TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        first_deferred_at INTEGER NOT NULL,
        last_attempted_at INTEGER NOT NULL,
        PRIMARY KEY (id, source_object_version, source_connector)
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_pending_facts_type
        ON knowledge_pending_facts(fact_type, last_attempted_at);

      CREATE TABLE IF NOT EXISTS knowledge_evidence (
        id TEXT PRIMARY KEY,
        entity_id TEXT,
        relationship_id TEXT,
        evidence_kind TEXT NOT NULL,
        source_name TEXT NOT NULL,
        source_url TEXT,
        source_object_id TEXT,
        source_object_version TEXT,
        source_connector TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '',
        confidence INTEGER CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
        tlp TEXT NOT NULL CHECK(tlp IN ('clear','green','amber','red','unknown')),
        observed_at TEXT,
        collected_at TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        CHECK((entity_id IS NOT NULL AND relationship_id IS NULL) OR
              (entity_id IS NULL AND relationship_id IS NOT NULL)),
        FOREIGN KEY (entity_id) REFERENCES knowledge_entities(id) ON DELETE CASCADE,
        FOREIGN KEY (relationship_id) REFERENCES knowledge_relationships(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_knowledge_evidence_entity
        ON knowledge_evidence(entity_id, created_at);
      CREATE INDEX IF NOT EXISTS idx_knowledge_evidence_relationship
        ON knowledge_evidence(relationship_id, created_at);

      CREATE TABLE IF NOT EXISTS knowledge_assessments (
        id TEXT PRIMARY KEY,
        subject_type TEXT NOT NULL CHECK(subject_type IN ('entity','relationship')),
        subject_ref TEXT NOT NULL,
        verdict TEXT NOT NULL CHECK(verdict IN ('supported','disputed','rejected','inconclusive')),
        rationale TEXT NOT NULL,
        confidence INTEGER CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
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
      CREATE INDEX IF NOT EXISTS idx_knowledge_assessments_subject
        ON knowledge_assessments(subject_type, subject_ref, modified_at);

      INSERT OR IGNORE INTO imported_stix_sources (
        object_id, version, connector, first_imported_at, last_imported_at
      )
      SELECT object_id, version, connector, first_imported_at, last_imported_at
      FROM imported_stix_objects;

      INSERT OR IGNORE INTO imported_stix_payloads (
        object_id, version, connector, payload_json, payload_sha256,
        first_imported_at, last_imported_at
      )
      SELECT object_id, version, connector, payload_json, '',
             first_imported_at, last_imported_at
      FROM imported_stix_objects;

      INSERT OR IGNORE INTO schema_migrations (version, applied_at)
      VALUES (4, CURRENT_TIMESTAMP);
      INSERT OR IGNORE INTO schema_migrations (version, applied_at)
      VALUES (5, CURRENT_TIMESTAMP);
      INSERT INTO schema_migrations (version, applied_at)
      VALUES (6, CURRENT_TIMESTAMP);
    `);
    if (rebuildAssessments) {
      database.exec(`
        PRAGMA defer_foreign_keys = ON;
        DROP INDEX IF EXISTS idx_knowledge_assessments_subject;
        ALTER TABLE knowledge_assessments RENAME TO knowledge_assessments_required_confidence;
        CREATE TABLE knowledge_assessments (
          id TEXT PRIMARY KEY,
          subject_type TEXT NOT NULL CHECK(subject_type IN ('entity','relationship')),
          subject_ref TEXT NOT NULL,
          verdict TEXT NOT NULL CHECK(verdict IN ('supported','disputed','rejected','inconclusive')),
          rationale TEXT NOT NULL,
          confidence INTEGER CHECK(confidence IS NULL OR (confidence >= 0 AND confidence <= 100)),
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
        INSERT INTO knowledge_assessments (
          id, subject_type, subject_ref, verdict, rationale, confidence, tlp,
          analyst_id, analyst_name, valid_from, valid_until, supersedes_id,
          created_at, modified_at
        )
        SELECT id, subject_type, subject_ref, verdict, rationale, confidence, tlp,
               analyst_id, analyst_name, valid_from, valid_until, supersedes_id,
               created_at, modified_at
        FROM knowledge_assessments_required_confidence;
        DROP TABLE knowledge_assessments_required_confidence;
        CREATE INDEX idx_knowledge_assessments_subject
          ON knowledge_assessments(subject_type, subject_ref, modified_at);
      `);
    }
  });
}
