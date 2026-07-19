import crypto from 'node:crypto';
import type { ApiRole } from '../types.js';
import type { SqliteDatabase } from '../persistenceDb.js';
import { withTransaction } from '../persistenceDb.js';
import { allowedKnowledgeTlpValues, isKnowledgeTlpAllowed } from './access.js';
import { canonicalizeKnowledgeName, normalizeKnowledgeAliases } from './canonicalize.js';
import { projectStixObjects } from './projector.js';
import { validateKnowledgeRelationship } from './relationshipPolicy.js';
import type {
  KnowledgeEntity,
  KnowledgeEntityType,
  KnowledgeEvidence,
  KnowledgeExternalReference,
  KnowledgeProjection,
  KnowledgeProjectionWarning,
  KnowledgeRelationshipFact,
  KnowledgeRelationshipType,
  KnowledgeSighting,
  KnowledgeSource,
  KnowledgeSourceKind,
  KnowledgeTlp,
} from './types.js';

interface EntityRow {
  id: string;
  entity_type: KnowledgeEntityType;
  modified_at: string;
  source_object_version: string;
  source_connector: string;
  first_projected_at: number;
  payload_json: string;
}

interface RelationshipRow {
  id: string;
  modified_at: string;
  source_object_version: string;
  source_connector: string;
  first_projected_at: number;
  payload_json: string;
}

interface SightingRow {
  id: string;
  modified_at: string;
  source_object_version: string;
  source_connector: string;
  first_projected_at: number;
  payload_json: string;
}

interface ImportedStixRow {
  payload_json: string;
  connector: string;
  last_imported_at: number;
}

interface PendingFactRow {
  id: string;
  fact_type: 'relationship' | 'sighting';
  source_object_version: string;
  source_connector: string;
  payload_json: string;
}

export interface KnowledgePersistResult {
  entities: number;
  relationships: number;
  sightings: number;
  evidence: number;
  skippedRelationships: number;
  skippedSightings: number;
  warnings: KnowledgeProjectionWarning[];
}

export interface KnowledgeEntityQuery {
  types?: KnowledgeEntityType[];
  q?: string;
  includeRevoked?: boolean;
  limit?: number;
  offset?: number;
}

export interface KnowledgeEntityPage {
  entities: KnowledgeEntity[];
  total: number;
  limit: number;
  offset: number;
}

export interface KnowledgeGraph {
  rootId: string;
  depth: number;
  entities: KnowledgeEntity[];
  relationships: KnowledgeRelationshipFact[];
  sightings: KnowledgeSighting[];
}

function emptyPersistResult(warnings: KnowledgeProjectionWarning[] = []): KnowledgePersistResult {
  return {
    entities: 0,
    relationships: 0,
    sightings: 0,
    evidence: 0,
    skippedRelationships: 0,
    skippedSightings: 0,
    warnings,
  };
}

function clampLimit(value: number | undefined, fallback: number, maximum = 1000): number {
  if (!Number.isFinite(value) || (value ?? 0) <= 0) return fallback;
  return Math.min(maximum, Math.max(1, Math.floor(value as number)));
}

function parseJson<T>(value: string): T | null {
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isKnowledgeTlp(value: unknown): value is KnowledgeTlp {
  return value === 'clear' || value === 'green' || value === 'amber' || value === 'red' || value === 'unknown';
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function isKnowledgeSources(value: unknown): value is KnowledgeSource[] {
  return Array.isArray(value) && value.every((item) => isRecord(item) && typeof item.name === 'string');
}

function isKnowledgeExternalReferences(value: unknown): value is KnowledgeExternalReference[] {
  return Array.isArray(value) && value.every((item) => isRecord(item) && typeof item.sourceName === 'string');
}

function isKnowledgeEvidence(value: unknown): value is KnowledgeEvidence[] {
  return (
    Array.isArray(value) &&
    value.every(
      (item) =>
        isRecord(item) &&
        typeof item.id === 'string' &&
        typeof item.kind === 'string' &&
        typeof item.summary === 'string' &&
        typeof item.collectedAt === 'string' &&
        isStringArray(item.objectRefs) &&
        isRecord(item.source) &&
        typeof item.source.name === 'string' &&
        (item.tlp === undefined || isKnowledgeTlp(item.tlp)),
    )
  );
}

const KNOWLEDGE_RELATIONSHIP_TYPES: ReadonlySet<string> = new Set<KnowledgeRelationshipType>([
  'attributed-to',
  'sponsored-by',
  'uses',
  'targets',
  'exploits',
  'indicates',
  'impersonates',
  'compromises',
  'owns',
  'hosts',
  'controls',
  'delivers',
  'downloads',
  'drops',
  'communicates-with',
  'consists-of',
  'related-to',
]);

function parseKnowledgeEntity(value: string): KnowledgeEntity | null {
  const entity = parseJson<unknown>(value);
  if (
    !isRecord(entity) ||
    typeof entity.id !== 'string' ||
    typeof entity.type !== 'string' ||
    !isKnowledgeEntityType(entity.type) ||
    typeof entity.name !== 'string' ||
    !isKnowledgeTlp(entity.tlp) ||
    !isStringArray(entity.aliases) ||
    !isStringArray(entity.objectMarkingRefs) ||
    !isKnowledgeSources(entity.sources) ||
    !isKnowledgeExternalReferences(entity.externalReferences) ||
    !isKnowledgeEvidence(entity.evidence) ||
    typeof entity.stixVersion !== 'string' ||
    typeof entity.createdAt !== 'string' ||
    typeof entity.modifiedAt !== 'string'
  ) {
    return null;
  }
  return entity as unknown as KnowledgeEntity;
}

function parseKnowledgeRelationship(value: string): KnowledgeRelationshipFact | null {
  const relationship = parseJson<unknown>(value);
  if (
    !isRecord(relationship) ||
    typeof relationship.id !== 'string' ||
    typeof relationship.relationshipType !== 'string' ||
    !KNOWLEDGE_RELATIONSHIP_TYPES.has(relationship.relationshipType) ||
    typeof relationship.sourceRef !== 'string' ||
    typeof relationship.targetRef !== 'string' ||
    !isKnowledgeTlp(relationship.tlp) ||
    !isStringArray(relationship.objectMarkingRefs) ||
    !isKnowledgeSources(relationship.sources) ||
    !isKnowledgeExternalReferences(relationship.externalReferences) ||
    !isKnowledgeEvidence(relationship.evidence) ||
    typeof relationship.stixVersion !== 'string' ||
    typeof relationship.createdAt !== 'string' ||
    typeof relationship.modifiedAt !== 'string'
  ) {
    return null;
  }
  return relationship as unknown as KnowledgeRelationshipFact;
}

function parseKnowledgeSighting(value: string): KnowledgeSighting | null {
  const sighting = parseJson<unknown>(value);
  if (
    !isRecord(sighting) ||
    typeof sighting.id !== 'string' ||
    typeof sighting.entityRef !== 'string' ||
    typeof sighting.firstSeen !== 'string' ||
    typeof sighting.lastSeen !== 'string' ||
    typeof sighting.count !== 'number' ||
    !isKnowledgeTlp(sighting.tlp) ||
    !isStringArray(sighting.objectMarkingRefs) ||
    !isKnowledgeSources(sighting.sources) ||
    !isKnowledgeExternalReferences(sighting.externalReferences) ||
    !isKnowledgeEvidence(sighting.evidence) ||
    typeof sighting.stixVersion !== 'string' ||
    typeof sighting.createdAt !== 'string' ||
    typeof sighting.modifiedAt !== 'string'
  ) {
    return null;
  }
  return sighting as unknown as KnowledgeSighting;
}

function versionTime(value: { modifiedAt: string; stixVersion: string }): number {
  const modified = Date.parse(value.modifiedAt);
  if (Number.isFinite(modified)) return modified;
  const version = Date.parse(value.stixVersion);
  return Number.isFinite(version) ? version : 0;
}

function sourceKey(source: KnowledgeSource): string {
  return [source.kind, source.name, source.externalId ?? '', source.url ?? ''].join('\u0000');
}

function connectorSourceKind(connector: string): KnowledgeSourceKind {
  const normalized = connector.toLowerCase();
  if (normalized.includes('taxii')) return 'taxii';
  if (normalized.includes('misp')) return 'misp';
  return 'stix';
}

function referenceKey(reference: KnowledgeExternalReference): string {
  return [reference.sourceName, reference.externalId ?? '', reference.url ?? '', reference.description ?? ''].join(
    '\u0000',
  );
}

function evidenceKey(evidence: KnowledgeEvidence): string {
  return [evidence.id, sourceKey(evidence.source), evidence.reference ?? ''].join('\u0000');
}

const KNOWLEDGE_TLP_RANK: Readonly<Record<KnowledgeTlp, number>> = {
  clear: 0,
  green: 1,
  amber: 2,
  red: 3,
  unknown: 4,
};

function effectiveKnowledgeTlp(
  recordTlps: readonly KnowledgeTlp[],
  evidenceItems: readonly KnowledgeEvidence[],
): KnowledgeTlp {
  let result: KnowledgeTlp = 'clear';
  for (const tlp of [...recordTlps, ...evidenceItems.map((evidence) => evidence.tlp ?? 'unknown')]) {
    if (KNOWLEDGE_TLP_RANK[tlp] > KNOWLEDGE_TLP_RANK[result]) result = tlp;
  }
  return result;
}

function mergeUnique<T>(first: readonly T[], second: readonly T[], key: (value: T) => string): T[] {
  const merged = new Map<string, T>();
  for (const value of [...first, ...second]) merged.set(key(value), value);
  return Array.from(merged.values());
}

function mergeEntity(existing: KnowledgeEntity | null, candidate: KnowledgeEntity): KnowledgeEntity {
  if (!existing) {
    return {
      ...candidate,
      aliases: normalizeKnowledgeAliases(candidate.name, candidate.aliases),
      tlp: effectiveKnowledgeTlp([candidate.tlp], candidate.evidence),
    };
  }
  const candidateWins = versionTime(candidate) >= versionTime(existing);
  const primary = candidateWins ? candidate : existing;
  const evidence = mergeUnique(existing.evidence, candidate.evidence, evidenceKey);
  return {
    ...primary,
    aliases: normalizeKnowledgeAliases(
      primary.name,
      mergeUnique(existing.aliases, candidate.aliases, canonicalizeKnowledgeName),
    ),
    externalReferences: mergeUnique(existing.externalReferences, candidate.externalReferences, referenceKey),
    sources: mergeUnique(existing.sources, candidate.sources, sourceKey),
    objectMarkingRefs: mergeUnique(existing.objectMarkingRefs, candidate.objectMarkingRefs, (value) => value),
    // Sources and external references have no item-level TLP, so the merged
    // record must retain the strictest classification of every contributor.
    tlp: effectiveKnowledgeTlp([existing.tlp, candidate.tlp], evidence),
    evidence,
  };
}

function mergeRelationship(
  existing: KnowledgeRelationshipFact | null,
  candidate: KnowledgeRelationshipFact,
): KnowledgeRelationshipFact {
  if (!existing) {
    return { ...candidate, tlp: effectiveKnowledgeTlp([candidate.tlp], candidate.evidence) };
  }
  const primary = versionTime(candidate) >= versionTime(existing) ? candidate : existing;
  const evidence = mergeUnique(existing.evidence, candidate.evidence, evidenceKey);
  return {
    ...primary,
    externalReferences: mergeUnique(existing.externalReferences, candidate.externalReferences, referenceKey),
    sources: mergeUnique(existing.sources, candidate.sources, sourceKey),
    objectMarkingRefs: mergeUnique(existing.objectMarkingRefs, candidate.objectMarkingRefs, (value) => value),
    tlp: effectiveKnowledgeTlp([existing.tlp, candidate.tlp], evidence),
    evidence,
  };
}

function mergeSighting(existing: KnowledgeSighting | null, candidate: KnowledgeSighting): KnowledgeSighting {
  if (!existing) {
    return { ...candidate, tlp: effectiveKnowledgeTlp([candidate.tlp], candidate.evidence) };
  }
  const primary = versionTime(candidate) >= versionTime(existing) ? candidate : existing;
  const evidence = mergeUnique(existing.evidence, candidate.evidence, evidenceKey);
  return {
    ...primary,
    externalReferences: mergeUnique(existing.externalReferences, candidate.externalReferences, referenceKey),
    sources: mergeUnique(existing.sources, candidate.sources, sourceKey),
    objectMarkingRefs: mergeUnique(existing.objectMarkingRefs, candidate.objectMarkingRefs, (value) => value),
    tlp: effectiveKnowledgeTlp([existing.tlp, candidate.tlp], evidence),
    evidence,
  };
}

function deterministicEvidenceId(
  evidence: KnowledgeEvidence,
  subjectType: 'entity' | 'relationship',
  subjectId: string,
  connector: string,
): string {
  const digest = crypto
    .createHash('sha256')
    .update([evidence.id, subjectType, subjectId, connector, sourceKey(evidence.source)].join('\u0000'))
    .digest('hex');
  return `evidence--${digest.slice(0, 32)}`;
}

function persistEvidence(
  database: SqliteDatabase,
  evidenceItems: readonly KnowledgeEvidence[],
  subjectType: 'entity' | 'relationship',
  subjectId: string,
  sourceObjectId: string,
  sourceObjectVersion: string,
  connector: string,
  now: number,
): number {
  const insert = database.prepare(`
    INSERT INTO knowledge_evidence (
      id, entity_id, relationship_id, evidence_kind, source_name, source_url,
      source_object_id, source_object_version, source_connector, summary,
      confidence, tlp, observed_at, collected_at, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      summary = excluded.summary,
      confidence = excluded.confidence,
      tlp = excluded.tlp,
      observed_at = excluded.observed_at,
      collected_at = excluded.collected_at
  `);
  let persisted = 0;
  for (const evidence of evidenceItems) {
    insert.run(
      deterministicEvidenceId(evidence, subjectType, subjectId, connector),
      subjectType === 'entity' ? subjectId : null,
      subjectType === 'relationship' ? subjectId : null,
      evidence.kind,
      evidence.source.name,
      evidence.reference ?? evidence.source.url ?? null,
      sourceObjectId,
      sourceObjectVersion,
      connector,
      evidence.summary,
      evidence.confidence ?? null,
      evidence.tlp ?? 'unknown',
      evidence.observedAt ?? null,
      evidence.collectedAt,
      now,
    );
    persisted += 1;
  }
  return persisted;
}

function persistEntity(
  database: SqliteDatabase,
  candidate: KnowledgeEntity,
  connector: string,
  now: number,
): { persisted: number; evidence: number } {
  const existingRow = database
    .prepare(`
      SELECT id, entity_type, modified_at, source_object_version, source_connector,
             first_projected_at, payload_json
      FROM knowledge_entities WHERE id = ?
    `)
    .get(candidate.id) as EntityRow | undefined;
  const existing = existingRow ? parseKnowledgeEntity(existingRow.payload_json) : null;
  const entity = mergeEntity(existing, candidate);
  const candidateWins = !existing || versionTime(candidate) >= versionTime(existing);
  const sourceConnector = candidateWins ? connector : (existingRow?.source_connector ?? connector);
  const firstProjectedAt = existingRow?.first_projected_at ?? now;

  database
    .prepare(`
      INSERT INTO knowledge_entities (
        id, entity_type, name, normalized_name, description, confidence, tlp,
        valid_from, valid_until, revoked, source_object_id, source_object_version,
        source_connector, payload_json, created_at, modified_at,
        first_projected_at, last_projected_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        entity_type = excluded.entity_type,
        name = excluded.name,
        normalized_name = excluded.normalized_name,
        description = excluded.description,
        confidence = excluded.confidence,
        tlp = excluded.tlp,
        valid_from = excluded.valid_from,
        valid_until = excluded.valid_until,
        revoked = excluded.revoked,
        source_object_id = excluded.source_object_id,
        source_object_version = excluded.source_object_version,
        source_connector = excluded.source_connector,
        payload_json = excluded.payload_json,
        created_at = excluded.created_at,
        modified_at = excluded.modified_at,
        last_projected_at = excluded.last_projected_at
    `)
    .run(
      entity.id,
      entity.type,
      entity.name,
      canonicalizeKnowledgeName(entity.name),
      entity.description ?? '',
      entity.confidence ?? null,
      entity.tlp,
      entity.validFrom ?? null,
      entity.validUntil ?? null,
      entity.revoked ? 1 : 0,
      entity.id,
      entity.stixVersion,
      sourceConnector,
      JSON.stringify(entity),
      entity.createdAt,
      entity.modifiedAt,
      firstProjectedAt,
      now,
    );

  const aliasInsert = database.prepare(`
    INSERT OR IGNORE INTO knowledge_aliases (
      entity_id, alias, normalized_alias, source_object_id,
      source_object_version, source_connector, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  for (const alias of normalizeKnowledgeAliases(entity.name, candidate.aliases)) {
    aliasInsert.run(
      entity.id,
      alias,
      canonicalizeKnowledgeName(alias),
      candidate.id,
      candidate.stixVersion,
      connector,
      now,
    );
  }

  const refInsert = database.prepare(`
    INSERT OR IGNORE INTO knowledge_external_refs (
      entity_id, source_name, external_id, url, description, source_object_id,
      source_object_version, source_connector
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const reference of candidate.externalReferences) {
    refInsert.run(
      entity.id,
      reference.sourceName,
      reference.externalId ?? '',
      reference.url ?? '',
      reference.description ?? '',
      candidate.id,
      candidate.stixVersion,
      connector,
    );
  }

  return {
    persisted: 1,
    evidence: persistEvidence(
      database,
      candidate.evidence,
      'entity',
      entity.id,
      candidate.id,
      candidate.stixVersion,
      connector,
      now,
    ),
  };
}

function entityTypesById(database: SqliteDatabase): Map<string, KnowledgeEntityType> {
  const rows = database.prepare('SELECT id, entity_type FROM knowledge_entities').all() as Array<{
    id: string;
    entity_type: KnowledgeEntityType;
  }>;
  return new Map(rows.map((row) => [row.id, row.entity_type]));
}

function persistRelationship(
  database: SqliteDatabase,
  candidate: KnowledgeRelationshipFact,
  connector: string,
  now: number,
  typeById: ReadonlyMap<string, KnowledgeEntityType>,
): { persisted: number; evidence: number } | null {
  const sourceType = typeById.get(candidate.sourceRef);
  const targetType = typeById.get(candidate.targetRef);
  if (!sourceType || !targetType) return null;
  if (!validateKnowledgeRelationship(candidate, sourceType, targetType).allowed) return null;

  const existingRow = database
    .prepare(`
      SELECT id, modified_at, source_object_version, source_connector,
             first_projected_at, payload_json
      FROM knowledge_relationships WHERE id = ?
    `)
    .get(candidate.id) as RelationshipRow | undefined;
  const existing = existingRow ? parseKnowledgeRelationship(existingRow.payload_json) : null;
  const relationship = mergeRelationship(existing, candidate);
  const candidateWins = !existing || versionTime(candidate) >= versionTime(existing);
  const sourceConnector = candidateWins ? connector : (existingRow?.source_connector ?? connector);

  database
    .prepare(`
      INSERT INTO knowledge_relationships (
        id, relationship_type, source_entity_id, target_entity_id, assertion_status,
        description, confidence, tlp, valid_from, valid_until, revoked,
        source_object_id, source_object_version, source_connector, payload_json,
        created_at, modified_at, first_projected_at, last_projected_at
      ) VALUES (?, ?, ?, ?, 'reported', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        relationship_type = excluded.relationship_type,
        source_entity_id = excluded.source_entity_id,
        target_entity_id = excluded.target_entity_id,
        description = excluded.description,
        confidence = excluded.confidence,
        tlp = excluded.tlp,
        valid_from = excluded.valid_from,
        valid_until = excluded.valid_until,
        revoked = excluded.revoked,
        source_object_id = excluded.source_object_id,
        source_object_version = excluded.source_object_version,
        source_connector = excluded.source_connector,
        payload_json = excluded.payload_json,
        created_at = excluded.created_at,
        modified_at = excluded.modified_at,
        last_projected_at = excluded.last_projected_at
    `)
    .run(
      relationship.id,
      relationship.relationshipType,
      relationship.sourceRef,
      relationship.targetRef,
      relationship.description ?? '',
      relationship.confidence ?? null,
      relationship.tlp,
      relationship.validFrom ?? null,
      relationship.validUntil ?? null,
      relationship.revoked ? 1 : 0,
      relationship.id,
      relationship.stixVersion,
      sourceConnector,
      JSON.stringify(relationship),
      relationship.createdAt,
      relationship.modifiedAt,
      existingRow?.first_projected_at ?? now,
      now,
    );

  return {
    persisted: 1,
    evidence: persistEvidence(
      database,
      candidate.evidence,
      'relationship',
      relationship.id,
      candidate.id,
      candidate.stixVersion,
      connector,
      now,
    ),
  };
}

function persistSighting(
  database: SqliteDatabase,
  candidate: KnowledgeSighting,
  connector: string,
  now: number,
  typeById: ReadonlyMap<string, KnowledgeEntityType>,
): number {
  if (!typeById.has(candidate.entityRef)) return 0;
  const existingRow = database
    .prepare(`
      SELECT id, modified_at, source_object_version, source_connector,
             first_projected_at, payload_json
      FROM knowledge_sightings WHERE id = ?
    `)
    .get(candidate.id) as SightingRow | undefined;
  const existing = existingRow ? parseKnowledgeSighting(existingRow.payload_json) : null;
  const sighting = mergeSighting(existing, candidate);
  const candidateWins = !existing || versionTime(candidate) >= versionTime(existing);

  database
    .prepare(`
      INSERT INTO knowledge_sightings (
        id, entity_id, indicator_ref, first_seen, last_seen, observation_count,
        confidence, tlp, where_sighted_refs_json, observed_data_refs_json,
        source_object_id, source_object_version, source_connector, payload_json,
        created_at, modified_at, first_projected_at, last_projected_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        entity_id = excluded.entity_id,
        indicator_ref = excluded.indicator_ref,
        first_seen = excluded.first_seen,
        last_seen = excluded.last_seen,
        observation_count = excluded.observation_count,
        confidence = excluded.confidence,
        tlp = excluded.tlp,
        where_sighted_refs_json = excluded.where_sighted_refs_json,
        observed_data_refs_json = excluded.observed_data_refs_json,
        source_object_id = excluded.source_object_id,
        source_object_version = excluded.source_object_version,
        source_connector = excluded.source_connector,
        payload_json = excluded.payload_json,
        created_at = excluded.created_at,
        modified_at = excluded.modified_at,
        last_projected_at = excluded.last_projected_at
    `)
    .run(
      sighting.id,
      sighting.entityRef,
      sighting.indicatorRef ?? null,
      sighting.firstSeen,
      sighting.lastSeen,
      sighting.count,
      sighting.confidence ?? null,
      sighting.tlp,
      '[]',
      '[]',
      sighting.id,
      sighting.stixVersion,
      candidateWins ? connector : (existingRow?.source_connector ?? connector),
      JSON.stringify(sighting),
      sighting.createdAt,
      sighting.modifiedAt,
      existingRow?.first_projected_at ?? now,
      now,
    );
  return 1;
}

function deferKnowledgeFact(
  database: SqliteDatabase,
  factType: PendingFactRow['fact_type'],
  fact: KnowledgeRelationshipFact | KnowledgeSighting,
  connector: string,
  now: number,
): void {
  database
    .prepare(`
      INSERT INTO knowledge_pending_facts (
        id, fact_type, source_object_version, source_connector, payload_json,
        first_deferred_at, last_attempted_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id, source_object_version, source_connector) DO UPDATE SET
        payload_json = excluded.payload_json,
        last_attempted_at = excluded.last_attempted_at
    `)
    .run(fact.id, factType, fact.stixVersion, connector, JSON.stringify(fact), now, now);
}

function removePendingFact(
  database: SqliteDatabase,
  id: string,
  version: string,
  connector: string,
): void {
  database
    .prepare(`
      DELETE FROM knowledge_pending_facts
      WHERE id = ? AND source_object_version = ? AND source_connector = ?
    `)
    .run(id, version, connector);
}

function retryPendingFacts(
  database: SqliteDatabase,
  typeById: ReadonlyMap<string, KnowledgeEntityType>,
  now: number,
  result: KnowledgePersistResult,
): void {
  const rows = database
    .prepare(`
      SELECT id, fact_type, source_object_version, source_connector, payload_json
      FROM knowledge_pending_facts
      ORDER BY first_deferred_at, id
    `)
    .all() as PendingFactRow[];
  const touch = database.prepare(`
    UPDATE knowledge_pending_facts SET last_attempted_at = ?
    WHERE id = ? AND source_object_version = ? AND source_connector = ?
  `);

  for (const row of rows) {
    if (row.fact_type === 'relationship') {
      const relationship = parseKnowledgeRelationship(row.payload_json);
      if (!relationship || relationship.id !== row.id || relationship.stixVersion !== row.source_object_version) {
        removePendingFact(database, row.id, row.source_object_version, row.source_connector);
        continue;
      }
      if (!knowledgeEntityTypeFromId(relationship.sourceRef) || !knowledgeEntityTypeFromId(relationship.targetRef)) {
        removePendingFact(database, row.id, row.source_object_version, row.source_connector);
        continue;
      }
      if (!typeById.has(relationship.sourceRef) || !typeById.has(relationship.targetRef)) {
        touch.run(now, row.id, row.source_object_version, row.source_connector);
        continue;
      }
      const persisted = persistRelationship(database, relationship, row.source_connector, now, typeById);
      removePendingFact(database, row.id, row.source_object_version, row.source_connector);
      if (!persisted) continue;
      result.relationships += persisted.persisted;
      result.evidence += persisted.evidence;
      continue;
    }

    const sighting = parseKnowledgeSighting(row.payload_json);
    if (!sighting || sighting.id !== row.id || sighting.stixVersion !== row.source_object_version) {
      removePendingFact(database, row.id, row.source_object_version, row.source_connector);
      continue;
    }
    if (!knowledgeEntityTypeFromId(sighting.entityRef)) {
      removePendingFact(database, row.id, row.source_object_version, row.source_connector);
      continue;
    }
    if (!typeById.has(sighting.entityRef)) {
      touch.run(now, row.id, row.source_object_version, row.source_connector);
      continue;
    }
    result.sightings += persistSighting(database, sighting, row.source_connector, now, typeById);
    removePendingFact(database, row.id, row.source_object_version, row.source_connector);
  }
}

function persistKnowledgeProjectionWithoutTransaction(
  database: SqliteDatabase,
  projection: KnowledgeProjection,
  connector: string,
  now: number,
): KnowledgePersistResult {
  const result = emptyPersistResult([...projection.warnings]);
  result.skippedRelationships = projection.warnings.filter(
    (warning) => warning.code === 'unsupported-relationship',
  ).length;
  for (const entity of projection.entities) {
    const persisted = persistEntity(database, entity, connector, now);
    result.entities += persisted.persisted;
    result.evidence += persisted.evidence;
  }

  const typeById = entityTypesById(database);
  for (const relationship of projection.relationships) {
    if (!knowledgeEntityTypeFromId(relationship.sourceRef) || !knowledgeEntityTypeFromId(relationship.targetRef)) {
      result.skippedRelationships += 1;
      continue;
    }
    if (!typeById.has(relationship.sourceRef) || !typeById.has(relationship.targetRef)) {
      deferKnowledgeFact(database, 'relationship', relationship, connector, now);
      result.skippedRelationships += 1;
      continue;
    }
    const persisted = persistRelationship(database, relationship, connector, now, typeById);
    if (!persisted) {
      removePendingFact(database, relationship.id, relationship.stixVersion, connector);
      result.skippedRelationships += 1;
      continue;
    }
    removePendingFact(database, relationship.id, relationship.stixVersion, connector);
    result.relationships += persisted.persisted;
    result.evidence += persisted.evidence;
  }
  for (const sighting of projection.sightings) {
    if (!knowledgeEntityTypeFromId(sighting.entityRef)) {
      result.skippedSightings += 1;
      continue;
    }
    if (!typeById.has(sighting.entityRef)) {
      deferKnowledgeFact(database, 'sighting', sighting, connector, now);
      result.skippedSightings += 1;
      continue;
    }
    const persisted = persistSighting(database, sighting, connector, now, typeById);
    removePendingFact(database, sighting.id, sighting.stixVersion, connector);
    result.sightings += persisted;
  }
  retryPendingFacts(database, typeById, now, result);
  return result;
}

export function persistKnowledgeProjection(
  database: SqliteDatabase,
  projection: KnowledgeProjection,
  connector: string,
  now = Date.now(),
): KnowledgePersistResult {
  return withTransaction(database, () =>
    persistKnowledgeProjectionWithoutTransaction(database, projection, connector, now),
  );
}

export function persistKnowledgeProjectionInOpenTransaction(
  database: SqliteDatabase,
  projection: KnowledgeProjection,
  connector: string,
  now = Date.now(),
): KnowledgePersistResult {
  return persistKnowledgeProjectionWithoutTransaction(database, projection, connector, now);
}

export function projectAndPersistKnowledgeObjectsInOpenTransaction(
  database: SqliteDatabase,
  objects: readonly unknown[],
  connector: string,
  now = Date.now(),
): KnowledgePersistResult {
  const types = entityTypesById(database);
  const projection = projectStixObjects(objects, {
    projectedAt: new Date(now),
    source: { name: connector, kind: connectorSourceKind(connector) },
    knownObjectIds: types.keys(),
    knownEntityTypes: types,
  });
  return persistKnowledgeProjectionWithoutTransaction(database, projection, connector, now);
}

export function projectAndPersistKnowledgeObjects(
  database: SqliteDatabase,
  objects: readonly unknown[],
  connector: string,
  now = Date.now(),
): KnowledgePersistResult {
  return withTransaction(database, () =>
    projectAndPersistKnowledgeObjectsInOpenTransaction(database, objects, connector, now),
  );
}

export function backfillKnowledgeProjection(database: SqliteDatabase): KnowledgePersistResult {
  const rows = database
    .prepare(`
      SELECT o.payload_json, COALESCE(s.connector, o.connector) AS connector,
             COALESCE(s.last_imported_at, o.last_imported_at) AS last_imported_at
      FROM imported_stix_objects o
      LEFT JOIN imported_stix_sources s
        ON s.object_id = o.object_id AND s.version = o.version
      LEFT JOIN imported_stix_payloads p
        ON p.object_id = s.object_id AND p.version = s.version AND p.connector = s.connector
      WHERE p.payload_json IS NULL OR p.payload_json = o.payload_json
      ORDER BY COALESCE(s.last_imported_at, o.last_imported_at), o.object_id, o.version
    `)
    .all() as ImportedStixRow[];
  const result = emptyPersistResult();
  if (rows.length === 0) return result;

  const entityObjectsByConnector = new Map<string, unknown[]>();
  const deferredObjectsByConnector = new Map<string, unknown[]>();
  for (const row of rows) {
    const object = parseJson<unknown>(row.payload_json);
    if (!object || typeof object !== 'object' || Array.isArray(object)) {
      result.warnings.push({ code: 'invalid-object', message: 'Stored STIX payload is not valid JSON.' });
      continue;
    }
    const type = typeof (object as { type?: unknown }).type === 'string' ? (object as { type: string }).type : '';
    const destination = isKnowledgeEntityType(type) ? entityObjectsByConnector : deferredObjectsByConnector;
    const objects = destination.get(row.connector) ?? [];
    objects.push(object);
    destination.set(row.connector, objects);
  }

  return withTransaction(database, () => {
    // Raw STIX is authoritative during a full replay. Rebuild the live pending
    // set from that archive instead of retrying stale normalized candidates.
    database.exec('DELETE FROM knowledge_pending_facts');
    const applyBatch = (connector: string, objects: unknown[]): void => {
        const partial = projectAndPersistKnowledgeObjectsInOpenTransaction(database, objects, connector);
        result.entities += partial.entities;
        result.relationships += partial.relationships;
        result.sightings += partial.sightings;
        result.evidence += partial.evidence;
        result.skippedRelationships += partial.skippedRelationships;
        result.skippedSightings += partial.skippedSightings;
        result.warnings.push(...partial.warnings);
    };
    for (const [connector, objects] of entityObjectsByConnector) applyBatch(connector, objects);
    for (const [connector, objects] of deferredObjectsByConnector) applyBatch(connector, objects);
    return result;
  });
}

function placeholders(values: readonly unknown[]): string {
  return values.map(() => '?').join(',');
}

function escapeLikePattern(value: string): string {
  return value.replace(/[!%_]/g, (character) => `!${character}`);
}

function entityVisibilityClause(role: ApiRole): { sql: string; params: KnowledgeTlp[] } {
  const tlp = allowedKnowledgeTlpValues(role);
  return { sql: `tlp IN (${placeholders(tlp)})`, params: tlp };
}

function evidenceForRole(evidence: readonly KnowledgeEvidence[], role: ApiRole): KnowledgeEvidence[] {
  return evidence.filter((item) => isKnowledgeTlpAllowed(item.tlp ?? 'unknown', role));
}

function entityForRole(entity: KnowledgeEntity, role: ApiRole): KnowledgeEntity {
  return { ...entity, evidence: evidenceForRole(entity.evidence, role) };
}

function relationshipForRole(
  relationship: KnowledgeRelationshipFact,
  role: ApiRole,
): KnowledgeRelationshipFact {
  return { ...relationship, evidence: evidenceForRole(relationship.evidence, role) };
}

function sightingForRole(sighting: KnowledgeSighting, role: ApiRole): KnowledgeSighting {
  return { ...sighting, evidence: evidenceForRole(sighting.evidence, role) };
}

export function listKnowledgeEntities(
  database: SqliteDatabase,
  role: ApiRole,
  query: KnowledgeEntityQuery = {},
): KnowledgeEntityPage {
  const visibility = entityVisibilityClause(role);
  const where: string[] = [visibility.sql];
  const params: unknown[] = [...visibility.params];
  if (!query.includeRevoked) where.push('revoked = 0');
  if (query.types && query.types.length > 0) {
    where.push(`entity_type IN (${placeholders(query.types)})`);
    params.push(...query.types);
  }
  const normalizedQuery = query.q ? canonicalizeKnowledgeName(query.q) : '';
  if (normalizedQuery) {
    where.push(`(
      normalized_name LIKE ? ESCAPE '!' OR EXISTS (
        SELECT 1 FROM knowledge_aliases a
        WHERE a.entity_id = knowledge_entities.id AND a.normalized_alias LIKE ? ESCAPE '!'
      ) OR EXISTS (
        SELECT 1 FROM knowledge_external_refs r
        WHERE r.entity_id = knowledge_entities.id AND lower(r.external_id) LIKE ? ESCAPE '!'
      )
    )`);
    const pattern = `%${escapeLikePattern(normalizedQuery)}%`;
    params.push(pattern, pattern, pattern);
  }
  const clause = where.join(' AND ');
  const totalRow = database.prepare(`SELECT COUNT(*) AS count FROM knowledge_entities WHERE ${clause}`).get(...params) as
    | { count: number }
    | undefined;
  const limit = clampLimit(query.limit, 100);
  const offset = Math.max(0, Math.floor(query.offset ?? 0));
  const rows = database
    .prepare(`
      SELECT id, entity_type, tlp, payload_json FROM knowledge_entities
      WHERE ${clause}
      ORDER BY entity_type, normalized_name, id
      LIMIT ? OFFSET ?
    `)
    .all(...params, limit, offset) as Array<{
      id: string;
      entity_type: KnowledgeEntityType;
      tlp: KnowledgeTlp;
      payload_json: string;
    }>;
  const entities = rows
    .map((row) => {
      const entity = parseKnowledgeEntity(row.payload_json);
      return entity && entity.id === row.id && entity.type === row.entity_type && entity.tlp === row.tlp ? entity : null;
    })
    .filter((value): value is KnowledgeEntity => Boolean(value))
    .map((entity) => entityForRole(entity, role));
  return {
    entities,
    total: totalRow?.count ?? 0,
    limit,
    offset,
  };
}

export function getKnowledgeEntity(
  database: SqliteDatabase,
  role: ApiRole,
  id: string,
): KnowledgeEntity | null {
  const visibility = entityVisibilityClause(role);
  const row = database
    .prepare(`SELECT id, entity_type, tlp, payload_json FROM knowledge_entities WHERE id = ? AND ${visibility.sql}`)
    .get(id, ...visibility.params) as
    | { id: string; entity_type: KnowledgeEntityType; tlp: KnowledgeTlp; payload_json: string }
    | undefined;
  if (!row) return null;
  const entity = parseKnowledgeEntity(row.payload_json);
  return entity && entity.id === row.id && entity.type === row.entity_type && entity.tlp === row.tlp
    ? entityForRole(entity, role)
    : null;
}

export function getKnowledgeGraph(
  database: SqliteDatabase,
  role: ApiRole,
  rootId: string,
  requestedDepth = 1,
): KnowledgeGraph | null {
  if (!getKnowledgeEntity(database, role, rootId)) return null;
  const depth = Math.min(3, Math.max(0, Math.floor(requestedDepth)));
  const allowedTlp = allowedKnowledgeTlpValues(role);
  const selected = new Set<string>([rootId]);
  const relationshipById = new Map<string, KnowledgeRelationshipFact>();
  let frontier = new Set<string>([rootId]);

  for (let level = 0; level < depth; level += 1) {
    const frontierIds = Array.from(frontier);
    const rows = database
      .prepare(`
        SELECT r.id, r.source_entity_id, r.target_entity_id, r.tlp, r.payload_json
        FROM knowledge_relationships r
        JOIN knowledge_entities source_entity ON source_entity.id = r.source_entity_id
        JOIN knowledge_entities target_entity ON target_entity.id = r.target_entity_id
        WHERE r.revoked = 0
          AND r.tlp IN (${placeholders(allowedTlp)})
          AND source_entity.tlp IN (${placeholders(allowedTlp)})
          AND target_entity.tlp IN (${placeholders(allowedTlp)})
          AND (
            r.source_entity_id IN (${placeholders(frontierIds)}) OR
            r.target_entity_id IN (${placeholders(frontierIds)})
          )
        ORDER BY r.modified_at DESC LIMIT 2000
      `)
      .all(...allowedTlp, ...allowedTlp, ...allowedTlp, ...frontierIds, ...frontierIds) as Array<{
      id: string;
      source_entity_id: string;
      target_entity_id: string;
      tlp: KnowledgeTlp;
      payload_json: string;
    }>;
    const nextFrontier = new Set<string>();
    for (const row of rows) {
      const relationship = parseKnowledgeRelationship(row.payload_json);
      if (
        !relationship ||
        relationship.id !== row.id ||
        relationship.sourceRef !== row.source_entity_id ||
        relationship.targetRef !== row.target_entity_id ||
        relationship.tlp !== row.tlp
      ) {
        continue;
      }
      relationshipById.set(relationship.id, relationship);
      for (const ref of [row.source_entity_id, row.target_entity_id]) {
        if (selected.has(ref)) continue;
        selected.add(ref);
        nextFrontier.add(ref);
      }
    }
    if (nextFrontier.size === 0) break;
    frontier = nextFrontier;
  }

  const ids = Array.from(selected);
  const entityRows = database
    .prepare(`
      SELECT id, entity_type, tlp, payload_json FROM knowledge_entities
      WHERE id IN (${placeholders(ids)}) AND tlp IN (${placeholders(allowedTlp)})
    `)
    .all(...ids, ...allowedTlp) as Array<{
      id: string;
      entity_type: KnowledgeEntityType;
      tlp: KnowledgeTlp;
      payload_json: string;
    }>;
  const entities = entityRows
    .map((row) => {
      const entity = parseKnowledgeEntity(row.payload_json);
      return entity && entity.id === row.id && entity.type === row.entity_type && entity.tlp === row.tlp ? entity : null;
    })
    .filter((value): value is KnowledgeEntity => Boolean(value))
    .map((entity) => entityForRole(entity, role));
  const visibleIds = new Set(entities.map((entity) => entity.id));
  const relationships = Array.from(relationshipById.values())
    .filter((relationship) => visibleIds.has(relationship.sourceRef) && visibleIds.has(relationship.targetRef))
    .map((relationship) => relationshipForRole(relationship, role));
  const sightingRows = database
    .prepare(`
      SELECT id, entity_id, tlp, payload_json FROM knowledge_sightings
      WHERE entity_id IN (${placeholders(ids)}) AND tlp IN (${placeholders(allowedTlp)})
      ORDER BY last_seen DESC LIMIT 2000
    `)
    .all(...ids, ...allowedTlp) as Array<{
      id: string;
      entity_id: string;
      tlp: KnowledgeTlp;
      payload_json: string;
    }>;
  const sightings = sightingRows
    .map((row) => {
      const sighting = parseKnowledgeSighting(row.payload_json);
      return sighting && sighting.id === row.id && sighting.entityRef === row.entity_id && sighting.tlp === row.tlp
        ? sighting
        : null;
    })
    .filter((value): value is KnowledgeSighting => value !== null && visibleIds.has(value.entityRef))
    .map((sighting) => sightingForRole(sighting, role));
  return { rootId, depth, entities, relationships, sightings };
}

export function knowledgeEntityTypes(): KnowledgeEntityType[] {
  return [
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
}

export function isKnowledgeEntityType(value: string): value is KnowledgeEntityType {
  return knowledgeEntityTypes().includes(value as KnowledgeEntityType);
}

function knowledgeEntityTypeFromId(id: string): KnowledgeEntityType | null {
  const separator = id.indexOf('--');
  if (separator <= 0) return null;
  const type = id.slice(0, separator);
  return isKnowledgeEntityType(type) ? type : null;
}
