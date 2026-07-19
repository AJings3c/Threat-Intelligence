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
  KnowledgeTlp,
} from './types.js';
import { validateKnowledgeRelationship } from './relationshipPolicy.js';

const ENTITY_TYPES: ReadonlySet<string> = new Set<KnowledgeEntityType>([
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
]);

const RELATIONSHIP_TYPES: ReadonlySet<string> = new Set<KnowledgeRelationshipType>([
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

const TLP_MARKING_IDS: Readonly<Record<string, Exclude<KnowledgeTlp, 'unknown'>>> = {
  'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487': 'clear',
  'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da': 'green',
  'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82': 'amber',
  'marking-definition--5e57c739-391a-4eb3-b6e7-5b9acb13fe73': 'red',
};

const TLP_RANK: Readonly<Record<Exclude<KnowledgeTlp, 'unknown'>, number>> = {
  clear: 0,
  green: 1,
  amber: 2,
  red: 3,
};

type StixRecord = Record<string, unknown>;

export interface StixProjectionOptions {
  source?: KnowledgeSource | string;
  projectedAt?: string | Date;
  /** IDs already present in the repository, used to avoid false unresolved-reference warnings. */
  knownObjectIds?: Iterable<string>;
  /** Typed entities already present in the repository, used for relationship policy validation. */
  knownEntityTypes?: ReadonlyMap<string, KnowledgeEntityType>;
}

interface ProjectionContext {
  projectedAt: string;
  source?: KnowledgeSource;
}

function asRecord(value: unknown): StixRecord | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as StixRecord)
    : null;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

function stringValues(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const result: string[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    const text = stringValue(item);
    if (!text || seen.has(text)) continue;
    seen.add(text);
    result.push(text);
  }
  return result;
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function normalizedTimestamp(value: string | Date | undefined): string {
  const parsed = value instanceof Date ? value : value ? new Date(value) : new Date();
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function projectionOptions(options: StixProjectionOptions | string): ProjectionContext & {
  knownObjectIds: Set<string>;
  knownEntityTypes: ReadonlyMap<string, KnowledgeEntityType>;
} {
  const normalized: StixProjectionOptions = typeof options === 'string' ? { source: options } : options;
  const projectedAt = normalizedTimestamp(normalized.projectedAt);
  const source = normalized.source
    ? typeof normalized.source === 'string'
      ? { name: normalized.source, kind: 'stix' as const, collectedAt: projectedAt }
      : { ...normalized.source, collectedAt: normalized.source.collectedAt ?? projectedAt }
    : undefined;
  return {
    projectedAt,
    source,
    knownObjectIds: new Set([
      ...(normalized.knownObjectIds ?? []),
      ...(normalized.knownEntityTypes?.keys() ?? []),
    ]),
    knownEntityTypes: normalized.knownEntityTypes ?? new Map<string, KnowledgeEntityType>(),
  };
}

function validBaseObject(object: StixRecord): { id: string; type: string } | null {
  const id = stringValue(object.id);
  const type = stringValue(object.type);
  if (!id || !type || !id.startsWith(`${type}--`)) return null;
  return { id, type };
}

function externalReferences(object: StixRecord): KnowledgeExternalReference[] {
  if (!Array.isArray(object.external_references)) return [];
  const references: KnowledgeExternalReference[] = [];
  for (const value of object.external_references) {
    const reference = asRecord(value);
    if (!reference) continue;
    const sourceName = stringValue(reference.source_name);
    if (!sourceName) continue;
    references.push({
      sourceName,
      externalId: stringValue(reference.external_id),
      url: stringValue(reference.url),
      description: stringValue(reference.description),
    });
  }
  return references;
}

function confidence(object: StixRecord): number | undefined {
  const value = finiteNumber(object.confidence);
  return value !== undefined && value >= 0 && value <= 100 ? value : undefined;
}

function objectMarkingRefs(object: StixRecord): string[] {
  return stringValues(object.object_marking_refs);
}

function explicitTlp(object: StixRecord): Exclude<KnowledgeTlp, 'unknown'> | undefined {
  const value = stringValue(object.x_threat_intel_tlp)?.toLowerCase();
  return value === 'clear' || value === 'green' || value === 'amber' || value === 'red' ? value : undefined;
}

function tlp(object: StixRecord): KnowledgeTlp {
  const markings = objectMarkingRefs(object);
  const values = markings
    .map((id) => TLP_MARKING_IDS[id])
    .filter((value): value is Exclude<KnowledgeTlp, 'unknown'> => Boolean(value));
  const stated = explicitTlp(object);
  if (stated) values.push(stated);
  if (values.length > 0) {
    return values.reduce((mostRestrictive, value) =>
      TLP_RANK[value] > TLP_RANK[mostRestrictive] ? value : mostRestrictive,
    );
  }
  return 'unknown';
}

function sourceReliability(object: StixRecord): KnowledgeSource['reliability'] {
  const value = stringValue(object.x_threat_intel_source_reliability);
  return value === 'A' || value === 'B' || value === 'C' || value === 'D' || value === 'E' || value === 'F'
    ? value
    : undefined;
}

function sources(object: StixRecord, context: ProjectionContext): KnowledgeSource[] {
  const result: KnowledgeSource[] = [];
  const seen = new Set<string>();
  const add = (source: KnowledgeSource): void => {
    const key = `${source.kind}\u0000${source.externalId ?? ''}\u0000${source.name}`;
    if (seen.has(key)) return;
    seen.add(key);
    result.push(source);
  };

  if (context.source) add(context.source);

  const reliability = sourceReliability(object);
  for (const name of stringValues(object.x_threat_intel_sources)) {
    add({ name, kind: 'feed', reliability, collectedAt: context.projectedAt });
  }

  for (const reference of externalReferences(object)) {
    add({
      name: reference.sourceName,
      kind: 'stix',
      externalId: reference.externalId,
      url: reference.url,
      collectedAt: context.projectedAt,
    });
  }

  const createdByRef = stringValue(object.created_by_ref);
  if (createdByRef) {
    add({ name: createdByRef, kind: 'stix', externalId: createdByRef, collectedAt: context.projectedAt });
  }

  if (result.length === 0) add({ name: 'stix-import', kind: 'stix', collectedAt: context.projectedAt });
  return result;
}

function objectTimes(object: StixRecord, projectedAt: string): {
  createdAt: string;
  modifiedAt: string;
  stixVersion: string;
} {
  const created = stringValue(object.created);
  const modified = stringValue(object.modified);
  const createdAt = created ?? modified ?? projectedAt;
  return {
    createdAt,
    modifiedAt: modified ?? createdAt,
    stixVersion: modified ?? created ?? 'unversioned',
  };
}

function evidence(
  object: StixRecord,
  base: { id: string; type: string },
  objectRefs: string[],
  objectSources: KnowledgeSource[],
  context: ProjectionContext,
  kind: KnowledgeEvidence['kind'],
): KnowledgeEvidence[] {
  const version = objectTimes(object, context.projectedAt).stixVersion;
  const refs = Array.from(new Set([base.id, ...objectRefs]));
  const reference = externalReferences(object).find((value) => value.url)?.url;
  const observedAt =
    stringValue(object.last_seen) ??
    stringValue(object.modified) ??
    stringValue(object.first_seen) ??
    stringValue(object.created);
  return objectSources.map((source, index) => ({
    id: `${base.id}:${version}:${kind}:${index + 1}`,
    kind,
    source,
    summary: `Imported STIX ${base.type} assertion ${base.id}.`,
    reference,
    objectRefs: refs,
    observedAt,
    collectedAt: source.collectedAt ?? context.projectedAt,
    confidence: confidence(object),
    tlp: tlp(object),
  }));
}

function isEntityType(type: string): type is KnowledgeEntityType {
  return ENTITY_TYPES.has(type);
}

function isRelationshipType(type: string): type is KnowledgeRelationshipType {
  return RELATIONSHIP_TYPES.has(type);
}

function projectEntity(object: StixRecord, base: { id: string; type: KnowledgeEntityType }, context: ProjectionContext): KnowledgeEntity | null {
  const name = stringValue(object.name) ?? (base.type === 'indicator' ? stringValue(object.pattern) : undefined);
  if (!name) return null;
  const objectSources = sources(object, context);
  const times = objectTimes(object, context.projectedAt);
  return {
    id: base.id,
    type: base.type,
    name,
    description: stringValue(object.description),
    aliases: stringValues(object.aliases),
    externalReferences: externalReferences(object),
    sources: objectSources,
    confidence: confidence(object),
    tlp: tlp(object),
    validFrom: stringValue(object.first_seen) ?? stringValue(object.valid_from),
    validUntil: stringValue(object.last_seen) ?? stringValue(object.valid_until),
    evidence: evidence(object, base, [], objectSources, context, 'source-assertion'),
    stixVersion: times.stixVersion,
    objectMarkingRefs: objectMarkingRefs(object),
    createdAt: times.createdAt,
    modifiedAt: times.modifiedAt,
    revoked: typeof object.revoked === 'boolean' ? object.revoked : undefined,
  };
}

function projectRelationship(
  object: StixRecord,
  base: { id: string; type: string },
  relationshipType: KnowledgeRelationshipType,
  context: ProjectionContext,
): KnowledgeRelationshipFact | null {
  const sourceRef = stringValue(object.source_ref);
  const targetRef = stringValue(object.target_ref);
  if (!sourceRef || !targetRef) return null;
  const objectSources = sources(object, context);
  const times = objectTimes(object, context.projectedAt);
  return {
    id: base.id,
    relationshipType,
    sourceRef,
    targetRef,
    description: stringValue(object.description),
    sources: objectSources,
    confidence: confidence(object),
    tlp: tlp(object),
    validFrom: stringValue(object.start_time),
    validUntil: stringValue(object.stop_time),
    externalReferences: externalReferences(object),
    evidence: evidence(object, base, [sourceRef, targetRef], objectSources, context, 'source-assertion'),
    stixVersion: times.stixVersion,
    objectMarkingRefs: objectMarkingRefs(object),
    createdAt: times.createdAt,
    modifiedAt: times.modifiedAt,
    revoked: typeof object.revoked === 'boolean' ? object.revoked : undefined,
  };
}

function projectSighting(
  object: StixRecord,
  base: { id: string; type: string },
  context: ProjectionContext,
): KnowledgeSighting | null {
  const entityRef = stringValue(object.sighting_of_ref);
  if (!entityRef) return null;
  const objectSources = sources(object, context);
  const times = objectTimes(object, context.projectedAt);
  const firstSeen = stringValue(object.first_seen) ?? times.createdAt;
  const count = finiteNumber(object.count);
  const supportingRefs = [...stringValues(object.observed_data_refs), ...stringValues(object.where_sighted_refs)];
  return {
    id: base.id,
    entityRef,
    indicatorRef: entityRef.startsWith('indicator--') ? entityRef : undefined,
    firstSeen,
    lastSeen: stringValue(object.last_seen) ?? firstSeen,
    count: count !== undefined && Number.isInteger(count) && count >= 0 ? count : 1,
    sources: objectSources,
    confidence: confidence(object),
    tlp: tlp(object),
    externalReferences: externalReferences(object),
    evidence: evidence(object, base, [entityRef, ...supportingRefs], objectSources, context, 'sighting'),
    stixVersion: times.stixVersion,
    objectMarkingRefs: objectMarkingRefs(object),
    createdAt: times.createdAt,
    modifiedAt: times.modifiedAt,
  };
}

function warning(
  warnings: KnowledgeProjectionWarning[],
  code: KnowledgeProjectionWarning['code'],
  message: string,
  objectId?: string,
): void {
  warnings.push({ code, message, objectId });
}

export function projectStixObjects(
  objects: readonly unknown[],
  options: StixProjectionOptions | string = {},
): KnowledgeProjection {
  const resolved = projectionOptions(options);
  const context: ProjectionContext = { projectedAt: resolved.projectedAt, source: resolved.source };
  const projection: KnowledgeProjection = {
    projectedAt: context.projectedAt,
    entities: [],
    relationships: [],
    sightings: [],
    warnings: [],
  };

  for (const value of objects) {
    const object = asRecord(value);
    if (!object) {
      warning(projection.warnings, 'invalid-object', 'STIX value must be a JSON object.');
      continue;
    }
    const base = validBaseObject(object);
    if (!base) {
      warning(
        projection.warnings,
        'invalid-object',
        'STIX object requires an id whose prefix matches its type.',
        stringValue(object.id),
      );
      continue;
    }

    if (isEntityType(base.type)) {
      const entity = projectEntity(object, { id: base.id, type: base.type }, context);
      if (entity) projection.entities.push(entity);
      else warning(projection.warnings, 'invalid-object', `STIX ${base.type} requires a name.`, base.id);
      continue;
    }

    if (base.type === 'relationship') {
      const relationshipType = stringValue(object.relationship_type);
      if (!relationshipType || !isRelationshipType(relationshipType)) {
        warning(
          projection.warnings,
          'unsupported-relationship',
          `Unsupported STIX relationship type: ${relationshipType ?? '(missing)'}.`,
          base.id,
        );
        continue;
      }
      const relationship = projectRelationship(object, base, relationshipType, context);
      if (relationship) projection.relationships.push(relationship);
      else warning(projection.warnings, 'invalid-object', 'STIX relationship requires source_ref and target_ref.', base.id);
      continue;
    }

    if (base.type === 'sighting') {
      const sighting = projectSighting(object, base, context);
      if (sighting) projection.sightings.push(sighting);
      else warning(projection.warnings, 'invalid-object', 'STIX sighting requires sighting_of_ref.', base.id);
      continue;
    }

    warning(projection.warnings, 'unsupported-type', `Unsupported STIX object type: ${base.type}.`, base.id);
  }

  const entityTypeById = new Map(resolved.knownEntityTypes);
  for (const entity of projection.entities) entityTypeById.set(entity.id, entity.type);
  projection.relationships = projection.relationships.filter((relationship) => {
    const sourceType = entityTypeById.get(relationship.sourceRef);
    const targetType = entityTypeById.get(relationship.targetRef);
    if (!sourceType || !targetType) return true;
    const policy = validateKnowledgeRelationship(relationship, sourceType, targetType);
    if (policy.allowed) return true;
    warning(
      projection.warnings,
      'unsupported-relationship',
      `Relationship ${relationship.id} failed policy: ${policy.violations.map((item) => item.code).join(', ')}.`,
      relationship.id,
    );
    return false;
  });

  const entityIds = new Set([...resolved.knownObjectIds, ...entityTypeById.keys()]);
  for (const relationship of projection.relationships) {
    for (const ref of [relationship.sourceRef, relationship.targetRef]) {
      if (!entityIds.has(ref)) {
        warning(
          projection.warnings,
          'unresolved-reference',
          `Relationship ${relationship.id} refers to unavailable entity ${ref}.`,
          relationship.id,
        );
      }
    }
  }
  for (const sighting of projection.sightings) {
    if (!entityIds.has(sighting.entityRef)) {
      warning(
        projection.warnings,
        'unresolved-reference',
        `Sighting ${sighting.id} refers to unavailable entity ${sighting.entityRef}.`,
        sighting.id,
      );
    }
  }

  return projection;
}

export function projectStixObject(
  object: unknown,
  options: StixProjectionOptions | string = {},
): KnowledgeProjection {
  return projectStixObjects([object], options);
}
