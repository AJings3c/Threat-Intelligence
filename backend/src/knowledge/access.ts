import type { ApiRole } from '../types.js';
import type {
  KnowledgeEntity,
  KnowledgeProjection,
  KnowledgeRelationshipFact,
  KnowledgeSighting,
  KnowledgeTlp,
} from './types.js';

const ROLE_TLP_RANK: Record<ApiRole, number> = { viewer: 1, analyst: 2, admin: 4 };
const TLP_RANK: Record<KnowledgeTlp, number> = { clear: 0, green: 1, amber: 2, red: 3, unknown: 4 };

export function allowedKnowledgeTlpValues(role: ApiRole): KnowledgeTlp[] {
  return (Object.keys(TLP_RANK) as KnowledgeTlp[]).filter((tlp) => isKnowledgeTlpAllowed(tlp, role));
}

export function isKnowledgeTlpAllowed(tlp: KnowledgeTlp, role: ApiRole): boolean {
  return TLP_RANK[tlp] <= ROLE_TLP_RANK[role];
}

export function filterKnowledgeProjectionForRole(
  projection: KnowledgeProjection,
  role: ApiRole,
): KnowledgeProjection {
  const entities = projection.entities.filter((entity) => isKnowledgeTlpAllowed(entity.tlp, role));
  const entityIds = new Set(entities.map((entity) => entity.id));
  const relationships = projection.relationships.filter(
    (relationship) =>
      isKnowledgeTlpAllowed(relationship.tlp, role) &&
      entityIds.has(relationship.sourceRef) &&
      entityIds.has(relationship.targetRef),
  );
  const sightings = projection.sightings.filter(
    (sighting) => isKnowledgeTlpAllowed(sighting.tlp, role) && entityIds.has(sighting.entityRef),
  );
  return { ...projection, entities, relationships, sightings };
}

export function knowledgeEntityAllowed(entity: KnowledgeEntity, role: ApiRole): boolean {
  return isKnowledgeTlpAllowed(entity.tlp, role);
}

export function knowledgeRelationshipAllowed(
  relationship: KnowledgeRelationshipFact,
  role: ApiRole,
): boolean {
  return isKnowledgeTlpAllowed(relationship.tlp, role);
}

export function knowledgeSightingAllowed(sighting: KnowledgeSighting, role: ApiRole): boolean {
  return isKnowledgeTlpAllowed(sighting.tlp, role);
}
