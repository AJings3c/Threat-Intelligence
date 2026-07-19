import type { ApiRole } from '../types.js';
import { withPersistenceDatabase } from '../persist.js';
import {
  getKnowledgeEntity,
  getKnowledgeGraph,
  knowledgeEntityTypes,
  listKnowledgeEntities,
  type KnowledgeEntityPage,
  type KnowledgeEntityQuery,
  type KnowledgeGraph,
} from './repository.js';
import type { KnowledgeEntity, KnowledgeEntityType } from './types.js';

export function listThreatKnowledge(
  role: ApiRole,
  query: KnowledgeEntityQuery = {},
): KnowledgeEntityPage {
  return withPersistenceDatabase(
    (database) => listKnowledgeEntities(database, role, query),
    { entities: [], total: 0, limit: query.limit ?? 100, offset: query.offset ?? 0 },
  );
}

export function getThreatKnowledgeEntity(role: ApiRole, id: string): KnowledgeEntity | null {
  return withPersistenceDatabase((database) => getKnowledgeEntity(database, role, id), null);
}

export function getThreatKnowledgeGraph(
  role: ApiRole,
  id: string,
  depth = 1,
): KnowledgeGraph | null {
  return withPersistenceDatabase((database) => getKnowledgeGraph(database, role, id, depth), null);
}

export function threatKnowledgeEntityTypes(): KnowledgeEntityType[] {
  return knowledgeEntityTypes();
}
