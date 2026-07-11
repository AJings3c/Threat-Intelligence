import type { ApiRole } from './types.js';
import type { StixObject } from './stix.js';

const ROLE_TLP_RANK: Record<ApiRole, number> = { viewer: 1, analyst: 2, admin: 3 };
const MARKING_RANK: Record<string, number> = {
  'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487': 0,
  'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da': 1,
  'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82': 2,
  'marking-definition--5e57c739-391a-4eb3-b6e7-5b9acb13fe73': 3,
};

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function allowedByMarking(object: StixObject, role: ApiRole): boolean {
  const maxRank = ROLE_TLP_RANK[role];
  if (object.type === 'marking-definition') {
    const rank = MARKING_RANK[object.id];
    return rank !== undefined ? rank <= maxRank : role === 'admin';
  }
  return stringArray(object.object_marking_refs).every((id) => {
    const rank = MARKING_RANK[id];
    return rank !== undefined ? rank <= maxRank : role === 'admin';
  });
}

// Enforce a conservative distribution policy at the export boundary:
// viewer <= GREEN, analyst <= AMBER, admin <= RED/unknown custom markings.
export function filterStixObjectsForRole(objects: StixObject[], role: ApiRole): StixObject[] {
  const allowed = objects.filter((object) => allowedByMarking(object, role));
  const ids = new Set(allowed.map((object) => object.id));
  const result: StixObject[] = [];
  for (const object of allowed) {
    if (object.type === 'relationship') {
      const source = typeof object.source_ref === 'string' ? object.source_ref : '';
      const target = typeof object.target_ref === 'string' ? object.target_ref : '';
      if (!ids.has(source) || !ids.has(target)) continue;
    }
    if (object.type === 'report') {
      const refs = stringArray(object.object_refs).filter((id) => ids.has(id));
      if (refs.length === 0) continue;
      result.push({ ...object, object_refs: refs });
      continue;
    }
    result.push(object);
  }
  const referencedMarkings = new Set(result.flatMap((object) => stringArray(object.object_marking_refs)));
  return result.filter((object) => object.type !== 'marking-definition' || referencedMarkings.has(object.id));
}
