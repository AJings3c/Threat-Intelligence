import type { StixObject } from './stix.js';

function refsOf(object: StixObject): string[] {
  const refs: string[] = [];
  for (const key of ['source_ref', 'target_ref', 'created_by_ref'] as const) {
    const value = object[key];
    if (typeof value === 'string') refs.push(value);
  }
  for (const key of ['object_refs', 'object_marking_refs'] as const) {
    const value = object[key];
    if (Array.isArray(value)) refs.push(...value.filter((item): item is string => typeof item === 'string'));
  }
  return refs;
}

export function queryStixObjects(
  objects: StixObject[],
  options: { type?: string; id?: string; limit?: number; offset?: number } = {},
): { objects: StixObject[]; total: number; offset: number; limit: number } {
  const filtered = objects.filter(
    (object) => (!options.type || object.type === options.type) && (!options.id || object.id === options.id),
  );
  const offset = Math.max(0, Math.floor(options.offset ?? 0));
  const limit = Math.min(1000, Math.max(1, Math.floor(options.limit ?? 100)));
  return { objects: filtered.slice(offset, offset + limit), total: filtered.length, offset, limit };
}

export function stixNeighborhood(objects: StixObject[], rootId: string, requestedDepth = 1): StixObject[] {
  const depth = Math.min(3, Math.max(0, Math.floor(requestedDepth)));
  const selected = new Set<string>([rootId]);
  for (let level = 0; level < depth; level += 1) {
    const before = selected.size;
    for (const object of objects) {
      const refs = refsOf(object);
      if (selected.has(object.id)) {
        for (const ref of refs) selected.add(ref);
      } else if (refs.some((ref) => selected.has(ref))) {
        selected.add(object.id);
        for (const ref of refs) selected.add(ref);
      }
    }
    if (selected.size === before) break;
  }
  return objects.filter((object) => selected.has(object.id));
}
