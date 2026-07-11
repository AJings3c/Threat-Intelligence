import { describe, expect, it } from 'vitest';
import { queryStixObjects, stixNeighborhood } from '../src/stixGraph.js';
import type { StixObject } from '../src/stix.js';

function object(type: string, id: string, extra: Record<string, unknown> = {}): StixObject {
  return { type, spec_version: '2.1', id, ...extra };
}

describe('STIX graph queries', () => {
  const malware = object('malware', 'malware--11111111-1111-4111-8111-111111111111');
  const technique = object('attack-pattern', 'attack-pattern--22222222-2222-4222-8222-222222222222');
  const relationship = object('relationship', 'relationship--33333333-3333-4333-8333-333333333333', {
    source_ref: malware.id,
    target_ref: technique.id,
    relationship_type: 'uses',
  });
  const unrelated = object('campaign', 'campaign--44444444-4444-4444-8444-444444444444');
  const objects = [malware, technique, relationship, unrelated];

  it('filters by type and paginates with a bounded limit', () => {
    expect(queryStixObjects(objects, { type: 'malware', limit: 5000 })).toEqual({
      objects: [malware],
      total: 1,
      offset: 0,
      limit: 1000,
    });
  });

  it('returns connected relationship endpoints but excludes unrelated entities', () => {
    expect(stixNeighborhood(objects, malware.id, 1)).toEqual([malware, technique, relationship]);
    expect(stixNeighborhood(objects, 'missing--id', 1)).toEqual([]);
  });
});
