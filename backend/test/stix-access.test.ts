import { describe, expect, it } from 'vitest';
import { filterStixObjectsForRole } from '../src/stixAccess.js';
import type { StixObject } from '../src/stix.js';

const CLEAR = 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487';
const AMBER = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82';

function object(type: string, id: string, extra: Record<string, unknown> = {}): StixObject {
  return { type, spec_version: '2.1', id, ...extra };
}

describe('STIX role distribution policy', () => {
  it('limits viewers to GREEN, analysts to AMBER, and removes dangling relationships', () => {
    const clearId = 'indicator--11111111-1111-4111-8111-111111111111';
    const amberId = 'indicator--22222222-2222-4222-8222-222222222222';
    const relationshipId = 'relationship--33333333-3333-4333-8333-333333333333';
    const objects = [
      object('marking-definition', CLEAR),
      object('marking-definition', AMBER),
      object('indicator', clearId, { object_marking_refs: [CLEAR] }),
      object('indicator', amberId, { object_marking_refs: [AMBER] }),
      object('relationship', relationshipId, { source_ref: clearId, target_ref: amberId }),
    ];

    expect(filterStixObjectsForRole(objects, 'viewer').map((item) => item.id)).toEqual([CLEAR, clearId]);
    expect(filterStixObjectsForRole(objects, 'analyst').map((item) => item.id)).toEqual([
      CLEAR,
      AMBER,
      clearId,
      amberId,
      relationshipId,
    ]);
  });

  it('treats unknown custom markings as admin-only', () => {
    const custom = 'marking-definition--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const marked = object('indicator', 'indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', {
      object_marking_refs: [custom],
    });
    expect(filterStixObjectsForRole([marked], 'analyst')).toEqual([]);
    expect(filterStixObjectsForRole([marked], 'admin')).toEqual([marked]);
  });
});
