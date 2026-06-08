import { describe, expect, it } from 'vitest';
import {
  buildTaxiiApiRoot,
  buildTaxiiCollections,
  buildTaxiiDiscovery,
  buildTaxiiEnvelope,
  buildTaxiiManifest,
  STIX_MEDIA_TYPE,
  TAXII_COLLECTION_ID,
} from '../src/taxii.js';
import type { StixObject } from '../src/stix.js';

const object: StixObject = {
  type: 'indicator',
  spec_version: '2.1',
  id: 'indicator--11111111-1111-4111-8111-111111111111',
  created: '2026-06-08T00:00:00.000Z',
  modified: '2026-06-08T00:00:00.000Z',
};

describe('TAXII helpers', () => {
  it('builds discovery and API root resources', () => {
    expect(buildTaxiiDiscovery('https://example.com').api_roots).toEqual([
      'https://example.com/taxii2/root/',
    ]);
    expect(buildTaxiiApiRoot().versions).toContain('taxii-2.1');
  });

  it('builds a read-only collection', () => {
    const collection = buildTaxiiCollections().collections[0];
    expect(collection).toMatchObject({
      id: TAXII_COLLECTION_ID,
      can_read: true,
      can_write: false,
      media_types: [STIX_MEDIA_TYPE],
    });
  });

  it('wraps STIX objects in envelope and manifest resources', () => {
    expect(buildTaxiiEnvelope([object])).toEqual({ more: false, objects: [object] });
    expect(buildTaxiiManifest([object]).objects[0]).toMatchObject({
      id: object.id,
      media_type: STIX_MEDIA_TYPE,
      version: object.modified,
    });
  });
});
