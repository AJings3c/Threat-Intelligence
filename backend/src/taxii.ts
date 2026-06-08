import type { StixObject } from './stix.js';

export const TAXII_MEDIA_TYPE = 'application/taxii+json;version=2.1';
export const STIX_MEDIA_TYPE = 'application/stix+json;version=2.1';
export const TAXII_API_ROOT = '/taxii2/root/';
export const TAXII_COLLECTION_ID = '2b7e6f58-9f42-4b7d-9f26-4fbf87f62d3a';

export interface TaxiiCollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
}

export function taxiiCollection(): TaxiiCollection {
  return {
    id: TAXII_COLLECTION_ID,
    title: 'Threat Intelligence Platform Indicators',
    description: 'Read-only STIX 2.1 indicators and vulnerabilities aggregated by this platform.',
    can_read: true,
    can_write: false,
    media_types: [STIX_MEDIA_TYPE],
  };
}

export function buildTaxiiDiscovery(baseUrl: string): { title: string; api_roots: string[] } {
  return {
    title: 'Threat Intelligence Platform TAXII Server',
    api_roots: [new URL(TAXII_API_ROOT, baseUrl).toString()],
  };
}

export function buildTaxiiApiRoot(): {
  title: string;
  description: string;
  versions: string[];
  max_content_length: number;
} {
  return {
    title: 'Threat Intelligence Platform TAXII API Root',
    description: 'Read-only TAXII 2.1 API root for aggregated public cyber threat intelligence.',
    versions: ['taxii-2.1'],
    max_content_length: 10 * 1024 * 1024,
  };
}

export function buildTaxiiCollections(): { collections: TaxiiCollection[] } {
  return { collections: [taxiiCollection()] };
}

export function buildTaxiiEnvelope(objects: StixObject[]): { more: boolean; objects: StixObject[] } {
  return { more: false, objects };
}

export function buildTaxiiManifest(objects: StixObject[]): {
  more: boolean;
  objects: Array<{ id: string; date_added: string; version: string; media_type: string }>;
} {
  return {
    more: false,
    objects: objects.map((object) => ({
      id: object.id,
      date_added: typeof object.created === 'string' ? object.created : new Date().toISOString(),
      version: typeof object.modified === 'string' ? object.modified : new Date().toISOString(),
      media_type: STIX_MEDIA_TYPE,
    })),
  };
}
