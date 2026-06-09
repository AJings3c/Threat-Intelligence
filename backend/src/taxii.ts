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

export interface TaxiiPageOptions {
  addedAfter?: string;
  limit?: number;
  next?: string;
}

interface TaxiiPage<T> {
  more: boolean;
  objects: T[];
  next?: string;
}

function dateOf(value: unknown): number {
  if (typeof value !== 'string') return 0;
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? 0 : parsed;
}

function pageObjects<T extends { id: string; created?: string; modified?: string }>(
  objects: T[],
  opts: TaxiiPageOptions = {},
): TaxiiPage<T> {
  const addedAfter = opts.addedAfter ? dateOf(opts.addedAfter) : 0;
  const offset = opts.next && /^\d+$/.test(opts.next) ? Number(opts.next) : 0;
  const limit = opts.limit && Number.isFinite(opts.limit) && opts.limit > 0 ? Math.min(Math.floor(opts.limit), 1000) : 1000;
  const filtered = objects
    .filter((object) => dateOf(object.created ?? object.modified) > addedAfter)
    .sort((a, b) => dateOf(a.created ?? a.modified) - dateOf(b.created ?? b.modified) || a.id.localeCompare(b.id));
  const page = filtered.slice(offset, offset + limit);
  const more = offset + limit < filtered.length;
  return { more, objects: page, ...(more ? { next: String(offset + limit) } : {}) };
}

export function buildTaxiiEnvelope(objects: StixObject[], opts: TaxiiPageOptions = {}): TaxiiPage<StixObject> {
  return pageObjects(objects, opts);
}

export function buildTaxiiManifest(objects: StixObject[], opts: TaxiiPageOptions = {}): {
  more: boolean;
  objects: Array<{ id: string; date_added: string; version: string; media_type: string }>;
  next?: string;
} {
  const page = pageObjects(objects, opts);
  return {
    more: page.more,
    ...(page.next ? { next: page.next } : {}),
    objects: page.objects.map((object) => ({
      id: object.id,
      date_added: typeof object.created === 'string' ? object.created : new Date().toISOString(),
      version: typeof object.modified === 'string' ? object.modified : new Date().toISOString(),
      media_type: STIX_MEDIA_TYPE,
    })),
  };
}
