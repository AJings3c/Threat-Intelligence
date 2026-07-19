import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchKnowledgeEntities, fetchKnowledgeGraph } from './api';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('threat knowledge API client', () => {
  it('encodes entity filters, literal search text, and pagination', async () => {
    const fetchMock = vi.fn(async (...args: Parameters<typeof fetch>) => {
      void args;
      return new Response(JSON.stringify({ entities: [], total: 0, limit: 40, offset: 80 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    await fetchKnowledgeEntities({
      types: ['threat-actor', 'intrusion-set'],
      q: 'APT 29 / G0016',
      limit: 40,
      offset: 80,
    });

    const requested = String(fetchMock.mock.calls[0]?.[0]);
    const url = new URL(requested, 'http://local.test');
    expect(url.pathname).toBe('/api/knowledge/entities');
    expect(url.searchParams.get('types')).toBe('threat-actor,intrusion-set');
    expect(url.searchParams.get('q')).toBe('APT 29 / G0016');
    expect(url.searchParams.get('limit')).toBe('40');
    expect(url.searchParams.get('offset')).toBe('80');
  });

  it('requests a bounded graph depth and preserves backend error detail', async () => {
    const fetchMock = vi.fn(async (...args: Parameters<typeof fetch>) => {
      void args;
      return new Response(JSON.stringify({ error: 'knowledge entity not found or not permitted by TLP policy' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(fetchKnowledgeGraph('threat-actor--one', 3)).rejects.toThrow(
      'knowledge entity not found or not permitted by TLP policy',
    );
    const requested = String(fetchMock.mock.calls[0]?.[0]);
    const url = new URL(requested, 'http://local.test');
    expect(url.pathname).toBe('/api/knowledge/entities/threat-actor--one/graph');
    expect(url.searchParams.get('depth')).toBe('3');
  });
});
