import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchFacebookPages } from '../src/sources/facebook.js';
import { fetchXRecentSearch } from '../src/sources/x.js';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env.X_BEARER_TOKEN;
  delete process.env.X_QUERY;
  delete process.env.FACEBOOK_ACCESS_TOKEN;
  delete process.env.FACEBOOK_PAGE_IDS;
});

describe('fetchXRecentSearch', () => {
  it('returns empty results when no bearer token is configured', async () => {
    const result = await fetchXRecentSearch();
    expect(result.error).toBeNull();
    expect(result.items).toEqual([]);
  });

  it('maps recent-search tweets into social indicators', async () => {
    process.env.X_BEARER_TOKEN = 'token';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({
          data: [
            {
              id: '123',
              text: 'New CVE exploit PoC observed in the wild',
              author_id: 'u1',
              created_at: '2026-06-08T01:02:03.000Z',
              public_metrics: { retweet_count: 20, like_count: 50, reply_count: 4, quote_count: 3 },
            },
          ],
          includes: { users: [{ id: 'u1', username: 'researcher' }] },
        }),
      ),
    );

    const result = await fetchXRecentSearch();
    expect(result.error).toBeNull();
    expect(result.items[0]).toMatchObject({
      id: 'x:123',
      source: 'x',
      type: 'social_intel',
      indicator: 'https://x.com/researcher/status/123',
      severity: 'critical',
    });
  });
});

describe('fetchFacebookPages', () => {
  it('maps page posts into social indicators', async () => {
    process.env.FACEBOOK_ACCESS_TOKEN = 'token';
    process.env.FACEBOOK_PAGE_IDS = 'page-1';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        jsonResponse({
          data: [
            {
              id: 'page-1_456',
              message: 'Ransomware campaign uses new malware loader',
              created_time: '2026-06-08T02:03:04+0000',
              permalink_url: 'https://facebook.com/page-1/posts/456',
              from: { name: 'Security Page' },
            },
          ],
        }),
      ),
    );

    const result = await fetchFacebookPages();
    expect(result.error).toBeNull();
    expect(result.items[0]).toMatchObject({
      id: 'facebook:page-1_456',
      source: 'facebook',
      type: 'social_intel',
      indicator: 'https://facebook.com/page-1/posts/456',
      severity: 'medium',
    });
  });
});
