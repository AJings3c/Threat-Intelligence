import type { FetchResult, ThreatIndicator } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';
import { clampLimit, headline, parseIsoTime, scoreSocialText } from './social.js';

interface FacebookPost {
  id: string;
  message?: string;
  created_time?: string;
  permalink_url?: string;
  from?: { id?: string; name?: string };
}

interface FacebookPostsResponse {
  data?: FacebookPost[];
}

function parsePageIds(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);
}

export async function fetchFacebookPages(): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const accessToken = process.env.FACEBOOK_ACCESS_TOKEN?.trim();
  const pageIds = parsePageIds(process.env.FACEBOOK_PAGE_IDS);
  if (!accessToken || pageIds.length === 0) return { items: [], fetchedAt, error: null };

  try {
    const apiBase = (process.env.FACEBOOK_API_BASE?.trim() || 'https://graph.facebook.com').replace(
      /\/+$/,
      '',
    );
    const graphVersion = (process.env.FACEBOOK_GRAPH_VERSION?.trim() || 'v23.0').replace(
      /^\/+|\/+$/g,
      '',
    );
    const limit = clampLimit(process.env.FACEBOOK_LIMIT, 25, 1, 100);
    const items: ThreatIndicator[] = [];

    for (const pageId of pageIds) {
      const params = new URLSearchParams({
        fields: 'id,message,created_time,permalink_url,from',
        limit: String(limit),
        access_token: accessToken,
      });
      const res = await fetchWithTimeout(
        `${apiBase}/${graphVersion}/${encodeURIComponent(pageId)}/posts?${params.toString()}`,
        {},
        30_000,
      );
      if (!res.ok) throw new Error(`page ${pageId}: HTTP ${res.status}`);
      const data = (await res.json()) as FacebookPostsResponse;
      for (const post of data.data ?? []) {
        const message = post.message?.trim();
        if (!message) continue;
        const url = post.permalink_url || `https://facebook.com/${post.id}`;
        const scored = scoreSocialText(message);
        items.push({
          id: `facebook:${post.id}`,
          source: 'facebook',
          type: 'social_intel',
          indicator: url,
          indicatorType: 'url',
          severity: scored.severity,
          title: headline(message),
          description: message,
          tags: ['facebook', post.from?.name ?? pageId, ...scored.tags],
          reference: url,
          firstSeen: parseIsoTime(post.created_time),
        });
      }
    }

    return { items, fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
