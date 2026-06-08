import type { FetchResult, ThreatIndicator } from '../types.js';
import { errorMessage, fetchWithTimeout } from '../util.js';
import { clampLimit, headline, parseIsoTime, scoreSocialText } from './social.js';

const DEFAULT_QUERY =
  '(CVE OR exploit OR 0day OR zero-day OR ransomware OR malware OR phishing OR APT OR IOC OR KEV) lang:en -is:retweet';

interface XTweet {
  id: string;
  text?: string;
  author_id?: string;
  created_at?: string;
  public_metrics?: {
    retweet_count?: number;
    reply_count?: number;
    like_count?: number;
    quote_count?: number;
  };
}

interface XUser {
  id: string;
  username?: string;
  name?: string;
}

interface XResponse {
  data?: XTweet[];
  includes?: { users?: XUser[] };
}

function metricBonus(metrics: XTweet['public_metrics']): number {
  if (!metrics) return 0;
  const reposts = (metrics.retweet_count ?? 0) + (metrics.quote_count ?? 0);
  const likes = metrics.like_count ?? 0;
  const replies = metrics.reply_count ?? 0;
  return (
    Math.min(15, Math.floor(Math.log1p(reposts) * 2)) +
    Math.min(10, Math.floor(Math.log1p(likes))) +
    Math.min(5, Math.floor(Math.log1p(replies)))
  );
}

export async function fetchXRecentSearch(): Promise<FetchResult<ThreatIndicator>> {
  const fetchedAt = Date.now();
  const bearerToken = process.env.X_BEARER_TOKEN?.trim();
  if (!bearerToken) return { items: [], fetchedAt, error: null };

  try {
    const apiBase = (process.env.X_API_BASE?.trim() || 'https://api.x.com/2').replace(/\/+$/, '');
    const query = process.env.X_QUERY?.trim() || DEFAULT_QUERY;
    const maxResults = clampLimit(process.env.X_MAX_RESULTS, 25, 10, 100);
    const params = new URLSearchParams({
      query,
      max_results: String(maxResults),
      'tweet.fields': 'created_at,author_id,public_metrics,entities',
      expansions: 'author_id',
      'user.fields': 'username,name',
    });

    const res = await fetchWithTimeout(
      `${apiBase}/tweets/search/recent?${params.toString()}`,
      { headers: { Authorization: `Bearer ${bearerToken}` } },
      30_000,
    );
    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const data = (await res.json()) as XResponse;
    const users = new Map((data.includes?.users ?? []).map((user) => [user.id, user]));
    const items: ThreatIndicator[] = [];
    for (const tweet of data.data ?? []) {
      const text = tweet.text?.trim();
      if (!text) continue;
      const user = tweet.author_id ? users.get(tweet.author_id) : undefined;
      const username = user?.username;
      const url = username
        ? `https://x.com/${username}/status/${tweet.id}`
        : `https://x.com/i/web/status/${tweet.id}`;
      const scored = scoreSocialText(text, metricBonus(tweet.public_metrics));
      items.push({
        id: `x:${tweet.id}`,
        source: 'x',
        type: 'social_intel',
        indicator: url,
        indicatorType: 'url',
        severity: scored.severity,
        title: headline(text),
        description: text,
        tags: ['x', ...(username ? [`@${username}`] : []), ...scored.tags],
        reference: url,
        firstSeen: parseIsoTime(tweet.created_at),
      });
    }

    return { items, fetchedAt, error: null };
  } catch (err) {
    return { items: [], fetchedAt, error: errorMessage(err) };
  }
}
