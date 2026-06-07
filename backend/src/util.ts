import type { Severity } from './types.js';

const USER_AGENT = 'threat-intel-platform/0.1 (+https://github.com/threat-intel-platform)';

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 25_000,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': USER_AGENT,
        Accept: 'application/json',
        ...(options.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

export function cvssToSeverity(score: number | undefined): Severity {
  if (score === undefined || Number.isNaN(score)) return 'low';
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// Pull an API credential from a request's Authorization (Bearer) header,
// X-Api-Token header, or ?token= query param, in that order.
export function extractToken(
  authorization: string | undefined,
  xApiToken: string | undefined,
  queryToken: string | undefined,
): string {
  if (authorization && authorization.startsWith('Bearer ')) return authorization.slice(7).trim();
  if (xApiToken) return xApiToken.trim();
  if (queryToken) return queryToken;
  return '';
}
