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

function retryDelayMs(response: Response | null, attempt: number): number {
  const retryAfter = response?.headers.get('retry-after');
  if (retryAfter) {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, 60_000);
    const date = new Date(retryAfter).getTime();
    if (Number.isFinite(date)) return Math.min(Math.max(0, date - Date.now()), 60_000);
  }
  return Math.min(1000 * 2 ** attempt + Math.floor(Math.random() * 250), 30_000);
}

function retryableStatus(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

export async function fetchWithRetry(
  url: string,
  options: RequestInit = {},
  timeoutMs = 25_000,
  maxAttempts = 3,
): Promise<Response> {
  const attempts = Math.max(1, Math.min(Math.floor(maxAttempts), 5));
  let lastError: unknown = null;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    let response: Response | null = null;
    try {
      response = await fetchWithTimeout(url, options, timeoutMs);
      if (!retryableStatus(response.status) || attempt === attempts - 1) return response;
      await response.body?.cancel();
    } catch (err) {
      lastError = err;
      if (attempt === attempts - 1) throw err;
    }
    await new Promise((resolve) => setTimeout(resolve, retryDelayMs(response, attempt)));
  }
  throw lastError instanceof Error ? lastError : new Error('request failed after retries');
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

// Pull an API credential from a request's Authorization (Bearer) header or
// X-Api-Token header. Credentials in URL query parameters are intentionally unsupported.
export function extractToken(
  authorization: string | undefined,
  xApiToken: string | undefined,
): string {
  if (authorization && authorization.startsWith('Bearer ')) return authorization.slice(7).trim();
  if (xApiToken) return xApiToken.trim();
  return '';
}
