import type { Severity } from './types.js';

const USER_AGENT = 'threat-intel-platform/0.1 (+https://github.com/threat-intel-platform)';

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchOnce(
  url: string,
  options: RequestInit,
  timeoutMs: number,
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

// Transient: network/timeout errors, 429, and 5xx are worth retrying.
function isRetryableStatus(status: number): boolean {
  return status === 429 || status >= 500;
}

/**
 * fetch() with a per-attempt timeout plus retry/backoff on transient failures
 * (network errors, timeouts, 429, 5xx). Non-retryable responses are returned as-is
 * so callers keep their existing `res.ok` handling.
 */
export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 25_000,
  retryOpts: { retries?: number; backoffMs?: number } = {},
): Promise<Response> {
  const retries = retryOpts.retries ?? 2;
  const backoffMs = retryOpts.backoffMs ?? 500;
  let lastErr: unknown;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetchOnce(url, options, timeoutMs);
      if (attempt < retries && isRetryableStatus(res.status)) {
        await delay(backoffMs * 2 ** attempt);
        continue;
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) {
        await delay(backoffMs * 2 ** attempt);
        continue;
      }
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
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
