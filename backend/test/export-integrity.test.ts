import { createHash, createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { exportIntegrityHeaders } from '../src/exportIntegrity.js';

describe('export integrity headers', () => {
  it('always emits a digest for the exact exported body', () => {
    const body = JSON.stringify({ type: 'bundle', objects: [] });
    const digest = createHash('sha256').update(body).digest('base64');

    expect(exportIntegrityHeaders(body, '')).toEqual({
      'Cache-Control': 'no-transform',
      'Content-Digest': `sha-256=:${digest}:`,
      'X-Content-SHA256': digest,
    });
  });

  it('adds an HMAC and key identifier only when a signing key is configured', () => {
    const body = '# Report\n';
    const signature = createHmac('sha256', 'test-secret').update(body).digest('base64');

    expect(exportIntegrityHeaders(body, 'test-secret', 'rotation-2026-07')).toMatchObject({
      'X-Content-HMAC-SHA256': signature,
      'X-Signature-Key-Id': 'rotation-2026-07',
    });
  });
});
