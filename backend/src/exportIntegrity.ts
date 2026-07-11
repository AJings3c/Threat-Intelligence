import { createHash, createHmac } from 'node:crypto';

export interface ExportIntegrityHeaders {
  'Cache-Control': 'no-transform';
  'Content-Digest': string;
  'X-Content-SHA256': string;
  'X-Content-HMAC-SHA256'?: string;
  'X-Signature-Key-Id'?: string;
}

// The digest covers the exact UTF-8 response body. Cache-Control: no-transform
// prevents intermediaries from changing that representation after signing.
export function exportIntegrityHeaders(
  body: string,
  signingKey = process.env.EXPORT_SIGNING_KEY?.trim() ?? '',
  keyId = process.env.EXPORT_SIGNING_KEY_ID?.trim() ?? '',
): ExportIntegrityHeaders {
  const digest = createHash('sha256').update(body, 'utf8').digest('base64');
  const headers: ExportIntegrityHeaders = {
    'Cache-Control': 'no-transform',
    'Content-Digest': `sha-256=:${digest}:`,
    'X-Content-SHA256': digest,
  };
  if (signingKey) {
    headers['X-Content-HMAC-SHA256'] = createHmac('sha256', signingKey).update(body, 'utf8').digest('base64');
    if (keyId) headers['X-Signature-Key-Id'] = keyId;
  }
  return headers;
}
