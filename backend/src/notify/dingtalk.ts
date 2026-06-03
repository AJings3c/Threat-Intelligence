import crypto from 'node:crypto';
import { fetchWithTimeout, errorMessage } from '../util.js';
import type { DigestContent } from './format.js';

export interface SendResult {
  ok: boolean;
  error: string | null;
}

// DingTalk custom-robot signing: append timestamp + HMAC-SHA256(sign) when a secret is set.
function signedUrl(webhook: string, secret: string): string {
  const timestamp = Date.now();
  const stringToSign = `${timestamp}\n${secret}`;
  const sign = crypto.createHmac('sha256', secret).update(stringToSign).digest('base64');
  const sep = webhook.includes('?') ? '&' : '?';
  return `${webhook}${sep}timestamp=${timestamp}&sign=${encodeURIComponent(sign)}`;
}

export async function sendDingtalk(
  config: { webhook: string; secret: string | null },
  digest: DigestContent,
): Promise<SendResult> {
  try {
    const url = config.secret ? signedUrl(config.webhook, config.secret) : config.webhook;
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          msgtype: 'markdown',
          markdown: { title: digest.title, text: digest.markdown },
        }),
      },
      15_000,
    );
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    // DingTalk returns { errcode, errmsg }; errcode 0 means success.
    const data = (await res.json()) as { errcode?: number; errmsg?: string };
    if (data.errcode && data.errcode !== 0) {
      return { ok: false, error: `dingtalk errcode ${data.errcode}: ${data.errmsg ?? ''}` };
    }
    return { ok: true, error: null };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}
