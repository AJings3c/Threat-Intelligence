import { fetchWithTimeout, errorMessage } from '../util.js';
import type { DigestContent } from './format.js';
import type { SendResult } from './dingtalk.js';

// Slack incoming webhook: accepts a simple { text } payload (mrkdwn). We send the
// plain-text digest, which renders cleanly in Slack without channel-specific markup.
export async function sendSlack(webhook: string, digest: DigestContent): Promise<SendResult> {
  try {
    const res = await fetchWithTimeout(
      webhook,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: `*${digest.title}*\n${digest.text}` }),
      },
      15_000,
    );
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true, error: null };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}

// Generic webhook (SIEM / automation): POST the structured digest as JSON so downstream
// systems can parse title/text/markdown themselves.
export async function sendWebhook(url: string, digest: DigestContent): Promise<SendResult> {
  try {
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: digest.title, text: digest.text, markdown: digest.markdown }),
      },
      15_000,
    );
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    return { ok: true, error: null };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}
