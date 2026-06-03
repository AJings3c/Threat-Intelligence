import { fetchWithTimeout, errorMessage } from '../util.js';
import type { DigestContent } from './format.js';
import type { SendResult } from './dingtalk.js';

export async function sendTelegram(
  config: { botToken: string; chatId: string },
  digest: DigestContent,
): Promise<SendResult> {
  try {
    const url = `https://api.telegram.org/bot${config.botToken}/sendMessage`;
    const res = await fetchWithTimeout(
      url,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.chatId,
          text: digest.markdown,
          parse_mode: 'Markdown',
          disable_web_page_preview: true,
        }),
      },
      15_000,
    );
    if (!res.ok) {
      const detail = await res.text().catch(() => '');
      return { ok: false, error: `HTTP ${res.status}${detail ? `: ${detail.slice(0, 200)}` : ''}` };
    }
    const data = (await res.json()) as { ok?: boolean; description?: string };
    if (!data.ok) return { ok: false, error: `telegram: ${data.description ?? 'unknown error'}` };
    return { ok: true, error: null };
  } catch (err) {
    return { ok: false, error: errorMessage(err) };
  }
}
