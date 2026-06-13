import { enrichIndicator } from '../enrich.js';
import { errorMessage } from '../util.js';

export async function executeWebhookAction(url: string, payload: unknown): Promise<void> {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'Threat-Intel-Platform/1.0',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Webhook request failed: ${response.status} ${response.statusText}`);
  }
}

export async function executeEnrichAction(iocValue: string): Promise<void> {
  try {
    const type = detectIndicatorType(iocValue);
    await enrichIndicator(iocValue, type);
  } catch (err) {
    throw new Error(`Enrichment failed: ${errorMessage(err)}`);
  }
}

function detectIndicatorType(value: string): 'ip' | 'domain' | 'url' | 'hash' {
  if (/^https?:\/\//.test(value)) return 'url';

  if (/^[0-9a-fA-F]{32}$/.test(value) || /^[0-9a-fA-F]{40}$/.test(value) || /^[0-9a-fA-F]{64}$/.test(value)) {
    return 'hash';
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';

  return 'domain';
}

export const actionHandlers = {
  webhook: executeWebhookAction,
  enrich: executeEnrichAction,
};
