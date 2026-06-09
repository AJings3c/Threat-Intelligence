import type {
  Stats,
  ThreatsResponse,
  MapResponse,
  CveResponse,
  HashIntelResponse,
  SourceHealth,
  TrendResponse,
  SourceHistoryResponse,
  ConfigStatusResponse,
  NotifyTestResponse,
  IocInvestigation,
  IndicatorType,
  EnrichmentResponse,
  IntegrationKind,
  IntegrationTestResult,
  EnrichmentProvider,
  ThreatSource,
  InvestigationHistoryEntry,
  ArchitectureThreatModel,
  Language,
} from './types';

const BASE = import.meta.env.VITE_API_BASE ?? '';
const TOKEN = import.meta.env.VITE_API_TOKEN;

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, TOKEN ? { headers: { 'x-api-token': TOKEN } } : undefined);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return (await res.json()) as T;
}

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      ...(TOKEN ? { 'x-api-token': TOKEN } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return (await res.json()) as T;
}

export interface ThreatQuery {
  source?: string;
  type?: string;
  severity?: string;
  q?: string;
  limit?: number;
}

export function fetchThreats(query: ThreatQuery = {}): Promise<ThreatsResponse> {
  const params = new URLSearchParams();
  if (query.source) params.set('source', query.source);
  if (query.type) params.set('type', query.type);
  if (query.severity) params.set('severity', query.severity);
  if (query.q) params.set('q', query.q);
  if (query.limit) params.set('limit', String(query.limit));
  const qs = params.toString();
  return getJson<ThreatsResponse>(`/api/threats${qs ? `?${qs}` : ''}`);
}

export function fetchMap(): Promise<MapResponse> {
  return getJson<MapResponse>('/api/map');
}

export function fetchStats(): Promise<Stats> {
  return getJson<Stats>('/api/stats');
}

export function fetchCves(limit = 40): Promise<CveResponse> {
  return getJson<CveResponse>(`/api/cve?limit=${limit}`);
}

export function fetchHashIntel(limit = 30): Promise<HashIntelResponse> {
  return getJson<HashIntelResponse>(`/api/hashes?limit=${limit}`);
}

export function fetchHealth(): Promise<{ sources: SourceHealth[] }> {
  return getJson<{ sources: SourceHealth[] }>('/api/sources/health');
}

export function fetchSourceHistory(days = 7): Promise<SourceHistoryResponse> {
  return getJson<SourceHistoryResponse>(`/api/sources/history?days=${days}`);
}

export function fetchTrend(days = 30): Promise<TrendResponse> {
  return getJson<TrendResponse>(`/api/trend?days=${days}`);
}

export function fetchConfigStatus(): Promise<ConfigStatusResponse> {
  return getJson<ConfigStatusResponse>('/api/config/status');
}

export function sendNotifyTest(): Promise<NotifyTestResponse> {
  return postJson<NotifyTestResponse>('/api/notify/test');
}

export function testIntegration(
  kind: IntegrationKind,
  id: ThreatSource | EnrichmentProvider,
): Promise<IntegrationTestResult> {
  return postJson<IntegrationTestResult>('/api/config/test', { kind, id });
}

export function investigateIoc(
  indicator: string,
  type?: IndicatorType | '',
  lang: Language = 'en',
): Promise<IocInvestigation> {
  const params = new URLSearchParams({ indicator, lang });
  if (type) params.set('type', type);
  return getJson<IocInvestigation>(`/api/investigate?${params.toString()}`);
}

export function enrichIoc(indicator: string, type: IndicatorType): Promise<EnrichmentResponse> {
  const params = new URLSearchParams({ indicator, type });
  return getJson<EnrichmentResponse>(`/api/enrich?${params.toString()}`);
}

export function fetchInvestigationHistory(limit = 20): Promise<{ enabled: boolean; points: InvestigationHistoryEntry[] }> {
  return getJson<{ enabled: boolean; points: InvestigationHistoryEntry[] }>(
    `/api/investigations/history?limit=${limit}`,
  );
}

export function fetchArchitectureThreatModel(lang: Language = 'en'): Promise<ArchitectureThreatModel> {
  return getJson<ArchitectureThreatModel>(`/api/threat-model?lang=${lang}`);
}

export async function fetchText(path: string): Promise<string> {
  const res = await fetch(`${BASE}${path}`, TOKEN ? { headers: { 'x-api-token': TOKEN } } : undefined);
  if (!res.ok) throw new Error(`Request failed: ${res.status}`);
  return await res.text();
}

export function investigationReport(
  indicator: string,
  type: IndicatorType,
  format: 'markdown' | 'json',
  lang: Language = 'en',
): Promise<string> {
  const params = new URLSearchParams({ indicator, type, format, lang });
  return fetchText(`/api/investigate/report?${params.toString()}`);
}

export function architectureReport(format: 'markdown' = 'markdown', lang: Language = 'en'): Promise<string> {
  return fetchText(`/api/threat-model?format=${format}&lang=${lang}`);
}
