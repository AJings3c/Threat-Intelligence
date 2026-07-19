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
  ProviderConfigStatus,
  ThreatSource,
  InvestigationHistoryEntry,
  ArchitectureThreatModel,
  Language,
  KnowledgeEntity,
  KnowledgeEntityPage,
  KnowledgeEntityType,
  KnowledgeGraph,
} from './types';

const BASE = import.meta.env.VITE_API_BASE ?? '';
const TOKEN = import.meta.env.VITE_API_TOKEN;

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (TOKEN) headers.set('x-api-token', TOKEN);
  return fetch(`${BASE}${path}`, { ...init, headers });
}

export async function apiJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await apiFetch(path, init);
  if (!res.ok) {
    let detail = '';
    try {
      const body = (await res.json()) as { error?: string; message?: string; description?: string };
      detail = body.error ?? body.message ?? body.description ?? '';
    } catch {
      detail = await res.text().catch(() => '');
    }
    throw new Error(detail || `Request failed: ${res.status}`);
  }
  return (await res.json()) as T;
}

async function getJson<T>(path: string): Promise<T> {
  return apiJson<T>(path);
}

async function postJson<T>(path: string, body?: unknown): Promise<T> {
  return apiJson<T>(path, {
    method: 'POST',
    headers: {
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
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

export function fetchEnrichmentProviders(): Promise<{ providers: ProviderConfigStatus[] }> {
  return getJson<{ providers: ProviderConfigStatus[] }>('/api/enrich/providers');
}

export function fetchInvestigationHistory(limit = 20): Promise<{ enabled: boolean; points: InvestigationHistoryEntry[] }> {
  return getJson<{ enabled: boolean; points: InvestigationHistoryEntry[] }>(
    `/api/investigations/history?limit=${limit}`,
  );
}

export function fetchArchitectureThreatModel(lang: Language = 'en'): Promise<ArchitectureThreatModel> {
  return getJson<ArchitectureThreatModel>(`/api/threat-model?lang=${lang}`);
}

export interface KnowledgeQuery {
  types?: KnowledgeEntityType[];
  q?: string;
  limit?: number;
  offset?: number;
}

export function fetchKnowledgeTypes(): Promise<{ entityTypes: KnowledgeEntityType[] }> {
  return getJson<{ entityTypes: KnowledgeEntityType[] }>('/api/knowledge/types');
}

export function fetchKnowledgeEntities(query: KnowledgeQuery = {}): Promise<KnowledgeEntityPage> {
  const params = new URLSearchParams();
  if (query.types?.length) params.set('types', query.types.join(','));
  if (query.q) params.set('q', query.q);
  if (query.limit !== undefined) params.set('limit', String(query.limit));
  if (query.offset !== undefined) params.set('offset', String(query.offset));
  const qs = params.toString();
  return getJson<KnowledgeEntityPage>(`/api/knowledge/entities${qs ? `?${qs}` : ''}`);
}

export function fetchKnowledgeEntity(id: string): Promise<KnowledgeEntity> {
  return getJson<KnowledgeEntity>(`/api/knowledge/entities/${encodeURIComponent(id)}`);
}

export function fetchKnowledgeGraph(id: string, depth = 1): Promise<KnowledgeGraph> {
  return getJson<KnowledgeGraph>(`/api/knowledge/entities/${encodeURIComponent(id)}/graph?depth=${depth}`);
}

export async function fetchText(path: string): Promise<string> {
  const res = await apiFetch(path);
  if (!res.ok) throw new Error((await res.text().catch(() => '')) || `Request failed: ${res.status}`);
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
