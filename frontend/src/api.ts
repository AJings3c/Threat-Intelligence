import type {
  Stats,
  ThreatsResponse,
  MapResponse,
  CveResponse,
  SourceHealth,
  TrendResponse,
} from './types';

const BASE = import.meta.env.VITE_API_BASE ?? '';
const TOKEN = import.meta.env.VITE_API_TOKEN;

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, TOKEN ? { headers: { 'x-api-token': TOKEN } } : undefined);
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

export function fetchHealth(): Promise<{ sources: SourceHealth[] }> {
  return getJson<{ sources: SourceHealth[] }>('/api/sources/health');
}

export function fetchTrend(days = 30): Promise<TrendResponse> {
  return getJson<TrendResponse>(`/api/trend?days=${days}`);
}
