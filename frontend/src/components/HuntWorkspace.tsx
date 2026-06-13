import { useState, type FormEvent } from 'react';
import { Search, Database, Download, AlertCircle } from 'lucide-react';
import type { Language, ThreatIndicator } from '../types';

interface HuntResult {
  ioc: string;
  matches: ThreatIndicator[];
  firstSeen?: string;
  lastSeen?: string;
  confidence: number;
}

interface HuntResponse {
  results: HuntResult[];
  totalMatches: number;
  queryTime: number;
}

const HUNT_TEXT = {
  en: {
    title: 'Threat Hunting',
    subtitle: 'Batch IOC search across historical intelligence feeds',
    iocInput: 'IOC Input',
    iocPlaceholder: 'Enter IOCs (one per line): IPs, domains, URLs, hashes',
    timeRange: 'Time Range',
    days30: 'Last 30 days',
    days90: 'Last 90 days',
    days180: 'Last 180 days',
    allTime: 'All time',
    hunt: 'Start Hunt',
    hunting: 'Hunting...',
    results: 'Hunt Results',
    noResults: 'No matches found',
    matches: 'matches',
    firstSeen: 'First Seen',
    lastSeen: 'Last Seen',
    confidence: 'Confidence',
    exportCSV: 'Export CSV',
    exportJSON: 'Export JSON',
    cleared: 'Results cleared',
  },
  zh: {
    title: '威胁狩猎',
    subtitle: '批量 IOC 搜索，覆盖历史情报源',
    iocInput: 'IOC 输入',
    iocPlaceholder: '输入 IOC（每行一个）：IP、域名、URL、哈希',
    timeRange: '时间范围',
    days30: '最近 30 天',
    days90: '最近 90 天',
    days180: '最近 180 天',
    allTime: '全部时间',
    hunt: '开始狩猎',
    hunting: '狩猎中...',
    results: '狩猎结果',
    noResults: '无匹配结果',
    matches: '个匹配',
    firstSeen: '首次发现',
    lastSeen: '最近发现',
    confidence: '置信度',
    exportCSV: '导出 CSV',
    exportJSON: '导出 JSON',
    cleared: '结果已清空',
  },
};

export function HuntWorkspace({ lang }: { lang: Language }) {
  const [iocInput, setIocInput] = useState('');
  const [timeRange, setTimeRange] = useState<30 | 90 | 180 | 0>(30);
  const [hunting, setHunting] = useState(false);
  const [results, setResults] = useState<HuntResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const t = HUNT_TEXT[lang];

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    const iocs = iocInput
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

    if (iocs.length === 0) return;

    setHunting(true);
    setError(null);

    try {
      const now = Date.now();
      const start = timeRange === 0 ? 0 : now - timeRange * 24 * 60 * 60 * 1000;

      const response = await fetch('/api/hunt/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          iocs,
          timeRange: { start, end: now },
        }),
      });

      if (!response.ok) throw new Error(`Hunt failed: ${response.status}`);

      const data = (await response.json()) as HuntResponse;
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Hunt failed');
    } finally {
      setHunting(false);
    }
  };

  const exportCSV = () => {
    if (!results) return;

    const rows = [['IOC', 'Matches', 'First Seen', 'Last Seen', 'Confidence']];
    for (const result of results.results) {
      rows.push([
        result.ioc,
        String(result.matches.length),
        result.firstSeen ?? '',
        result.lastSeen ?? '',
        String(result.confidence),
      ]);
    }

    const csv = rows.map((row) => row.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hunt-results-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportJSON = () => {
    if (!results) return;

    const json = JSON.stringify(results, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hunt-results-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      <form onSubmit={handleSubmit} className="surface rounded-lg p-4">
        <div className="mb-4">
          <label htmlFor="ioc-input" className="mb-2 block text-sm font-semibold text-slate-300">
            {t.iocInput}
          </label>
          <textarea
            id="ioc-input"
            value={iocInput}
            onChange={(e) => setIocInput(e.target.value)}
            placeholder={t.iocPlaceholder}
            rows={8}
            className="control w-full resize-y font-mono text-sm"
          />
        </div>

        <div className="mb-4">
          <label className="mb-2 block text-sm font-semibold text-slate-300">{t.timeRange}</label>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {[
              { value: 30 as const, label: t.days30 },
              { value: 90 as const, label: t.days90 },
              { value: 180 as const, label: t.days180 },
              { value: 0 as const, label: t.allTime },
            ].map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => setTimeRange(option.value)}
                className={`control px-3 py-2 text-sm font-semibold ${
                  timeRange === option.value ? 'bg-teal-300/15 text-teal-100' : 'text-slate-300'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={hunting || iocInput.trim().length === 0}
          className="primary-action control inline-flex items-center gap-2 px-4 py-2 text-sm font-bold disabled:opacity-50"
        >
          <Search className="h-4 w-4" />
          {hunting ? t.hunting : t.hunt}
        </button>
      </form>

      {error && (
        <div className="flex items-start gap-3 rounded-lg border border-red-400/45 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {results && (
        <div className="surface rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-teal-200" />
              <h3 className="text-lg font-bold text-slate-50">{t.results}</h3>
              <span className="text-sm text-slate-400">
                ({results.totalMatches} {t.matches})
              </span>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={exportCSV}
                className="control inline-flex items-center gap-2 px-3 py-1.5 text-sm"
              >
                <Download className="h-3.5 w-3.5" />
                {t.exportCSV}
              </button>
              <button
                type="button"
                onClick={exportJSON}
                className="control inline-flex items-center gap-2 px-3 py-1.5 text-sm"
              >
                <Download className="h-3.5 w-3.5" />
                {t.exportJSON}
              </button>
            </div>
          </div>

          {results.results.length === 0 ? (
            <div className="py-8 text-center text-sm text-slate-400">{t.noResults}</div>
          ) : (
            <div className="space-y-3">
              {results.results.map((result) => (
                <div key={result.ioc} className="surface-raised rounded-lg p-3">
                  <div className="mb-2 flex items-start justify-between">
                    <code className="text-sm font-semibold text-teal-100">{result.ioc}</code>
                    <span className="rounded bg-teal-300/15 px-2 py-0.5 text-xs font-bold text-teal-100">
                      {result.matches.length} {t.matches}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <div className="text-slate-500">{t.firstSeen}</div>
                      <div className="font-semibold text-slate-300">
                        {result.firstSeen ? new Date(result.firstSeen).toLocaleDateString() : '-'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">{t.lastSeen}</div>
                      <div className="font-semibold text-slate-300">
                        {result.lastSeen ? new Date(result.lastSeen).toLocaleDateString() : '-'}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500">{t.confidence}</div>
                      <div className="font-semibold text-slate-300">{result.confidence}%</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
