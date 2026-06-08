import { useEffect, useState } from 'react';
import { architectureReport, fetchArchitectureThreatModel } from '../api';
import type { ArchitectureThreatModel } from '../types';
import { SeverityBadge } from './SeverityBadge';

function downloadText(filename: string, text: string): void {
  const blob = new Blob([text], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function ArchitectureThreatModelPanel() {
  const [model, setModel] = useState<ArchitectureThreatModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      setModel(await fetchArchitectureThreatModel());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load threat model');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const exportMarkdown = async () => {
    setExporting(true);
    try {
      downloadText(`architecture-threat-model-${Date.now()}.md`, await architectureReport());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="rounded-xl border border-white/10 bg-panel/70 shadow-lg">
      <div className="flex flex-col gap-3 border-b border-white/10 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Architecture Threat Model</h2>
          <div className="mt-1 text-xs text-slate-500">
            {loading
              ? 'Loading'
              : model
                ? `${model.assets.length} assets · ${model.dataFlows.length} flows · ${model.scenarios.length} STRIDE scenarios`
                : 'Unavailable'}
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void load()}
            disabled={loading}
            className="rounded-lg border border-sky-400/40 bg-sky-400/10 px-3 py-2 text-xs font-semibold text-sky-200 hover:bg-sky-400/15 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? 'Refreshing' : 'Refresh model'}
          </button>
          <button
            type="button"
            onClick={() => void exportMarkdown()}
            disabled={!model || exporting}
            className="rounded-lg border border-white/10 bg-panel-2 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {exporting ? 'Exporting' : 'Export Markdown'}
          </button>
        </div>
      </div>
      {error && <div className="border-b border-white/10 px-4 py-2 text-xs text-red-300">{error}</div>}
      {model ? (
        <div className="grid gap-0 divide-y divide-white/5 lg:grid-cols-[340px_1fr] lg:divide-x lg:divide-y-0">
          <div className="max-h-[360px] overflow-auto">
            <div className="px-4 py-2 text-xs font-semibold text-slate-300">Assets</div>
            {model.assets.map((asset) => (
              <div key={asset.id} className="border-b border-white/5 px-4 py-3 last:border-b-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-slate-200">{asset.name}</span>
                  <SeverityBadge severity={asset.criticality} />
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  {asset.kind} · {asset.trustZone}
                </div>
              </div>
            ))}
          </div>
          <div className="max-h-[360px] overflow-auto">
            <div className="grid gap-0 divide-y divide-white/5 md:grid-cols-2 md:divide-x md:divide-y-0">
              <div>
                <div className="px-4 py-2 text-xs font-semibold text-slate-300">Trust boundaries</div>
                {model.trustBoundaries.map((boundary) => (
                  <div key={boundary.id} className="border-b border-white/5 px-4 py-3 last:border-b-0">
                    <div className="text-sm font-semibold text-slate-200">{boundary.name}</div>
                    <div className="mt-1 text-xs text-slate-500">{boundary.description}</div>
                  </div>
                ))}
              </div>
              <div>
                <div className="px-4 py-2 text-xs font-semibold text-slate-300">Data flows</div>
                {model.dataFlows.map((flow) => (
                  <div key={flow.id} className="border-b border-white/5 px-4 py-3 last:border-b-0">
                    <div className="text-sm font-semibold text-slate-200">{flow.name}</div>
                    <div className="mt-1 text-xs text-slate-500">
                      {flow.from} to {flow.to} · {flow.protocol}
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="border-t border-white/10 px-4 py-3">
              <div className="text-xs font-semibold text-slate-300">Top scenarios</div>
              <div className="mt-2 grid gap-2 md:grid-cols-2">
                {model.scenarios.slice(0, 4).map((scenario) => (
                  <div key={scenario.id} className="rounded border border-white/10 bg-panel-2 p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[11px] font-semibold text-slate-400">{scenario.stride}</span>
                      <SeverityBadge severity={scenario.severity} />
                    </div>
                    <div className="mt-2 text-xs font-semibold text-slate-200">{scenario.title}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="px-4 py-8 text-center text-sm text-slate-400">No architecture model loaded.</div>
      )}
    </div>
  );
}
