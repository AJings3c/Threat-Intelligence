import { useState, type FormEvent } from 'react';
import { AlertCircle, Braces, Download, FileSearch, RefreshCw } from 'lucide-react';
import { apiFetch, apiJson, fetchText } from '../api';
import type { DetectionArtifact, Language, StixObject } from '../types';

type View = 'extract' | 'stix' | 'artifacts' | 'admin';

const TEXT = {
  en: {
    extract: 'Text extraction', stix: 'STIX graph', artifacts: 'Detection artifacts', admin: 'Operations',
    paste: 'Paste email, ticket, or news text', placeholder: 'Paste text containing defanged URLs, domains, IPs, hashes, or CVEs…', run: 'Extract IOCs', running: 'Extracting…', local: 'Local match', noIocs: 'No supported IOC was found.',
    type: 'Object type', id: 'Object ID (optional)', query: 'Query objects', graph: 'Load neighborhood', export: 'Export STIX bundle', noObjects: 'No permitted STIX objects matched this query.',
    format: 'Format', loadArtifacts: 'Load artifacts', noArtifacts: 'No imported detection artifacts are available.', nonExecutable: 'Review only — these artifacts are never executed automatically.',
    refreshOps: 'Refresh operations', jobs: 'Background jobs', audit: 'Audit events', metrics: 'Metrics', empty: 'No records available.', retry: 'Try again',
  },
  zh: {
    extract: '文本提取', stix: 'STIX 图谱', artifacts: '检测制品', admin: '运维状态',
    paste: '粘贴邮件、工单或新闻正文', placeholder: '粘贴包含反混淆 URL、域名、IP、哈希或 CVE 的正文…', run: '提取 IOC', running: '提取中…', local: '本地命中', noIocs: '未发现受支持的 IOC。',
    type: '对象类型', id: '对象 ID（可选）', query: '查询对象', graph: '加载关系邻域', export: '导出 STIX Bundle', noObjects: '没有匹配且当前角色可访问的 STIX 对象。',
    format: '格式', loadArtifacts: '加载检测制品', noArtifacts: '当前没有导入的检测制品。', nonExecutable: '仅供审阅——这些制品不会被自动执行。',
    refreshOps: '刷新运维状态', jobs: '后台任务', audit: '审计事件', metrics: '指标', empty: '暂无记录。', retry: '重试',
  },
};

interface ExtractedIoc { value: string; indicatorType: string; localMatch: boolean }
interface Job { id: string; type: string; status: string; attempts: number; lastError: string; updatedAt: number }
interface AuditEvent { ts: string; role: string; principal: string; action: string; path: string; ok: boolean; detail: string }

function ErrorNotice({ message }: { message: string }) {
  return <div role="alert" className="flex items-start gap-2 rounded-lg border border-red-400/45 bg-red-500/10 px-4 py-3 text-sm text-red-200"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><span className="break-words">{message}</span></div>;
}

export function OperationsWorkspace({ lang }: { lang: Language }) {
  const t = TEXT[lang];
  const [view, setView] = useState<View>('extract');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [text, setText] = useState('');
  const [iocs, setIocs] = useState<ExtractedIoc[]>([]);
  const [stixType, setStixType] = useState('indicator');
  const [stixId, setStixId] = useState('');
  const [stixObjects, setStixObjects] = useState<StixObject[]>([]);
  const [artifactFormat, setArtifactFormat] = useState('sigma');
  const [artifacts, setArtifacts] = useState<DetectionArtifact[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [metrics, setMetrics] = useState('');

  const run = async (work: () => Promise<void>) => {
    setBusy(true); setError(null);
    try { await work(); } catch (err) { setError(err instanceof Error ? err.message : String(err)); }
    finally { setBusy(false); }
  };

  const extract = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const result = await apiJson<{ iocs: ExtractedIoc[] }>('/api/extract-iocs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text }) });
      setIocs(result.iocs);
    });
  };

  const queryStix = () => void run(async () => {
    const params = new URLSearchParams();
    if (stixType.trim()) params.set('type', stixType.trim());
    if (stixId.trim()) params.set('id', stixId.trim());
    const result = await apiJson<{ objects: StixObject[] }>(`/api/stix/objects?${params}`);
    setStixObjects(result.objects);
  });

  const loadGraph = () => void run(async () => {
    if (!stixId.trim()) throw new Error(lang === 'zh' ? '请先输入对象 ID。' : 'Enter an object ID first.');
    const result = await apiJson<{ objects: StixObject[] }>(`/api/stix/graph/${encodeURIComponent(stixId.trim())}?depth=1`);
    setStixObjects(result.objects);
  });

  const exportStix = () => void run(async () => {
    const response = await apiFetch('/api/export/stix');
    if (!response.ok) throw new Error(await response.text());
    const blob = await response.blob();
    const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
    anchor.href = url; anchor.download = 'threat-intel-stix.json'; anchor.click(); URL.revokeObjectURL(url);
  });

  const loadArtifacts = () => void run(async () => {
    const result = await apiJson<{ artifacts: DetectionArtifact[] }>(`/api/detection-artifacts?format=${artifactFormat}`);
    setArtifacts(result.artifacts);
  });

  const loadOperations = () => void run(async () => {
    const settled = await Promise.allSettled([
      apiJson<{ jobs: Job[] }>('/api/jobs'), apiJson<{ events: AuditEvent[] }>('/api/audit?limit=50'), fetchText('/api/metrics'),
    ]);
    if (settled[0].status === 'fulfilled') setJobs(settled[0].value.jobs);
    if (settled[1].status === 'fulfilled') setAudit(settled[1].value.events);
    if (settled[2].status === 'fulfilled') setMetrics(settled[2].value);
    const failures = settled.filter((item): item is PromiseRejectedResult => item.status === 'rejected');
    if (failures.length === settled.length) throw failures[0].reason;
    if (failures.length) setError(lang === 'zh' ? '部分管理员数据因权限不足不可用。' : 'Some admin data is unavailable for the current role.');
  });

  const tabs: Array<{ id: View; label: string }> = [{ id: 'extract', label: t.extract }, { id: 'stix', label: t.stix }, { id: 'artifacts', label: t.artifacts }, { id: 'admin', label: t.admin }];
  return <div className="space-y-4">
    <div role="tablist" aria-label={t.admin} className="flex flex-wrap gap-2 rounded-lg bg-panel-2/60 p-2">
      {tabs.map((tab) => <button key={tab.id} type="button" role="tab" aria-selected={view === tab.id} onClick={() => setView(tab.id)} className={`control min-h-11 px-4 text-sm font-semibold ${view === tab.id ? 'bg-teal-300/15 text-teal-100' : 'text-slate-300'}`}>{tab.label}</button>)}
    </div>
    {error && <ErrorNotice message={error} />}

    {view === 'extract' && <form onSubmit={extract} className="surface rounded-lg p-4">
      <label htmlFor="extract-text" className="mb-2 block text-sm font-semibold text-slate-200">{t.paste}</label>
      <textarea id="extract-text" rows={8} maxLength={200000} value={text} onChange={(event) => setText(event.target.value)} placeholder={t.placeholder} className="control w-full resize-y p-3 font-mono text-sm" />
      <button disabled={busy || !text.trim()} className="primary-action control mt-3 inline-flex min-h-11 items-center gap-2 px-4 text-sm font-bold disabled:opacity-50"><FileSearch className="h-4 w-4" aria-hidden="true" />{busy ? t.running : t.run}</button>
      <div className="mt-4 space-y-2" aria-live="polite">{iocs.length ? iocs.map((ioc) => <div key={`${ioc.indicatorType}:${ioc.value}`} className="surface-raised flex flex-wrap items-start justify-between gap-2 rounded-lg p-3"><code className="min-w-0 break-all text-sm text-sky-300">{ioc.value}</code><span className="text-xs text-slate-400">{ioc.indicatorType}{ioc.localMatch ? ` · ${t.local}` : ''}</span></div>) : <p className="text-sm text-slate-400">{t.noIocs}</p>}</div>
    </form>}

    {view === 'stix' && <section className="surface rounded-lg p-4">
      <div className="grid gap-3 md:grid-cols-2"><label className="text-sm text-slate-300">{t.type}<input value={stixType} onChange={(e) => setStixType(e.target.value)} className="control mt-2 w-full px-3 text-sm" /></label><label className="text-sm text-slate-300">{t.id}<input value={stixId} onChange={(e) => setStixId(e.target.value)} className="control mt-2 w-full px-3 font-mono text-sm" /></label></div>
      <div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={queryStix} disabled={busy} className="primary-action control min-h-11 px-4 text-sm font-bold"><Braces className="mr-2 inline h-4 w-4" aria-hidden="true" />{t.query}</button><button type="button" onClick={loadGraph} disabled={busy || !stixId.trim()} className="control min-h-11 px-4 text-sm">{t.graph}</button><button type="button" onClick={exportStix} disabled={busy} className="control min-h-11 px-4 text-sm"><Download className="mr-2 inline h-4 w-4" aria-hidden="true" />{t.export}</button></div>
      <div className="mt-4 space-y-2">{stixObjects.length ? stixObjects.map((object, index) => <details key={`${object.id}:${object.modified ?? index}`} className="surface-raised rounded-lg p-3"><summary className="break-all text-sm font-semibold text-sky-300">{object.type} · {object.id}</summary><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs text-slate-300">{JSON.stringify(object, null, 2)}</pre></details>) : <p className="text-sm text-slate-400">{t.noObjects}</p>}</div>
    </section>}

    {view === 'artifacts' && <section className="surface rounded-lg p-4"><p className="mb-3 text-sm text-amber-200">{t.nonExecutable}</p><div className="flex flex-wrap items-end gap-3"><label className="text-sm text-slate-300">{t.format}<select value={artifactFormat} onChange={(e) => setArtifactFormat(e.target.value)} className="control mt-2 block min-w-40 px-3"><option value="sigma">Sigma</option><option value="yara">YARA</option><option value="snort">Snort</option></select></label><button type="button" onClick={loadArtifacts} disabled={busy} className="primary-action control min-h-11 px-4 text-sm font-bold">{t.loadArtifacts}</button></div><div className="mt-4 space-y-2">{artifacts.length ? artifacts.map((artifact) => <details key={artifact.id} className="surface-raised rounded-lg p-3"><summary className="break-words text-sm font-semibold text-slate-100">{artifact.title}</summary><pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-all text-xs text-slate-300">{artifact.content}</pre></details>) : <p className="text-sm text-slate-400">{t.noArtifacts}</p>}</div></section>}

    {view === 'admin' && <section className="space-y-4"><button type="button" onClick={loadOperations} disabled={busy} className="primary-action control min-h-11 px-4 text-sm font-bold"><RefreshCw className="mr-2 inline h-4 w-4" aria-hidden="true" />{t.refreshOps}</button><div className="grid gap-4 xl:grid-cols-2"><div className="surface rounded-lg p-4"><h2 className="section-title">{t.jobs}</h2><div className="mt-3 space-y-2">{jobs.length ? jobs.map((job) => <div key={job.id} className="surface-raised rounded-lg p-3 text-xs"><div className="flex flex-wrap justify-between gap-2"><span className="break-all font-mono text-sky-300">{job.type}</span><span>{job.status} · {job.attempts}</span></div>{job.lastError && <p className="mt-2 break-words text-red-200">{job.lastError}</p>}</div>) : <p className="text-sm text-slate-400">{t.empty}</p>}</div></div><div className="surface rounded-lg p-4"><h2 className="section-title">{t.audit}</h2><div className="mt-3 max-h-96 space-y-2 overflow-auto">{audit.length ? audit.map((event, index) => <div key={`${event.ts}:${index}`} className="surface-raised rounded-lg p-3 text-xs"><div className="break-words text-slate-200">{event.action} · {event.ok ? 'OK' : 'FAILED'}</div><div className="mt-1 break-all text-slate-500">{event.principal} · {event.path}</div></div>) : <p className="text-sm text-slate-400">{t.empty}</p>}</div></div></div><details className="surface rounded-lg p-4"><summary className="section-title">{t.metrics}</summary><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs text-slate-300">{metrics || t.empty}</pre></details></section>}
  </div>;
}
