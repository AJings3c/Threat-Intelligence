/* eslint-disable react-refresh/only-export-components -- this module intentionally shares presentation constants, helpers, and small components. */
import { ExternalLink } from 'lucide-react';
import type {
  KnowledgeEntity,
  KnowledgeEntityType,
  KnowledgeEvidence,
  KnowledgeExternalReference,
  KnowledgeSource,
  KnowledgeTlp,
  Language,
} from '../../types';

export type InspectorMode = 'graph' | 'relations' | 'evidence';

export const TEXT = {
  en: {
    search: 'Search names, aliases or external IDs',
    clearSearch: 'Clear search',
    allTypes: 'All entity types',
    directory: 'Entity directory',
    resultCount: 'entities',
    noEntities: 'No visible knowledge entities match this query.',
    unavailable: 'Threat knowledge is unavailable.',
    detailFailed: 'Entity detail could not be loaded.',
    graphFailed: 'Relationship graph could not be loaded.',
    retry: 'Retry',
    inspectorViews: 'Entity inspector views',
    noSelection: 'Select an entity to inspect its evidence and relationships.',
    previous: 'Previous page',
    next: 'Next page',
    page: 'Page',
    of: 'of',
    confidence: 'Confidence',
    unknown: 'Unknown',
    modified: 'Modified',
    validity: 'Validity',
    aliases: 'Aliases',
    externalIds: 'External references',
    sources: 'Sources',
    evidence: 'Evidence',
    graph: 'Graph',
    relations: 'Relationships',
    sightings: 'Sightings',
    depth: 'Depth',
    refresh: 'Refresh selected entity',
    loading: 'Loading threat knowledge',
    noRelations: 'No visible relationships for this entity.',
    noEvidence: 'No visible evidence for this entity.',
    noSources: 'No source metadata is available.',
    noReferences: 'No external references are available.',
    collected: 'Collected',
    observed: 'Observed',
    source: 'Source',
    target: 'Target',
    relationship: 'Relationship',
    count: 'Count',
    lastSeen: 'Last seen',
    revoked: 'Revoked',
    active: 'Active',
    factDetails: 'Fact provenance',
    description: 'Description',
    validFrom: 'Valid from',
    validUntil: 'Valid until',
    objectRefs: 'Object refs',
  },
  zh: {
    search: '搜索名称、别名或外部编号',
    clearSearch: '清除搜索',
    allTypes: '全部实体类型',
    directory: '实体目录',
    resultCount: '个实体',
    noEntities: '没有符合当前条件且有权查看的知识实体。',
    unavailable: '威胁知识当前不可用。',
    detailFailed: '实体详情加载失败。',
    graphFailed: '关系图加载失败。',
    retry: '重试',
    inspectorViews: '实体检查视图',
    noSelection: '选择一个实体以查看证据和关系。',
    previous: '上一页',
    next: '下一页',
    page: '第',
    of: '页，共',
    confidence: '置信度',
    unknown: '未知',
    modified: '更新时间',
    validity: '有效期',
    aliases: '别名',
    externalIds: '外部引用',
    sources: '来源',
    evidence: '证据',
    graph: '关系图',
    relations: '关系列表',
    sightings: '观测',
    depth: '深度',
    refresh: '刷新所选实体',
    loading: '正在加载威胁知识',
    noRelations: '该实体没有可见关系。',
    noEvidence: '该实体没有可见证据。',
    noSources: '没有可用的来源元数据。',
    noReferences: '没有可用的外部引用。',
    collected: '采集时间',
    observed: '观测时间',
    source: '源实体',
    target: '目标实体',
    relationship: '关系',
    count: '次数',
    lastSeen: '最近观测',
    revoked: '已撤销',
    active: '有效',
    factDetails: '事实溯源',
    description: '描述',
    validFrom: '起始有效期',
    validUntil: '终止有效期',
    objectRefs: '对象引用',
  },
} as const;

export const TYPE_LABEL: Record<Language, Record<KnowledgeEntityType, string>> = {
  en: {
    'threat-actor': 'Threat actor',
    'intrusion-set': 'Intrusion set',
    campaign: 'Campaign',
    malware: 'Malware',
    tool: 'Tool',
    'attack-pattern': 'Attack pattern',
    identity: 'Identity',
    vulnerability: 'Vulnerability',
    infrastructure: 'Infrastructure',
    indicator: 'Indicator',
  },
  zh: {
    'threat-actor': '威胁行为者',
    'intrusion-set': '入侵集',
    campaign: '攻击战役',
    malware: '恶意软件',
    tool: '工具',
    'attack-pattern': '攻击模式',
    identity: '身份/组织',
    vulnerability: '漏洞',
    infrastructure: '基础设施',
    indicator: '指标',
  },
};

export const TYPE_COLOR: Record<KnowledgeEntityType, string> = {
  'threat-actor': '#fb7185',
  'intrusion-set': '#f97316',
  campaign: '#fbbf24',
  malware: '#c084fc',
  tool: '#60a5fa',
  'attack-pattern': '#22d3ee',
  identity: '#4ade80',
  vulnerability: '#fb923c',
  infrastructure: '#94a3b8',
  indicator: '#2dd4bf',
};

const TLP_CLASS: Record<KnowledgeTlp, string> = {
  clear: 'border-slate-400/50 bg-slate-400/10 text-slate-300',
  green: 'border-emerald-400/45 bg-emerald-400/10 text-emerald-300',
  amber: 'border-amber-400/45 bg-amber-400/10 text-amber-300',
  red: 'border-red-400/45 bg-red-400/10 text-red-300',
  unknown: 'border-purple-400/45 bg-purple-400/10 text-purple-300',
};

export function formatDate(value: string | undefined, lang: Language): string {
  if (!value) return '-';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString(lang === 'zh' ? 'zh-CN' : 'en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function safeHttpUrl(value: string | undefined): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.toString() : null;
  } catch {
    return null;
  }
}

export function TlpBadge({ value }: { value: KnowledgeTlp }) {
  return (
    <span className={`inline-flex min-h-6 items-center rounded border px-2 py-0.5 text-[11px] font-bold uppercase ${TLP_CLASS[value]}`}>
      TLP:{value}
    </span>
  );
}

export function EntityTypeLabel({ entity, lang }: { entity: KnowledgeEntity; lang: Language }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-400">
      <span className="h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: TYPE_COLOR[entity.type] }} />
      {TYPE_LABEL[lang][entity.type]}
    </span>
  );
}

export function LoadingRows() {
  return (
    <div className="divide-y divide-line/40" aria-hidden="true">
      {Array.from({ length: 7 }, (_, index) => (
        <div key={index} className="animate-pulse px-4 py-3">
          <div className="h-3 w-24 rounded bg-slate-700/70" />
          <div className="mt-2 h-4 w-2/3 rounded bg-slate-700/60" />
          <div className="mt-2 h-3 w-1/2 rounded bg-slate-800/80" />
        </div>
      ))}
    </div>
  );
}

export function FactProvenance({
  description,
  sources,
  evidence,
  externalReferences,
  validFrom,
  validUntil,
  lang,
}: {
  description?: string;
  sources: KnowledgeSource[];
  evidence: KnowledgeEvidence[];
  externalReferences: KnowledgeExternalReference[];
  validFrom?: string;
  validUntil?: string;
  lang: Language;
}) {
  const t = TEXT[lang];
  return (
    <div className="border-t border-line/45 bg-panel-2/25 px-4 py-4">
      {(description || validFrom || validUntil) && (
        <div className="mb-4 grid gap-4 border-b border-line/40 pb-4 md:grid-cols-3">
          <div className="md:col-span-2">
            <div className="text-xs font-semibold text-slate-500">{t.description}</div>
            <p className="mt-1 break-words text-sm leading-6 text-slate-300">{description || '-'}</p>
          </div>
          <dl className="space-y-2 text-xs">
            <div><dt className="font-semibold text-slate-500">{t.validFrom}</dt><dd className="mt-1 text-slate-300">{formatDate(validFrom, lang)}</dd></div>
            <div><dt className="font-semibold text-slate-500">{t.validUntil}</dt><dd className="mt-1 text-slate-300">{formatDate(validUntil, lang)}</dd></div>
          </dl>
        </div>
      )}
      <div className="grid gap-5 md:grid-cols-3">
        <section className="min-w-0">
          <h4 className="text-xs font-bold text-slate-400">{t.sources}</h4>
          <div className="mt-2 divide-y divide-line/35">
            {sources.map((source, index) => (
              <div key={`${source.kind}:${source.name}:${index}`} className="py-2 first:pt-0">
                <div className="break-words text-xs font-semibold text-slate-200">{source.name}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-slate-500">
                  <span>{source.kind}</span>
                  {source.reliability && <span>{source.reliability}</span>}
                  {source.collectedAt && <span>{formatDate(source.collectedAt, lang)}</span>}
                </div>
              </div>
            ))}
            {sources.length === 0 && <p className="py-2 text-xs text-slate-500">{t.noSources}</p>}
          </div>
        </section>
        <section className="min-w-0">
          <h4 className="text-xs font-bold text-slate-400">{t.externalIds}</h4>
          <div className="mt-2 divide-y divide-line/35">
            {externalReferences.map((reference, index) => {
              const href = safeHttpUrl(reference.url);
              return (
                <div key={`${reference.sourceName}:${reference.externalId ?? reference.url ?? index}`} className="py-2 first:pt-0">
                  <div className="text-[11px] font-semibold text-slate-500">{reference.sourceName}</div>
                  {href ? (
                    <a href={href} target="_blank" rel="noreferrer" className="mt-1 inline-flex max-w-full items-start gap-1 break-all text-xs font-semibold text-sky-300 hover:underline">
                      <span>{reference.externalId ?? reference.url}</span><ExternalLink className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" />
                    </a>
                  ) : <div className="mt-1 break-all text-xs text-slate-300">{reference.externalId ?? '-'}</div>}
                </div>
              );
            })}
            {externalReferences.length === 0 && <p className="py-2 text-xs text-slate-500">{t.noReferences}</p>}
          </div>
        </section>
        <section className="min-w-0">
          <h4 className="text-xs font-bold text-slate-400">{t.evidence}</h4>
          <div className="mt-2 max-h-72 divide-y divide-line/35 overflow-y-auto pr-1">
            {evidence.map((item) => {
              const href = safeHttpUrl(item.reference);
              return (
                <div key={item.id} className="py-2 first:pt-0">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[11px] font-semibold text-slate-500">{item.kind}</span>
                    <span className="flex items-center gap-2">
                      {item.confidence !== undefined && <span className="text-[11px] font-semibold text-slate-400">{item.confidence}%</span>}
                      {item.tlp && <TlpBadge value={item.tlp} />}
                    </span>
                  </div>
                  <p className="mt-1 break-words text-xs leading-5 text-slate-300">{item.summary}</p>
                  <div className="mt-1 text-[11px] text-slate-500">{item.source.name} · {formatDate(item.collectedAt, lang)}</div>
                  {item.objectRefs.length > 0 && <div className="mt-1 break-all text-[11px] leading-4 text-slate-500">{t.objectRefs}: {item.objectRefs.join(', ')}</div>}
                  {href && <a href={href} target="_blank" rel="noreferrer" className="mt-1 inline-flex max-w-full items-start gap-1 break-all text-[11px] font-semibold text-sky-300 hover:underline"><span>{item.reference}</span><ExternalLink className="mt-0.5 h-3 w-3 shrink-0" aria-hidden="true" /></a>}
                </div>
              );
            })}
            {evidence.length === 0 && <p className="py-2 text-xs text-slate-500">{t.noEvidence}</p>}
          </div>
        </section>
      </div>
    </div>
  );
}
