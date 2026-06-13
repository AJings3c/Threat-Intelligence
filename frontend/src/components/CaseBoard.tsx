import { useState, useEffect } from 'react';
import { Plus, Folder, User, Calendar, MessageSquare, AlertCircle } from 'lucide-react';
import type { Language, Severity } from '../types';

type CaseStatus = 'open' | 'investigating' | 'resolved' | 'closed';

interface CaseComment {
  id: string;
  caseId: string;
  author: string;
  content: string;
  createdAt: number;
}

interface Case {
  id: string;
  title: string;
  status: CaseStatus;
  severity: Severity;
  assignee?: string;
  iocIds: string[];
  comments: CaseComment[];
  createdAt: number;
  updatedAt: number;
}

const CASE_TEXT = {
  en: {
    title: 'Cases',
    subtitle: 'Collaborative incident investigation and tracking',
    createCase: 'Create Case',
    caseTitle: 'Case Title',
    titlePlaceholder: 'APT campaign targeting financial sector',
    severity: 'Severity',
    assignee: 'Assignee (optional)',
    assigneePlaceholder: 'analyst@example.com',
    create: 'Create',
    cancel: 'Cancel',
    noCases: 'No cases found',
    open: 'Open',
    investigating: 'Investigating',
    resolved: 'Resolved',
    closed: 'Closed',
    iocs: 'IOCs',
    comments: 'Comments',
    createdAt: 'Created',
    updatedAt: 'Updated',
    moveToInvestigating: 'Start Investigation',
    moveToResolved: 'Mark Resolved',
    moveToClosed: 'Close Case',
    reopen: 'Reopen',
  },
  zh: {
    title: '案例',
    subtitle: '协作事件调查与跟踪',
    createCase: '创建案例',
    caseTitle: '案例标题',
    titlePlaceholder: 'APT 针对金融行业的攻击活动',
    severity: '严重性',
    assignee: '负责人（可选）',
    assigneePlaceholder: 'analyst@example.com',
    create: '创建',
    cancel: '取消',
    noCases: '无案例',
    open: '待处理',
    investigating: '调查中',
    resolved: '已解决',
    closed: '已关闭',
    iocs: 'IOC 数量',
    comments: '评论',
    createdAt: '创建时间',
    updatedAt: '更新时间',
    moveToInvestigating: '开始调查',
    moveToResolved: '标记为已解决',
    moveToClosed: '关闭案例',
    reopen: '重新打开',
  },
};

const STATUS_COLORS = {
  open: 'bg-blue-300/15 text-blue-100',
  investigating: 'bg-amber-300/15 text-amber-100',
  resolved: 'bg-emerald-300/15 text-emerald-100',
  closed: 'bg-slate-500/15 text-slate-400',
};

const SEVERITY_COLORS = {
  critical: 'bg-red-300/15 text-red-100',
  high: 'bg-orange-300/15 text-orange-100',
  medium: 'bg-yellow-300/15 text-yellow-100',
  low: 'bg-blue-300/15 text-blue-100',
};

export function CaseBoard({ lang }: { lang: Language }) {
  const [cases, setCases] = useState<Case[]>([]);
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [formTitle, setFormTitle] = useState('');
  const [formSeverity, setFormSeverity] = useState<Severity>('medium');
  const [formAssignee, setFormAssignee] = useState('');

  const t = CASE_TEXT[lang];

  const loadCases = async () => {
    setLoading(true);
    try {
      const response = await fetch('/api/cases');
      if (!response.ok) throw new Error(`Failed to load cases: ${response.status}`);
      const data = (await response.json()) as { cases: Case[] };
      setCases(data.cases);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load cases');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadCases();
  }, []);

  const handleCreate = async () => {
    if (!formTitle.trim()) return;

    try {
      const response = await fetch('/api/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: formTitle,
          severity: formSeverity,
          assignee: formAssignee || undefined,
        }),
      });

      if (!response.ok) throw new Error(`Failed to create case: ${response.status}`);

      await loadCases();
      setCreating(false);
      setFormTitle('');
      setFormSeverity('medium');
      setFormAssignee('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create case');
    }
  };

  const updateCaseStatus = async (caseId: string, status: CaseStatus) => {
    try {
      const response = await fetch(`/api/cases/${caseId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });

      if (!response.ok) throw new Error(`Failed to update case: ${response.status}`);
      await loadCases();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update case');
    }
  };

  const casesByStatus = {
    open: cases.filter((c) => c.status === 'open'),
    investigating: cases.filter((c) => c.status === 'investigating'),
    resolved: cases.filter((c) => c.status === 'resolved'),
    closed: cases.filter((c) => c.status === 'closed'),
  };

  if (loading) {
    return (
      <div className="py-12 text-center text-sm text-slate-400">
        <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-teal-200 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {error && (
        <div className="flex items-start gap-3 rounded-lg border border-red-400/45 bg-red-500/10 px-4 py-3 text-sm text-red-200">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex justify-between">
        <div />
        <button
          type="button"
          onClick={() => setCreating(!creating)}
          className="primary-action control inline-flex items-center gap-2 px-4 py-2 text-sm font-bold"
        >
          <Plus className="h-4 w-4" />
          {t.createCase}
        </button>
      </div>

      {creating && (
        <div className="surface rounded-lg p-4">
          <div className="mb-4">
            <label htmlFor="case-title" className="mb-2 block text-sm font-semibold text-slate-300">
              {t.caseTitle}
            </label>
            <input
              id="case-title"
              type="text"
              value={formTitle}
              onChange={(e) => setFormTitle(e.target.value)}
              placeholder={t.titlePlaceholder}
              className="control w-full text-sm"
            />
          </div>

          <div className="mb-4">
            <label className="mb-2 block text-sm font-semibold text-slate-300">{t.severity}</label>
            <div className="grid grid-cols-4 gap-2">
              {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setFormSeverity(sev)}
                  className={`control px-3 py-2 text-sm capitalize ${
                    formSeverity === sev ? SEVERITY_COLORS[sev] : 'text-slate-300'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <div className="mb-4">
            <label htmlFor="case-assignee" className="mb-2 block text-sm font-semibold text-slate-300">
              {t.assignee}
            </label>
            <input
              id="case-assignee"
              type="text"
              value={formAssignee}
              onChange={(e) => setFormAssignee(e.target.value)}
              placeholder={t.assigneePlaceholder}
              className="control w-full text-sm"
            />
          </div>

          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleCreate}
              disabled={!formTitle.trim()}
              className="primary-action control px-4 py-2 text-sm font-bold disabled:opacity-50"
            >
              {t.create}
            </button>
            <button type="button" onClick={() => setCreating(false)} className="control px-4 py-2 text-sm">
              {t.cancel}
            </button>
          </div>
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-4">
        {(['open', 'investigating', 'resolved', 'closed'] as CaseStatus[]).map((status) => (
          <div key={status} className="surface rounded-lg p-3">
            <div className="mb-3 flex items-center justify-between">
              <h3 className={`text-sm font-bold ${STATUS_COLORS[status]}`}>{t[status]}</h3>
              <span className="rounded bg-slate-500/20 px-2 py-0.5 text-xs font-bold text-slate-400">
                {casesByStatus[status].length}
              </span>
            </div>

            <div className="space-y-2">
              {casesByStatus[status].length === 0 ? (
                <div className="py-6 text-center text-xs text-slate-500">{t.noCases}</div>
              ) : (
                casesByStatus[status].map((caseItem) => (
                  <div key={caseItem.id} className="surface-raised rounded-lg p-3">
                    <div className="mb-2">
                      <div className="mb-1 flex items-start gap-2">
                        <Folder className="mt-0.5 h-3.5 w-3.5 shrink-0 text-teal-200" />
                        <h4 className="flex-1 text-sm font-semibold text-slate-100">{caseItem.title}</h4>
                      </div>
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-bold ${SEVERITY_COLORS[caseItem.severity]}`}>
                        {caseItem.severity}
                      </span>
                    </div>

                    {caseItem.assignee && (
                      <div className="mb-2 flex items-center gap-1.5 text-xs text-slate-400">
                        <User className="h-3 w-3" />
                        {caseItem.assignee}
                      </div>
                    )}

                    <div className="mb-2 flex items-center gap-3 text-xs text-slate-500">
                      <span>{caseItem.iocIds.length} {t.iocs}</span>
                      <span className="flex items-center gap-1">
                        <MessageSquare className="h-3 w-3" />
                        {caseItem.comments.length}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-slate-500">
                      <Calendar className="h-3 w-3" />
                      {new Date(caseItem.updatedAt).toLocaleDateString()}
                    </div>

                    <div className="mt-2 flex gap-1">
                      {status === 'open' && (
                        <button
                          type="button"
                          onClick={() => updateCaseStatus(caseItem.id, 'investigating')}
                          className="control w-full px-2 py-1 text-xs"
                        >
                          {t.moveToInvestigating}
                        </button>
                      )}
                      {status === 'investigating' && (
                        <button
                          type="button"
                          onClick={() => updateCaseStatus(caseItem.id, 'resolved')}
                          className="control w-full px-2 py-1 text-xs"
                        >
                          {t.moveToResolved}
                        </button>
                      )}
                      {status === 'resolved' && (
                        <button
                          type="button"
                          onClick={() => updateCaseStatus(caseItem.id, 'closed')}
                          className="control w-full px-2 py-1 text-xs"
                        >
                          {t.moveToClosed}
                        </button>
                      )}
                      {status === 'closed' && (
                        <button
                          type="button"
                          onClick={() => updateCaseStatus(caseItem.id, 'open')}
                          className="control w-full px-2 py-1 text-xs"
                        >
                          {t.reopen}
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
