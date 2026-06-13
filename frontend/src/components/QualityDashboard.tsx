import { useState, useEffect } from 'react';
import { BarChart3, TrendingUp, AlertTriangle, CheckCircle } from 'lucide-react';
import type { Language } from '../types';

interface QualityDistribution {
  excellent: number;
  high: number;
  medium: number;
  low: number;
  unreliable: number;
  total: number;
}

interface QualityTrendPoint {
  date: string;
  averageScore: number;
  count: number;
}

interface FalsePositive {
  iocValue: string;
  markedBy: string;
  reason: string | null;
  markedAt: number;
}

const QUALITY_TEXT = {
  en: {
    title: 'Intelligence Quality',
    subtitle: 'Quality scoring, time decay, and false positive tracking',
    distribution: 'Quality Distribution',
    trend: 'Quality Trend (30 days)',
    falsePositives: 'False Positives',
    excellent: 'Excellent',
    high: 'High',
    medium: 'Medium',
    low: 'Low',
    unreliable: 'Unreliable',
    score: 'Score',
    count: 'Count',
    averageScore: 'Avg Score',
    markedBy: 'Marked By',
    reason: 'Reason',
    markedAt: 'Marked At',
    noFalsePositives: 'No false positives marked',
    loading: 'Loading...',
  },
  zh: {
    title: '情报质量',
    subtitle: '质量评分、时间衰减与假阳性跟踪',
    distribution: '质量分布',
    trend: '质量趋势（30天）',
    falsePositives: '假阳性',
    excellent: '优秀',
    high: '高',
    medium: '中',
    low: '低',
    unreliable: '不可靠',
    score: '评分',
    count: '数量',
    averageScore: '平均分',
    markedBy: '标记人',
    reason: '原因',
    markedAt: '标记时间',
    noFalsePositives: '无假阳性标记',
    loading: '加载中...',
  },
};

const GRADE_COLORS = {
  excellent: 'bg-emerald-300/15 text-emerald-100',
  high: 'bg-teal-300/15 text-teal-100',
  medium: 'bg-yellow-300/15 text-yellow-100',
  low: 'bg-orange-300/15 text-orange-100',
  unreliable: 'bg-red-300/15 text-red-100',
};

export function QualityDashboard({ lang }: { lang: Language }) {
  const [distribution, setDistribution] = useState<QualityDistribution | null>(null);
  const [trend, setTrend] = useState<QualityTrendPoint[]>([]);
  const [falsePositives, setFalsePositives] = useState<FalsePositive[]>([]);
  const [loading, setLoading] = useState(true);

  const t = QUALITY_TEXT[lang];

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [distResponse, trendResponse, fpResponse] = await Promise.all([
          fetch('/api/quality/distribution'),
          fetch('/api/quality/trend?days=30'),
          fetch('/api/quality/false-positives'),
        ]);

        if (distResponse.ok) {
          const distData = (await distResponse.json()) as QualityDistribution;
          setDistribution(distData);
        }

        if (trendResponse.ok) {
          const trendData = (await trendResponse.json()) as { trend: QualityTrendPoint[] };
          setTrend(trendData.trend);
        }

        if (fpResponse.ok) {
          const fpData = (await fpResponse.json()) as { falsePositives: FalsePositive[] };
          setFalsePositives(fpData.falsePositives);
        }
      } catch {
        // Non-blocking errors for quality dashboard
      } finally {
        setLoading(false);
      }
    };

    void loadData();
  }, []);

  if (loading) {
    return (
      <div className="py-12 text-center text-sm text-slate-400">
        <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-teal-200 border-t-transparent" />
        <div className="mt-2">{t.loading}</div>
      </div>
    );
  }

  const maxTrendScore = Math.max(...trend.map((p) => p.averageScore), 100);

  return (
    <div className="space-y-5">
      <div className="surface rounded-lg p-4">
        <div className="mb-4 flex items-center gap-2">
          <BarChart3 className="h-4 w-4 text-teal-200" />
          <h3 className="text-lg font-bold text-slate-50">{t.distribution}</h3>
        </div>

        {distribution && (
          <div className="space-y-3">
            {(
              [
                { key: 'excellent' as const, label: t.excellent, range: '81-100' },
                { key: 'high' as const, label: t.high, range: '61-80' },
                { key: 'medium' as const, label: t.medium, range: '41-60' },
                { key: 'low' as const, label: t.low, range: '21-40' },
                { key: 'unreliable' as const, label: t.unreliable, range: '0-20' },
              ] as const
            ).map((grade) => {
              const count = distribution[grade.key];
              const percentage = distribution.total > 0 ? (count / distribution.total) * 100 : 0;

              return (
                <div key={grade.key}>
                  <div className="mb-1 flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <span className={`rounded px-2 py-0.5 text-xs font-bold ${GRADE_COLORS[grade.key]}`}>
                        {grade.label}
                      </span>
                      <span className="text-xs text-slate-500">{grade.range}</span>
                    </div>
                    <span className="font-semibold text-slate-300">
                      {count} ({percentage.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-panel-2/60">
                    <div
                      className={`h-full transition-all ${GRADE_COLORS[grade.key]}`}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="surface rounded-lg p-4">
        <div className="mb-4 flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-teal-200" />
          <h3 className="text-lg font-bold text-slate-50">{t.trend}</h3>
        </div>

        {trend.length > 0 ? (
          <div className="relative h-48">
            <div className="absolute inset-0 flex items-end gap-1">
              {trend.map((point, index) => {
                const height = (point.averageScore / maxTrendScore) * 100;
                return (
                  <div key={index} className="group relative flex-1">
                    <div
                      className="w-full rounded-t bg-teal-300/30 transition-all group-hover:bg-teal-300/50"
                      style={{ height: `${height}%` }}
                    />
                    <div className="pointer-events-none absolute bottom-full left-1/2 mb-2 hidden -translate-x-1/2 whitespace-nowrap rounded bg-panel-3 px-2 py-1 text-xs text-slate-100 group-hover:block">
                      <div className="font-semibold">{new Date(point.date).toLocaleDateString()}</div>
                      <div className="text-slate-400">
                        {t.averageScore}: {point.averageScore}
                      </div>
                      <div className="text-slate-400">
                        {t.count}: {point.count}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ) : (
          <div className="py-8 text-center text-sm text-slate-400">No trend data available</div>
        )}
      </div>

      <div className="surface rounded-lg p-4">
        <div className="mb-4 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-200" />
          <h3 className="text-lg font-bold text-slate-50">{t.falsePositives}</h3>
          <span className="rounded bg-amber-300/15 px-2 py-0.5 text-xs font-bold text-amber-100">
            {falsePositives.length}
          </span>
        </div>

        {falsePositives.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-slate-400">
            <CheckCircle className="h-4 w-4 text-emerald-300" />
            {t.noFalsePositives}
          </div>
        ) : (
          <div className="space-y-2">
            {falsePositives.slice(0, 10).map((fp) => (
              <div key={fp.iocValue} className="surface-raised rounded-lg p-3">
                <div className="mb-1 flex items-start justify-between">
                  <code className="text-sm font-semibold text-red-200">{fp.iocValue}</code>
                  <span className="text-xs text-slate-500">
                    {new Date(fp.markedAt).toLocaleDateString()}
                  </span>
                </div>
                <div className="text-xs text-slate-400">
                  {t.markedBy}: {fp.markedBy}
                  {fp.reason && ` • ${fp.reason}`}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
