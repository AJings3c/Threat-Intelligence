import { useState, useEffect, useRef } from 'react';
import { Play, Pause, RotateCcw, ChevronLeft, ChevronRight } from 'lucide-react';
import type { Language, ThreatIndicator } from '../types';
import { evidenceCategory } from '../evidence';

interface TimelineEvent {
  id: string;
  timestamp: number;
  indicator: ThreatIndicator;
  category: string;
}

interface ActivityGroup {
  category: string;
  events: TimelineEvent[];
  color: string;
}

const TIMELINE_TEXT = {
  en: {
    title: 'Attack Timeline',
    subtitle: 'Chronological IOC observations grouped by evidence-backed categories',
    play: 'Play',
    pause: 'Pause',
    reset: 'Reset',
    speed: 'Speed',
    events: 'Events',
    noData: 'No timeline data available',
    currentEvent: 'Current Event',
    phase: 'Evidence category',
    indicator: 'Indicator',
    type: 'Type', previous: 'Previous event', next: 'Next event', eventLabel: 'Select event',
  },
  zh: {
    title: '攻击时间线',
    subtitle: '按可核验证据类别展示 IOC 观测时间线',
    play: '播放',
    pause: '暂停',
    reset: '重置',
    speed: '速度',
    events: '事件',
    noData: '无时间线数据',
    currentEvent: '当前事件',
    phase: '证据类别',
    indicator: '指标',
    type: '类型', previous: '上一事件', next: '下一事件', eventLabel: '选择事件',
  },
};

const ACTIVITY_CATEGORIES = [
  { id: 'phishing', en: 'Phishing indicator', zh: '钓鱼指标', color: '#8b5cf6' },
  { id: 'command-and-control', en: 'Command-and-control indicator', zh: '命令与控制指标', color: '#ef4444' },
  { id: 'malware', en: 'Malware indicator', zh: '恶意软件指标', color: '#ec4899' },
  { id: 'vulnerability', en: 'Vulnerability evidence', zh: '漏洞证据', color: '#f59e0b' },
  { id: 'scanner', en: 'Scanning activity', zh: '扫描活动', color: '#3b82f6' },
  { id: 'network', en: 'Malicious network indicator', zh: '恶意网络指标', color: '#f97316' },
  { id: 'social', en: 'Social intelligence mention', zh: '社交情报提及', color: '#06b6d4' },
  { id: 'other', en: 'Other observation', zh: '其他观测', color: '#64748b' },
];

function languageName(category: (typeof ACTIVITY_CATEGORIES)[number], lang: Language): string {
  return lang === 'zh' ? category.zh : category.en;
}

export function AttackTimeline({ lang, indicators }: { lang: Language; indicators: ThreatIndicator[] }) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [speed, setSpeed] = useState(1);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  const t = TIMELINE_TEXT[lang];

  const events: TimelineEvent[] = indicators
    .filter((ind) => ind.firstSeen)
    .sort((a, b) => {
      const aTime = typeof a.firstSeen === 'string' ? new Date(a.firstSeen).getTime() : (a.firstSeen ?? 0);
      const bTime = typeof b.firstSeen === 'string' ? new Date(b.firstSeen).getTime() : (b.firstSeen ?? 0);
      return aTime - bTime;
    })
    .slice(0, 50)
    .map((ind) => {
      const timestamp = typeof ind.firstSeen === 'string' ? new Date(ind.firstSeen).getTime() : (ind.firstSeen ?? Date.now());
      return {
        id: ind.id,
        timestamp,
        indicator: ind,
        category: evidenceCategory(ind),
      };
    });

  const groups: ActivityGroup[] = ACTIVITY_CATEGORIES.map((category) => ({
    category: languageName(category, lang),
    events: events.filter((event) => event.category === category.id),
    color: category.color,
  })).filter((phase) => phase.events.length > 0);

  useEffect(() => {
    if (isPlaying && currentIndex < events.length - 1) {
      intervalRef.current = setInterval(() => {
        setCurrentIndex((prev) => {
          if (prev >= events.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 2000 / speed);
    } else if (!isPlaying && intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [isPlaying, currentIndex, events.length, speed]);

  useEffect(() => {
    setCurrentIndex((index) => Math.min(index, Math.max(0, events.length - 1)));
  }, [events.length]);

  const handlePlayPause = () => {
    if (currentIndex >= events.length - 1) {
      setCurrentIndex(0);
    }
    setIsPlaying(!isPlaying);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentIndex(0);
  };

  const handlePrev = () => {
    setCurrentIndex((prev) => Math.max(0, prev - 1));
  };

  const handleNext = () => {
    setCurrentIndex((prev) => Math.min(events.length - 1, prev + 1));
  };

  if (events.length === 0) {
    return (
      <div className="surface flex h-96 items-center justify-center rounded-lg">
        <p className="text-sm text-slate-400">{t.noData}</p>
      </div>
    );
  }

  const currentEvent = events[currentIndex];
  const currentCategory = ACTIVITY_CATEGORIES.find((category) => category.id === currentEvent.category);
  const progress = events.length > 1 ? (currentIndex / (events.length - 1)) * 100 : 0;

  return (
    <div className="space-y-4">
      <div className="surface rounded-lg p-4">
        <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handlePlayPause}
              className="control inline-flex items-center gap-2 px-3 py-2 text-sm font-bold"
            >
              {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {isPlaying ? t.pause : t.play}
            </button>
            <button
              type="button"
              onClick={handleReset}
              className="control inline-flex items-center gap-2 px-3 py-2 text-sm"
            >
              <RotateCcw className="h-4 w-4" />
              {t.reset}
            </button>
            <button type="button" onClick={handlePrev} disabled={currentIndex === 0} aria-label={t.previous} className="control flex h-11 w-11 items-center justify-center text-sm disabled:opacity-40">
              <ChevronLeft className="h-4 w-4" aria-hidden="true" />
            </button>
            <button type="button" onClick={handleNext} disabled={currentIndex === events.length - 1} aria-label={t.next} className="control flex h-11 w-11 items-center justify-center text-sm disabled:opacity-40">
              <ChevronRight className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs text-slate-400">{t.speed}</span>
            <div className="flex gap-1">
              {[0.5, 1, 2, 4].map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSpeed(s)}
                  aria-pressed={speed === s}
                  className={`control min-h-11 min-w-11 px-2 text-xs ${speed === s ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400'}`}
                >
                  {s}x
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="relative mb-4">
          <div className="h-2 rounded-full bg-slate-700">
            <div
              className="h-full rounded-full bg-teal-400 transition-all duration-200"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="mt-2 flex justify-between text-xs text-slate-400">
            <span>
              {currentIndex + 1} / {events.length} {t.events}
            </span>
            <span>{new Date(currentEvent.timestamp).toLocaleString(lang === 'zh' ? 'zh-CN' : 'en-US')}</span>
          </div>
        </div>

        {currentEvent && (
          <div className="surface-raised rounded-lg p-4">
            <h3 className="mb-3 text-sm font-bold text-slate-200">{t.currentEvent}</h3>
            <div className="grid gap-3 md:grid-cols-3">
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-400">{t.phase}</div>
                <div
                  className="inline-block rounded px-2 py-1 text-xs font-bold"
                  style={{
                    backgroundColor: `${currentCategory?.color ?? '#64748b'}22`,
                    color: currentCategory?.color ?? '#94a3b8',
                  }}
                >
                  {currentCategory ? languageName(currentCategory, lang) : currentEvent.category}
                </div>
              </div>
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-400">{t.indicator}</div>
                <div className="font-mono text-sm text-slate-200">{currentEvent.indicator.indicator}</div>
              </div>
              <div>
                <div className="mb-1 text-xs font-semibold text-slate-400">{t.type}</div>
                <div className="inline-block rounded bg-slate-500/20 px-2 py-1 text-xs font-bold capitalize text-slate-300">
                  {currentEvent.indicator.indicatorType}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="surface rounded-lg p-4">
        <h3 className="mb-3 text-sm font-bold text-slate-200">{lang === 'zh' ? 'IOC 观测类别' : 'IOC observation categories'}</h3>
        <div className="space-y-2">
          {groups.map((group) => (
            <div key={group.category} className="surface-raised rounded-lg p-3">
              <div className="mb-2 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="h-3 w-3 rounded-full" style={{ backgroundColor: group.color }} />
                  <span className="text-sm font-semibold text-slate-200">{group.category}</span>
                </div>
                <span className="rounded bg-slate-500/20 px-2 py-0.5 text-xs font-bold text-slate-400">
                  {group.events.length}
                </span>
              </div>
              <div className="grid grid-cols-[repeat(auto-fit,minmax(44px,1fr))] gap-1">
                {group.events.map((event) => (
                  <button
                    key={event.id}
                    type="button"
                    onClick={() => setCurrentIndex(events.indexOf(event))}
                    aria-label={`${t.eventLabel}: ${event.indicator.indicator}`}
                    aria-pressed={events.indexOf(event) === currentIndex}
                    className="flex h-11 min-w-11 items-center"
                    title={event.indicator.indicator}
                  >
                    <span aria-hidden="true" className={`h-2 w-full rounded transition-all ${
                      events.indexOf(event) === currentIndex
                        ? 'bg-teal-400'
                        : events.indexOf(event) < currentIndex
                          ? 'bg-slate-500'
                          : 'bg-slate-700'
                    }`} />
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
