import { useMemo, useState } from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import type { Language, ThreatIndicator, Severity } from '../types';
import { Maximize2, Minimize2, Layers } from 'lucide-react';
import countries110m from 'world-atlas/countries-110m.json';

const GEO_DATA = countries110m as unknown as Record<string, unknown>;

const HEATMAP_TEXT = {
  en: {
    title: 'Geographic Threat Heatmap',
    subtitle: 'Global threat distribution with density visualization',
    fullscreen: 'Fullscreen',
    exitFullscreen: 'Exit Fullscreen',
    layer: 'Layer',
    points: 'Points',
    heatmap: 'Heatmap',
    density: 'Density',
    threats: 'threats',
    noData: 'No geographic data available',
  },
  zh: {
    title: '地理威胁热力图',
    subtitle: '全球威胁分布与密度可视化',
    fullscreen: '全屏',
    exitFullscreen: '退出全屏',
    layer: '图层',
    points: '点',
    heatmap: '热力图',
    density: '密度',
    threats: '威胁',
    noData: '无地理数据',
  },
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#fbbf24',
  low: '#60a5fa',
};

interface HeatmapCell {
  lat: number;
  lon: number;
  count: number;
  severity: number;
  color: string;
  radius: number;
}

function aggregateThreatsToGrid(threats: ThreatIndicator[], gridSize: number): HeatmapCell[] {
  const cells = new Map<string, { count: number; severities: number[] }>();

  threats.forEach((threat) => {
    if (threat.lat === undefined || threat.lon === undefined) return;

    const latCell = Math.floor(threat.lat / gridSize) * gridSize;
    const lonCell = Math.floor(threat.lon / gridSize) * gridSize;
    const key = `${latCell},${lonCell}`;

    const severityScore =
      threat.severity === 'critical' ? 4 :
      threat.severity === 'high' ? 3 :
      threat.severity === 'medium' ? 2 : 1;

    if (!cells.has(key)) {
      cells.set(key, { count: 0, severities: [] });
    }
    const cell = cells.get(key)!;
    cell.count += 1;
    cell.severities.push(severityScore);
  });

  const maxCount = Math.max(...Array.from(cells.values()).map((c) => c.count));

  return Array.from(cells.entries()).map(([key, data]) => {
    const [lat, lon] = key.split(',').map(Number);
    const avgSeverity = data.severities.reduce((a, b) => a + b, 0) / data.severities.length;
    const intensity = data.count / maxCount;

    const color =
      avgSeverity >= 3.5 ? '#dc2626' :
      avgSeverity >= 2.5 ? '#f97316' :
      avgSeverity >= 1.5 ? '#fbbf24' : '#60a5fa';

    return {
      lat: lat + gridSize / 2,
      lon: lon + gridSize / 2,
      count: data.count,
      severity: avgSeverity,
      color,
      radius: Math.sqrt(intensity) * 8 + 2,
    };
  });
}

export function ThreatHeatmap({ lang, indicators }: { lang: Language; indicators: ThreatIndicator[] }) {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [layerMode, setLayerMode] = useState<'points' | 'heatmap'>('heatmap');
  const t = HEATMAP_TEXT[lang];

  const geoIndicators = useMemo(() => {
    return indicators.filter((ind) => ind.lat !== undefined && ind.lon !== undefined);
  }, [indicators]);

  const heatmapCells = useMemo(() => {
    return aggregateThreatsToGrid(geoIndicators, 5);
  }, [geoIndicators]);

  const countryCounts = useMemo(() => {
    const counts = new Map<string, number>();
    geoIndicators.forEach((ind) => {
      if (ind.country) {
        counts.set(ind.country, (counts.get(ind.country) ?? 0) + 1);
      }
    });
    return counts;
  }, [geoIndicators]);

  const toggleFullscreen = () => {
    const container = document.getElementById('heatmap-container');
    if (!container) return;

    if (!isFullscreen) {
      container.requestFullscreen().then(() => setIsFullscreen(true));
    } else {
      document.exitFullscreen().then(() => setIsFullscreen(false));
    }
  };

  if (geoIndicators.length === 0) {
    return (
      <div className="surface flex h-96 items-center justify-center rounded-lg">
        <p className="text-sm text-slate-400">{t.noData}</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="text-sm text-slate-400">
          {geoIndicators.length} {t.threats} · {countryCounts.size} countries
        </div>
        <div className="flex gap-2">
          <div className="flex rounded-lg border border-line/60 bg-slate-800/50">
            <button
              type="button"
              onClick={() => setLayerMode('points')}
              className={`inline-flex items-center gap-2 px-3 py-1.5 text-xs transition-colors ${
                layerMode === 'points' ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:text-slate-300'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              {t.points}
            </button>
            <button
              type="button"
              onClick={() => setLayerMode('heatmap')}
              className={`inline-flex items-center gap-2 px-3 py-1.5 text-xs transition-colors ${
                layerMode === 'heatmap' ? 'bg-teal-300/15 text-teal-100' : 'text-slate-400 hover:text-slate-300'
              }`}
            >
              <Layers className="h-3.5 w-3.5" />
              {t.heatmap}
            </button>
          </div>
          <button
            type="button"
            onClick={toggleFullscreen}
            className="control inline-flex items-center gap-2 px-3 py-1.5 text-xs"
          >
            {isFullscreen ? <Minimize2 className="h-3.5 w-3.5" /> : <Maximize2 className="h-3.5 w-3.5" />}
            {isFullscreen ? t.exitFullscreen : t.fullscreen}
          </button>
        </div>
      </div>

      <div id="heatmap-container" className="surface relative overflow-hidden rounded-lg p-2">
        <ComposableMap projectionConfig={{ scale: 147 }} height={500} style={{ width: '100%', height: 'auto' }}>
          <Geographies geography={GEO_DATA}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#16223c"
                  stroke="#243049"
                  strokeWidth={0.4}
                  style={{
                    default: { outline: 'none' },
                    hover: { fill: '#1d2c4d', outline: 'none' },
                    pressed: { outline: 'none' },
                  }}
                />
              ))
            }
          </Geographies>

          {layerMode === 'points' &&
            geoIndicators.slice(0, 500).map((ind) => (
              <Marker key={ind.id} coordinates={[ind.lon as number, ind.lat as number]}>
                <circle
                  r={2}
                  fill={SEVERITY_COLORS[ind.severity]}
                  fillOpacity={0.7}
                  stroke="#0b1220"
                  strokeWidth={0.5}
                >
                  <title>{`${ind.indicator} · ${ind.severity}${ind.country ? ` · ${ind.country}` : ''}`}</title>
                </circle>
              </Marker>
            ))}

          {layerMode === 'heatmap' &&
            heatmapCells.map((cell, idx) => (
              <Marker key={`cell-${idx}`} coordinates={[cell.lon, cell.lat]}>
                <circle r={cell.radius} fill={cell.color} fillOpacity={0.5} stroke="none">
                  <title>{`${cell.count} threats (avg severity: ${cell.severity.toFixed(1)})`}</title>
                </circle>
              </Marker>
            ))}
        </ComposableMap>
      </div>

      <div className="surface-raised rounded-lg p-3">
        <div className="mb-2 text-xs font-semibold text-slate-300">Top Threat Locations</div>
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          {Array.from(countryCounts.entries())
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8)
            .map(([country, count]) => (
              <div key={country} className="flex items-center justify-between rounded bg-slate-700/30 px-2 py-1.5">
                <span className="text-xs font-semibold text-slate-300">{country}</span>
                <span className="rounded bg-slate-600/50 px-1.5 py-0.5 text-xs font-bold text-slate-400">{count}</span>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}
