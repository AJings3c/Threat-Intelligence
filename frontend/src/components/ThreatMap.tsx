import { useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import type { Language, ThreatIndicator } from '../types';
import { SEVERITY_COLORS } from '../constants';
import { UI_TEXT } from '../i18n';
// Bundle the basemap locally instead of fetching from a CDN at runtime, so the map
// works in air-gapped / internal deployments and is reproducible.
import countries110m from 'world-atlas/countries-110m.json';

const GEO_DATA = countries110m as unknown as Record<string, unknown>;

const MAX_MARKERS = 600;

export function ThreatMap({ points, lang, theme }: { points: ThreatIndicator[]; lang: Language; theme: 'dark' | 'light' }) {
  const t = UI_TEXT[lang];
  const mapColor =
    theme === 'light'
      ? {
          fill: '#dbe7f3',
          hover: '#cbdbea',
          stroke: '#b6c7d8',
          markerStroke: '#ffffff',
        }
      : {
          fill: '#16223c',
          hover: '#1d2c4d',
          stroke: '#243049',
          markerStroke: '#0b1220',
        };
  const markers = useMemo(() => {
    return points
      .filter((p) => p.lat !== undefined && p.lon !== undefined)
      .slice(0, MAX_MARKERS);
  }, [points]);

  return (
    <div className="surface relative overflow-hidden rounded-lg p-2">
      <div className="absolute left-4 top-3 z-10">
        <h2 className="section-title">{t.globalThreatMap}</h2>
        <p className="text-xs text-slate-400">
          {markers.length} {t.geolocatedIndicators}
        </p>
      </div>
      <ComposableMap
        projectionConfig={{ scale: 147 }}
        height={420}
        style={{ width: '100%', height: 'auto' }}
      >
        <Geographies geography={GEO_DATA}>
          {({ geographies }) =>
            geographies.map((geo) => (
              <Geography
                key={geo.rsmKey}
                geography={geo}
                fill={mapColor.fill}
                stroke={mapColor.stroke}
                strokeWidth={0.4}
                style={{
                  default: { outline: 'none' },
                  hover: { fill: mapColor.hover, outline: 'none' },
                  pressed: { outline: 'none' },
                }}
              />
            ))
          }
        </Geographies>
        {markers.map((m) => (
          <Marker key={m.id} coordinates={[m.lon as number, m.lat as number]}>
            <circle
              r={2.6}
              fill={SEVERITY_COLORS[m.severity]}
              fillOpacity={0.75}
              stroke={mapColor.markerStroke}
              strokeWidth={0.4}
            >
              <title>{`${m.indicator} · ${m.severity}${m.country ? ` · ${m.country}` : ''}`}</title>
            </circle>
          </Marker>
        ))}
      </ComposableMap>
    </div>
  );
}
