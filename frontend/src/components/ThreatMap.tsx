import { useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import type { ThreatIndicator } from '../types';
import { SEVERITY_COLORS } from '../constants';

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

const MAX_MARKERS = 600;

export function ThreatMap({ points }: { points: ThreatIndicator[] }) {
  const markers = useMemo(() => {
    return points
      .filter((p) => p.lat !== undefined && p.lon !== undefined)
      .slice(0, MAX_MARKERS);
  }, [points]);

  return (
    <div className="relative rounded-xl border border-white/10 bg-panel-2/70 p-2 shadow-lg">
      <div className="absolute left-4 top-3 z-10">
        <h2 className="text-sm font-semibold text-slate-200">Global Threat Map</h2>
        <p className="text-xs text-slate-400">{markers.length} geolocated indicators</p>
      </div>
      <ComposableMap
        projectionConfig={{ scale: 147 }}
        height={420}
        style={{ width: '100%', height: 'auto' }}
      >
        <Geographies geography={GEO_URL}>
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
        {markers.map((m) => (
          <Marker key={m.id} coordinates={[m.lon as number, m.lat as number]}>
            <circle
              r={2.6}
              fill={SEVERITY_COLORS[m.severity]}
              fillOpacity={0.75}
              stroke="#0b1220"
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
