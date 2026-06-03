# Threat Intelligence Platform

**Global threat-intelligence resource platform** — aggregates public cyber threat-intel feeds into a unified situational-awareness dashboard. Inspired by [koala73/worldmonitor](https://github.com/koala73/worldmonitor).

The platform pulls indicators from multiple open feeds, normalizes them into a single
data model, geolocates IP indicators, and surfaces everything through a real-time
dashboard: a world threat map, a live indicator feed, a latest-CVE panel, severity
filtering/search, and per-source freshness/health monitoring.

## Data sources (all public, no API key required)

| Source | Content | Type |
|--------|---------|------|
| **CISA KEV** | Known Exploited Vulnerabilities catalog | Exploited vulns |
| **abuse.ch Feodo Tracker** | Botnet C2 server IPs | C2 servers |
| **abuse.ch URLhaus** | Malware distribution URLs | Malicious URLs |
| **NVD** | Latest published CVEs | Vulnerabilities |

> ThreatFox / AlienVault OTX / AbuseIPDB require API keys and can be added later.

## Architecture

```
threat-intel-platform/
├── backend/      Node + Express + TypeScript API (fetch → normalize → geo → cache)
│   └── src/
│       ├── sources/   one module per feed (cisaKev, feodo, urlhaus, nvd)
│       ├── store.ts   in-memory aggregator + periodic refresh + stats
│       ├── geo.ts     best-effort IP geolocation (ip-api batch)
│       └── index.ts   Express server + REST API
└── frontend/     Vite + React + TypeScript + Tailwind dashboard
    └── src/components/  map, feed table, CVE panel, stats, source health
```

The backend fetches all feeds on startup and every `REFRESH_INTERVAL_MS` (default 15 min),
normalizes them into a unified `ThreatIndicator` model, and serves cached results so the
UI stays fast and the upstream feeds are not hammered.

### REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Service status + per-source health |
| `GET /api/threats` | Indicators, filterable by `source`, `type`, `severity`, `q`, `limit` |
| `GET /api/map` | Geolocated indicators for the map |
| `GET /api/cve` | Latest CVEs from NVD |
| `GET /api/stats` | Aggregate counts (by source/type/severity, top countries) |
| `GET /api/sources/health` | Per-source freshness and error state |

## Quick start

Requires Node.js >= 20 (see `.nvmrc`).

```bash
npm install          # installs both workspaces
npm run dev          # backend on :4000, frontend on :5173 (proxies /api)
```

Open http://localhost:5173.

### Production build

```bash
npm run build        # builds backend (tsc) + frontend (vite)
npm start            # serves API and the built frontend from :4000
```

When `frontend/dist` exists, the backend serves it directly, so a single process hosts
both the API and the dashboard.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Run backend + frontend in watch mode |
| `npm run build` | Build both workspaces |
| `npm run typecheck` | Type-check both workspaces |
| `npm run lint` | Lint both workspaces |

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PORT` | `4000` | Backend port |
| `REFRESH_INTERVAL_MS` | `900000` | Feed refresh interval (15 min) |
| `VITE_API_BASE` | `''` | Frontend API base (leave empty to use same-origin / dev proxy) |

## License

MIT. For defensive and research use. All upstream data remains subject to each provider's
terms (CISA, abuse.ch, NVD).
