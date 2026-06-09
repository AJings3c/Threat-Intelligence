<p align="center">
  <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo" width="104" />
</p>

<h1 align="center">Threat Intelligence Platform</h1>

<p align="center">
  <strong>Evidence Command Workbench for source-backed threat intelligence, IOC investigation, and STRIDE/DREAD threat modeling.</strong>
</p>

<p align="center">
  <a href="README.md">中文</a> | <strong>EN</strong>
</p>

<p align="center">
  <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo" width="240" />
</p>

## Feature Gallery

<table>
  <tr>
    <td width="50%">
      <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo for Sources and configuration workspace" width="180" />
      <br />
      <sub><strong>Sources & Config</strong></sub>
    </td>
    <td width="50%">
      <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo for IOC investigation workspace" width="180" />
      <br />
      <sub><strong>IOC Investigation</strong></sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo for Threat modeling workspace" width="180" />
      <br />
      <sub><strong>Threat Modeling</strong></sub>
    </td>
    <td width="50%">
      <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo for Intel feed table and details" width="180" />
      <br />
      <sub><strong>Intel Feed</strong></sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo for Source-backed IOC graph" width="180" />
      <br />
      <sub><strong>Source-backed Graph</strong></sub>
    </td>
    <td width="50%">
      <img src="frontend/public/brand-logo-dark.png" alt="Threat Intelligence Platform product logo for Mobile overview workspace" width="180" />
      <br />
      <sub><strong>Mobile Workbench</strong></sub>
    </td>
  </tr>
</table>

Threat Intelligence Platform is a React + Node.js workbench for collecting public and configured cyber threat intelligence, normalizing it into a single evidence model, and giving analysts a fast path from current threat posture to IOC investigation, graph exploration, STRIDE/DREAD modeling, and report export.

The interface is built as an **Evidence Command Workbench**: a dense, operator-focused product UI with source health, configuration checks, IOC search, enrichment, Graph/List views, bilingual copy, and dark/light themes.

### What It Shows

- Source health, freshness, configuration state, and per-source test results.
- Global geolocated indicators, severity distribution, top origin countries, trends, CVEs, and malware/hash intelligence.
- A filterable live threat feed with source, type, severity, country, timestamps, confidence, reliability, TLP, tags, and reference evidence.
- IOC investigation for domains, IPs, URLs, hashes, CIDR ranges, and CVEs.
- Local evidence-backed STRIDE scenarios, DREAD scoring, mitigations, next steps, Markdown/JSON reports, and investigation history.
- Architecture-level threat modeling with assets, trust boundaries, data flows, attack paths, controls, and a Graph/List explorer.
- STIX 2.1 export and a read-only TAXII 2.1 API.

The platform does not invent threat sources. Threat models and graphs are derived from the project data sources, local evidence, configuration state, and backend APIs.

### UI Workspaces

| Workspace | Purpose |
| --- | --- |
| **Overview** | Source health, stats, map, CVE panel, trend panel, and Hash/Malware overview. |
| **Sources & Config** | Source matrix, configuration status, source tests, enrichment provider tests, and notification test controls. |
| **Investigation** | IOC command, exact matches, related indicators, enrichment, STRIDE scenarios, mitigations, report export, and source-backed graph. |
| **Threat Modeling** | Architecture model, DFD-style graph, STRIDE/DREAD explorer, assets, flows, controls, and attack paths. |
| **Intel Feed** | Sticky filters, threat table, row selection, details side panel, and external references. |

### Themes, Logo, and Brand Assets

The UI supports explicit dark and light theme switching. Theme choice is stored in `localStorage.theme`, and the favicon follows the active theme.

| Asset | Use |
| --- | --- |
| `frontend/public/brand-logo-dark.png` | UI logo and favicon in dark theme. |
| `frontend/public/brand-logo-light.png` | UI logo and favicon in light theme. |
| `frontend/public/brand-logo.png` | Default compatibility logo. |

The previous icon set has been removed.

### Data Sources

#### Public sources, no API key required

| Source | Content | Indicator types |
| --- | --- | --- |
| CISA KEV | Known Exploited Vulnerabilities catalog | CVE, exploited vulnerability |
| abuse.ch Feodo Tracker | Botnet C2 server IPs | IP, C2 server |
| abuse.ch URLhaus | Malware distribution URLs | URL, malware host |
| abuse.ch ThreatFox | Recent IOCs | IP, domain, URL, hash |
| abuse.ch MalwareBazaar | Malware sample hashes and families | SHA256 hash, malware family |
| OpenPhish | Community phishing URLs | URL, phishing |
| Spamhaus DROP | Do-not-route malicious IPv4 netblocks | CIDR, malicious network |
| SANS ISC DShield | Top attacking IPv4 subnets | CIDR, scanner network |
| NVD + FIRST EPSS | CVEs with CVSS and exploitation probability | CVE, vulnerability |

#### Optional credentialed sources and enrichers

| Integration | Purpose | Required config |
| --- | --- | --- |
| X Recent Search | Security posts matching a configurable query | `X_BEARER_TOKEN` |
| Facebook Graph API | Posts from configured security pages | `FACEBOOK_ACCESS_TOKEN`, `FACEBOOK_PAGE_IDS` |
| PhishTank | Verified online phishing URLs | `PHISHTANK_APP_KEY` |
| AbuseIPDB | High-confidence abusive IPv4 blacklist | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | Indicators from subscribed pulses | `OTX_API_KEY` |
| External TAXII | STIX 2.1 objects from an external TAXII collection | `TAXII_IMPORT_OBJECTS_URL` |
| VirusTotal | On-demand observable enrichment | `VIRUSTOTAL_API_KEY` |
| Shodan | On-demand IP enrichment | `SHODAN_API_KEY` |
| Censys | On-demand host enrichment | `CENSYS_API_ID`, `CENSYS_API_SECRET` |

Missing credentials do not break public-feed refresh. Credentialed sources appear as disabled until configured.

### Architecture

```text
threat-intel-platform/
├── backend/
│   └── src/
│       ├── sources/                  Feed adapters
│       ├── store.ts                  Refresh, normalize, cache, correlate
│       ├── architectureThreatModel.ts Source-backed architecture threat model
│       ├── reports.ts                Markdown report generation
│       ├── security.ts               API tokens, roles, rate limit, audit
│       ├── stix.ts / taxii.ts        STIX bundle and TAXII API
│       └── index.ts                  Express REST/SSE/TAXII server
└── frontend/
    └── src/
        ├── App.tsx                   App shell, workspaces, theme switch
        ├── components/               Panels, tables, map, graph explorer
        ├── i18n.ts                   English/Chinese UI copy
        └── index.css                 Design tokens, dark/light themes
```

Backend:

- Express + TypeScript API.
- Startup refresh plus periodic refresh, default `REFRESH_INTERVAL_MS=900000`.
- Per-source refresh intervals to avoid over-fetching slow feeds.
- Optional SQLite persistence when `DATA_DIR` is set.
- SSE stream at `/api/stream` for live refresh updates.

Frontend:

- React 18 + Vite 8 + TypeScript + Tailwind CSS.
- React Flow powered graph explorer via `@xyflow/react`.
- Local `world-atlas` map data, no runtime CDN dependency for the basemap.
- Hash-based workspaces, no React Router requirement.

### Requirements

- Node.js `>=20.19`.
- npm `>=11` recommended.
- Persistence via `DATA_DIR` uses Node's SQLite support, so Node 22+ is recommended when persistence is enabled.

### Quick Start

```bash
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

Development ports:

- Backend API: `http://localhost:4000`
- Frontend dev server: `http://localhost:5173`
- Vite dev proxy: `/api` to `VITE_API_PROXY` or `http://localhost:4000`

### Production Build

```bash
npm run build
npm start
```

When `frontend/dist` exists, the backend serves the built frontend and API from one process on `PORT`, default `4000`.

### Scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Run backend and frontend in watch mode. |
| `npm run build` | Build backend and frontend. |
| `npm run typecheck` | Type-check both workspaces. |
| `npm run lint` | Lint both workspaces. |
| `npm run test` | Run backend tests. |
| `npm start` | Start the compiled backend and serve frontend build if present. |

### REST API

| Endpoint | Description |
| --- | --- |
| `GET /api/health` | Service status and source health. This stays open for probes. |
| `GET /api/stream` | Server-Sent Events refresh stream. |
| `GET /api/threats` | Indicators, filterable by `source`, `type`, `severity`, `q`, and `limit`. |
| `GET /api/map` | Geolocated indicators for the map. |
| `GET /api/cve` | Latest CVEs from NVD. |
| `GET /api/hashes` | Hash IOCs and malware family aggregations. |
| `GET /api/stats` | Aggregate counts by source, type, severity, country, and refresh time. |
| `GET /api/sources/health` | Per-source freshness and error state. |
| `GET /api/sources/history` | Historical source health samples when persistence is enabled. |
| `GET /api/trend` | Historical indicator trend when persistence is enabled. |
| `GET /api/config/status` | Non-secret source, provider, notification, and persistence configuration state. |
| `POST /api/config/test` | Test one source or enrichment provider. Requires admin role when auth is enabled. |
| `GET /api/enrich` | On-demand enrichment for one observable. Requires analyst role when auth is enabled. |
| `GET /api/investigate` | Local IOC investigation and STRIDE model. Requires analyst role when auth is enabled. |
| `GET /api/investigations/history` | Recent IOC investigation history. |
| `GET /api/investigate/report` | IOC investigation report as Markdown or JSON. |
| `GET /api/threat-model` | Architecture-level threat model as JSON or Markdown. |
| `GET /api/export/stix` | STIX 2.1 bundle export. |
| `GET /api/notify/status` | Notification configuration and last-run status. |
| `POST /api/notify/test` | Send a test digest to configured channels. Requires admin role and may require `NOTIFY_TEST_TOKEN`. |
| `GET /api/audit` | Recent audit events when persistence is enabled. Requires admin role. |

TAXII endpoints:

- `GET /taxii2/`
- `GET /taxii2/root/`
- `GET /taxii2/root/collections/`
- `GET /taxii2/root/collections/:id/objects/`
- `GET /taxii2/root/collections/:id/manifest/`

### IOC Investigation Examples

```bash
curl 'http://localhost:4000/api/investigate?indicator=CVE-2026-28318&type=cve&lang=en'
curl 'http://localhost:4000/api/investigate?indicator=example.com&type=domain&lang=zh'
curl 'http://localhost:4000/api/investigate/report?indicator=example.com&type=domain&format=markdown&lang=en'
curl 'http://localhost:4000/api/investigate/report?indicator=example.com&type=domain&format=json&lang=zh'
```

### Architecture Threat Model Examples

```bash
curl 'http://localhost:4000/api/threat-model?lang=en'
curl 'http://localhost:4000/api/threat-model?lang=zh'
curl 'http://localhost:4000/api/threat-model?format=markdown&lang=en'
```

The architecture model includes:

- Scope and methodology.
- Assets, trust boundaries, and data flows.
- STRIDE scenarios and DREAD scores.
- Attack paths and controls.
- Assumptions and evidence notes.

### Configuration Checks

```bash
curl http://localhost:4000/api/config/status
curl -X POST http://localhost:4000/api/config/test \
  -H 'Content-Type: application/json' \
  -d '{"kind":"source","id":"cisa_kev"}'
curl -X POST http://localhost:4000/api/config/test \
  -H 'Content-Type: application/json' \
  -d '{"kind":"provider","id":"virustotal"}'
curl -X POST http://localhost:4000/api/notify/test
```

`/api/config/status` never returns secret values. It only reports configured flags and required environment variable names.

### Security and Access Control

Authentication is optional for private/local deployments.

When tokens are configured:

- `API_TOKEN` is treated as an admin token.
- `API_VIEWER_TOKENS`, `API_ANALYST_TOKENS`, and `API_ADMIN_TOKENS` provide role-scoped access.
- Viewer routes cover read-only data.
- Analyst routes cover investigation, enrichment, report generation, and threat modeling.
- Admin routes cover integration tests, notification tests, and audit access.

Tokens can be passed as:

- `Authorization: Bearer <token>`
- `x-api-token: <token>`
- `?token=<token>`

Use `CORS_ORIGINS`, `API_RATE_LIMIT_WINDOW_MS`, `API_RATE_LIMIT_MAX`, and `JSON_BODY_LIMIT` for browser deployments and request safety.

### Alerting

Scheduled alert digests are disabled by default. Enable them with `NOTIFY_ENABLED=true` and configure at least one channel:

- DingTalk custom robot.
- Telegram bot.
- Slack incoming webhook.
- Generic webhook.

The notifier primes its baseline on startup, so the first digest only contains new threats after the service starts. When persistence is enabled, channel push events and retries are recorded.

### Key Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4000` | Backend port. |
| `REFRESH_INTERVAL_MS` | `900000` | Feed refresh interval. |
| `REFRESH_<SOURCE>_INTERVAL_MS` | Source default | Per-source minimum refresh interval override. |
| `DATA_DIR` | Empty | Enables SQLite persistence for geo cache, trends, audit, push events, and investigation history. |
| `VITE_API_BASE` | Empty | Frontend API base. Empty means same-origin or dev proxy. |
| `VITE_API_PROXY` | `http://localhost:4000` | Vite dev proxy target for `/api`. |
| `VITE_API_TOKEN` | Empty | Token attached by the frontend when API auth is enabled. It is embedded in the built bundle. |
| `API_TOKEN` | Empty | Admin API token. |
| `API_VIEWER_TOKENS` / `API_ANALYST_TOKENS` / `API_ADMIN_TOKENS` | Empty | Role-scoped token lists. |
| `CORS_ORIGINS` | Empty | Browser origin allow-list. |
| `NVD_API_KEY` | Empty | Optional NVD rate-limit increase. |
| `GEOLITE2_DB` | Empty | Optional offline MaxMind GeoLite2 database path. |
| `PHISHTANK_APP_KEY` | Empty | Enables PhishTank feed. |
| `ABUSEIPDB_API_KEY` | Empty | Enables AbuseIPDB feed. |
| `OTX_API_KEY` | Empty | Enables AlienVault OTX pulse import. |
| `TAXII_IMPORT_OBJECTS_URL` | Empty | Enables external TAXII object import. |
| `VIRUSTOTAL_API_KEY` | Empty | Enables VirusTotal enrichment. |
| `SHODAN_API_KEY` | Empty | Enables Shodan enrichment. |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Empty | Enables Censys enrichment. |
| `X_BEARER_TOKEN` | Empty | Enables X Recent Search collection. |
| `FACEBOOK_ACCESS_TOKEN` / `FACEBOOK_PAGE_IDS` | Empty | Enables Facebook page collection. |
| `NOTIFY_ENABLED` | `false` | Enables scheduled alert digest. |
| `NOTIFY_MIN_SEVERITY` | `critical` | Minimum severity for alert digest. |
| `NOTIFY_SOURCES` | All | Optional source allow-list for alerts. |
| `DINGTALK_WEBHOOK` / `DINGTALK_SECRET` | Empty | DingTalk alerting. |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Empty | Telegram alerting. |
| `SLACK_WEBHOOK` | Empty | Slack alerting. |
| `WEBHOOK_URL` | Empty | Generic JSON webhook alerting. |

See `.env.example` for the full variable list.

### Verification

```bash
npm run typecheck
npm run lint
npm run build
npm run test
npm audit --json
```

The current frontend build chain uses Vite 8 and `@vitejs/plugin-react` 6.

### Docker

```bash
docker build -t threat-intel-platform .
docker run --rm -p 4000:4000 threat-intel-platform
```

The Dockerfile uses a Node 22 image, which is compatible with Vite 8 and optional persistence.

### License

MIT. For defensive and research use. Upstream data remains subject to each provider's terms.
