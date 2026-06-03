# Threat Intelligence Platform

**Global threat-intelligence resource platform** — aggregates public cyber threat-intel feeds into a unified situational-awareness dashboard.

The platform pulls indicators from multiple open feeds, normalizes them into a single
data model, geolocates IP indicators, and surfaces everything through a real-time
dashboard: a world threat map, a live indicator feed, a latest-CVE panel, severity
filtering/search, and per-source freshness/health monitoring. It can also push
scheduled alert digests of new high-severity threats to **DingTalk** and **Telegram**.

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
| `GET /api/notify/status` | Alert notifier config + last-run state |
| `POST /api/notify/test` | Send a test digest to configured channels now |

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

## Alerting (DingTalk / Telegram scheduled push)

The backend can periodically push a digest of **new** threats (deduplicated by indicator ID,
filtered by severity/source) to DingTalk and/or Telegram robots. It is **off by default** and
activates only when `NOTIFY_ENABLED=true` and at least one channel is configured.

On startup the notifier primes its baseline against the initial dataset, so the first digest
only contains threats that appear *after* the service starts — no historical spam.

```bash
# enable + DingTalk (full webhook URL or just the access_token)
NOTIFY_ENABLED=true \
DINGTALK_WEBHOOK="https://oapi.dingtalk.com/robot/send?access_token=xxxx" \
DINGTALK_SECRET="SECxxxx" \           # optional: enables HMAC-SHA256 signing
NOTIFY_MIN_SEVERITY=critical \
npm start -w backend

# Telegram
NOTIFY_ENABLED=true \
TELEGRAM_BOT_TOKEN="123456:ABC..." \
TELEGRAM_CHAT_ID="-1001234567890" \
npm start -w backend
```

Verify wiring at any time with `curl -X POST http://localhost:4000/api/notify/test`.
See `.env.example` for the full list of variables.

- **DingTalk:** Group → Settings → Bots → add *Custom* robot. Use a keyword or the *Signed*
  security option (set `DINGTALK_SECRET`). Copy the webhook (or just its `access_token`).
- **Telegram:** create a bot via [@BotFather](https://t.me/BotFather) to get the token, then
  get your chat ID (e.g. message the bot and read `https://api.telegram.org/bot<token>/getUpdates`,
  or add the bot to a group/channel).

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `PORT` | `4000` | Backend port |
| `REFRESH_INTERVAL_MS` | `900000` | Feed refresh interval (15 min) |
| `VITE_API_BASE` | `''` | Frontend API base (leave empty to use same-origin / dev proxy) |
| `NOTIFY_ENABLED` | `false` | Master switch for scheduled alert push |
| `NOTIFY_INTERVAL_MS` | `3600000` | Digest push interval (1 h) |
| `NOTIFY_MIN_SEVERITY` | `critical` | Minimum severity to alert (`low`/`medium`/`high`/`critical`) |
| `NOTIFY_SOURCES` | _(all)_ | Comma list to restrict sources (`cisa_kev,feodo,urlhaus,nvd`) |
| `NOTIFY_MAX_ITEMS` | `10` | Max items per digest message |
| `DINGTALK_WEBHOOK` | — | DingTalk robot webhook URL or `access_token` |
| `DINGTALK_SECRET` | — | DingTalk signing secret (optional) |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token from BotFather |
| `TELEGRAM_CHAT_ID` | — | Telegram chat/group/channel ID |

## License

MIT. For defensive and research use. All upstream data remains subject to each provider's
terms (CISA, abuse.ch, NVD).
