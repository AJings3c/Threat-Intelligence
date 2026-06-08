# Threat Intelligence Platform

**Global threat-intelligence resource platform** — aggregates public cyber threat-intel feeds into a unified situational-awareness dashboard.

The platform pulls indicators from multiple open feeds, normalizes them into a single
data model, geolocates IP indicators, and surfaces everything through a real-time
dashboard: a world threat map, a live indicator feed, a latest-CVE panel, severity
filtering/search, IOC investigation, STRIDE-style threat modeling, and per-source
freshness/health monitoring. It can also push scheduled alert digests of new
high-severity threats to **DingTalk**, **Telegram**, **Slack**, or a generic webhook.

## Data sources (all public, no API key required)

| Source | Content | Type |
|--------|---------|------|
| **CISA KEV** | Known Exploited Vulnerabilities catalog | Exploited vulns |
| **abuse.ch Feodo Tracker** | Botnet C2 server IPs | C2 servers |
| **abuse.ch URLhaus** | Malware distribution URLs | Malicious URLs |
| **abuse.ch ThreatFox** | Recent IOCs (C2, domains, URLs, hashes) | Multi-IOC |
| **abuse.ch MalwareBazaar** | Recent malware sample SHA256 hashes | File hashes |
| **OpenPhish** | Community phishing URL feed | Phishing URLs |
| **Spamhaus DROP** | Do-not-route malicious IPv4 netblocks | Malicious networks |
| **SANS ISC DShield** | Top attacking IPv4 subnets over recent days | Scanner networks |
| **NVD + FIRST EPSS** | Latest published CVEs with exploitation probability | Vulnerabilities |

> AlienVault OTX / AbuseIPDB / VirusTotal / Shodan / Censys require API keys.

## Optional credentialed sources

| Source | Content | Required config |
|--------|---------|-----------------|
| **X Recent Search** | Security posts matching a configurable query | `X_BEARER_TOKEN` |
| **Facebook Graph API** | Posts from configured security pages | `FACEBOOK_ACCESS_TOKEN`, `FACEBOOK_PAGE_IDS` |
| **PhishTank** | Verified online phishing URLs | `PHISHTANK_APP_KEY` |
| **AbuseIPDB** | High-confidence abusive IPv4 blacklist | `ABUSEIPDB_API_KEY` |
| **AlienVault OTX** | Indicators from subscribed OTX pulses | `OTX_API_KEY` |
| **External TAXII** | STIX 2.1 objects from a TAXII collection objects URL | `TAXII_IMPORT_OBJECTS_URL` |
| **VirusTotal / Shodan / Censys** | On-demand observable enrichment via `/api/enrich` | Provider API keys |

Credentialed sources are disabled by default. If credentials are missing, they return an empty
result and do not affect the public-feed refresh cycle.

## Architecture

```
threat-intel-platform/
├── backend/      Node + Express + TypeScript API (fetch → normalize → geo → cache)
│   └── src/
│       ├── sources/   one module per feed (cisaKev, feodo, urlhaus, threatfox, etc.)
│       ├── store.ts   in-memory aggregator + periodic refresh + stats
│       ├── geo.ts     best-effort IP geolocation (ip-api batch)
│       └── index.ts   Express server + REST API
└── frontend/     Vite + React + TypeScript + Tailwind dashboard
    └── src/components/  map, feed table, CVE panel, stats, source health
```

The backend checks feeds on startup and every `REFRESH_INTERVAL_MS` (default 15 min),
but each source also has its own minimum refresh interval so slow-moving feeds are not over-fetched.
normalizes them into a unified `ThreatIndicator` model, and serves cached results so the
UI stays fast and the upstream feeds are not hammered.

### REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Service status + per-source health |
| `GET /api/threats` | Indicators, filterable by `source`, `type`, `severity`, `q`, `limit` |
| `GET /api/map` | Geolocated indicators for the map |
| `GET /api/cve` | Latest CVEs from NVD |
| `GET /api/hashes` | Hash IOCs and malware-family aggregations |
| `GET /api/enrich` | On-demand enrichment, query `indicator` + `type` |
| `GET /api/investigate` | Local IOC investigation + STRIDE-style threat model, query `indicator` and optional `type` |
| `GET /api/stats` | Aggregate counts (by source/type/severity, top countries) |
| `GET /api/sources/health` | Per-source freshness and error state |
| `GET /api/sources/history` | Historical source health samples (requires `DATA_DIR`) |
| `GET /api/config/status` | Non-secret integration configuration status |
| `GET /api/notify/status` | Alert notifier config + last-run state |
| `POST /api/notify/test` | Send a test digest to configured channels now |
| `GET /taxii2/` | TAXII 2.1 discovery document |
| `GET /taxii2/root/collections/:id/objects/` | Read-only TAXII envelope of STIX 2.1 objects |

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

### STIX / TAXII export

The platform exposes a STIX bundle at `/api/export/stix` and a read-only TAXII 2.1 API root
under `/taxii2/root/`. The TAXII collection id is stable and advertised by
`GET /taxii2/root/collections/`. When `API_TOKEN` is configured, TAXII endpoints accept the
same bearer/header/query token options as the REST API.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Run backend + frontend in watch mode |
| `npm run build` | Build both workspaces |
| `npm run typecheck` | Type-check both workspaces |
| `npm run lint` | Lint both workspaces |

## IOC investigation and threat modeling

Use the dashboard's **IOC Investigation & Threat Model** panel or call the API directly:

```bash
curl 'http://localhost:4000/api/investigate?indicator=1.2.3.4&type=ip'
curl 'http://localhost:4000/api/investigate?indicator=example.com'
```

The response contains exact local matches, related indicators, source summary, confidence,
highest severity, and STRIDE-style scenarios with evidence and mitigation steps. This is
local evidence modeling, not a replacement for a full architecture data-flow diagram review.

## Configuration checks

Use the dashboard's **Configuration Check** panel or call:

```bash
curl http://localhost:4000/api/config/status
curl -X POST http://localhost:4000/api/notify/test
```

`/api/config/status` never returns secret values. Credentialed sources show as `disabled`
until the required environment variables are present.

## Alerting (DingTalk / Telegram / Slack / Webhook scheduled push)

The backend can periodically push a digest of **new** threats (deduplicated by indicator ID,
filtered by severity/source) to DingTalk, Telegram, Slack, or a generic webhook. It is **off by default** and
activates only when `NOTIFY_ENABLED=true` and at least one channel is configured.

On startup the notifier primes its baseline against the initial dataset, so the first digest
only contains threats that appear *after* the service starts — no historical spam.
When `DATA_DIR` is enabled, each channel also records successful/failed pushes in SQLite
(`push_events`), so a failed channel can be retried without resending to channels that
already succeeded.

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
| `REFRESH_<SOURCE>_INTERVAL_MS` | source default | Optional per-source minimum refresh interval, e.g. `REFRESH_NVD_INTERVAL_MS` |
| `VITE_API_BASE` | `''` | Frontend API base (leave empty to use same-origin / dev proxy) |
| `DATA_DIR` | — | Enables SQLite persistence for geo cache, first/last-seen, trends, push events |
| `NVD_API_KEY` | — | Optional NVD API key, increases NVD rate limits |
| `PHISHTANK_APP_KEY` | — | Optional PhishTank app key; enables PhishTank feed collection |
| `ABUSEIPDB_API_KEY` | — | Optional AbuseIPDB API key; enables high-confidence IP blacklist collection |
| `ABUSEIPDB_CONFIDENCE_MINIMUM` | `90` | Minimum AbuseIPDB confidence score for blacklist entries |
| `ABUSEIPDB_LIMIT` | source limit | Max AbuseIPDB blacklist entries per refresh |
| `OTX_API_KEY` | — | Optional AlienVault OTX API key; enables subscribed pulse import |
| `OTX_LIMIT` | source limit | Max OTX indicators per refresh |
| `TAXII_IMPORT_OBJECTS_URL` | — | Optional external TAXII collection objects URL to import |
| `TAXII_IMPORT_BEARER_TOKEN` | — | Optional bearer token for external TAXII import |
| `TAXII_IMPORT_USERNAME` / `TAXII_IMPORT_PASSWORD` | — | Optional basic auth for external TAXII import |
| `VIRUSTOTAL_API_KEY` | — | Optional VirusTotal API key for `/api/enrich` |
| `SHODAN_API_KEY` | — | Optional Shodan API key for IP enrichment |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | — | Optional Censys Search credentials for IP enrichment |
| `X_BEARER_TOKEN` | — | X Recent Search bearer token; enables X collection when set |
| `X_QUERY` | security query | X Recent Search query |
| `X_MAX_RESULTS` | `25` | X results per refresh, clamped to 10..100 |
| `FACEBOOK_ACCESS_TOKEN` | — | Facebook Graph API token; enables Facebook collection with page IDs |
| `FACEBOOK_PAGE_IDS` | — | Comma-separated Facebook page IDs/usernames |
| `FACEBOOK_GRAPH_VERSION` | `v23.0` | Facebook Graph API version |
| `NOTIFY_ENABLED` | `false` | Master switch for scheduled alert push |
| `NOTIFY_INTERVAL_MS` | `3600000` | Digest push interval (1 h) |
| `NOTIFY_MIN_SEVERITY` | `critical` | Minimum severity to alert (`low`/`medium`/`high`/`critical`) |
| `NOTIFY_SOURCES` | _(all)_ | Comma list to restrict sources (`cisa_kev,feodo,urlhaus,nvd,x,facebook,openphish,threatfox,malwarebazaar,spamhaus_drop,dshield,phishtank,abuseipdb,otx,taxii_import`) |
| `NOTIFY_MAX_ITEMS` | `10` | Max items per digest message |
| `DINGTALK_WEBHOOK` | — | DingTalk robot webhook URL or `access_token` |
| `DINGTALK_SECRET` | — | DingTalk signing secret (optional) |
| `TELEGRAM_BOT_TOKEN` | — | Telegram bot token from BotFather |
| `TELEGRAM_CHAT_ID` | — | Telegram chat/group/channel ID |
| `SLACK_WEBHOOK` | — | Slack incoming webhook URL |
| `WEBHOOK_URL` | — | Generic webhook URL for JSON digests |

## License

MIT. For defensive and research use. All upstream data remains subject to each provider's
terms (CISA, abuse.ch, OpenPhish, Spamhaus, SANS ISC, NVD, FIRST, PhishTank, AbuseIPDB,
AlienVault OTX, and any configured TAXII provider).
