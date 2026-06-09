<p align="center">
  <img src="frontend/public/brand-logo-light.png" alt="Threat Intelligence Platform logo" width="104" />
</p>

<h1 align="center">Threat Intelligence Platform</h1>

<p align="center">
  <strong>Evidence Command Workbench for source-backed threat intelligence, IOC investigation, and STRIDE/DREAD threat modeling.</strong>
</p>

<p align="center">
  <a href="#english">English</a> |
  <a href="#中文">中文</a>
</p>

<p align="center">
  <img src="artifacts/home-dark-overview.png" alt="Threat Intelligence Platform homepage" width="92%" />
</p>

## Feature Gallery / 功能截图

<table>
  <tr>
    <td width="50%">
      <img src="artifacts/vite8-sources-desktop.png" alt="Sources and configuration workspace" />
      <br />
      <sub><strong>Sources & Config</strong> / 来源与配置</sub>
    </td>
    <td width="50%">
      <img src="artifacts/vite8-investigation-desktop.png" alt="IOC investigation workspace" />
      <br />
      <sub><strong>IOC Investigation</strong> / IOC 调查</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="artifacts/vite8-modeling-desktop.png" alt="Threat modeling workspace" />
      <br />
      <sub><strong>Threat Modeling</strong> / 威胁建模</sub>
    </td>
    <td width="50%">
      <img src="artifacts/vite8-feed-desktop.png" alt="Intel feed table and details" />
      <br />
      <sub><strong>Intel Feed</strong> / 情报列表</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="artifacts/source-backed-ioc-graph.png" alt="Source-backed IOC graph" />
      <br />
      <sub><strong>Source-backed Graph</strong> / 基于来源的 Graph</sub>
    </td>
    <td width="50%">
      <img src="artifacts/uiux-workbench-overview-mobile.png" alt="Mobile overview workspace" />
      <br />
      <sub><strong>Mobile Workbench</strong> / 移动端工作台</sub>
    </td>
  </tr>
</table>

## English

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

The old shield logo has been removed.

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

## 中文

Threat Intelligence Platform 是一个面向安全运营、威胁情报分析、应急响应和红蓝队研究的威胁情报工作台。项目使用 React + Vite + Tailwind 构建前端，使用 Node.js + Express + TypeScript 构建后端，聚合公开和可选配置的威胁情报源，并把数据统一成可调查、可建模、可导出的证据模型。

当前 UI 定位为 **证据指挥工作台**：不是装饰性大屏，也不是营销页，而是面向分析人员的密集型操作界面。它强调来源、证据、置信度、可靠性、时间戳、配置状态和可复核的威胁模型。

### 可以展示什么数据

- 情报源健康状态、刷新时间、配置状态和单源测试结果。
- 全球地理化 IOC、严重性分布、主要来源国家或地区、趋势、CVE、Hash 和恶意软件家族情报。
- 可过滤威胁情报列表，包含来源、类型、严重性、国家或地区、时间、置信度、可靠性、TLP、标签和参考链接。
- 针对域名、IP、URL、Hash、CIDR、CVE 的 IOC 调查结果。
- 基于本地情报证据的 STRIDE 场景、DREAD 评分、缓解建议、下一步行动、Markdown/JSON 报告和历史记录。
- 架构级威胁建模，包含资产、信任边界、数据流、攻击路径、控制措施和 Graph/List 双视图。
- STIX 2.1 导出和只读 TAXII 2.1 API。

系统不会凭空虚构情报来源。Graph、威胁建模和建议都基于当前项目已有的数据源、本地证据、配置状态和后端接口生成。

### UI 工作区

| 工作区 | 作用 |
| --- | --- |
| **总览 Overview** | 情报源健康、核心指标、地图、CVE、趋势、Hash/Malware 总览。 |
| **来源与配置 Sources & Config** | 来源矩阵、配置检查、单源测试、富化服务商测试、通知测试。 |
| **调查 Investigation** | IOC 命令、精确匹配、关联指标、富化、STRIDE 场景、缓解建议、报告导出和来源 Graph。 |
| **威胁建模 Threat Modeling** | 架构模型、DFD 风格 Graph、STRIDE/DREAD 场景、资产、数据流、控制项和攻击路径。 |
| **情报列表 Intel Feed** | Sticky 筛选器、威胁表格、行选中、详情侧栏和外部参考链接。 |

### 主题、Logo 与品牌资产

平台支持用户显式切换深色和浅色模式，选择会保存到 `localStorage.theme`，favicon 也会跟随当前主题切换。

| 资产 | 用途 |
| --- | --- |
| `frontend/public/brand-logo-dark.png` | 深色模式 UI logo 和 favicon。 |
| `frontend/public/brand-logo-light.png` | 浅色模式 UI logo 和 favicon。 |
| `frontend/public/brand-logo.png` | 默认兼容 logo。 |

旧盾牌 logo 已移除。

### 情报来源

#### 公开来源，无需 API key

| 来源 | 内容 | 指标类型 |
| --- | --- | --- |
| CISA KEV | 已知被利用漏洞目录 | CVE、已利用漏洞 |
| abuse.ch Feodo Tracker | Botnet C2 服务器 IP | IP、C2 |
| abuse.ch URLhaus | 恶意软件分发 URL | URL、恶意软件主机 |
| abuse.ch ThreatFox | 最新 IOC | IP、域名、URL、Hash |
| abuse.ch MalwareBazaar | 恶意样本 Hash 与家族 | SHA256、恶意软件家族 |
| OpenPhish | 社区钓鱼 URL | URL、钓鱼 |
| Spamhaus DROP | 恶意 IPv4 网段 | CIDR、恶意网络 |
| SANS ISC DShield | 高攻击 IPv4 子网 | CIDR、扫描网络 |
| NVD + FIRST EPSS | CVE、CVSS 和利用概率 | CVE、漏洞 |

#### 可选凭据来源和富化服务

| 集成 | 作用 | 必需配置 |
| --- | --- | --- |
| X Recent Search | 按查询采集安全相关帖子 | `X_BEARER_TOKEN` |
| Facebook Graph API | 采集指定安全页面帖子 | `FACEBOOK_ACCESS_TOKEN`, `FACEBOOK_PAGE_IDS` |
| PhishTank | 已验证在线钓鱼 URL | `PHISHTANK_APP_KEY` |
| AbuseIPDB | 高置信度恶意 IPv4 黑名单 | `ABUSEIPDB_API_KEY` |
| AlienVault OTX | 订阅 Pulse 中的指标 | `OTX_API_KEY` |
| External TAXII | 外部 TAXII collection 中的 STIX 2.1 对象 | `TAXII_IMPORT_OBJECTS_URL` |
| VirusTotal | 按需富化可观测对象 | `VIRUSTOTAL_API_KEY` |
| Shodan | 按需 IP 富化 | `SHODAN_API_KEY` |
| Censys | 按需主机富化 | `CENSYS_API_ID`, `CENSYS_API_SECRET` |

凭据缺失不会影响公开源刷新。未配置的凭据源会显示为 disabled，并可在配置面板中查看缺失项。

### 架构

```text
threat-intel-platform/
├── backend/
│   └── src/
│       ├── sources/                  情报源适配器
│       ├── store.ts                  刷新、归一化、缓存、关联
│       ├── architectureThreatModel.ts 架构威胁建模
│       ├── reports.ts                Markdown 报告
│       ├── security.ts               API token、角色、限速、审计
│       ├── stix.ts / taxii.ts        STIX 和 TAXII
│       └── index.ts                  Express REST/SSE/TAXII 服务
└── frontend/
    └── src/
        ├── App.tsx                   应用壳、工作区、主题切换
        ├── components/               面板、表格、地图、Graph
        ├── i18n.ts                   中英文文案
        └── index.css                 设计 token、深浅色主题
```

后端能力：

- Express + TypeScript API。
- 启动刷新和周期刷新，默认 `REFRESH_INTERVAL_MS=900000`。
- 每个来源有独立最小刷新间隔，避免过度请求上游。
- 设置 `DATA_DIR` 后启用 SQLite 持久化。
- `/api/stream` 提供刷新事件的 SSE 流。

前端能力：

- React 18 + Vite 8 + TypeScript + Tailwind CSS。
- 使用 `@xyflow/react` 构建 Graph Explorer。
- 地图数据来自本地 `world-atlas`，运行时不依赖 CDN 加载底图。
- 使用 URL hash 管理工作区，不引入 React Router。

### 环境要求

- Node.js `>=20.19`。
- 推荐 npm `>=11`。
- `DATA_DIR` 持久化使用 Node SQLite 能力，启用持久化时推荐 Node 22+。

### 快速启动

```bash
npm install
npm run dev
```

打开：

```text
http://localhost:5173
```

开发端口：

- 后端 API：`http://localhost:4000`
- 前端 dev server：`http://localhost:5173`
- Vite dev proxy：`/api` 转发到 `VITE_API_PROXY` 或 `http://localhost:4000`

### 生产构建

```bash
npm run build
npm start
```

当 `frontend/dist` 存在时，后端会直接托管前端构建产物和 API，默认端口为 `4000`。

### 脚本

| 命令 | 说明 |
| --- | --- |
| `npm run dev` | 同时启动后端和前端 watch 模式。 |
| `npm run build` | 构建后端和前端。 |
| `npm run typecheck` | 检查两个 workspace 的 TypeScript 类型。 |
| `npm run lint` | 检查两个 workspace 的 ESLint。 |
| `npm run test` | 运行后端测试。 |
| `npm start` | 启动已编译后端，并在有前端构建产物时托管前端。 |

### REST API

| 接口 | 说明 |
| --- | --- |
| `GET /api/health` | 服务状态和情报源健康状态。探活接口保持开放。 |
| `GET /api/stream` | Server-Sent Events 刷新流。 |
| `GET /api/threats` | 威胁指标，可按 `source`、`type`、`severity`、`q`、`limit` 过滤。 |
| `GET /api/map` | 用于地图的地理化指标。 |
| `GET /api/cve` | NVD 最新 CVE。 |
| `GET /api/hashes` | Hash IOC 和恶意软件家族聚合。 |
| `GET /api/stats` | 按来源、类型、严重性、国家或地区聚合的统计。 |
| `GET /api/sources/health` | 每个来源的刷新、错误和健康状态。 |
| `GET /api/sources/history` | 启用持久化后的来源健康历史。 |
| `GET /api/trend` | 启用持久化后的指标数量趋势。 |
| `GET /api/config/status` | 非敏感配置状态，包括来源、富化服务、通知和持久化。 |
| `POST /api/config/test` | 测试单个来源或富化服务。启用认证后需要 admin 角色。 |
| `GET /api/enrich` | 对单个可观测对象进行按需富化。启用认证后需要 analyst 角色。 |
| `GET /api/investigate` | IOC 调查和 STRIDE 模型。启用认证后需要 analyst 角色。 |
| `GET /api/investigations/history` | IOC 调查历史。 |
| `GET /api/investigate/report` | 生成 IOC 调查 Markdown 或 JSON 报告。 |
| `GET /api/threat-model` | 架构级威胁模型，支持 JSON 或 Markdown。 |
| `GET /api/export/stix` | 导出 STIX 2.1 bundle。 |
| `GET /api/notify/status` | 通知配置和最近运行状态。 |
| `POST /api/notify/test` | 向已配置渠道发送测试摘要。启用认证后需要 admin 角色，生产环境可能还需要 `NOTIFY_TEST_TOKEN`。 |
| `GET /api/audit` | 启用持久化后的审计事件。启用认证后需要 admin 角色。 |

TAXII 接口：

- `GET /taxii2/`
- `GET /taxii2/root/`
- `GET /taxii2/root/collections/`
- `GET /taxii2/root/collections/:id/objects/`
- `GET /taxii2/root/collections/:id/manifest/`

### IOC 调查示例

```bash
curl 'http://localhost:4000/api/investigate?indicator=CVE-2026-28318&type=cve&lang=en'
curl 'http://localhost:4000/api/investigate?indicator=example.com&type=domain&lang=zh'
curl 'http://localhost:4000/api/investigate/report?indicator=example.com&type=domain&format=markdown&lang=en'
curl 'http://localhost:4000/api/investigate/report?indicator=example.com&type=domain&format=json&lang=zh'
```

### 架构威胁建模示例

```bash
curl 'http://localhost:4000/api/threat-model?lang=en'
curl 'http://localhost:4000/api/threat-model?lang=zh'
curl 'http://localhost:4000/api/threat-model?format=markdown&lang=en'
```

架构模型包含：

- 范围和方法论。
- 资产、信任边界和数据流。
- STRIDE 场景和 DREAD 评分。
- 攻击路径和控制措施。
- 假设和证据说明。

### 配置检查

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

`/api/config/status` 不返回任何 secret，只返回是否配置、缺失环境变量名等安全状态信息。

### 安全与访问控制

私有或本地部署可以不启用认证。

配置 token 后：

- `API_TOKEN` 视为 admin token。
- `API_VIEWER_TOKENS`、`API_ANALYST_TOKENS`、`API_ADMIN_TOKENS` 提供角色级访问。
- viewer 用于只读数据。
- analyst 用于调查、富化、报告和威胁建模。
- admin 用于集成测试、通知测试和审计访问。

Token 传递方式：

- `Authorization: Bearer <token>`
- `x-api-token: <token>`
- `?token=<token>`

浏览器部署建议配置 `CORS_ORIGINS`、`API_RATE_LIMIT_WINDOW_MS`、`API_RATE_LIMIT_MAX` 和 `JSON_BODY_LIMIT`。

### 告警推送

定时告警摘要默认关闭。设置 `NOTIFY_ENABLED=true` 并配置至少一个渠道后启用：

- DingTalk 自定义机器人。
- Telegram Bot。
- Slack Incoming Webhook。
- 通用 Webhook。

服务启动时会以当前数据作为 baseline，所以第一次摘要只发送启动后新增的威胁。启用持久化后，渠道推送事件和重试状态会写入 SQLite。

### 关键环境变量

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `PORT` | `4000` | 后端端口。 |
| `REFRESH_INTERVAL_MS` | `900000` | 情报刷新周期。 |
| `REFRESH_<SOURCE>_INTERVAL_MS` | 来源默认值 | 单个来源最小刷新间隔覆盖。 |
| `DATA_DIR` | 空 | 启用 SQLite 持久化，包括 geo cache、趋势、审计、推送事件和调查历史。 |
| `VITE_API_BASE` | 空 | 前端 API base。空值表示同源或开发代理。 |
| `VITE_API_PROXY` | `http://localhost:4000` | Vite 开发环境 `/api` 代理目标。 |
| `VITE_API_TOKEN` | 空 | 前端请求携带的 API token。它会进入构建产物，不是后端 secret。 |
| `API_TOKEN` | 空 | admin API token。 |
| `API_VIEWER_TOKENS` / `API_ANALYST_TOKENS` / `API_ADMIN_TOKENS` | 空 | 角色级 token 列表。 |
| `CORS_ORIGINS` | 空 | 浏览器来源白名单。 |
| `NVD_API_KEY` | 空 | 提升 NVD 速率限制。 |
| `GEOLITE2_DB` | 空 | 本地 MaxMind GeoLite2 数据库路径。 |
| `PHISHTANK_APP_KEY` | 空 | 启用 PhishTank 来源。 |
| `ABUSEIPDB_API_KEY` | 空 | 启用 AbuseIPDB 来源。 |
| `OTX_API_KEY` | 空 | 启用 AlienVault OTX。 |
| `TAXII_IMPORT_OBJECTS_URL` | 空 | 启用外部 TAXII 导入。 |
| `VIRUSTOTAL_API_KEY` | 空 | 启用 VirusTotal 富化。 |
| `SHODAN_API_KEY` | 空 | 启用 Shodan 富化。 |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | 空 | 启用 Censys 富化。 |
| `X_BEARER_TOKEN` | 空 | 启用 X Recent Search。 |
| `FACEBOOK_ACCESS_TOKEN` / `FACEBOOK_PAGE_IDS` | 空 | 启用 Facebook 页面采集。 |
| `NOTIFY_ENABLED` | `false` | 启用定时告警摘要。 |
| `NOTIFY_MIN_SEVERITY` | `critical` | 告警最低严重性。 |
| `NOTIFY_SOURCES` | 全部 | 告警来源白名单。 |
| `DINGTALK_WEBHOOK` / `DINGTALK_SECRET` | 空 | DingTalk 告警。 |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | 空 | Telegram 告警。 |
| `SLACK_WEBHOOK` | 空 | Slack 告警。 |
| `WEBHOOK_URL` | 空 | 通用 JSON Webhook 告警。 |

完整变量请查看 `.env.example`。

### 验证命令

```bash
npm run typecheck
npm run lint
npm run build
npm run test
npm audit --json
```

当前前端构建链使用 Vite 8 和 `@vitejs/plugin-react` 6。

### Docker

```bash
docker build -t threat-intel-platform .
docker run --rm -p 4000:4000 threat-intel-platform
```

Dockerfile 使用 Node 22 镜像，兼容 Vite 8 和可选持久化能力。

### License

MIT。仅用于防御和研究用途。上游数据仍受各来源服务条款约束。
