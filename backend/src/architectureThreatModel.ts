import type { ArchitectureThreatModel, DreadScore, Language, Severity, SourceHealth, ThreatModelScenario } from './types.js';

interface StatsLike {
  totalIndicators: number;
  totalCves: number;
}

export interface ArchitectureThreatModelContext {
  authConfigured?: boolean;
  persistenceEnabled?: boolean;
  notifyEnabled?: boolean;
  configuredNotifyChannels?: string[];
  corsRestricted?: boolean;
  rateLimitMax?: number;
  jsonBodyLimit?: string;
}

interface ScenarioOptions {
  assetIds?: string[];
  dataFlowIds?: string[];
  threat?: string;
  impact?: string;
  dread?: DreadScore;
  controls?: string[];
  treatment?: ThreatModelScenario['treatment'];
  verification?: string[];
}

function text(zh: boolean, en: string, cn: string): string {
  return zh ? cn : en;
}

function list(zh: boolean, en: string[], cn: string[]): string[] {
  return zh ? cn : en;
}

function riskFromAverage(average: number): Severity {
  if (average >= 8) return 'critical';
  if (average >= 6) return 'high';
  if (average >= 4) return 'medium';
  return 'low';
}

function dread(input: Omit<DreadScore, 'total' | 'average' | 'risk'>): DreadScore {
  const total =
    input.damage +
    input.reproducibility +
    input.exploitability +
    input.affectedUsers +
    input.discoverability;
  const average = Number((total / 5).toFixed(1));
  return { ...input, total, average, risk: riskFromAverage(average) };
}

function scenario(
  id: string,
  title: string,
  stride: ThreatModelScenario['stride'],
  severity: Severity,
  confidence: number,
  evidence: string[],
  recommendations: string[],
  options: ScenarioOptions = {},
): ThreatModelScenario {
  return {
    id,
    title,
    stride,
    severity: options.dread?.risk ?? severity,
    confidence,
    evidence,
    recommendations,
    ...options,
  };
}

function configuredChannels(channels: string[] | undefined, zh: boolean): string {
  if (!channels || channels.length === 0) return text(zh, 'none', '无');
  return channels.join(', ');
}

export function buildArchitectureThreatModel(
  stats: StatsLike,
  health: SourceHealth[],
  language: Language = 'en',
  context: ArchitectureThreatModelContext = {},
): ArchitectureThreatModel {
  const zh = language === 'zh';
  const disabled = health.filter((source) => source.status === 'disabled');
  const failing = health.filter((source) => source.status === 'error' || source.status === 'stale');
  const configuredCredentialed = health.filter((source) => source.credentialed && source.configured);
  const credentialedSourceCount = health.filter((source) => source.credentialed).length;
  const publicSourceCount = health.filter((source) => !source.credentialed).length;
  const authConfigured = context.authConfigured ?? false;
  const persistenceEnabled = context.persistenceEnabled ?? false;
  const notifyEnabled = context.notifyEnabled ?? false;
  const notifyChannels = context.configuredNotifyChannels ?? [];
  const corsRestricted = context.corsRestricted ?? false;
  const rateLimitMax = context.rateLimitMax ?? 180;
  const jsonBodyLimit = context.jsonBodyLimit ?? '1mb';

  return {
    scope: text(zh, 'Threat Intelligence Platform', '威胁情报平台'),
    generatedAt: new Date().toISOString(),
    methodology: {
      framework: 'STRIDE',
      scoring: 'DREAD',
      process: list(
        zh,
        [
          'Define scope, assets, users, entry points, and trust boundaries from the current codebase',
          'Draw data flows across browser, Express API, collectors, persistence, third-party feeds, TAXII, and notifier channels',
          'Run STRIDE per element: asset, data flow, trust boundary, and external dependency',
          'Prioritize scenarios with DREAD and current runtime evidence such as source health and deployment configuration',
          'Track treatment decisions, controls, and verification steps before adding new sources or exposing deployments',
        ],
        [
          '从当前代码库定义范围、资产、用户、入口点和信任边界',
          '绘制浏览器、Express API、采集器、持久化、第三方情报源、TAXII 和通知通道之间的数据流',
          '按资产、数据流、信任边界和外部依赖逐项执行 STRIDE 分析',
          '结合来源健康状态和部署配置，用 DREAD 对场景排序',
          '新增来源、接口或对外部署前，记录处置决策、控制措施和验证方式',
        ],
      ),
      reviewTriggers: list(
        zh,
        [
          'New external feed, enrichment provider, notification channel, or TAXII consumer',
          'New analyst/admin endpoint, role, token path, or browser-exposed credential pattern',
          'Persistence, queue, scheduler, container, or multi-instance deployment changes',
          'Production exposure, CORS changes, auth proxy changes, or incident-response workflow changes',
        ],
        [
          '新增外部情报源、富化服务商、通知通道或 TAXII 消费者',
          '新增分析员/管理员接口、角色、Token 传递路径或浏览器侧凭据模式',
          '持久化、队列、调度器、容器或多实例部署发生变化',
          '对生产环境开放、CORS 变更、认证代理变更或事件响应流程变化',
        ],
      ),
      references: [
        {
          title: text(zh, 'STRIDE threat modeling execution process', '基于 STRIDE 的威胁建模执行流程'),
          url: 'https://tonydeng.github.io/2022/04/20/threat-modeling-was-conducted-based-on-STRIDE/',
        },
        {
          title: text(zh, 'Meituan threat modeling practice', '美团威胁建模实践'),
          url: 'https://tech.meituan.com/2021/04/08/Threat-Modeling-Security.html',
        },
        {
          title: text(zh, 'Fortinet threat modeling overview', 'Fortinet 威胁建模概览'),
          url: 'https://www.fortinet.com/cn/resources/cyberglossary/threat-modeling',
        },
      ],
    },
    layers: [
      {
        layer: 'system',
        description: text(
          zh,
          'Internet CTI sources, browser users, SIEM/TAXII consumers, and notifier platforms around the platform boundary.',
          '平台边界外包含互联网 CTI 来源、浏览器用户、SIEM/TAXII 消费者和通知平台。',
        ),
        assets: ['analyst', 'feeds', 'consumers', 'notifiers'],
        trustBoundaries: ['browser-api', 'api-internet', 'api-consumers'],
        entryPoints: ['/api/*', '/taxii2/*', notifyEnabled ? 'scheduled notifier' : 'notification test endpoint'],
      },
      {
        layer: 'application',
        description: text(
          zh,
          'React dashboard and Express API surface for search, investigation, enrichment, reporting, and configuration checks.',
          'React 仪表盘与 Express API 承载检索、调查、富化、报告和配置检查。',
        ),
        assets: ['dashboard', 'api'],
        trustBoundaries: ['browser-api'],
        entryPoints: ['/api/threats', '/api/investigate', '/api/enrich', '/api/threat-model', '/api/config/test'],
      },
      {
        layer: 'service',
        description: text(
          zh,
          'Collectors, enrichers, geolocation, STIX/TAXII export, notifier delivery, and optional Python hub pipeline.',
          '服务层包含采集器、富化器、地理定位、STIX/TAXII 导出、通知发送和可选 Python hub 管道。',
        ),
        assets: ['collectors', 'enrichers', 'taxii', 'notifiers', 'python_hub'],
        trustBoundaries: ['api-internet', 'api-consumers', 'python-hub-internet'],
        entryPoints: [
          'backend/src/sources/*',
          'backend/src/enrich.ts',
          'backend/src/geo.ts',
          'security-intel-hub/security_intel_hub/pipeline.py',
        ],
      },
      {
        layer: 'code',
        description: text(
          zh,
          'Config, secrets, SQLite-backed state, audit events, health samples, and generated reports.',
          '代码与运行态状态包含配置、密钥、SQLite 状态、审计事件、健康样本和生成报告。',
        ),
        assets: ['store', 'secrets'],
        trustBoundaries: ['api-data', 'deployment-secrets'],
        entryPoints: ['environment variables', 'DATA_DIR/threat-intel.db', 'config.example.json'],
      },
    ],
    assets: [
      {
        id: 'analyst',
        name: text(zh, 'Security analyst', '安全分析员'),
        kind: 'user',
        trustZone: text(zh, 'operator', '操作员区'),
        criticality: 'medium',
        data: list(zh, ['investigation decisions', 'exported reports'], ['调查决策', '导出报告']),
        owner: text(zh, 'SOC / IR team', 'SOC / 应急响应团队'),
        securityObjectives: ['integrity', 'accountability'],
      },
      {
        id: 'dashboard',
        name: text(zh, 'React dashboard', 'React 仪表盘'),
        kind: 'service',
        trustZone: text(zh, 'application', '应用区'),
        criticality: 'medium',
        data: list(zh, ['IOC searches', 'configuration status', 'model output'], ['IOC 检索', '配置状态', '模型输出']),
        owner: text(zh, 'Frontend', '前端'),
        securityObjectives: ['confidentiality', 'integrity'],
      },
      {
        id: 'api',
        name: 'Express API',
        kind: 'service',
        trustZone: text(zh, 'application', '应用区'),
        criticality: 'high',
        data: list(
          zh,
          ['normalized indicators', 'source health', 'enrichment responses'],
          ['标准化指标', '来源健康状态', '富化响应'],
        ),
        owner: text(zh, 'Backend', '后端'),
        securityObjectives: ['confidentiality', 'integrity', 'availability', 'accountability'],
      },
      {
        id: 'collectors',
        name: text(zh, 'Feed collectors and normalizers', '情报采集器与归一化器'),
        kind: 'service',
        trustZone: text(zh, 'application', '应用区'),
        criticality: 'high',
        data: list(
          zh,
          ['public feed payloads', 'credentialed feed responses', 'parsed IOCs'],
          ['公开情报源载荷', '凭据化情报源响应', '解析后的 IOC'],
        ),
        owner: text(zh, 'Backend', '后端'),
        securityObjectives: ['integrity', 'availability'],
      },
      {
        id: 'enrichers',
        name: text(zh, 'On-demand enrichment providers', '按需富化服务商'),
        kind: 'integration',
        trustZone: text(zh, 'internet', '互联网区'),
        criticality: 'high',
        data: list(
          zh,
          ['indicator queries', 'provider summaries', 'quota-consuming API calls'],
          ['指标查询', '服务商摘要', '消耗配额的 API 调用'],
        ),
        owner: text(zh, 'Backend / SOC', '后端 / SOC'),
        securityObjectives: ['confidentiality', 'availability'],
      },
      {
        id: 'store',
        name: text(zh, 'Aggregator store and optional SQLite persistence', '聚合存储与可选 SQLite 持久化'),
        kind: 'data_store',
        trustZone: text(zh, 'data', '数据区'),
        criticality: 'high',
        data: list(
          zh,
          ['first/last seen', 'investigation history', 'audit events', 'geo cache'],
          ['首次/最近出现时间', '调查历史', '审计事件', '地理缓存'],
        ),
        owner: text(zh, 'Backend / Platform', '后端 / 平台'),
        securityObjectives: ['integrity', 'availability', 'accountability'],
      },
      {
        id: 'feeds',
        name: text(zh, 'External threat-intelligence feeds', '外部威胁情报源'),
        kind: 'external_source',
        trustZone: text(zh, 'internet', '互联网区'),
        criticality: 'high',
        data: list(zh, ['public IOCs', 'credentialed feed data', 'CVE data'], ['公开 IOC', '凭据化来源数据', 'CVE 数据']),
        owner: text(zh, 'Third parties', '第三方'),
        securityObjectives: ['integrity', 'availability'],
      },
      {
        id: 'secrets',
        name: text(zh, 'API keys and notification webhooks', 'API 密钥和通知 Webhook'),
        kind: 'secret',
        trustZone: text(zh, 'deployment', '部署区'),
        criticality: 'critical',
        data: list(
          zh,
          ['API tokens', 'OTX/AbuseIPDB/VT/Shodan/Censys credentials', 'push channel webhooks'],
          ['API Token', 'OTX/AbuseIPDB/VT/Shodan/Censys 凭据', '推送通道 Webhook'],
        ),
        owner: text(zh, 'Platform / DevOps', '平台 / DevOps'),
        securityObjectives: ['confidentiality', 'accountability'],
      },
      {
        id: 'taxii',
        name: text(zh, 'STIX/TAXII export surface', 'STIX/TAXII 导出面'),
        kind: 'integration',
        trustZone: text(zh, 'application', '应用区'),
        criticality: 'medium',
        data: list(
          zh,
          ['STIX 2.1 objects', 'TAXII collection manifests', 'pagination cursors'],
          ['STIX 2.1 对象', 'TAXII Collection Manifest', '分页游标'],
        ),
        owner: text(zh, 'Backend', '后端'),
        securityObjectives: ['integrity', 'availability'],
      },
      {
        id: 'notifiers',
        name: text(zh, 'Notification channels', '通知通道'),
        kind: 'integration',
        trustZone: text(zh, 'external_consumer', '外部消费区'),
        criticality: 'medium',
        data: list(zh, ['alert digests', 'webhook URLs', 'bot messages'], ['告警摘要', 'Webhook URL', '机器人消息']),
        owner: text(zh, 'SOC / ChatOps', 'SOC / ChatOps'),
        securityObjectives: ['confidentiality', 'integrity', 'availability'],
      },
      {
        id: 'consumers',
        name: text(zh, 'SIEM, TAXII, and notification consumers', 'SIEM、TAXII 和通知消费者'),
        kind: 'integration',
        trustZone: text(zh, 'external_consumer', '外部消费区'),
        criticality: 'medium',
        data: list(zh, ['STIX objects', 'digest messages', 'reports'], ['STIX 对象', '摘要消息', '报告']),
        owner: text(zh, 'Downstream teams', '下游团队'),
        securityObjectives: ['integrity'],
      },
      {
        id: 'python_hub',
        name: text(zh, 'Security Intel Hub Python CLI', 'Security Intel Hub Python CLI'),
        kind: 'service',
        trustZone: text(zh, 'scheduled_worker', '定时任务区'),
        criticality: 'medium',
        data: list(
          zh,
          ['X/Facebook/RSS items', 'SQLite dedupe state', 'Telegram/DingTalk pushes'],
          ['X/Facebook/RSS 情报项', 'SQLite 去重状态', 'Telegram/钉钉推送'],
        ),
        owner: text(zh, 'Automation', '自动化'),
        securityObjectives: ['confidentiality', 'integrity', 'availability'],
      },
    ],
    trustBoundaries: [
      {
        id: 'browser-api',
        name: text(zh, 'Browser to API', '浏览器到 API'),
        description: text(zh, 'Operators send searches and actions from the dashboard to the API.', '操作员从仪表盘向 API 发送检索和操作请求。'),
        assets: ['analyst', 'dashboard', 'api'],
      },
      {
        id: 'api-internet',
        name: text(zh, 'API to internet feeds', 'API 到互联网情报源'),
        description: text(
          zh,
          'Collectors and enrichers receive untrusted upstream data and provider responses.',
          '采集器和富化器接收不可信的上游数据和服务商响应。',
        ),
        assets: ['api', 'collectors', 'enrichers', 'feeds'],
      },
      {
        id: 'api-data',
        name: text(zh, 'API to persistence', 'API 到持久化存储'),
        description: text(zh, 'The API writes operational history, audit data, and cached observations.', 'API 写入操作历史、审计数据和缓存观测。'),
        assets: ['api', 'store'],
      },
      {
        id: 'api-consumers',
        name: text(zh, 'API to downstream consumers', 'API 到下游消费者'),
        description: text(zh, 'Exports and notifications leave the platform boundary.', '导出和通知会离开平台边界。'),
        assets: ['api', 'taxii', 'notifiers', 'consumers'],
      },
      {
        id: 'deployment-secrets',
        name: text(zh, 'Deployment secrets', '部署密钥'),
        description: text(
          zh,
          'Runtime environment variables and local config files carry API tokens, provider keys, and webhooks.',
          '运行时环境变量和本地配置文件承载 API Token、服务商密钥和 Webhook。',
        ),
        assets: ['api', 'secrets', 'python_hub'],
      },
      {
        id: 'python-hub-internet',
        name: text(zh, 'Python hub to internet platforms', 'Python hub 到互联网平台'),
        description: text(zh, 'The optional Python CLI reads official APIs/RSS feeds and sends bot notifications.', '可选 Python CLI 读取官方 API/RSS 并发送机器人通知。'),
        assets: ['python_hub', 'feeds', 'notifiers'],
      },
    ],
    dataFlows: [
      {
        id: 'search-flow',
        from: 'dashboard',
        to: 'api',
        name: text(zh, 'IOC search and threat modeling', 'IOC 检索与威胁建模'),
        protocol: 'HTTPS/JSON',
        crossesTrustBoundary: true,
        data: list(zh, ['indicator', 'indicator type', 'model response'], ['指标', '指标类型', '模型响应']),
        trustBoundary: 'browser-api',
        threatSurface: list(zh, ['query parameters', 'role-scoped token', 'downloaded reports'], ['查询参数', '角色范围 Token', '下载报告']),
      },
      {
        id: 'stream-flow',
        from: 'api',
        to: 'dashboard',
        name: text(zh, 'Server-Sent Events refresh stream', 'SSE 刷新流'),
        protocol: 'HTTPS text/event-stream',
        crossesTrustBoundary: true,
        data: list(zh, ['refresh timestamps', 'aggregate counts', 'optional query token'], ['刷新时间戳', '聚合计数', '可选查询 Token']),
        trustBoundary: 'browser-api',
        threatSurface: list(zh, ['long-lived connection', 'query-token transport'], ['长连接', '查询参数传递 Token']),
      },
      {
        id: 'feed-flow',
        from: 'feeds',
        to: 'collectors',
        name: text(zh, 'Feed collection and enrichment', '情报源采集与富化'),
        protocol: 'HTTPS/JSON, CSV, STIX/TAXII',
        crossesTrustBoundary: true,
        data: list(zh, ['IOCs', 'CVEs', 'provider summaries'], ['IOC', 'CVE', '服务商摘要']),
        trustBoundary: 'api-internet',
        threatSurface: list(zh, ['third-party feed payloads', 'provider quotas', 'parser assumptions'], ['第三方情报源载荷', '服务商配额', '解析器假设']),
      },
      {
        id: 'geo-flow',
        from: 'api',
        to: 'feeds',
        name: text(zh, 'IP geolocation enrichment', 'IP 地理定位富化'),
        protocol: 'HTTP batch API',
        crossesTrustBoundary: true,
        data: list(zh, ['public IP indicators', 'country', 'latitude/longitude'], ['公开 IP 指标', '国家', '经纬度']),
        trustBoundary: 'api-internet',
        threatSurface: list(zh, ['cleartext network path', 'third-party availability'], ['明文网络路径', '第三方可用性']),
      },
      {
        id: 'persist-flow',
        from: 'api',
        to: 'store',
        name: text(zh, 'Operational persistence', '操作数据持久化'),
        protocol: 'SQLite',
        crossesTrustBoundary: false,
        data: list(zh, ['history', 'audit events', 'source health'], ['历史记录', '审计事件', '来源健康状态']),
        trustBoundary: 'api-data',
        threatSurface: list(zh, ['local filesystem permissions', 'single-writer behavior', 'backup handling'], ['本地文件权限', '单写者行为', '备份处理']),
      },
      {
        id: 'export-flow',
        from: 'taxii',
        to: 'consumers',
        name: text(zh, 'STIX/TAXII/report/notification export', 'STIX/TAXII/报告/通知导出'),
        protocol: 'HTTPS/JSON, STIX 2.1, Markdown',
        crossesTrustBoundary: true,
        data: list(zh, ['indicator bundle', 'threat model', 'alert digest'], ['指标包', '威胁模型', '告警摘要']),
        trustBoundary: 'api-consumers',
        threatSurface: list(
          zh,
          ['downstream trust in generated content', 'pagination cursors', 'message formatting'],
          ['下游对生成内容的信任', '分页游标', '消息格式化'],
        ),
      },
      {
        id: 'notify-flow',
        from: 'notifiers',
        to: 'consumers',
        name: text(zh, 'Scheduled and test alert delivery', '定时和测试告警发送'),
        protocol: 'HTTPS webhook/bot API',
        crossesTrustBoundary: true,
        data: list(zh, ['alert digest', 'webhook token', 'chat identifier'], ['告警摘要', 'Webhook Token', '聊天标识']),
        trustBoundary: 'api-consumers',
        threatSurface: list(zh, ['real outbound messages', 'webhook replay', 'chat leakage'], ['真实外发消息', 'Webhook 重放', '聊天泄露']),
      },
      {
        id: 'python-hub-flow',
        from: 'python_hub',
        to: 'feeds',
        name: text(zh, 'Standalone Python collection pipeline', '独立 Python 采集管道'),
        protocol: 'HTTPS API/RSS',
        crossesTrustBoundary: true,
        data: list(zh, ['social posts', 'RSS entries', 'scores', 'SQLite dedupe keys'], ['社交帖子', 'RSS 条目', '评分', 'SQLite 去重 Key']),
        trustBoundary: 'python-hub-internet',
        threatSurface: list(zh, ['JSON config', 'official API credentials', 'local SQLite file'], ['JSON 配置', '官方 API 凭据', '本地 SQLite 文件']),
      },
    ],
    threatMatrix: [
      {
        elementId: 'browser-api',
        elementType: 'trust_boundary',
        elementName: text(zh, 'Browser to API', '浏览器到 API'),
        priority: authConfigured ? 'high' : 'critical',
        stride: {
          Spoofing: [text(zh, 'Stolen API token or query token impersonates analyst/admin traffic', '被盗 API Token 或查询 Token 可冒充分析员/管理员请求')],
          Repudiation: [text(zh, 'Without persistent audit events, enrichment/config actions are hard to attribute', '没有持久化审计时，富化/配置动作难以归因')],
          'Elevation of Privilege': [text(zh, 'Shared admin token allows viewer workflows to reach analyst/admin routes', '共享管理员 Token 会让查看者流程触达分析员/管理员接口')],
        },
      },
      {
        elementId: 'feed-flow',
        elementType: 'data_flow',
        elementName: text(zh, 'External feed ingestion', '外部情报源摄取'),
        priority: failing.length > 0 ? 'high' : 'medium',
        stride: {
          Spoofing: [text(zh, 'Lookalike or compromised upstream source publishes false indicators', '仿冒或被攻陷的上游来源发布虚假指标')],
          Tampering: [text(zh, 'Unexpected payload structure changes parser output or confidence', '非预期载荷结构改变解析输出或置信度')],
          'Denial of Service': [text(zh, 'Upstream outage, rate limiting, or slow feeds stale the dashboard', '上游故障、限流或慢响应导致仪表盘数据过期')],
        },
      },
      {
        elementId: 'geo-flow',
        elementType: 'data_flow',
        elementName: text(zh, 'HTTP geolocation enrichment', 'HTTP 地理定位富化'),
        priority: 'medium',
        stride: {
          Tampering: [text(zh, 'Cleartext response can alter map country/lat/lon context', '明文响应可能被篡改地图国家/经纬度上下文')],
          'Information Disclosure': [text(zh, 'Public IP indicators are sent to a third-party geolocation API', '公开 IP 指标会发送给第三方地理定位 API')],
        },
      },
      {
        elementId: 'secrets',
        elementType: 'asset',
        elementName: text(zh, 'API keys and notification webhooks', 'API 密钥和通知 Webhook'),
        priority: configuredCredentialed.length > 0 || notifyEnabled ? 'critical' : 'high',
        stride: {
          'Information Disclosure': [text(zh, 'Environment variables, config files, or logs expose provider credentials', '环境变量、配置文件或日志暴露服务商凭据')],
          Spoofing: [text(zh, 'Leaked webhook or bot token lets an attacker send trusted-looking alerts', '泄露的 Webhook 或机器人 Token 可发送看似可信的告警')],
          'Elevation of Privilege': [text(zh, 'Leaked admin token bypasses route role checks', '泄露的管理员 Token 可绕过路由角色检查')],
        },
      },
      {
        elementId: 'persist-flow',
        elementType: 'data_flow',
        elementName: text(zh, 'SQLite operational persistence', 'SQLite 操作持久化'),
        priority: persistenceEnabled ? 'medium' : 'high',
        stride: {
          Tampering: [text(zh, 'Local DB modification changes seen-state, audit history, or cached context', '本地 DB 被改动会改变已见状态、审计历史或缓存上下文')],
          Repudiation: [text(zh, 'In-memory deployments lose investigation and audit evidence on restart', '纯内存部署重启后丢失调查和审计证据')],
          'Denial of Service': [text(zh, 'Single-node SQLite is unsuitable for multiple concurrent writers', '单节点 SQLite 不适合多个写入实例并发写入')],
        },
      },
      {
        elementId: 'export-flow',
        elementType: 'data_flow',
        elementName: text(zh, 'STIX/TAXII/report export', 'STIX/TAXII/报告导出'),
        priority: 'high',
        stride: {
          Tampering: [text(zh, 'Unsigned reports can be modified before downstream use', '未签名报告可能在下游使用前被修改')],
          'Information Disclosure': [text(zh, 'Exports may reveal investigation focus, source mix, or internal triage notes', '导出可能暴露调查关注点、来源组合或内部研判信息')],
          Repudiation: [text(zh, 'Downstream consumers need generated-at and provenance to trace decisions', '下游消费者需要生成时间和来源信息追踪决策')],
        },
      },
      {
        elementId: 'notify-flow',
        elementType: 'data_flow',
        elementName: text(zh, 'Notification delivery', '通知发送'),
        priority: notifyEnabled ? 'high' : 'medium',
        stride: {
          Spoofing: [text(zh, 'Webhook token compromise produces fake SOC alerts', 'Webhook Token 泄露可生成伪造 SOC 告警')],
          'Denial of Service': [text(zh, 'Repeated tests or alert storms flood ChatOps channels', '重复测试或告警风暴会刷屏 ChatOps 通道')],
          'Information Disclosure': [text(zh, 'Digest messages leave the platform boundary into chat systems', '摘要消息会离开平台边界进入聊天系统')],
        },
      },
    ],
    scenarios: [
      scenario(
        'spoofed-feed-data',
        text(zh, 'Untrusted upstream feed data pollutes local intelligence', '不可信上游情报污染本地威胁库'),
        'Spoofing',
        failing.length > 0 ? 'high' : 'medium',
        70,
        [
          text(zh, `${publicSourceCount} public sources are ingested from the internet`, `当前从互联网采集 ${publicSourceCount} 个公开来源`),
          text(zh, `${stats.totalIndicators} indicators are currently normalized`, `当前已标准化 ${stats.totalIndicators} 条指标`),
          failing.length > 0
            ? text(zh, `${failing.length} sources are stale or failing`, `${failing.length} 个来源处于过期或失败状态`)
            : text(zh, 'No stale/error sources in current health', '当前健康状态中没有过期或错误来源'),
        ],
        list(
          zh,
          [
            'Preserve source provenance, reliability, TLP, and confidence near every indicator',
            'Corroborate high-impact decisions across multiple sources or enrichment providers',
            'Alert on source health regression before using stale-only evidence',
          ],
          ['在每条指标附近保留来源、可靠性、TLP 和置信度', '高影响处置需跨多个来源或富化服务交叉验证', '在只剩过期证据前对来源健康退化告警'],
        ),
        {
          assetIds: ['feeds', 'collectors', 'api'],
          dataFlowIds: ['feed-flow'],
          threat: text(zh, 'An upstream feed or provider returns false, stale, or intentionally misleading indicators.', '上游情报源或服务商返回虚假、过期或故意误导的指标。'),
          impact: text(zh, 'Analysts may block benign infrastructure, miss a real campaign, or propagate bad STIX/TAXII data.', '分析员可能封禁正常基础设施、漏掉真实攻击活动，或传播错误 STIX/TAXII 数据。'),
          dread: dread({
            damage: 8,
            reproducibility: 6,
            exploitability: 6,
            affectedUsers: 7,
            discoverability: 7,
            rationale: list(
              zh,
              ['Feed ingestion is automated and internet-facing', 'Cross-source corroboration exists but source identity is still externally controlled'],
              ['情报摄取是自动化且面向互联网的', '系统有跨来源交叉验证，但来源身份仍由外部控制'],
            ),
          }),
          controls: ['source-provenance', 'source-health-alerting'],
          treatment: 'implemented',
          verification: list(zh, ['Run feed parser tests', 'Review source health before high-impact action'], ['运行情报源解析测试', '高影响动作前复核来源健康状态']),
        },
      ),
      scenario(
        'tampered-model-output',
        text(zh, 'A client or intermediary tampers with exported reports or model output', '客户端或中间环节篡改导出报告或模型输出'),
        'Tampering',
        'high',
        65,
        list(
          zh,
          ['Reports and STIX/TAXII exports leave the API trust boundary', 'Operators may use exports in downstream workflows'],
          ['报告和 STIX/TAXII 导出会离开 API 信任边界', '操作员可能在下游流程中使用导出内容'],
        ),
        list(
          zh,
          [
            'Serve exports only over TLS behind trusted ingress',
            'Record audit events for report generation and configuration tests',
            'Add file signing or checksum validation for regulated downstream exchange',
          ],
          ['仅通过受信入口和 TLS 提供导出', '记录报告生成和配置测试的审计事件', '在合规交换场景中增加文件签名或校验和验证'],
        ),
        {
          assetIds: ['api', 'taxii', 'consumers'],
          dataFlowIds: ['export-flow'],
          threat: text(zh, 'A generated report, TAXII response, or Markdown export is altered after it leaves the API.', '生成报告、TAXII 响应或 Markdown 导出在离开 API 后被修改。'),
          impact: text(zh, 'Downstream incident response or compliance evidence may rely on modified findings.', '下游应急响应或合规证据可能依赖被修改的结论。'),
          dread: dread({
            damage: 8,
            reproducibility: 5,
            exploitability: 5,
            affectedUsers: 6,
            discoverability: 6,
            rationale: list(
              zh,
              ['Exports are trusted by downstream consumers', 'The code does not currently sign report artifacts'],
              ['导出内容会被下游消费者信任', '当前代码尚未对报告制品签名'],
            ),
          }),
          controls: ['audit-events', 'signed-exports'],
          treatment: 'planned',
          verification: list(
            zh,
            ['Export Markdown and validate generated timestamp/provenance', 'Add checksum/signature tests when implemented'],
            ['导出 Markdown 并校验生成时间/来源信息', '实现后增加校验和/签名测试'],
          ),
        },
      ),
      scenario(
        'missing-audit-accountability',
        text(zh, 'Configuration and investigation actions cannot be attributed', '配置和调查操作无法归因'),
        'Repudiation',
        persistenceEnabled ? 'medium' : 'high',
        60,
        [
          text(zh, 'Configuration tests and enrichment calls can create external provider traffic', '配置测试和富化调用会产生外部服务商流量'),
          text(zh, 'Investigation history is operational evidence', '调查历史属于操作证据'),
          persistenceEnabled ? text(zh, 'DATA_DIR persistence is enabled', 'DATA_DIR 持久化已启用') : text(zh, 'DATA_DIR persistence is disabled or unavailable', 'DATA_DIR 持久化未启用或不可用'),
        ],
        list(
          zh,
          [
            'Use role-scoped API tokens for analyst/admin actions',
            'Persist audit events when DATA_DIR is configured',
            'Review audit logs during incident review and source onboarding',
          ],
          ['为分析员和管理员操作使用角色范围 API Token', '配置 DATA_DIR 后持久化审计事件', '在事件复盘和情报源接入时审查审计日志'],
        ),
        {
          assetIds: ['api', 'store', 'analyst'],
          dataFlowIds: ['search-flow', 'persist-flow'],
          threat: text(zh, 'A user denies running enrichment, report generation, notification tests, or integration tests.', '用户否认执行过富化、报告生成、通知测试或集成测试。'),
          impact: text(zh, 'External quota consumption, ChatOps messages, or triage decisions cannot be reliably reconstructed.', '外部配额消耗、ChatOps 消息或研判决策无法可靠复盘。'),
          dread: dread({
            damage: persistenceEnabled ? 5 : 7,
            reproducibility: 6,
            exploitability: 5,
            affectedUsers: 5,
            discoverability: 6,
            rationale: list(
              zh,
              [
                'Audit middleware exists for sensitive routes',
                persistenceEnabled ? 'Persistence can retain audit events' : 'In-memory operation drops audit history on restart',
              ],
              ['敏感路由已有审计中间件', persistenceEnabled ? '持久化可保留审计事件' : '纯内存运行会在重启后丢失审计历史'],
            ),
          }),
          controls: ['role-scoped-auth', 'audit-events'],
          treatment: persistenceEnabled ? 'implemented' : 'planned',
          verification: list(zh, ['Call /api/audit after analyst/admin actions when DATA_DIR is enabled'], ['启用 DATA_DIR 后，在分析员/管理员操作后调用 /api/audit 查看审计记录']),
        },
      ),
      scenario(
        'secret-disclosure',
        text(zh, 'Provider credentials or webhook URLs are exposed', '服务商凭据或 Webhook 地址泄露'),
        'Information Disclosure',
        configuredCredentialed.length > 0 ? 'critical' : 'high',
        80,
        [
          text(
            zh,
            `${configuredCredentialed.length} of ${credentialedSourceCount} credentialed sources are configured`,
            `${credentialedSourceCount} 个凭据化来源中已配置 ${configuredCredentialed.length} 个`,
          ),
          text(
            zh,
            `${disabled.length} credentialed sources are currently disabled or missing configuration`,
            `当前 ${disabled.length} 个凭据化来源被禁用或缺少配置`,
          ),
          notifyEnabled
            ? text(zh, `Notification delivery is enabled for ${configuredChannels(notifyChannels, zh)}`, `通知发送已启用，通道：${configuredChannels(notifyChannels, zh)}`)
            : text(zh, 'Notification delivery is disabled', '通知发送未启用'),
        ],
        list(
          zh,
          [
            'Never return secret values from configuration APIs',
            'Keep credentials in environment or secret manager only',
            'Rotate provider keys after failed deployment or suspicious audit entries',
          ],
          ['配置 API 永不返回密钥原文', '凭据仅存放在环境变量或密钥管理器中', '部署失败或出现可疑审计记录后轮换服务商密钥'],
        ),
        {
          assetIds: ['secrets', 'api', 'notifiers', 'python_hub'],
          dataFlowIds: ['notify-flow', 'python-hub-flow'],
          threat: text(zh, 'Secrets leak through environment dumps, config files, deployment logs, browser bundles, or chat webhook URLs.', '密钥通过环境导出、配置文件、部署日志、浏览器包或聊天 Webhook 泄露。'),
          impact: text(zh, 'Attackers can query paid providers, impersonate SOC notifications, or access protected API routes.', '攻击者可查询付费服务商、冒充 SOC 通知，或访问受保护 API 路由。'),
          dread: dread({
            damage: 9,
            reproducibility: 7,
            exploitability: 7,
            affectedUsers: 8,
            discoverability: configuredCredentialed.length > 0 || notifyEnabled ? 7 : 5,
            rationale: list(
              zh,
              [
                'Several collectors and enrichers rely on provider tokens',
                'Config status intentionally redacts values, but deployment handling remains critical',
              ],
              ['多个采集器和富化器依赖服务商 Token', '配置状态会刻意隐藏值，但部署侧密钥处理仍然关键'],
            ),
          }),
          controls: ['secret-redaction', 'secret-management'],
          treatment: 'implemented',
          verification: list(zh, ['Call /api/config/status and confirm no raw secret values are returned'], ['调用 /api/config/status 并确认不会返回密钥原文']),
        },
      ),
      scenario(
        'enrichment-abuse',
        text(zh, 'High-volume enrichment requests exhaust API quota or degrade service', '高频富化请求耗尽 API 配额或拖慢服务'),
        'Denial of Service',
        'high',
        75,
        list(
          zh,
          ['On-demand enrichment calls external providers', 'IOC searches and reports are interactive analyst workflows'],
          ['按需富化会调用外部服务商', 'IOC 检索和报告属于交互式分析员工作流'],
        ),
        list(
          zh,
          [
            'Keep rate limiting enabled for API routes',
            'Cache enrichment results or add provider-specific backoff before production scale',
            'Restrict enrichment and config testing to analyst/admin roles',
          ],
          ['保持 API 路由限流开启', '生产规模前缓存富化结果或增加服务商级退避策略', '将富化和配置测试限制为分析员/管理员角色'],
        ),
        {
          assetIds: ['api', 'enrichers', 'secrets'],
          dataFlowIds: ['search-flow', 'feed-flow'],
          threat: text(zh, 'Automated requests repeatedly call /api/enrich or /api/config/test against paid or rate-limited providers.', '自动化请求反复调用 /api/enrich 或 /api/config/test，击中付费或限流服务商。'),
          impact: text(zh, 'Provider quota is exhausted, API latency rises, and analysts lose enrichment context during active triage.', '服务商配额被耗尽、API 延迟升高，分析员在处置时失去富化上下文。'),
          dread: dread({
            damage: 7,
            reproducibility: 8,
            exploitability: authConfigured ? 5 : 8,
            affectedUsers: 6,
            discoverability: 8,
            rationale: list(
              zh,
              [
                `In-memory API rate limit is configured around ${rateLimitMax} requests/window`,
                'Provider-specific result caching/backoff is not yet implemented',
              ],
              [`内存 API 限流约为每窗口 ${rateLimitMax} 次请求`, '尚未实现服务商级结果缓存/退避'],
            ),
          }),
          controls: ['api-rate-limit', 'role-scoped-auth', 'provider-backoff'],
          treatment: 'planned',
          verification: list(zh, ['Exercise rate-limit tests', 'Add provider-cache tests before broad deployment'], ['执行限流测试', '大规模部署前补充服务商缓存测试']),
        },
      ),
      scenario(
        'overbroad-admin-token',
        authConfigured
          ? text(zh, 'A broad API token enables unauthorized configuration tests or outbound messages', '过宽的管理员 Token 导致未授权配置测试或外发消息')
          : text(zh, 'Unconfigured API tokens leave analyst/admin routes implicitly trusted', '未配置 API Token 时分析员/管理员接口被隐式信任'),
        'Elevation of Privilege',
        authConfigured ? 'high' : 'critical',
        70,
        [
          authConfigured ? text(zh, 'API token or role-scoped token configuration is present', '已配置 API Token 或角色范围 Token') : text(zh, 'No API token configuration is present', '未配置 API Token'),
          text(zh, 'Notify test sends real messages', '通知测试会发送真实消息'),
          text(zh, 'Configuration test can call credentialed providers', '配置测试可能调用凭据化服务商'),
          corsRestricted ? text(zh, 'CORS origins are restricted', 'CORS 来源已限制') : text(zh, 'CORS allow-list is not configured', '未配置 CORS 允许列表'),
        ],
        list(
          zh,
          [
            'Use viewer, analyst, and admin token sets instead of one shared token',
            'Require admin role for notification and integration test endpoints',
            'Keep production deployments behind an auth proxy when browser users are untrusted',
          ],
          ['使用查看者、分析员、管理员三类 Token，而不是共享一个 Token', '通知和集成测试接口要求管理员角色', '当浏览器用户不可信时，将生产部署放在认证代理之后'],
        ),
        {
          assetIds: ['api', 'dashboard', 'notifiers', 'secrets'],
          dataFlowIds: ['search-flow', 'notify-flow'],
          threat: text(zh, 'A user or script gains more privilege than intended because API tokens are missing, shared, or exposed to a browser.', '由于 API Token 缺失、共享或暴露在浏览器侧，用户或脚本获得超出预期的权限。'),
          impact: text(zh, 'Unauthorized users can trigger outbound tests, consume provider quota, or view analyst-only threat models.', '未授权用户可以触发外发测试、消耗服务商配额或查看仅分析员可见的威胁模型。'),
          dread: dread({
            damage: authConfigured ? 7 : 9,
            reproducibility: 8,
            exploitability: authConfigured ? 5 : 9,
            affectedUsers: 7,
            discoverability: 8,
            rationale: list(
              zh,
              [
                'Route-level roles are implemented in code',
                authConfigured ? 'Deployment has an auth signal configured' : 'Without tokens, the API treats requests as admin for private deployments',
              ],
              ['代码中已实现路由级角色', authConfigured ? '部署已有鉴权信号' : '没有 Token 时，API 会按私有部署假设把请求视为管理员'],
            ),
          }),
          controls: ['role-scoped-auth', 'cors-allowlist'],
          treatment: authConfigured ? 'implemented' : 'planned',
          verification: list(
            zh,
            ['Run API auth tests with viewer, analyst, and admin tokens', 'Validate production ingress/auth proxy settings'],
            ['使用查看者、分析员、管理员 Token 执行 API 鉴权测试', '校验生产入口和认证代理设置'],
          ),
        },
      ),
      scenario(
        'cleartext-geo-enrichment',
        text(zh, 'HTTP geolocation can leak or alter map context', 'HTTP 地理定位可能泄露或改变地图上下文'),
        'Information Disclosure',
        'medium',
        65,
        list(
          zh,
          [
            'backend/src/geo.ts calls the ip-api.com free batch endpoint over HTTP',
            'Only IP indicators and geolocation context are sent, not provider secrets',
          ],
          ['backend/src/geo.ts 通过 HTTP 调用 ip-api.com 免费批量接口', '仅发送 IP 指标和地理定位上下文，不发送服务商密钥'],
        ),
        list(
          zh,
          [
            'Prefer a local MaxMind database or a provider endpoint that supports HTTPS before production use',
            'Treat geolocation as best-effort context, not enforcement evidence',
            'Keep raw indicators and source provenance available beside map output',
          ],
          ['生产使用前优先改为本地 MaxMind 数据库或支持 HTTPS 的服务商接口', '将地理定位视为尽力而为的上下文，不作为强执行证据', '地图输出旁保留原始指标和来源信息'],
        ),
        {
          assetIds: ['api', 'feeds'],
          dataFlowIds: ['geo-flow'],
          threat: text(zh, 'A network observer reads IP indicators sent for geolocation or tampers with country/coordinate responses.', '网络观察者读取用于地理定位的 IP 指标，或篡改国家/坐标响应。'),
          impact: text(zh, 'The map can mislead triage or expose which IPs analysts are currently tracking.', '地图可能误导研判，或暴露分析员正在关注哪些 IP。'),
          dread: dread({
            damage: 4,
            reproducibility: 7,
            exploitability: 6,
            affectedUsers: 3,
            discoverability: 8,
            rationale: list(zh, ['The data flow is cleartext HTTP', 'Geolocation is contextual and not a blocking decision by itself'], ['该数据流是明文 HTTP', '地理定位本身只是上下文，不直接作为阻断决策']),
          }),
          controls: ['local-geoip'],
          treatment: 'planned',
          verification: list(zh, ['Switch to local/HTTPS geolocation and assert no HTTP URL remains in geo.ts'], ['切换到本地/HTTPS 地理定位，并确认 geo.ts 不再保留 HTTP URL']),
        },
      ),
      scenario(
        'python-hub-config-exposure',
        text(zh, 'Standalone Python hub config or SQLite state exposes notification credentials', '独立 Python hub 配置或 SQLite 状态暴露通知凭据'),
        'Information Disclosure',
        'high',
        55,
        list(
          zh,
          [
            'security-intel-hub/config.example.json resolves environment placeholders for X, Meta, Telegram, and DingTalk',
            'security-intel-hub stores intel and push state in SQLite',
          ],
          ['security-intel-hub/config.example.json 会解析 X、Meta、Telegram、钉钉环境变量占位符', 'security-intel-hub 使用 SQLite 存储情报和推送状态'],
        ),
        list(
          zh,
          [
            'Keep production config files outside Git and restrict file permissions',
            'Use environment variables or a secrets manager for bot tokens and webhooks',
            'Back up and protect SQLite files because push history and source metadata are operational records',
          ],
          ['生产配置文件放在 Git 之外并限制文件权限', '机器人 Token 和 Webhook 使用环境变量或密钥管理器', '备份并保护 SQLite 文件，因为推送历史和来源元数据属于操作记录'],
        ),
        {
          assetIds: ['python_hub', 'secrets', 'notifiers'],
          dataFlowIds: ['python-hub-flow'],
          threat: text(zh, 'A local config, environment dump, or SQLite backup leaks tokens or reveals notification workflow details.', '本地配置、环境导出或 SQLite 备份泄露 Token 或通知工作流细节。'),
          impact: text(zh, 'Attackers can impersonate bot messages, mine source focus, or replay operational context.', '攻击者可冒充机器人消息、挖掘关注来源，或重放操作上下文。'),
          dread: dread({
            damage: 7,
            reproducibility: 6,
            exploitability: 6,
            affectedUsers: 5,
            discoverability: 6,
            rationale: list(zh, ['The Python hub is a local scheduled worker', 'Secrets are intended to come from environment variables'], ['Python hub 是本地定时任务', '密钥设计上来自环境变量']),
          }),
          controls: ['secret-management', 'python-config-permissions'],
          treatment: 'planned',
          verification: list(zh, ['Check production config permissions', 'Confirm real tokens are not committed'], ['检查生产配置权限', '确认真实 Token 未提交到仓库']),
        },
      ),
    ],
    attackPaths: [
      {
        id: 'ap-token-to-admin-actions',
        actor: text(zh, 'External user with leaked token or open private API access', '持有泄露 Token 或可访问开放私有 API 的外部用户'),
        objective: text(zh, 'Trigger privileged operations or consume provider quota', '触发特权操作或消耗服务商配额'),
        entryPoint: '/api/config/test, /api/notify/test, /api/enrich',
        path: list(
          zh,
          ['Obtain shared token or reach an unprotected deployment', 'Call analyst/admin endpoints', 'Send real messages or query providers'],
          ['获取共享 Token 或访问未保护部署', '调用分析员/管理员接口', '发送真实消息或查询服务商'],
        ),
        impactedAssets: ['api', 'secrets', 'notifiers', 'enrichers'],
        stride: ['Spoofing', 'Elevation of Privilege', 'Denial of Service'],
        severity: authConfigured ? 'high' : 'critical',
        mitigations: ['role-scoped-auth', 'api-rate-limit', 'cors-allowlist'],
      },
      {
        id: 'ap-feed-poisoning-to-operator-decision',
        actor: text(zh, 'Compromised or malicious upstream source', '被攻陷或恶意的上游来源'),
        objective: text(zh, 'Influence analyst decisions through false indicators', '通过虚假指标影响分析员决策'),
        entryPoint: 'backend/src/sources/* collector payload',
        path: list(
          zh,
          ['Publish false IOC', 'Collector normalizes it', 'Dashboard and exports present it as evidence', 'Analyst or downstream system acts on it'],
          ['发布虚假 IOC', '采集器归一化该 IOC', '仪表盘和导出将其呈现为证据', '分析员或下游系统据此行动'],
        ),
        impactedAssets: ['collectors', 'api', 'analyst', 'consumers'],
        stride: ['Spoofing', 'Tampering'],
        severity: 'high',
        mitigations: ['source-provenance', 'source-health-alerting'],
      },
      {
        id: 'ap-cleartext-geo-context',
        actor: text(zh, 'Network-positioned attacker', '具备网络位置的攻击者'),
        objective: text(zh, 'Observe tracked IPs or manipulate geographic context', '观察被跟踪 IP 或操纵地理上下文'),
        entryPoint: 'backend/src/geo.ts HTTP batch request',
        path: list(
          zh,
          ['Observe outbound HTTP batch', 'Read or alter IP-to-location response', 'Dashboard map renders misleading context'],
          ['观察外发 HTTP 批量请求', '读取或修改 IP 到位置响应', '仪表盘地图展示误导性上下文'],
        ),
        impactedAssets: ['api', 'dashboard', 'analyst'],
        stride: ['Tampering', 'Information Disclosure'],
        severity: 'medium',
        mitigations: ['local-geoip'],
      },
      {
        id: 'ap-export-tamper-to-siem',
        actor: text(zh, 'Intermediary or downstream integration account', '中间环节或下游集成账号'),
        objective: text(zh, 'Modify threat-model or STIX evidence before consumption', '在消费前修改威胁模型或 STIX 证据'),
        entryPoint: '/api/export/stix, /taxii2/*, /api/threat-model?format=markdown',
        path: list(
          zh,
          ['Fetch export', 'Alter report or object set', 'Forward to SIEM or ticket', 'Responder relies on modified evidence'],
          ['获取导出内容', '修改报告或对象集', '转发到 SIEM 或工单', '响应人员依赖被修改证据'],
        ),
        impactedAssets: ['taxii', 'consumers', 'analyst'],
        stride: ['Tampering', 'Repudiation'],
        severity: 'high',
        mitigations: ['audit-events', 'signed-exports'],
      },
    ],
    controls: [
      {
        id: 'role-scoped-auth',
        name: text(zh, 'Viewer/analyst/admin token roles on API routes', 'API 路由上的查看者/分析员/管理员 Token 角色'),
        status: authConfigured ? 'implemented' : 'planned',
        owner: text(zh, 'Backend / DevOps', '后端 / DevOps'),
        scenarios: ['overbroad-admin-token', 'enrichment-abuse', 'missing-audit-accountability'],
        verification: list(zh, ['backend/test/util.test.ts token extraction', 'manual route checks with each role'], ['backend/test/util.test.ts Token 提取', '使用各角色手动检查路由']),
      },
      {
        id: 'api-rate-limit',
        name: text(zh, 'In-memory per-client API rate limiting', '按客户端划分的内存 API 限流'),
        status: 'implemented',
        owner: text(zh, 'Backend', '后端'),
        scenarios: ['enrichment-abuse'],
        verification: [text(zh, `Confirm API_RATE_LIMIT_MAX=${rateLimitMax}`, `确认 API_RATE_LIMIT_MAX=${rateLimitMax}`), text(zh, 'Add regression tests for 429 behavior under burst load', '增加突发负载下 429 行为的回归测试')],
      },
      {
        id: 'source-provenance',
        name: text(zh, 'Source reliability, TLP, confidence, and multi-source corroboration', '来源可靠性、TLP、置信度和多来源交叉验证'),
        status: 'implemented',
        owner: text(zh, 'Backend / CTI', '后端 / CTI'),
        scenarios: ['spoofed-feed-data'],
        verification: list(zh, ['backend/test/store.test.ts correlation and confidence cases', 'Review exported indicator provenance'], ['backend/test/store.test.ts 关联和置信度用例', '复核导出指标的来源信息']),
      },
      {
        id: 'source-health-alerting',
        name: text(zh, 'Per-source freshness, stale/error state, and optional notifier health alerts', '单来源新鲜度、过期/错误状态与可选健康通知'),
        status: 'implemented',
        owner: text(zh, 'Backend / SOC', '后端 / SOC'),
        scenarios: ['spoofed-feed-data'],
        verification: list(zh, ['backend/test/health.test.ts', 'Monitor /api/sources/health before analyst shifts'], ['backend/test/health.test.ts', '分析员值班前监控 /api/sources/health']),
      },
      {
        id: 'secret-redaction',
        name: text(zh, 'Non-secret configuration status APIs', '不返回密钥原文的配置状态 API'),
        status: 'implemented',
        owner: text(zh, 'Backend', '后端'),
        scenarios: ['secret-disclosure'],
        verification: [text(zh, 'Call /api/config/status and inspect that only configured/requiredEnv flags are returned', '调用 /api/config/status，确认仅返回 configured/requiredEnv 等标志')],
      },
      {
        id: 'secret-management',
        name: text(zh, 'Environment or secret-manager storage for provider tokens and webhooks', '服务商 Token 和 Webhook 使用环境变量或密钥管理器存储'),
        status: 'planned',
        owner: 'DevOps',
        scenarios: ['secret-disclosure', 'python-hub-config-exposure'],
        verification: [text(zh, 'Deployment review confirms no real secrets in Git, images, logs, or frontend bundles', '部署评审确认 Git、镜像、日志和前端包中没有真实密钥')],
      },
      {
        id: 'audit-events',
        name: text(zh, 'Persistent audit events for sensitive analyst/admin actions', '敏感分析员/管理员操作的持久化审计事件'),
        status: persistenceEnabled ? 'implemented' : 'planned',
        owner: text(zh, 'Backend / SOC', '后端 / SOC'),
        scenarios: ['missing-audit-accountability', 'tampered-model-output'],
        verification: [text(zh, 'Enable DATA_DIR and review /api/audit entries after enrichment/report/config actions', '启用 DATA_DIR，并在富化/报告/配置动作后查看 /api/audit')],
      },
      {
        id: 'provider-backoff',
        name: text(zh, 'Provider-specific enrichment cache and backoff', '服务商级富化缓存和退避'),
        status: 'planned',
        owner: text(zh, 'Backend', '后端'),
        scenarios: ['enrichment-abuse'],
        verification: [text(zh, 'Unit tests prove repeated IOC enrichment reuses cache within TTL', '单元测试证明重复 IOC 富化会在 TTL 内复用缓存')],
      },
      {
        id: 'signed-exports',
        name: text(zh, 'Checksum or signature for regulated STIX/report exchange', '合规 STIX/报告交换的校验和或签名'),
        status: 'planned',
        owner: text(zh, 'Backend / GRC', '后端 / GRC'),
        scenarios: ['tampered-model-output'],
        verification: [text(zh, 'Generated reports include detached checksum or signature metadata', '生成报告包含分离校验和或签名元数据')],
      },
      {
        id: 'local-geoip',
        name: text(zh, 'HTTPS or local geolocation provider', 'HTTPS 或本地地理定位服务'),
        status: 'planned',
        owner: text(zh, 'Backend / DevOps', '后端 / DevOps'),
        scenarios: ['cleartext-geo-enrichment'],
        verification: [text(zh, 'No HTTP geolocation endpoint remains in production configuration', '生产配置中不再保留 HTTP 地理定位端点')],
      },
      {
        id: 'cors-allowlist',
        name: text(zh, 'Browser origin allow-list and trusted ingress', '浏览器来源允许列表与受信入口'),
        status: corsRestricted ? 'implemented' : 'planned',
        owner: 'DevOps',
        scenarios: ['overbroad-admin-token'],
        verification: list(zh, ['CORS_ORIGINS is set for browser deployments', 'Ingress terminates TLS'], ['浏览器部署设置 CORS_ORIGINS', '入口层终止 TLS']),
      },
      {
        id: 'python-config-permissions',
        name: text(zh, 'Restricted Python hub config/database permissions', '限制 Python hub 配置/数据库权限'),
        status: 'planned',
        owner: text(zh, 'Automation / DevOps', '自动化 / DevOps'),
        scenarios: ['python-hub-config-exposure'],
        verification: [text(zh, 'Production config and SQLite files are outside Git and readable only by the worker user', '生产配置和 SQLite 文件位于 Git 之外，且仅 Worker 用户可读')],
      },
    ],
    assumptions: list(
      zh,
      [
        'The model is generated from platform architecture, code paths, and current source health; production teams should still review a deployment-specific DFD.',
        'Credential presence is treated as a secret-handling risk even though secret values are never returned.',
        'Provider and source connectivity tests are operator-triggered because they may consume quota.',
        `Express JSON body limit is ${jsonBodyLimit}; endpoints are mostly query-driven but POST routes still need bounded payloads.`,
        `Authentication is ${authConfigured ? 'configured' : 'not configured'} for this runtime model.`,
        `Persistence is ${persistenceEnabled ? 'enabled' : 'disabled'} for this runtime model.`,
      ],
      [
        '该模型基于平台架构、代码路径和当前来源健康状态生成；生产团队仍需评审部署专属 DFD。',
        '即使密钥原文不会返回，只要存在凭据配置，就视为密钥处理风险。',
        '服务商和来源连接测试由操作员触发，因为可能消耗配额。',
        `Express JSON 请求体限制为 ${jsonBodyLimit}；多数接口以查询为主，但 POST 路由仍需限制载荷。`,
        `该运行态模型中的鉴权状态：${authConfigured ? '已配置' : '未配置'}。`,
        `该运行态模型中的持久化状态：${persistenceEnabled ? '已启用' : '未启用'}。`,
      ],
    ),
    nextSteps: list(
      zh,
      [
        'Review critical/high DREAD scenarios before exposing the dashboard outside a private network',
        'Enable role-scoped tokens, CORS allow-list, TLS ingress, and DATA_DIR audit persistence for production',
        'Replace HTTP geolocation with HTTPS or local GeoIP when map context is used in incident workflow',
        'Add provider-specific enrichment caching/backoff before heavy analyst usage',
        'Review every new source, endpoint, notification channel, and export format through this STRIDE checklist',
      ],
      [
        '仪表盘离开私有网络前，评审严重/高危 DREAD 场景',
        '生产环境启用角色范围 Token、CORS 允许列表、TLS 入口和 DATA_DIR 审计持久化',
        '当地图上下文进入事件流程时，将 HTTP 地理定位替换为 HTTPS 或本地 GeoIP',
        '高频分析员使用前增加服务商级富化缓存/退避',
        '所有新来源、新接口、新通知通道和新导出格式都走这份 STRIDE 清单',
      ],
    ),
  };
}
