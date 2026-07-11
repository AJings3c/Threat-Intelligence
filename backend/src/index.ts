import express from 'express';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { store } from './store.js';
import { notifier } from './notify/index.js';
import { errorMessage } from './util.js';
import {
  closePersistence,
  getBackgroundJobs,
  getBackgroundJobCounts,
  getDetectionArtifacts,
  getSourceHealthHistory,
  getTrend,
  initPersistence,
  isPersistEnabled,
  loadIntelSnapshot,
  loadStixObjects,
} from './persist.js';
import { getAuditEvents } from './persist.js';
import { buildStixBundle } from './stix.js';
import {
  buildTaxiiApiRoot,
  buildTaxiiCollections,
  buildTaxiiDiscovery,
  buildTaxiiEnvelope,
  buildTaxiiManifest,
  TAXII_COLLECTION_ID,
  TAXII_MEDIA_TYPE,
  taxiiCollection,
} from './taxii.js';
import { enrichmentConfigStatus, parseIndicatorType } from './enrich.js';
import { enrichWithCache, startCacheCleanupTask } from './enrichCache.js';
import { testIntegration } from './integrationTests.js';
import { investigationMarkdown, architectureThreatModelMarkdown } from './reports.js';
import { buildArchitectureThreatModel } from './architectureThreatModel.js';
import {
  apiAuth,
  audit,
  corsOptions,
  isApiAuthConfigured,
  isUnauthenticatedAccessAllowed,
  rateLimit,
  resolveRequestIdentity,
} from './security.js';
import type {
  ApiRole,
  CaseStatus,
  DetectionArtifactFormat,
  EnrichmentProvider,
  IntegrationKind,
  ThreatSource,
} from './types.js';
import { parseLanguage } from './language.js';
import { createCase, updateCase, getCase, listCases, addIocToCase, addComment } from './cases.js';
import { batchHunt, getHuntHistory } from './hunt.js';
import { createRule, updateRule, getRule, listRules, getRuleExecutionHistory } from './rules/index.js';
import { markAsFalsePositive, listFalsePositives, getQualityDistribution, getQualityTrend } from './quality.js';
import { setupAutoTrigger } from './rules/autoTrigger.js';
import { DurableJobWorker, enqueueDurableJob } from './jobs.js';
import { exportIntegrityHeaders } from './exportIntegrity.js';
import { prometheusMetrics } from './metrics.js';
import { filterStixObjectsForRole } from './stixAccess.js';
import { queryStixObjects, stixNeighborhood } from './stixGraph.js';
import { extractIocs } from './iocExtract.js';


const PORT = Number(process.env.PORT ?? 4000);
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS ?? 15 * 60 * 1000);
const THREAT_SOURCES: ThreatSource[] = [
  'cisa_kev',
  'feodo',
  'urlhaus',
  'nvd',
  'x',
  'facebook',
  'openphish',
  'threatfox',
  'malwarebazaar',
  'spamhaus_drop',
  'dshield',
  'phishtank',
  'abuseipdb',
  'otx',
  'misp',
  'taxii_import',
];
const ENRICHMENT_PROVIDERS: EnrichmentProvider[] = ['virustotal', 'shodan', 'censys', 'greynoise', 'urlscan'];
const CASE_STATUSES: CaseStatus[] = ['open', 'investigating', 'resolved', 'closed'];

// Optional API auth. When API_TOKEN is set, all /api routes (except /health) require it.
// A static token suits machine/SIEM access or a private deployment; a browser SPA cannot
// keep it truly secret, so for public dashboards put a real auth proxy in front.
const API_TOKEN = process.env.API_TOKEN?.trim() || null;

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        connectSrc: ["'self'"],
        imgSrc: ["'self'", 'data:', 'blob:'],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
      },
    },
  }),
);
app.use(cors(corsOptions()));

let server: ReturnType<typeof app.listen> | null = null;
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let backgroundWorker: DurableJobWorker | null = null;
let stopCacheCleanup: (() => void) | null = null;

function taxiiBaseUrl(req: express.Request): string {
  return `${req.protocol}://${req.get('host') ?? `localhost:${PORT}`}`;
}

function setTaxiiHeaders(res: express.Response): void {
  res.setHeader('Content-Type', TAXII_MEDIA_TYPE);
}

function sendIntegrityProtected(
  res: express.Response,
  payload: unknown,
  contentType = 'application/json; charset=utf-8',
): void {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  res.setHeader('Content-Type', contentType);
  for (const [name, value] of Object.entries(exportIntegrityHeaders(body))) res.setHeader(name, value);
  res.send(body);
}

function sendTaxii(res: express.Response, payload: unknown): void {
  sendIntegrityProtected(res, payload, TAXII_MEDIA_TYPE);
}

function guardTaxii(req: express.Request, res: express.Response): boolean {
  const identity = resolveRequestIdentity(req, API_TOKEN);
  if (identity) {
    res.locals.role = identity.role;
    res.locals.principal = identity.principal;
    return true;
  }
  if (isUnauthenticatedAccessAllowed(API_TOKEN)) {
    res.locals.role = 'admin';
    res.locals.principal = 'local-development-admin';
    return true;
  }
  setTaxiiHeaders(res);
  if (!isApiAuthConfigured(API_TOKEN)) {
    res.status(503).json({ title: 'Unavailable', description: 'server authentication is not configured' });
    return false;
  }
  res.status(401).json({
    title: 'Unauthorized',
    description: 'invalid or missing API token',
    error_code: 'unauthorized',
  });
  return false;
}

function stixBundle(role: ApiRole) {
  const bundle = buildStixBundle(store.getIndicators(), store.getAllCves());
  const byVersion = new Map(
    bundle.objects.map((object) => [`${object.id}:${object.modified ?? object.created ?? 'unversioned'}`, object]),
  );
  for (const object of loadStixObjects()) {
    if (object.spec_version !== undefined && object.spec_version !== '2.1') continue;
    byVersion.set(`${object.id}:${object.modified ?? object.created ?? 'unversioned'}`, {
      ...object,
      spec_version: '2.1',
    });
  }
  return { ...bundle, objects: filterStixObjectsForRole(Array.from(byVersion.values()), role) };
}

function stixObjects(role: ApiRole) {
  return stixBundle(role).objects;
}

function taxiiPageOptions(req: express.Request) {
  const limit = req.query.limit ? Number(req.query.limit) : undefined;
  return {
    addedAfter: typeof req.query.added_after === 'string' ? req.query.added_after : undefined,
    limit: Number.isFinite(limit) ? limit : undefined,
    next: typeof req.query.next === 'string' ? req.query.next : undefined,
  };
}

// Server-Sent Events stream for live updates. Registered BEFORE compression so the
// long-lived response is not buffered. Emits a `refresh` event after each feed refresh.
app.get('/api/stream', (req, res) => {
  if (!resolveRequestIdentity(req, API_TOKEN) && !isUnauthenticatedAccessAllowed(API_TOKEN)) {
    if (!isApiAuthConfigured(API_TOKEN)) {
      res.status(503).json({ error: 'server authentication is not configured' });
      return;
    }
    res.status(401).json({ error: 'unauthorized: invalid or missing API token' });
    return;
  }
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (): void => {
    const s = store.getStats();
    const payload = {
      totalIndicators: s.totalIndicators,
      totalCves: s.totalCves,
      lastRefresh: store.lastRefreshAt ? new Date(store.lastRefreshAt).toISOString() : null,
    };
    res.write(`event: refresh\ndata: ${JSON.stringify(payload)}\n\n`);
  };

  res.write('event: hello\ndata: {}\n\n');
  const unsubscribe = store.onRefresh(send);
  const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
  req.on('close', () => {
    clearInterval(ping);
    unsubscribe();
    res.end();
  });
});

app.use(compression());
app.use(express.json({ limit: process.env.JSON_BODY_LIMIT ?? '1mb' }));

app.get(['/taxii2', '/taxii2/'], (req, res) => {
  if (!guardTaxii(req, res)) return;
  sendTaxii(res, buildTaxiiDiscovery(taxiiBaseUrl(req)));
});

app.get('/taxii2/root/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  sendTaxii(res, buildTaxiiApiRoot());
});

app.get('/taxii2/root/collections/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  sendTaxii(res, buildTaxiiCollections());
});

app.get('/taxii2/root/collections/:id/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  sendTaxii(res, taxiiCollection());
});

app.get('/taxii2/root/collections/:id/objects/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  sendTaxii(res, buildTaxiiEnvelope(stixObjects(res.locals.role as ApiRole), taxiiPageOptions(req)));
});

app.get('/taxii2/root/collections/:id/manifest/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  sendTaxii(res, buildTaxiiManifest(stixObjects(res.locals.role as ApiRole), taxiiPageOptions(req)));
});

const api = express.Router();
const auth = apiAuth(API_TOKEN);
const requirePersistence: express.RequestHandler = (_req, res, next) => {
  if (isPersistEnabled()) {
    next();
    return;
  }
  res.status(503).json({ error: 'persistence required: configure DATA_DIR and restart the service' });
};
api.use(auth.attachRole);
api.use(rateLimit());

// Gate every /api route behind the token when configured; /health stays open for probes.
api.use(auth.requireToken);

api.get('/health', (_req, res) => {
  res.json({
    status: store.isReady ? 'ok' : 'warming_up',
    lastRefresh: store.lastRefreshAt ? new Date(store.lastRefreshAt).toISOString() : null,
    sources: store.getHealth(),
  });
});

api.get('/metrics', auth.requireRole('viewer'), (_req, res) => {
  const stats = store.getStats();
  res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
  res.send(
    prometheusMetrics({
      totalIndicators: stats.totalIndicators,
      totalCves: stats.totalCves,
      lastRefreshAt: store.lastRefreshAt,
      health: store.getHealth(),
      persistenceEnabled: isPersistEnabled(),
      jobs: getBackgroundJobCounts(),
    }),
  );
});

api.get('/threats', (req, res) => {
  const { source, type, severity, q } = req.query;
  const limit = req.query.limit ? Number(req.query.limit) : undefined;
  const result = store.queryThreats({
    source: typeof source === 'string' ? source : undefined,
    type: typeof type === 'string' ? type : undefined,
    severity: typeof severity === 'string' ? severity : undefined,
    q: typeof q === 'string' ? q : undefined,
    limit: Number.isFinite(limit) ? limit : undefined,
  });
  res.json({ ...result, generatedAt: new Date().toISOString() });
});

api.get('/map', (_req, res) => {
  res.json({ points: store.getMapPoints(), generatedAt: new Date().toISOString() });
});

api.get('/cve', (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 60;
  res.json({ ...store.getCves(Number.isFinite(limit) ? limit : 60) });
});

api.get('/hashes', (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 50;
  res.json({ ...store.getHashIntel(Number.isFinite(limit) ? limit : 50) });
});

api.get('/enrich', auth.requireRole('analyst'), audit('enrich'), (req, res) => {
  const indicator = typeof req.query.indicator === 'string' ? req.query.indicator.trim() : '';
  const indicatorType = parseIndicatorType(typeof req.query.type === 'string' ? req.query.type : undefined);
  if (!indicator || !indicatorType) {
    res.status(400).json({ error: 'missing or invalid indicator/type query parameters' });
    return;
  }
  enrichWithCache(indicator, indicatorType)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: errorMessage(err) }));
});

api.get('/enrich/aggregate/:indicator', auth.requireRole('analyst'), audit('enrich_aggregate'), (req, res) => {
  const indicator = req.params.indicator?.trim();
  const indicatorType = parseIndicatorType(typeof req.query.type === 'string' ? req.query.type : undefined);
  if (!indicator || !indicatorType) {
    res.status(400).json({ error: 'missing or invalid indicator/type' });
    return;
  }
  enrichWithCache(indicator, indicatorType)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: errorMessage(err) }));
});

api.get('/enrich/providers', (_req, res) => {
  res.json({ providers: enrichmentConfigStatus() });
});

api.get('/investigate', auth.requireRole('analyst'), audit('investigate'), (req, res) => {
  const indicator = typeof req.query.indicator === 'string' ? req.query.indicator.trim() : '';
  const indicatorType = parseIndicatorType(typeof req.query.type === 'string' ? req.query.type : undefined);
  const language = parseLanguage(req.query.lang);
  if (!indicator) {
    res.status(400).json({ error: 'missing indicator query parameter' });
    return;
  }
  res.json(store.investigateIndicator(indicator, indicatorType ?? undefined, { language }));
});

api.get('/investigations/history', auth.requireRole('analyst'), (_req, res) => {
  const limit = _req.query.limit ? Number(_req.query.limit) : 50;
  res.json({
    enabled: true,
    points: store.getInvestigationHistory(Number.isFinite(limit) ? limit : 50),
  });
});

api.get('/investigate/report', auth.requireRole('analyst'), audit('investigation_report'), (req, res) => {
  const indicator = typeof req.query.indicator === 'string' ? req.query.indicator.trim() : '';
  const indicatorType = parseIndicatorType(typeof req.query.type === 'string' ? req.query.type : undefined);
  const format = typeof req.query.format === 'string' ? req.query.format : 'markdown';
  const language = parseLanguage(req.query.lang);
  if (!indicator) {
    res.status(400).json({ error: 'missing indicator query parameter' });
    return;
  }
  const result = store.investigateIndicator(indicator, indicatorType ?? undefined, {
    recordHistory: false,
    language,
  });
  if (format === 'json') {
    res.json({ result, report: investigationMarkdown(result, language), generatedAt: new Date().toISOString() });
    return;
  }
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  sendIntegrityProtected(res, investigationMarkdown(result, language), 'text/markdown; charset=utf-8');
});

api.get('/stats', (_req, res) => {
  res.json(store.getStats());
});

api.get('/sources/health', (_req, res) => {
  res.json({ sources: store.getHealth() });
});

api.get('/config/status', (_req, res) => {
  res.json({
    sources: store.getSourceConfigStatus(),
    enrichmentProviders: enrichmentConfigStatus(),
    notify: notifier.status(),
    persistence: { enabled: isPersistEnabled() },
  });
});

api.post('/config/test', auth.requireRole('admin'), audit('config_test'), (req, res) => {
  const kind = req.body?.kind as IntegrationKind | undefined;
  const id = req.body?.id as ThreatSource | EnrichmentProvider | undefined;
  if (
    (kind !== 'source' && kind !== 'provider') ||
    !id ||
    (kind === 'source' && !THREAT_SOURCES.includes(id as ThreatSource)) ||
    (kind === 'provider' && !ENRICHMENT_PROVIDERS.includes(id as EnrichmentProvider))
  ) {
    res.status(400).json({ error: 'missing or invalid kind/id' });
    return;
  }
  testIntegration(kind, id)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: errorMessage(err) }));
});

api.get('/threat-model', auth.requireRole('analyst'), audit('architecture_threat_model'), (req, res) => {
  const language = parseLanguage(req.query.lang);
  const notifyStatus = notifier.status();
  const configuredNotifyChannels = Object.entries(notifyStatus.channels)
    .filter(([, configured]) => configured)
    .map(([channel]) => channel);
  const model = buildArchitectureThreatModel(store.getStats(), store.getHealth(), language, {
    authConfigured: isApiAuthConfigured(API_TOKEN),
    persistenceEnabled: isPersistEnabled(),
    notifyEnabled: notifyStatus.enabled,
    configuredNotifyChannels,
    corsRestricted: Boolean(process.env.CORS_ORIGINS?.trim()),
    rateLimitMax: Number(process.env.API_RATE_LIMIT_MAX ?? 180),
    jsonBodyLimit: process.env.JSON_BODY_LIMIT ?? '1mb',
  });
  if (req.query.format === 'markdown') {
    sendIntegrityProtected(res, architectureThreatModelMarkdown(model, language), 'text/markdown; charset=utf-8');
    return;
  }
  res.json(model);
});

// Historical source-health samples (requires persistence; empty when disabled).
api.get('/sources/history', (req, res) => {
  const days = req.query.days ? Number(req.query.days) : 7;
  const window = Number.isFinite(days) && days > 0 ? Math.min(days, 365) : 7;
  const since = Date.now() - window * 24 * 60 * 60 * 1000;
  res.json({ enabled: isPersistEnabled(), points: getSourceHealthHistory(since) });
});

// Historical indicator-count trend (requires persistence; empty when disabled).
api.get('/trend', (req, res) => {
  const days = req.query.days ? Number(req.query.days) : 30;
  const window = Number.isFinite(days) && days > 0 ? Math.min(days, 365) : 30;
  const since = Date.now() - window * 24 * 60 * 60 * 1000;
  res.json({ enabled: isPersistEnabled(), points: getTrend(since) });
});

api.get('/notify/status', (_req, res) => {
  res.json(notifier.status());
});

api.get('/audit', auth.requireRole('admin'), (_req, res) => {
  const limit = _req.query.limit ? Number(_req.query.limit) : 100;
  res.json({ enabled: isPersistEnabled(), events: getAuditEvents(Number.isFinite(limit) ? limit : 100) });
});

api.get('/jobs', auth.requireRole('admin'), requirePersistence, (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 100;
  res.json({ jobs: getBackgroundJobs(Number.isFinite(limit) ? limit : 100) });
});

api.get('/detection-artifacts', auth.requireRole('analyst'), requirePersistence, (req, res) => {
  const requestedFormat = typeof req.query.format === 'string' ? req.query.format : undefined;
  const format =
    requestedFormat === 'sigma' || requestedFormat === 'yara' || requestedFormat === 'snort'
      ? (requestedFormat as DetectionArtifactFormat)
      : undefined;
  if (requestedFormat && !format) {
    res.status(400).json({ error: 'format must be sigma, yara, or snort' });
    return;
  }
  const requestedLimit = req.query.limit ? Number(req.query.limit) : 100;
  const limit = Number.isFinite(requestedLimit) ? requestedLimit : 100;
  const artifacts = getDetectionArtifacts(format, limit);
  res.json({ artifacts, total: artifacts.length, executable: false });
});

api.get('/stix/objects', auth.requireRole('analyst'), audit('stix_object_query'), (req, res) => {
  const type = typeof req.query.type === 'string' ? req.query.type.trim() : undefined;
  const id = typeof req.query.id === 'string' ? req.query.id.trim() : undefined;
  if (type && !/^[a-z0-9-]{1,64}$/.test(type)) {
    res.status(400).json({ error: 'invalid STIX object type' });
    return;
  }
  if (id && (id.length > 200 || !id.includes('--'))) {
    res.status(400).json({ error: 'invalid STIX object id' });
    return;
  }
  res.json(
    queryStixObjects(stixObjects(res.locals.role as ApiRole), {
      type,
      id,
      limit: req.query.limit ? Number(req.query.limit) : undefined,
      offset: req.query.offset ? Number(req.query.offset) : undefined,
    }),
  );
});

api.get('/stix/graph/:id', auth.requireRole('analyst'), audit('stix_graph_query'), (req, res) => {
  const id = req.params.id.trim();
  if (id.length > 200 || !id.includes('--')) {
    res.status(400).json({ error: 'invalid STIX object id' });
    return;
  }
  const depth = req.query.depth ? Number(req.query.depth) : 1;
  const normalizedDepth = Math.min(3, Math.max(0, Math.floor(Number.isFinite(depth) ? depth : 1)));
  const objects = stixNeighborhood(
    stixObjects(res.locals.role as ApiRole),
    id,
    normalizedDepth,
  );
  if (!objects.some((object) => object.id === id)) {
    res.status(404).json({ error: 'STIX object not found or not permitted by TLP policy' });
    return;
  }
  res.json({ rootId: id, depth: normalizedDepth, objects });
});

api.post('/extract-iocs', auth.requireRole('analyst'), audit('ioc_text_extract'), (req, res) => {
  const text = typeof req.body?.text === 'string' ? req.body.text : '';
  if (!text) {
    res.status(400).json({ error: 'text is required' });
    return;
  }
  if (text.length > 200_000) {
    res.status(413).json({ error: 'text exceeds the 200000 character extraction limit' });
    return;
  }
  const requestedLimit = Number(req.body?.limit ?? 1000);
  const limit = Number.isFinite(requestedLimit) ? Math.min(2000, Math.max(1, Math.floor(requestedLimit))) : 1000;
  const iocs = extractIocs(text, limit);
  const localKeys = new Set(
    store.getIndicators().map((indicator) => `${indicator.indicatorType}:${indicator.indicator.toLowerCase()}`),
  );
  res.json({
    iocs: iocs.map((ioc) => ({
      ...ioc,
      localMatch: localKeys.has(`${ioc.indicatorType}:${ioc.value.toLowerCase()}`),
    })),
    total: iocs.length,
  });
});

// STIX 2.1 bundle export for sharing with MISP / OpenCTI / SIEMs.
api.get('/export/stix', (_req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="threat-intel-stix.json"');
  sendIntegrityProtected(res, stixBundle(res.locals.role as ApiRole), 'application/stix+json;version=2.1');
});

// Manually trigger a digest push to all configured channels (DingTalk / Telegram).
// Guarded: this endpoint sends real messages, so it must not be open to the world.
// - If NOTIFY_TEST_TOKEN is set, the caller must supply it in x-notify-token.
// - If it is not set, the route is allowed only outside production.
const NOTIFY_TEST_TOKEN = process.env.NOTIFY_TEST_TOKEN?.trim() || null;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

api.post('/notify/test', auth.requireRole('admin'), audit('notify_test'), (req, res) => {
  if (NOTIFY_TEST_TOKEN) {
    const provided = typeof req.headers['x-notify-token'] === 'string' ? req.headers['x-notify-token'] : '';
    if (provided !== NOTIFY_TEST_TOKEN) {
      res.status(401).json({ error: 'unauthorized: invalid or missing notify test token' });
      return;
    }
  } else if (IS_PRODUCTION) {
    res.status(403).json({ error: 'forbidden: set NOTIFY_TEST_TOKEN to enable this endpoint' });
    return;
  }
  notifier
    .sendTest()
    .then((out) => res.json(out))
    .catch((err) => res.status(500).json({ error: errorMessage(err) }));
});

// Phase 1: Platform Upgrade - Cases Management API

api.post('/cases', auth.requireRole('analyst'), requirePersistence, audit('create_case'), (req, res) => {
  const { title, severity, assignee } = req.body || {};
  if (!title || !severity) {
    res.status(400).json({ error: 'missing required fields: title, severity' });
    return;
  }
  if (!['low', 'medium', 'high', 'critical'].includes(severity)) {
    res.status(400).json({ error: 'invalid severity level' });
    return;
  }
  try {
    const newCase = createCase({ title, severity, assignee });
    res.status(201).json(newCase);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/cases', auth.requireRole('analyst'), requirePersistence, (_req, res) => {
  const status =
    typeof _req.query.status === 'string' && CASE_STATUSES.includes(_req.query.status as CaseStatus)
      ? (_req.query.status as CaseStatus)
      : undefined;
  const assignee = typeof _req.query.assignee === 'string' ? _req.query.assignee : undefined;
  try {
    const cases = listCases({ status, assignee });
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/cases/:id', auth.requireRole('analyst'), requirePersistence, (req, res) => {
  try {
    const caseData = getCase(req.params.id);
    if (!caseData) {
      res.status(404).json({ error: 'case not found' });
      return;
    }
    res.json(caseData);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.patch('/cases/:id', auth.requireRole('analyst'), requirePersistence, audit('update_case'), (req, res) => {
  const { status, assignee } = req.body || {};
  try {
    const updated = updateCase(req.params.id, { status, assignee });
    if (!updated) {
      res.status(404).json({ error: 'case not found' });
      return;
    }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.post('/cases/:id/iocs', auth.requireRole('analyst'), requirePersistence, audit('add_case_ioc'), (req, res) => {
  const { iocId } = req.body || {};
  if (!iocId) {
    res.status(400).json({ error: 'missing required field: iocId' });
    return;
  }
  try {
    const success = addIocToCase(req.params.id, iocId);
    if (!success) {
      res.status(404).json({ error: 'case not found' });
      return;
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.post('/cases/:id/comments', auth.requireRole('analyst'), requirePersistence, audit('add_case_comment'), (req, res) => {
  const { content } = req.body || {};
  if (!content) {
    res.status(400).json({ error: 'missing required field: content' });
    return;
  }
  try {
    const comment = addComment(req.params.id, {
      author: (res.locals.principal as string | null) ?? 'anonymous',
      content,
    });
    if (!comment) {
      res.status(404).json({ error: 'case not found' });
      return;
    }
    res.status(201).json(comment);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

// Phase 1: Platform Upgrade - Threat Hunting API

api.post('/hunt/batch', auth.requireRole('analyst'), audit('hunt_batch'), (req, res) => {
  const startedAt = Date.now();
  const { iocs, timeRange, sources } = req.body || {};
  if (!iocs || !Array.isArray(iocs) || iocs.length === 0) {
    res.status(400).json({ error: 'missing or invalid field: iocs (must be non-empty array)' });
    return;
  }
  if (iocs.length > 500 || iocs.some((ioc) => typeof ioc !== 'string' || ioc.trim().length === 0 || ioc.length > 2048)) {
    res.status(400).json({ error: 'iocs must contain 1-500 non-empty strings of at most 2048 characters' });
    return;
  }
  if (!timeRange || typeof timeRange.start !== 'number' || typeof timeRange.end !== 'number') {
    res.status(400).json({ error: 'missing or invalid field: timeRange (must have start and end)' });
    return;
  }
  try {
    const searchableIndicators = isPersistEnabled() ? loadIntelSnapshot(false).indicators : store.getIndicators();
    const result = batchHunt(
      { iocs, timeRange, sources },
      searchableIndicators,
      (res.locals.principal as string | null) ?? 'anonymous',
    );
    res.json({
      ...result,
      totalMatches: result.results.reduce((total, item) => total + item.matches.length, 0),
      queryTime: Date.now() - startedAt,
      historical: isPersistEnabled(),
    });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/hunt/history', auth.requireRole('analyst'), requirePersistence, (_req, res) => {
  const limit = _req.query.limit ? Number(_req.query.limit) : 50;
  try {
    const history = getHuntHistory(Number.isFinite(limit) ? limit : 50);
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

// Phase 1: Platform Upgrade - Rules Engine API

api.post('/rules', auth.requireRole('admin'), requirePersistence, audit('create_rule'), (req, res) => {
  const { name, triggerType, triggerConfig, actions, enabled } = req.body || {};
  if (!name || !triggerType || !triggerConfig || !actions) {
    res.status(400).json({ error: 'missing required fields: name, triggerType, triggerConfig, actions' });
    return;
  }
  if (!['ioc_match', 'threshold'].includes(triggerType)) {
    res.status(400).json({ error: 'unsupported triggerType: supported values are ioc_match and threshold' });
    return;
  }
  if (!Array.isArray(actions)) {
    res.status(400).json({ error: 'actions must be an array' });
    return;
  }
  if (actions.length === 0 || actions.some((action) => !action || !['webhook', 'enrich'].includes(action.type))) {
    res.status(400).json({ error: 'actions must contain only implemented webhook or enrich actions' });
    return;
  }
  if (actions.some((action) => action.type === 'webhook' && typeof action.config?.url !== 'string')) {
    res.status(400).json({ error: 'webhook actions require config.url' });
    return;
  }
  try {
    const rule = createRule({ name, triggerType, triggerConfig, actions, enabled });
    res.status(201).json(rule);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/rules', auth.requireRole('analyst'), requirePersistence, (_req, res) => {
  const enabledOnly = _req.query.enabled === 'true';
  try {
    const rules = listRules(enabledOnly);
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/rules/:id', auth.requireRole('analyst'), requirePersistence, (req, res) => {
  try {
    const rule = getRule(req.params.id);
    if (!rule) {
      res.status(404).json({ error: 'rule not found' });
      return;
    }
    res.json(rule);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.patch('/rules/:id', auth.requireRole('admin'), requirePersistence, audit('update_rule'), (req, res) => {
  const { enabled } = req.body || {};
  if (enabled === undefined) {
    res.status(400).json({ error: 'missing field: enabled' });
    return;
  }
  try {
    const updated = updateRule(req.params.id, { enabled });
    if (!updated) {
      res.status(404).json({ error: 'rule not found' });
      return;
    }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/rules/:id/executions', auth.requireRole('analyst'), requirePersistence, (req, res) => {
  const limit = req.query.limit ? Number(req.query.limit) : 50;
  try {
    const executions = getRuleExecutionHistory(req.params.id, Number.isFinite(limit) ? limit : 50);
    res.json({ executions });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

// Phase 2: Platform Upgrade - Quality Scoring API

api.get('/quality/distribution', auth.requireRole('analyst'), (_req, res) => {
  try {
    const indicators = store.getIndicators();
    const distribution = getQualityDistribution(indicators);
    res.json(distribution);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/quality/trend', auth.requireRole('analyst'), (req, res) => {
  const days = req.query.days ? Number(req.query.days) : 7;
  try {
    const indicators = store.getIndicators();
    const trend = getQualityTrend(indicators, Number.isFinite(days) && days > 0 ? Math.min(days, 90) : 7);
    res.json({ trend });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.post('/quality/false-positive', auth.requireRole('analyst'), requirePersistence, audit('mark_false_positive'), (req, res) => {
  const { iocValue, reason } = req.body || {};
  if (!iocValue) {
    res.status(400).json({ error: 'missing required field: iocValue' });
    return;
  }
  try {
    markAsFalsePositive(iocValue, (res.locals.principal as string | null) ?? 'anonymous', reason);
    res.json({ success: true, iocValue });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/quality/false-positives', auth.requireRole('analyst'), requirePersistence, (_req, res) => {
  try {
    const falsePositives = listFalsePositives();
    res.json({ falsePositives });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

app.use('/api', api);

// Unknown /api/* routes return JSON 404 (not the SPA shell).
app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'not found' });
});

// Serve the built frontend if present (single-process production deploy).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDist = path.resolve(__dirname, '../../frontend/dist');
if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
}

// Global error handler: never leak stack traces, always return JSON.
app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(`[server] unhandled error: ${errorMessage(err)}`);
  if (res.headersSent) return;
  res.status(500).json({ error: 'internal server error' });
});

async function bootstrap(): Promise<void> {
  // Open persistence first (no-op unless DATA_DIR is set) so the first refresh can
  // hydrate the geo cache and record first/last-seen.
  initPersistence();
  store.hydrateFromPersistence();

  server = app.listen(PORT, () => {
    console.log(`[server] threat-intel-platform API listening on :${PORT}`);
  });

  // Initial load + periodic refresh.
  try {
    console.log('[server] initial feed refresh starting...');
    await store.refresh();
    const stats = store.getStats();
    console.log(
      `[server] initial refresh done: ${stats.totalIndicators} indicators, ${stats.totalCves} CVEs`,
    );
    // Prime the alert baseline against the initial dataset so we only push new threats later.
    await notifier.runOnce();
    await notifier.checkSourceHealth(store.getHealth());
  } catch (err) {
    console.error(`[server] initial refresh failed: ${errorMessage(err)}`);
  }

  // Start the scheduled alert push (no-op if disabled / unconfigured).
  notifier.start();

  // Start enrichment cache cleanup task (runs every hour).
  stopCacheCleanup = startCacheCleanupTask();

  // Setup automatic rule triggering on new indicators.
  setupAutoTrigger(store);
  console.log('[server] rule auto-trigger enabled');

  const refreshFeeds = async (): Promise<void> => {
    await store.refresh();
    console.log('[server] feeds refreshed');
    await notifier.checkSourceHealth(store.getHealth());
  };
  if (isPersistEnabled()) {
    backgroundWorker = new DurableJobWorker({ feed_refresh: async () => refreshFeeds() });
    backgroundWorker.start();
    refreshTimer = setInterval(() => {
      enqueueDurableJob('feed_refresh', {}, { dedupeKey: 'scheduled-feed-refresh', maxAttempts: 5 });
    }, REFRESH_INTERVAL_MS);
  } else {
    refreshTimer = setInterval(() => {
      refreshFeeds().catch((err) => console.error(`[server] refresh failed: ${errorMessage(err)}`));
    }, REFRESH_INTERVAL_MS);
  }
}

void bootstrap();

function shutdown(signal: string): void {
  console.log(`[server] ${signal} received; stopping background work`);
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = null;
  backgroundWorker?.stop();
  stopCacheCleanup?.();
  notifier.stop();
  const finish = () => {
    closePersistence();
    process.exitCode = 0;
  };
  if (server) server.close(finish);
  else finish();
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
