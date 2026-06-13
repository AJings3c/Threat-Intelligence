import express from 'express';
import cors from 'cors';
import compression from 'compression';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { store } from './store.js';
import { notifier } from './notify/index.js';
import { errorMessage, extractToken } from './util.js';
import { initPersistence, getTrend, isPersistEnabled, getSourceHealthHistory } from './persist.js';
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
import { enrichIndicator, enrichmentConfigStatus, parseIndicatorType } from './enrich.js';
import { testIntegration } from './integrationTests.js';
import { investigationMarkdown, architectureThreatModelMarkdown } from './reports.js';
import { buildArchitectureThreatModel } from './architectureThreatModel.js';
import { apiAuth, audit, corsOptions, rateLimit } from './security.js';
import type { EnrichmentProvider, IntegrationKind, ThreatSource } from './types.js';
import { parseLanguage } from './language.js';
import { createCase, updateCase, getCase, listCases, addIocToCase, addComment } from './cases.js';
import { batchHunt, getHuntHistory } from './hunt.js';
import { createRule, updateRule, getRule, listRules, getRuleExecutionHistory } from './rules/index.js';
import { markAsFalsePositive, listFalsePositives, getQualityDistribution, getQualityTrend } from './quality.js';


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
  'taxii_import',
];
const ENRICHMENT_PROVIDERS: EnrichmentProvider[] = ['virustotal', 'shodan', 'censys'];

// Optional API auth. When API_TOKEN is set, all /api routes (except /health) require it.
// A static token suits machine/SIEM access or a private deployment; a browser SPA cannot
// keep it truly secret, so for public dashboards put a real auth proxy in front.
const API_TOKEN = process.env.API_TOKEN?.trim() || null;
const tokenOf = (req: express.Request): string =>
  extractToken(
    typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined,
    typeof req.headers['x-api-token'] === 'string' ? req.headers['x-api-token'] : undefined,
    typeof req.query.token === 'string' ? req.query.token : undefined,
  );

const app = express();
app.use(cors(corsOptions()));

function taxiiBaseUrl(req: express.Request): string {
  return `${req.protocol}://${req.get('host') ?? `localhost:${PORT}`}`;
}

function setTaxiiHeaders(res: express.Response): void {
  res.setHeader('Content-Type', TAXII_MEDIA_TYPE);
}

function guardTaxii(req: express.Request, res: express.Response): boolean {
  if (!API_TOKEN || tokenOf(req) === API_TOKEN) return true;
  setTaxiiHeaders(res);
  res.status(401).json({
    title: 'Unauthorized',
    description: 'invalid or missing API token',
    error_code: 'unauthorized',
  });
  return false;
}

function stixObjects() {
  return buildStixBundle(store.getIndicators(), store.getAllCves()).objects;
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
  if (API_TOKEN && tokenOf(req) !== API_TOKEN) {
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
  setTaxiiHeaders(res);
  res.json(buildTaxiiDiscovery(taxiiBaseUrl(req)));
});

app.get('/taxii2/root/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  res.json(buildTaxiiApiRoot());
});

app.get('/taxii2/root/collections/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  res.json(buildTaxiiCollections());
});

app.get('/taxii2/root/collections/:id/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  res.json(taxiiCollection());
});

app.get('/taxii2/root/collections/:id/objects/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  res.json(buildTaxiiEnvelope(stixObjects(), taxiiPageOptions(req)));
});

app.get('/taxii2/root/collections/:id/manifest/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  res.json(buildTaxiiManifest(stixObjects(), taxiiPageOptions(req)));
});

const api = express.Router();
const auth = apiAuth(API_TOKEN);
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
  enrichIndicator(indicator, indicatorType)
    .then((result) => res.json(result))
    .catch((err) => res.status(500).json({ error: errorMessage(err) }));
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
  res.send(investigationMarkdown(result, language));
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
    authConfigured: Boolean(
      API_TOKEN ||
        process.env.API_VIEWER_TOKENS?.trim() ||
        process.env.API_ANALYST_TOKENS?.trim() ||
        process.env.API_ADMIN_TOKENS?.trim(),
    ),
    persistenceEnabled: isPersistEnabled(),
    notifyEnabled: notifyStatus.enabled,
    configuredNotifyChannels,
    corsRestricted: Boolean(process.env.CORS_ORIGINS?.trim()),
    rateLimitMax: Number(process.env.API_RATE_LIMIT_MAX ?? 180),
    jsonBodyLimit: process.env.JSON_BODY_LIMIT ?? '1mb',
  });
  if (req.query.format === 'markdown') {
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.send(architectureThreatModelMarkdown(model, language));
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

// STIX 2.1 bundle export for sharing with MISP / OpenCTI / SIEMs.
api.get('/export/stix', (_req, res) => {
  const bundle = buildStixBundle(store.getIndicators(), store.getAllCves());
  res.setHeader('Content-Disposition', 'attachment; filename="threat-intel-stix.json"');
  res.json(bundle);
});

// Manually trigger a digest push to all configured channels (DingTalk / Telegram).
// Guarded: this endpoint sends real messages, so it must not be open to the world.
// - If NOTIFY_TEST_TOKEN is set, the caller must supply it (x-notify-token header or ?token=).
// - If it is not set, the route is allowed only outside production.
const NOTIFY_TEST_TOKEN = process.env.NOTIFY_TEST_TOKEN?.trim() || null;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

api.post('/notify/test', auth.requireRole('admin'), audit('notify_test'), (req, res) => {
  if (NOTIFY_TEST_TOKEN) {
    const provided =
      (typeof req.headers['x-notify-token'] === 'string' ? req.headers['x-notify-token'] : '') ||
      (typeof req.query.token === 'string' ? req.query.token : '');
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

api.post('/cases', auth.requireRole('analyst'), audit('create_case'), (req, res) => {
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

api.get('/cases', auth.requireRole('analyst'), (_req, res) => {
  const status = typeof _req.query.status === 'string' ? _req.query.status : undefined;
  const assignee = typeof _req.query.assignee === 'string' ? _req.query.assignee : undefined;
  try {
    const cases = listCases({ status: status as any, assignee });
    res.json({ cases });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/cases/:id', auth.requireRole('analyst'), (req, res) => {
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

api.patch('/cases/:id', auth.requireRole('analyst'), audit('update_case'), (req, res) => {
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

api.post('/cases/:id/iocs', auth.requireRole('analyst'), audit('add_case_ioc'), (req, res) => {
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

api.post('/cases/:id/comments', auth.requireRole('analyst'), audit('add_case_comment'), (req, res) => {
  const { author, content } = req.body || {};
  if (!author || !content) {
    res.status(400).json({ error: 'missing required fields: author, content' });
    return;
  }
  try {
    const comment = addComment(req.params.id, { author, content });
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
  const { iocs, timeRange, sources } = req.body || {};
  if (!iocs || !Array.isArray(iocs) || iocs.length === 0) {
    res.status(400).json({ error: 'missing or invalid field: iocs (must be non-empty array)' });
    return;
  }
  if (!timeRange || typeof timeRange.start !== 'number' || typeof timeRange.end !== 'number') {
    res.status(400).json({ error: 'missing or invalid field: timeRange (must have start and end)' });
    return;
  }
  try {
    const result = batchHunt(
      { iocs, timeRange, sources },
      store.getIndicators(),
      req.headers['x-user-id'] as string || 'unknown',
    );
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/hunt/history', auth.requireRole('analyst'), (_req, res) => {
  const limit = _req.query.limit ? Number(_req.query.limit) : 50;
  try {
    const history = getHuntHistory(Number.isFinite(limit) ? limit : 50);
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

// Phase 1: Platform Upgrade - Rules Engine API

api.post('/rules', auth.requireRole('admin'), audit('create_rule'), (req, res) => {
  const { name, triggerType, triggerConfig, actions, enabled } = req.body || {};
  if (!name || !triggerType || !triggerConfig || !actions) {
    res.status(400).json({ error: 'missing required fields: name, triggerType, triggerConfig, actions' });
    return;
  }
  if (!['ioc_match', 'threshold', 'schedule'].includes(triggerType)) {
    res.status(400).json({ error: 'invalid triggerType' });
    return;
  }
  if (!Array.isArray(actions)) {
    res.status(400).json({ error: 'actions must be an array' });
    return;
  }
  try {
    const rule = createRule({ name, triggerType, triggerConfig, actions, enabled });
    res.status(201).json(rule);
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/rules', auth.requireRole('analyst'), (_req, res) => {
  const enabledOnly = _req.query.enabled === 'true';
  try {
    const rules = listRules(enabledOnly);
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/rules/:id', auth.requireRole('analyst'), (req, res) => {
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

api.patch('/rules/:id', auth.requireRole('admin'), audit('update_rule'), (req, res) => {
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

api.get('/rules/:id/executions', auth.requireRole('analyst'), (req, res) => {
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

api.post('/quality/false-positive', auth.requireRole('analyst'), audit('mark_false_positive'), (req, res) => {
  const { iocValue, markedBy, reason } = req.body || {};
  if (!iocValue || !markedBy) {
    res.status(400).json({ error: 'missing required fields: iocValue, markedBy' });
    return;
  }
  try {
    markAsFalsePositive(iocValue, markedBy, reason);
    res.json({ success: true, iocValue });
  } catch (err) {
    res.status(500).json({ error: errorMessage(err) });
  }
});

api.get('/quality/false-positives', auth.requireRole('analyst'), (_req, res) => {
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

  app.listen(PORT, () => {
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

  setInterval(() => {
    store
      .refresh()
      .then(() => {
        console.log('[server] feeds refreshed');
        return notifier.checkSourceHealth(store.getHealth());
      })
      .catch((err) => console.error(`[server] refresh failed: ${errorMessage(err)}`));
  }, REFRESH_INTERVAL_MS);
}

void bootstrap();
