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

const PORT = Number(process.env.PORT ?? 4000);
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS ?? 15 * 60 * 1000);

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
app.use(cors());

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
app.use(express.json());

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
  res.json(buildTaxiiEnvelope(stixObjects()));
});

app.get('/taxii2/root/collections/:id/manifest/', (req, res) => {
  if (!guardTaxii(req, res)) return;
  setTaxiiHeaders(res);
  if (req.params.id !== TAXII_COLLECTION_ID) {
    res.status(404).json({ title: 'Not found', description: 'collection not found' });
    return;
  }
  res.json(buildTaxiiManifest(stixObjects()));
});

const api = express.Router();

// Gate every /api route behind the token when configured; /health stays open for probes.
if (API_TOKEN) {
  api.use((req, res, next) => {
    if (req.path === '/health') {
      next();
      return;
    }
    if (tokenOf(req) === API_TOKEN) {
      next();
      return;
    }
    res.status(401).json({ error: 'unauthorized: invalid or missing API token' });
  });
}

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

api.get('/enrich', (req, res) => {
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

api.get('/investigate', (req, res) => {
  const indicator = typeof req.query.indicator === 'string' ? req.query.indicator.trim() : '';
  const indicatorType = parseIndicatorType(typeof req.query.type === 'string' ? req.query.type : undefined);
  if (!indicator) {
    res.status(400).json({ error: 'missing indicator query parameter' });
    return;
  }
  res.json(store.investigateIndicator(indicator, indicatorType ?? undefined));
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

api.post('/notify/test', (req, res) => {
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
