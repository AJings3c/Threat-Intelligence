import express from 'express';
import cors from 'cors';
import compression from 'compression';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { store } from './store.js';
import { notifier } from './notify/index.js';
import { toStixBundle } from './stix.js';
import { errorMessage } from './util.js';

const PORT = Number(process.env.PORT ?? 4000);
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS ?? 15 * 60 * 1000);
const API_RATE_WINDOW_MS = Number(process.env.API_RATE_WINDOW_MS ?? 60_000);
const API_RATE_MAX = Number(process.env.API_RATE_MAX ?? 120);

// Allowed query enum values, kept in sync with the data model.
const SOURCES = ['cisa_kev', 'feodo', 'urlhaus', 'nvd'];
const TYPES = ['c2_server', 'malware_host', 'malicious_url', 'exploited_vuln', 'vulnerability'];
const SEVERITIES = ['low', 'medium', 'high', 'critical'];

// Validate an optional enum query param; returns the value, undefined, or an error string.
function pickEnum(
  value: unknown,
  allowed: string[],
  name: string,
): { value?: string; error?: string } {
  if (value === undefined) return {};
  if (typeof value !== 'string' || !allowed.includes(value)) {
    return { error: `invalid ${name}; expected one of: ${allowed.join(', ')}` };
  }
  return { value };
}

// Parse + clamp an optional numeric limit to a safe range.
function pickLimit(value: unknown, fallback: number, max = 1000): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

const app = express();
app.disable('x-powered-by');
// CSP is disabled because a separate SPA is served from this origin; the other
// helmet protections (HSTS, noSniff, frameguard, etc.) still apply.
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '256kb' }));

const api = express.Router();
api.use(
  rateLimit({
    windowMs: API_RATE_WINDOW_MS,
    max: API_RATE_MAX,
    standardHeaders: true,
    legacyHeaders: false,
  }),
);

api.get('/health', (_req, res) => {
  res.json({
    status: store.isReady ? 'ok' : 'warming_up',
    lastRefresh: store.lastRefreshAt ? new Date(store.lastRefreshAt).toISOString() : null,
    sources: store.getHealth(),
  });
});

api.get('/threats', (req, res) => {
  const source = pickEnum(req.query.source, SOURCES, 'source');
  const type = pickEnum(req.query.type, TYPES, 'type');
  const severity = pickEnum(req.query.severity, SEVERITIES, 'severity');
  const firstError = source.error ?? type.error ?? severity.error;
  if (firstError) {
    res.status(400).json({ error: firstError });
    return;
  }
  const { q } = req.query;
  const result = store.queryThreats({
    source: source.value,
    type: type.value,
    severity: severity.value,
    q: typeof q === 'string' ? q : undefined,
    limit: pickLimit(req.query.limit, 500),
  });
  res.json({ ...result, generatedAt: new Date().toISOString() });
});

api.get('/map', (_req, res) => {
  res.json({ points: store.getMapPoints(), generatedAt: new Date().toISOString() });
});

api.get('/cve', (req, res) => {
  res.json({ ...store.getCves(pickLimit(req.query.limit, 60)) });
});

// STIX 2.1 bundle export for interoperability with MISP/OpenCTI/SIEMs.
api.get('/stix', (_req, res) => {
  res.json(toStixBundle(store.getIndicators(), store.getAllCves()));
});

api.get('/stats', (_req, res) => {
  res.json(store.getStats());
});

api.get('/sources/health', (_req, res) => {
  res.json({ sources: store.getHealth() });
});

api.get('/notify/status', (_req, res) => {
  res.json(notifier.status());
});

// Manually trigger a digest push to all configured channels (DingTalk / Telegram).
api.post('/notify/test', (_req, res) => {
  notifier
    .sendTest()
    .then((out) => res.json(out))
    .catch((err) => res.status(500).json({ error: errorMessage(err) }));
});

app.use('/api', api);

// Serve the built frontend if present (single-process production deploy).
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const frontendDist = path.resolve(__dirname, '../../frontend/dist');
if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
}

async function bootstrap(): Promise<void> {
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
  } catch (err) {
    console.error(`[server] initial refresh failed: ${errorMessage(err)}`);
  }

  // Start the scheduled alert push (no-op if disabled / unconfigured).
  notifier.start();

  setInterval(() => {
    store
      .refresh()
      .then(() => console.log('[server] feeds refreshed'))
      .catch((err) => console.error(`[server] refresh failed: ${errorMessage(err)}`));
  }, REFRESH_INTERVAL_MS);
}

void bootstrap();
