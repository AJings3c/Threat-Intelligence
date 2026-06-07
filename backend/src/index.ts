import express from 'express';
import cors from 'cors';
import compression from 'compression';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { store } from './store.js';
import { notifier } from './notify/index.js';
import { errorMessage } from './util.js';

const PORT = Number(process.env.PORT ?? 4000);
const REFRESH_INTERVAL_MS = Number(process.env.REFRESH_INTERVAL_MS ?? 15 * 60 * 1000);

const app = express();
app.use(cors());
app.use(compression());
app.use(express.json());

const api = express.Router();

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
