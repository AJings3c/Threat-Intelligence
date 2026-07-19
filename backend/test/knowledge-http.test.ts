import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  closePersistence,
  initPersistence,
  persistStixObjects,
} from '../src/persist.js';

const backendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const serverEntry = path.join(backendRoot, 'src', 'index.ts');
const disableOutboundFetch = `data:text/javascript,${encodeURIComponent(
  "globalThis.fetch=async()=>{throw new Error('outbound fetch disabled by HTTP integration test')}",
)}`;
const CLEAR = 'marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487';
const RED = 'marking-definition--5e57c739-391a-4eb3-b6e7-5b9acb13fe73';
const CLEAR_ENTITY_ID = 'threat-actor--00000000-0000-4000-8000-000000000101';
const RED_ENTITY_ID = 'threat-actor--00000000-0000-4000-8000-000000000102';
const AUTH_ENV_KEYS = [
  'API_TOKEN',
  'API_VIEWER_TOKENS',
  'API_ANALYST_TOKENS',
  'API_ADMIN_TOKENS',
  'AUTH_PROXY_ENABLED',
  'AUTH_PROXY_SHARED_SECRET',
  'ALLOW_INSECURE_NO_AUTH',
] as const;

interface RunningServer {
  baseUrl: string;
  child: ChildProcess;
  logs: () => string;
}

interface JsonResponse {
  status: number;
  body: Record<string, unknown>;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function availablePort(): Promise<number> {
  const listener = createServer();
  await new Promise<void>((resolve, reject) => {
    listener.once('error', reject);
    listener.listen(0, '127.0.0.1', resolve);
  });
  const address = listener.address();
  if (!address || typeof address === 'string') throw new Error('failed to allocate a test server port');
  await new Promise<void>((resolve, reject) => listener.close((error) => (error ? reject(error) : resolve())));
  return address.port;
}

function childEnvironment(overrides: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const environment = { ...process.env };
  for (const key of AUTH_ENV_KEYS) delete environment[key];
  delete environment.DATA_DIR;
  return {
    ...environment,
    NODE_ENV: 'test',
    REFRESH_INTERVAL_MS: '86400000',
    ...overrides,
  };
}

async function startServer(overrides: NodeJS.ProcessEnv): Promise<RunningServer> {
  const port = await availablePort();
  const child = spawn(process.execPath, ['--import', 'tsx', '--import', disableOutboundFetch, serverEntry], {
    cwd: backendRoot,
    env: childEnvironment({ ...overrides, PORT: String(port) }),
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  let output = '';
  const capture = (chunk: Buffer): void => {
    output = `${output}${chunk.toString('utf8')}`.slice(-20_000);
  };
  child.stdout?.on('data', capture);
  child.stderr?.on('data', capture);

  const baseUrl = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`test server exited with code ${child.exitCode}\n${output}`);
    }
    try {
      const response = await fetch(`${baseUrl}/api/health`, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) return { baseUrl, child, logs: () => output };
    } catch {
      // The listener is not ready yet.
    }
    await delay(50);
  }
  child.kill('SIGKILL');
  throw new Error(`test server did not become ready\n${output}`);
}

async function stopServer(server: RunningServer | undefined): Promise<void> {
  if (!server || server.child.exitCode !== null) return;
  const exited = once(server.child, 'exit');
  server.child.kill('SIGTERM');
  const graceful = await Promise.race([exited.then(() => true), delay(2_000).then(() => false)]);
  if (!graceful && server.child.exitCode === null) {
    server.child.kill('SIGKILL');
    await Promise.race([exited, delay(2_000)]);
  }
}

async function getJson(server: RunningServer, pathname: string, token?: string): Promise<JsonResponse> {
  const response = await fetch(`${server.baseUrl}${pathname}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    signal: AbortSignal.timeout(5_000),
  });
  return {
    status: response.status,
    body: (await response.json()) as Record<string, unknown>,
  };
}

describe('threat knowledge HTTP routes', () => {
  let dataDir = '';
  let persistentServer: RunningServer | undefined;
  let ephemeralServer: RunningServer | undefined;
  let unconfiguredAuthServer: RunningServer | undefined;

  beforeAll(async () => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'threat-knowledge-http-'));
    const previousDataDir = process.env.DATA_DIR;
    process.env.DATA_DIR = dataDir;
    try {
      initPersistence();
      const created = '2026-01-01T00:00:00.000Z';
      const persisted = persistStixObjects(
        [
          {
            type: 'threat-actor',
            spec_version: '2.1',
            id: CLEAR_ENTITY_ID,
            created,
            modified: created,
            name: 'Visible HTTP Test Actor',
            object_marking_refs: [CLEAR],
          },
          {
            type: 'threat-actor',
            spec_version: '2.1',
            id: RED_ENTITY_ID,
            created,
            modified: created,
            name: 'Restricted HTTP Test Actor',
            object_marking_refs: [RED],
          },
        ],
        'http-integration-test',
        Date.parse(created),
      );
      expect(persisted).toBe(2);
    } finally {
      closePersistence();
      if (previousDataDir === undefined) delete process.env.DATA_DIR;
      else process.env.DATA_DIR = previousDataDir;
    }

    persistentServer = await startServer({
      DATA_DIR: dataDir,
      API_TOKEN: 'admin-secret',
      API_VIEWER_TOKENS: 'viewer-secret',
      API_ANALYST_TOKENS: 'analyst-secret',
    });
    ephemeralServer = await startServer({
      API_TOKEN: 'admin-secret',
      API_VIEWER_TOKENS: 'viewer-secret',
    });
    unconfiguredAuthServer = await startServer({ NODE_ENV: 'production' });
  }, 60_000);

  afterAll(async () => {
    await Promise.all([
      stopServer(persistentServer),
      stopServer(ephemeralServer),
      stopServer(unconfiguredAuthServer),
    ]);
    closePersistence();
    if (dataDir) rmSync(dataDir, { recursive: true, force: true });
  }, 15_000);

  it('enforces configured authentication and fails closed when production auth is absent', async () => {
    const missingToken = await getJson(persistentServer!, '/api/knowledge/types');
    expect(missingToken).toEqual({
      status: 401,
      body: { error: 'unauthorized: invalid or missing API token' },
    });

    const invalidToken = await getJson(persistentServer!, '/api/knowledge/types', 'wrong-secret');
    expect(invalidToken.status).toBe(401);

    const noServerAuth = await getJson(unconfiguredAuthServer!, '/api/knowledge/types');
    expect(noServerAuth).toEqual({
      status: 503,
      body: { error: 'server authentication is not configured' },
    });
  });

  it('serves the supported types without requiring DATA_DIR', async () => {
    const response = await getJson(ephemeralServer!, '/api/knowledge/types', 'viewer-secret');
    expect(response).toEqual({
      status: 200,
      body: {
        entityTypes: [
          'threat-actor',
          'intrusion-set',
          'campaign',
          'malware',
          'tool',
          'attack-pattern',
          'identity',
          'vulnerability',
          'infrastructure',
          'indicator',
        ],
      },
    });
  });

  it('returns 503 for entity queries when DATA_DIR persistence is unavailable', async () => {
    const response = await getJson(ephemeralServer!, '/api/knowledge/entities', 'viewer-secret');
    expect(response).toEqual({
      status: 503,
      body: { error: 'persistence required: configure DATA_DIR and restart the service' },
    });
  });

  it('validates entity filters, search length, and entity IDs at the route boundary', async () => {
    const invalidTypes = await getJson(
      persistentServer!,
      '/api/knowledge/entities?types=threat-actor,unsupported',
      'viewer-secret',
    );
    expect(invalidTypes).toEqual({
      status: 400,
      body: { error: 'types contains an unsupported knowledge entity type' },
    });

    const longQuery = await getJson(
      persistentServer!,
      `/api/knowledge/entities?q=${encodeURIComponent('x'.repeat(201))}`,
      'viewer-secret',
    );
    expect(longQuery).toEqual({
      status: 400,
      body: { error: 'q exceeds the 200 character search limit' },
    });

    const invalidId = await getJson(persistentServer!, '/api/knowledge/entities/not-a-stix-id', 'viewer-secret');
    expect(invalidId).toEqual({
      status: 400,
      body: { error: 'invalid knowledge entity id' },
    });
  });

  it('applies TLP filtering as a non-disclosing 404 while admins can read the entity', async () => {
    const viewerResponse = await getJson(
      persistentServer!,
      `/api/knowledge/entities/${RED_ENTITY_ID}`,
      'viewer-secret',
    );
    expect(viewerResponse).toEqual({
      status: 404,
      body: { error: 'knowledge entity not found or not permitted by TLP policy' },
    });

    const adminResponse = await getJson(
      persistentServer!,
      `/api/knowledge/entities/${RED_ENTITY_ID}`,
      'admin-secret',
    );
    expect(adminResponse.status).toBe(200);
    expect(adminResponse.body).toMatchObject({ id: RED_ENTITY_ID, tlp: 'red' });
  });

  it('normalizes graph depth and hides a TLP-restricted root', async () => {
    const visibleGraph = await getJson(
      persistentServer!,
      `/api/knowledge/entities/${CLEAR_ENTITY_ID}/graph?depth=99`,
      'viewer-secret',
    );
    expect(visibleGraph.status).toBe(200);
    expect(visibleGraph.body).toMatchObject({ rootId: CLEAR_ENTITY_ID, depth: 3 });
    expect(visibleGraph.body.entities).toEqual([
      expect.objectContaining({ id: CLEAR_ENTITY_ID, tlp: 'clear' }),
    ]);

    const restrictedGraph = await getJson(
      persistentServer!,
      `/api/knowledge/entities/${RED_ENTITY_ID}/graph`,
      'viewer-secret',
    );
    expect(restrictedGraph).toEqual({
      status: 404,
      body: { error: 'knowledge entity not found or not permitted by TLP policy' },
    });
  });

  it('filters list results by role using the persisted projection', async () => {
    const viewerResponse = await getJson(persistentServer!, '/api/knowledge/entities', 'viewer-secret');
    expect(viewerResponse.status).toBe(200);
    expect(viewerResponse.body).toMatchObject({ total: 1 });
    expect(viewerResponse.body.entities).toEqual([
      expect.objectContaining({ id: CLEAR_ENTITY_ID, tlp: 'clear' }),
    ]);

    const adminResponse = await getJson(persistentServer!, '/api/knowledge/entities', 'admin-secret');
    expect(adminResponse.status).toBe(200);
    expect(adminResponse.body).toMatchObject({ total: 2 });
  });
});
