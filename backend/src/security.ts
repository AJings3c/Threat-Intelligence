import type { NextFunction, Request, Response } from 'express';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { CorsOptions } from 'cors';
import type { ApiRole, AuditEvent } from './types.js';
import { recordAuditEvent } from './persist.js';
import { extractToken } from './util.js';

const ROLE_RANK: Record<ApiRole, number> = { viewer: 0, analyst: 1, admin: 2 };

function splitCsv(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

function tokenOf(req: Request): string {
  return extractToken(
    typeof req.headers.authorization === 'string' ? req.headers.authorization : undefined,
    typeof req.headers['x-api-token'] === 'string' ? req.headers['x-api-token'] : undefined,
  );
}

function principalForToken(token: string): string {
  if (!token) return 'local-development-admin';
  return `token:${createHash('sha256').update(token).digest('hex').slice(0, 16)}`;
}

function safeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export interface RequestIdentity {
  role: ApiRole;
  principal: string;
  mechanism: 'token' | 'trusted-proxy' | 'development-open';
}

function proxyAuthConfigured(): boolean {
  return process.env.AUTH_PROXY_ENABLED === 'true' && Boolean(process.env.AUTH_PROXY_SHARED_SECRET?.trim());
}

function trustedProxyIdentity(req: Request): RequestIdentity | null {
  if (!proxyAuthConfigured()) return null;
  const expectedSecret = process.env.AUTH_PROXY_SHARED_SECRET?.trim() ?? '';
  const suppliedSecret = typeof req.headers['x-auth-proxy-secret'] === 'string' ? req.headers['x-auth-proxy-secret'] : '';
  if (!suppliedSecret || !safeEqual(suppliedSecret, expectedSecret)) return null;
  const principal = typeof req.headers['x-auth-user'] === 'string' ? req.headers['x-auth-user'].trim() : '';
  const role = typeof req.headers['x-auth-role'] === 'string' ? req.headers['x-auth-role'].trim() : '';
  if (!principal || (role !== 'viewer' && role !== 'analyst' && role !== 'admin')) return null;
  return { role, principal, mechanism: 'trusted-proxy' };
}

function roleMap(primaryToken: string | null): Map<string, ApiRole> {
  const map = new Map<string, ApiRole>();
  if (primaryToken) map.set(primaryToken, 'admin');
  for (const token of splitCsv(process.env.API_VIEWER_TOKENS)) map.set(token, 'viewer');
  for (const token of splitCsv(process.env.API_ANALYST_TOKENS)) map.set(token, 'analyst');
  for (const token of splitCsv(process.env.API_ADMIN_TOKENS)) map.set(token, 'admin');
  return map;
}

export function resolveApiRole(token: string, primaryToken: string | null): ApiRole | null {
  return roleMap(primaryToken).get(token) ?? null;
}

export function resolveRequestIdentity(req: Request, primaryToken: string | null): RequestIdentity | null {
  const proxyIdentity = trustedProxyIdentity(req);
  if (proxyIdentity) return proxyIdentity;
  const token = tokenOf(req);
  const role = resolveApiRole(token, primaryToken);
  return role ? { role, principal: principalForToken(token), mechanism: 'token' } : null;
}

export function isApiAuthConfigured(primaryToken: string | null): boolean {
  return roleMap(primaryToken).size > 0 || proxyAuthConfigured();
}

export function isUnauthenticatedAccessAllowed(primaryToken: string | null): boolean {
  return !isApiAuthConfigured(primaryToken) &&
    (process.env.NODE_ENV !== 'production' || process.env.ALLOW_INSECURE_NO_AUTH === 'true');
}

export function apiAuth(primaryToken: string | null): {
  attachRole: (req: Request, res: Response, next: NextFunction) => void;
  requireToken: (req: Request, res: Response, next: NextFunction) => void;
  requireRole: (role: ApiRole) => (req: Request, res: Response, next: NextFunction) => void;
} {
  const authConfigured = isApiAuthConfigured(primaryToken);
  const allowUnauthenticated = isUnauthenticatedAccessAllowed(primaryToken);
  return {
    attachRole(req, res, next) {
      const identity = resolveRequestIdentity(req, primaryToken) ??
        (allowUnauthenticated
          ? { role: 'admin' as const, principal: 'local-development-admin', mechanism: 'development-open' as const }
          : null);
      res.locals.role = identity?.role ?? null;
      res.locals.principal = identity?.principal ?? null;
      res.locals.authMechanism = identity?.mechanism ?? null;
      next();
    },
    requireToken(req, res, next) {
      if (req.path === '/health') {
        next();
        return;
      }
      if (!authConfigured && !allowUnauthenticated) {
        res.status(503).json({ error: 'server authentication is not configured' });
        return;
      }
      if (res.locals.role) {
        next();
        return;
      }
      res.status(401).json({ error: 'unauthorized: invalid or missing API token' });
    },
    requireRole(role) {
      return (_req, res, next) => {
        const current = res.locals.role as ApiRole | null;
        if (current && ROLE_RANK[current] >= ROLE_RANK[role]) {
          next();
          return;
        }
        res.status(403).json({ error: `forbidden: ${role} role required` });
      };
    },
  };
}

export function corsOptions(): CorsOptions {
  const origins = splitCsv(process.env.CORS_ORIGINS);
  if (origins.length === 0) return process.env.NODE_ENV === 'production' ? { origin: false } : {};
  return {
    origin(origin, callback) {
      if (!origin || origins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error('CORS origin denied'));
    },
  };
}

export function rateLimit(): (req: Request, res: Response, next: NextFunction) => void {
  const windowMs = Math.max(1000, Number(process.env.API_RATE_LIMIT_WINDOW_MS ?? 60_000));
  const max = Math.max(1, Number(process.env.API_RATE_LIMIT_MAX ?? 180));
  const buckets = new Map<string, { resetAt: number; count: number }>();
  return (req, res, next) => {
    if (req.path === '/health') {
      next();
      return;
    }
    const now = Date.now();
    const key = `${req.ip}:${res.locals.role ?? 'anonymous'}`;
    const bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      buckets.set(key, { resetAt: now + windowMs, count: 1 });
      next();
      return;
    }
    bucket.count += 1;
    if (bucket.count > max) {
      res.setHeader('Retry-After', String(Math.ceil((bucket.resetAt - now) / 1000)));
      res.status(429).json({ error: 'rate limit exceeded' });
      return;
    }
    next();
  };
}

export function audit(action: string, detail: (req: Request, res: Response) => string = () => '') {
  return (req: Request, res: Response, next: NextFunction): void => {
    res.on('finish', () => {
      const event: AuditEvent = {
        ts: new Date().toISOString(),
        role: (res.locals.role as ApiRole | null) ?? 'viewer',
        principal: (res.locals.principal as string | null) ?? 'anonymous',
        action,
        path: req.originalUrl,
        ok: res.statusCode < 400,
        detail: detail(req, res),
      };
      recordAuditEvent(event);
    });
    next();
  };
}
