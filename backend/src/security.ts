import type { NextFunction, Request, Response } from 'express';
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
    typeof req.query.token === 'string' ? req.query.token : undefined,
  );
}

function roleMap(primaryToken: string | null): Map<string, ApiRole> {
  const map = new Map<string, ApiRole>();
  if (primaryToken) map.set(primaryToken, 'admin');
  for (const token of splitCsv(process.env.API_VIEWER_TOKENS)) map.set(token, 'viewer');
  for (const token of splitCsv(process.env.API_ANALYST_TOKENS)) map.set(token, 'analyst');
  for (const token of splitCsv(process.env.API_ADMIN_TOKENS)) map.set(token, 'admin');
  return map;
}

export function apiAuth(primaryToken: string | null): {
  attachRole: (req: Request, res: Response, next: NextFunction) => void;
  requireToken: (req: Request, res: Response, next: NextFunction) => void;
  requireRole: (role: ApiRole) => (req: Request, res: Response, next: NextFunction) => void;
} {
  const roles = roleMap(primaryToken);
  const authEnabled = roles.size > 0;
  return {
    attachRole(req, res, next) {
      const role = roles.get(tokenOf(req)) ?? (authEnabled ? null : 'admin');
      res.locals.role = role;
      next();
    },
    requireToken(req, res, next) {
      if (req.path === '/health') {
        next();
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
  if (origins.length === 0) return {};
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
