import { afterEach, describe, expect, it, vi } from 'vitest';
import type { NextFunction, Request, Response } from 'express';
import {
  apiAuth,
  corsOptions,
  isApiAuthConfigured,
  isUnauthenticatedAccessAllowed,
  resolveApiRole,
  resolveRequestIdentity,
} from '../src/security.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('production security defaults', () => {
  it('fails closed without API credentials in production', () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('ALLOW_INSECURE_NO_AUTH', 'false');
    vi.stubEnv('API_VIEWER_TOKENS', '');
    vi.stubEnv('API_ANALYST_TOKENS', '');
    vi.stubEnv('API_ADMIN_TOKENS', '');

    expect(isApiAuthConfigured(null)).toBe(false);
    expect(isUnauthenticatedAccessAllowed(null)).toBe(false);
    expect(corsOptions()).toMatchObject({ origin: false });
  });

  it('resolves every configured role and permits an explicit development escape hatch', () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('API_VIEWER_TOKENS', 'viewer-token');
    vi.stubEnv('API_ANALYST_TOKENS', 'analyst-token');
    vi.stubEnv('API_ADMIN_TOKENS', 'admin-token');

    expect(resolveApiRole('primary-token', 'primary-token')).toBe('admin');
    expect(resolveApiRole('viewer-token', null)).toBe('viewer');
    expect(resolveApiRole('analyst-token', null)).toBe('analyst');
    expect(resolveApiRole('admin-token', null)).toBe('admin');

    vi.stubEnv('API_VIEWER_TOKENS', '');
    vi.stubEnv('API_ANALYST_TOKENS', '');
    vi.stubEnv('API_ADMIN_TOKENS', '');
    vi.stubEnv('ALLOW_INSECURE_NO_AUTH', 'true');
    expect(isUnauthenticatedAccessAllowed(null)).toBe(true);
  });

  it('accepts identity headers only when signed by the trusted authentication proxy', () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('AUTH_PROXY_ENABLED', 'true');
    vi.stubEnv('AUTH_PROXY_SHARED_SECRET', 'proxy-secret');
    vi.stubEnv('API_VIEWER_TOKENS', '');
    vi.stubEnv('API_ANALYST_TOKENS', '');
    vi.stubEnv('API_ADMIN_TOKENS', '');
    const request = {
      headers: {
        'x-auth-proxy-secret': 'proxy-secret',
        'x-auth-user': 'analyst@example.test',
        'x-auth-role': 'analyst',
      },
    } as unknown as Request;

    expect(isApiAuthConfigured(null)).toBe(true);
    expect(resolveRequestIdentity(request, null)).toEqual({
      role: 'analyst',
      principal: 'analyst@example.test',
      mechanism: 'trusted-proxy',
    });
    request.headers['x-auth-proxy-secret'] = 'wrong-secret';
    expect(resolveRequestIdentity(request, null)).toBeNull();
  });

  it('allows a valid identity when trusted proxy auth is the only configured mechanism', () => {
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('AUTH_PROXY_ENABLED', 'true');
    vi.stubEnv('AUTH_PROXY_SHARED_SECRET', 'proxy-secret');
    vi.stubEnv('API_VIEWER_TOKENS', '');
    vi.stubEnv('API_ANALYST_TOKENS', '');
    vi.stubEnv('API_ADMIN_TOKENS', '');
    const request = {
      path: '/api/intel',
      headers: {
        'x-auth-proxy-secret': 'proxy-secret',
        'x-auth-user': 'viewer@example.test',
        'x-auth-role': 'viewer',
      },
    } as unknown as Request;
    const status = vi.fn().mockReturnThis();
    const json = vi.fn().mockReturnThis();
    const response = { locals: {}, status, json } as unknown as Response;
    const next = vi.fn() as unknown as NextFunction;
    const middleware = apiAuth(null);

    middleware.attachRole(request, response, next);
    expect(response.locals).toMatchObject({
      role: 'viewer',
      principal: 'viewer@example.test',
      authMechanism: 'trusted-proxy',
    });
    middleware.requireToken(request, response, next);

    expect(status).not.toHaveBeenCalled();
    expect(json).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledTimes(2);
  });
});
