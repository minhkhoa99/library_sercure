import { ExecutionContext, HttpException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import {
  RATE_LIMIT_METADATA,
  SECURITY_POLICY_METADATA,
} from '../../constants/security.constants';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { RequestFingerprint } from '../../types/request-fingerprint.types';
import { RateLimitGuard } from './rate-limit.guard';

describe('RateLimitGuard', () => {
  it('allows request when service result is allowed', async () => {
    const service = {
      checkLimit: jest.fn().mockResolvedValue({ allowed: true }),
    };
    const reflector = new Reflector();
    const guard = new RateLimitGuard(reflector, service as never, createOptions());
    const context = createContext();

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(service.checkLimit).toHaveBeenCalledWith(
      context.switchToHttp().getRequest().securityFingerprint,
      undefined,
    );
  });

  it('throws 429 when route specific policy exceeds the limit', async () => {
    const service = {
      checkLimit: jest.fn().mockResolvedValue({
        allowed: false,
        retryAfterMs: 600000,
        limit: 5,
        current: 6,
      }),
    };
    const reflector = new Reflector();
    const handler = () => undefined;
    Reflect.defineMetadata(RATE_LIMIT_METADATA, {
      name: 'auth-login',
      keyBy: 'ip-route',
      limit: 5,
      windowMs: 600000,
    }, handler);

    const guard = new RateLimitGuard(reflector, service as never, createOptions());
    const context = createContext(handler);

    await expect(guard.canActivate(context)).rejects.toMatchObject({ status: 429 });
    expect(service.checkLimit).toHaveBeenCalledWith(
      context.switchToHttp().getRequest().securityFingerprint,
      {
        name: 'auth-login',
        keyBy: 'ip-route',
        limit: 5,
        windowMs: 600000,
      },
    );
  });

  it('logs attack details when rate limit is exceeded', async () => {
    const service = {
      checkLimit: jest.fn().mockResolvedValue({
        allowed: false,
        retryAfterMs: 600000,
        limit: 5,
        current: 6,
      }),
    };
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const reflector = new Reflector();
    const guard = new RateLimitGuard(reflector, service as never, createOptions(), undefined, logger as never);

    await expect(guard.canActivate(createContext())).rejects.toMatchObject({ status: 429 });
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'rate_limit.exceeded',
        ip: '127.0.0.1',
        method: 'POST',
        path: '/auth/login',
        retryAfterMs: 600000,
        current: 6,
        limit: 5,
      }),
    );
  });

  it('resolves named policy through registry metadata', async () => {
    const service = {
      checkLimit: jest.fn().mockResolvedValue({ allowed: true }),
    };
    const policyRegistry = {
      get: jest.fn().mockReturnValue({
        name: 'admin-default',
        keyBy: 'ip',
        limit: 10,
        windowMs: 60_000,
      }),
    };
    const reflector = new Reflector();
    const handler = () => undefined;
    Reflect.defineMetadata(SECURITY_POLICY_METADATA, 'admin-default', handler);

    const guard = new RateLimitGuard(
      reflector,
      service as never,
      createOptions(),
      policyRegistry as never,
    );

    await expect(guard.canActivate(createContext(handler))).resolves.toBe(true);
    expect(policyRegistry.get).toHaveBeenCalledWith('admin-default');
    expect(service.checkLimit).toHaveBeenCalledWith(
      createContext(handler).switchToHttp().getRequest().securityFingerprint,
      {
        name: 'admin-default',
        keyBy: 'ip',
        limit: 10,
        windowMs: 60_000,
      },
    );
  });
});

function createContext(handler: () => void = () => undefined): ExecutionContext {
  const request = {
    securityFingerprint: {
      ip: '127.0.0.1',
      method: 'POST',
      route: '/auth/login',
      path: '/auth/login',
      userAgent: 'jest',
      requestId: 'req-1',
    } satisfies RequestFingerprint,
  };

  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => ({}),
      getNext: () => undefined,
    }),
    getHandler: () => handler,
    getClass: () => class TestController {},
    getArgs: () => [],
    getArgByIndex: () => undefined,
    switchToRpc: () => ({ getData: () => undefined, getContext: () => undefined }),
    switchToWs: () => ({ getClient: () => undefined, getData: () => undefined }),
    getType: () => 'http',
  } as unknown as ExecutionContext;
}

function createOptions(): SecurityModuleOptions {
  return {
    trustProxy: false,
    globalRateLimit: {
      keyBy: 'ip',
      limit: 60,
      windowMs: 60_000,
    },
    blocklist: {
      enabled: true,
      baseBlockDurationMs: 900_000,
    },
    abuseDetection: {
      enabled: true,
      scoreTtlMs: 3_600_000,
    },
    bodyLimits: {
      jsonBytes: 1024,
      formBytes: 2048,
      queryStringMaxLength: 512,
    },
    timeoutMs: 15_000,
    policies: {},
    suspiciousRoutePatterns: [],
    skipRoutes: [],
    logging: {
      enabled: true,
      verbose: false,
      minLevel: 'warn',
      persistAudit: true,
      includeHeaders: false,
      includeQueryMetadata: false,
      redactFields: [],
    },
  };
}
