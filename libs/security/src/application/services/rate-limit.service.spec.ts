import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { RequestFingerprint } from '../../types/request-fingerprint.types';
import { RateLimitService } from './rate-limit.service';

describe('RateLimitService', () => {
  it('uses global policy when no route override exists', async () => {
    const storage = createStorageMock(2);
    const service = new RateLimitService(storage as never, createOptions());

    const result = await service.checkLimit(createFingerprint(), undefined, 5_000);

    expect(storage.trackSlidingWindow).toHaveBeenCalledWith({
      key: 'sec:rl:ip:127.0.0.1:global',
      member: '5000:POST:/auth/login:req-1',
      now: 5_000,
      windowMs: 60_000,
    });
    expect(result).toEqual({
      allowed: true,
      current: 2,
      limit: 60,
      remaining: 58,
      retryAfterMs: 0,
      scope: 'global',
    });
  });

  it('builds route specific keys from policy key strategy', async () => {
    const storage = createStorageMock(6);
    const service = new RateLimitService(storage as never, createOptions());

    const result = await service.checkLimit(
      createFingerprint(),
      {
        name: 'auth-login',
        keyBy: 'ip-route',
        limit: 5,
        windowMs: 600_000,
      },
      8_000,
    );

    expect(storage.trackSlidingWindow).toHaveBeenCalledWith({
      key: 'sec:rl:ip:127.0.0.1:route:/auth/login',
      member: '8000:POST:/auth/login:req-1',
      now: 8_000,
      windowMs: 600_000,
    });
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBe(600_000);
    expect(result.scope).toBe('auth-login');
  });
});

function createStorageMock(currentCount: number) {
  return {
    buildKey: jest.fn((namespace: string, ...parts: string[]) => ['sec', namespace, ...parts].join(':')),
    trackSlidingWindow: jest.fn().mockResolvedValue(currentCount),
  };
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

function createFingerprint(): RequestFingerprint {
  return {
    ip: '127.0.0.1',
    method: 'POST',
    route: '/auth/login',
    path: '/auth/login',
    userAgent: 'jest',
    userId: 'user-1',
    requestId: 'req-1',
  };
}
