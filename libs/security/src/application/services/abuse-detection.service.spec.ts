import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { RequestFingerprint } from '../../types/request-fingerprint.types';
import { AbuseDetectionService } from './abuse-detection.service';

describe('AbuseDetectionService', () => {
  it('adds score for suspicious paths', async () => {
    const storage = createStorageMock();
    const blocklist = createBlocklistMock();
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AbuseDetectionService(
      storage as never,
      blocklist as never,
      createOptions(),
      logger as never,
    );

    const result = await service.analyze({
      fingerprint: createFingerprint({ path: '/.env', route: '/.env' }),
      statusCode: 404,
      now: 10_000,
    });

    expect(result.triggeredRules).toContain('suspicious-path');
    expect(result.scoreDelta).toBe(5);
    expect(storage.incrementAbuseScore).toHaveBeenCalledWith(
      'sec:abuse:score:ip:127.0.0.1',
      5,
      3_600_000,
    );
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'abuse.suspicious_path',
        ip: '127.0.0.1',
        metadata: expect.objectContaining({ matchedPattern: '/.env' }),
      }),
    );
  });

  it('adds score when 404 burst threshold is exceeded', async () => {
    const storage = createStorageMock({ slidingCount: 12 });
    const blocklist = createBlocklistMock();
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AbuseDetectionService(
      storage as never,
      blocklist as never,
      createOptions(),
      logger as never,
    );

    const result = await service.analyze({
      fingerprint: createFingerprint(),
      statusCode: 404,
      now: 20_000,
    });

    expect(result.triggeredRules).toContain('404-burst');
    expect(result.scoreDelta).toBe(2);
    expect(storage.trackSlidingWindow).toHaveBeenCalledWith({
      key: 'sec:abuse:404:ip:127.0.0.1',
      member: '20000:404:/auth/login:req-1',
      now: 20_000,
      windowMs: 60_000,
    });
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'abuse.404_burst' }),
    );
  });

  it('escalates to blocklist when score reaches blocking threshold', async () => {
    const storage = createStorageMock({
      existingScore: 18,
      slidingCount: 12,
    });
    const blocklist = createBlocklistMock();
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AbuseDetectionService(
      storage as never,
      blocklist as never,
      createOptions(),
      logger as never,
    );

    const result = await service.analyze({
      fingerprint: createFingerprint(),
      statusCode: 404,
      now: 30_000,
    });

    expect(result.totalScore).toBe(20);
    expect(blocklist.blockIp).toHaveBeenCalledWith(
      '127.0.0.1',
      'abuse-score:20',
      900_000,
    );
    expect(result.action).toBe('block');
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'abuse.escalated', score: 20 }),
    );
  });

  it('tracks 401/403 burst against user identity when available', async () => {
    const storage = createStorageMock({ slidingCount: 7 });
    const blocklist = createBlocklistMock();
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AbuseDetectionService(
      storage as never,
      blocklist as never,
      createOptions(),
      logger as never,
    );

    const result = await service.analyze({
      fingerprint: createFingerprint({ userId: 'user-1' }),
      statusCode: 401,
      now: 40_000,
    });

    expect(result.triggeredRules).toContain('401-403-burst');
    expect(result.scoreDelta).toBe(3);
    expect(storage.trackSlidingWindow).toHaveBeenCalledWith({
      key: 'sec:abuse:auth:user:user-1',
      member: '40000:401:/auth/login:req-1',
      now: 40_000,
      windowMs: 300_000,
    });
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'abuse.401_403_burst' }),
    );
  });
});

function createStorageMock(options?: {
  existingScore?: number;
  slidingCount?: number;
}) {
  return {
    buildKey: jest.fn((namespace: string, ...parts: string[]) => ['sec', namespace, ...parts].join(':')),
    getJson: jest.fn().mockImplementation(async (key: string) => {
      if (key === 'sec:abuse:score:ip:127.0.0.1') {
        return { score: options?.existingScore ?? 0 };
      }

      return null;
    }),
    setJson: jest.fn().mockResolvedValue(undefined),
    incrementAbuseScore: jest
      .fn()
      .mockImplementation(async (_key: string, delta: number) => (options?.existingScore ?? 0) + delta),
    trackSlidingWindow: jest.fn().mockResolvedValue(options?.slidingCount ?? 0),
  };
}

function createBlocklistMock() {
  return {
    blockIp: jest.fn().mockResolvedValue(undefined),
    blockUser: jest.fn().mockResolvedValue(undefined),
  };
}

function createOptions(): SecurityModuleOptions {
  return {
    trustProxy: false,
    globalRateLimit: { keyBy: 'ip', limit: 60, windowMs: 60_000 },
    blocklist: { enabled: true, baseBlockDurationMs: 900_000 },
    abuseDetection: { enabled: true, scoreTtlMs: 3_600_000 },
    bodyLimits: { jsonBytes: 1024, formBytes: 2048, queryStringMaxLength: 512 },
    timeoutMs: 15_000,
    policies: {},
    suspiciousRoutePatterns: ['/.env', '/admin', '/wp-login'],
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

function createFingerprint(
  overrides: Partial<RequestFingerprint> = {},
): RequestFingerprint {
  return {
    ip: '127.0.0.1',
    method: 'POST',
    route: '/auth/login',
    path: '/auth/login',
    userAgent: 'jest',
    requestId: 'req-1',
    ...overrides,
  };
}
