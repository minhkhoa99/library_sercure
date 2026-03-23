import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import { BlocklistService } from './blocklist.service';

describe('BlocklistService', () => {
  it('stores an ip block with configured ttl', async () => {
    const storage = createStorageMock();
    const service = new BlocklistService(storage as never, createOptions());

    await service.blockIp('127.0.0.1', 'rate-limit', 300_000);

    expect(storage.setJson).toHaveBeenCalledWith(
      'sec:block:ip:127.0.0.1',
      expect.objectContaining({
        subject: '127.0.0.1',
        subjectType: 'ip',
        reason: 'rate-limit',
      }),
      300_000,
    );
  });

  it('returns active ip or user block', async () => {
    const storage = createStorageMock({
      'sec:block:ip:127.0.0.1': null,
      'sec:block:user:user-1': {
        subject: 'user-1',
        subjectType: 'user',
        reason: 'abuse',
        expiresAt: '2026-03-23T03:00:00.000Z',
      },
    });
    const service = new BlocklistService(storage as never, createOptions());

    const result = await service.findActiveBlock('127.0.0.1', 'user-1');

    expect(result).toEqual({
      subject: 'user-1',
      subjectType: 'user',
      reason: 'abuse',
      expiresAt: '2026-03-23T03:00:00.000Z',
    });
  });
});

function createStorageMock(initial: Record<string, unknown> = {}) {
  return {
    buildKey: jest.fn((namespace: string, ...parts: string[]) => ['sec', namespace, ...parts].join(':')),
    setJson: jest.fn().mockResolvedValue(undefined),
    getJson: jest.fn().mockImplementation(async (key: string) => initial[key] ?? null),
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
