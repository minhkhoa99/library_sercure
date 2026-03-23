import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { AuditEvent } from '../../types/audit-event.types';
import { AuditLogService } from './audit-log.service';

describe('AuditLogService', () => {
  it('writes structured security event into storage with ttl', async () => {
    const storage = {
      buildKey: jest.fn((namespace: string, ...parts: string[]) => ['sec', namespace, ...parts].join(':')),
      setJson: jest.fn().mockResolvedValue(undefined),
    };
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AuditLogService(storage as never, createOptions(), logger as never);
    const event: AuditEvent = {
      type: 'RATE_LIMIT',
      ip: '127.0.0.1',
      route: '/auth/login',
      path: '/auth/login',
      method: 'POST',
      userAgent: 'jest-agent',
      statusCode: 429,
      timestamp: '2026-03-23T04:00:00.000Z',
      metadata: { scope: 'auth-login' },
    };

    await service.record(event);

    expect(storage.setJson).toHaveBeenCalledWith(
      'sec:audit:RATE_LIMIT:2026-03-23T04:00:00.000Z:127.0.0.1',
      event,
      86_400_000,
    );
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'audit.rate_limit',
        ip: '127.0.0.1',
        statusCode: 429,
      }),
    );
  });

  it('can persist audit without emitting runtime log when logging is disabled', async () => {
    const storage = {
      buildKey: jest.fn((namespace: string, ...parts: string[]) => ['sec', namespace, ...parts].join(':')),
      setJson: jest.fn().mockResolvedValue(undefined),
    };
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const service = new AuditLogService(
      storage as never,
      createOptions({ enabled: false, persistAudit: true }),
      logger as never,
    );

    await service.record({
      type: 'BLOCK',
      ip: '127.0.0.1',
      route: '/admin',
      path: '/admin',
      method: 'GET',
      userAgent: 'jest-agent',
      statusCode: 403,
      timestamp: '2026-03-23T04:00:00.000Z',
      metadata: {},
    });

    expect(storage.setJson).toHaveBeenCalled();
    expect(logger.log).not.toHaveBeenCalled();
  });
});

function createOptions(overrides: Partial<SecurityModuleOptions['logging']> = {}): SecurityModuleOptions {
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
      ...overrides,
    },
  };
}
