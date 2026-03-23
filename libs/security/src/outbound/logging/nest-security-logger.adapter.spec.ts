import type { LoggerService } from '@nestjs/common';

import type { SecurityLogEntry } from '../../types/security-log-entry.types';
import { NestSecurityLoggerAdapter } from './nest-security-logger.adapter';
import { NoopSecurityLoggerAdapter } from './noop-security-logger.adapter';

describe('NestSecurityLoggerAdapter', () => {
  it('routes warn entries to Nest logger with structured payload', async () => {
    const logger = createLoggerMock();
    const adapter = new NestSecurityLoggerAdapter(logger);

    await adapter.log(createEntry({ severity: 'warn' }));

    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining('IP 203.0.113.10'),
      expect.objectContaining({
        ip: '203.0.113.10',
        path: '/auth/login',
        method: 'POST',
      }),
    );
  });

  it('routes error entries to Nest logger error method', async () => {
    const logger = createLoggerMock();
    const adapter = new NestSecurityLoggerAdapter(logger);

    await adapter.log(createEntry({ severity: 'error' }));

    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('POST /auth/login'),
      expect.objectContaining({ severity: 'error' }),
    );
  });
});

describe('NoopSecurityLoggerAdapter', () => {
  it('accepts entries without side effects', async () => {
    const adapter = new NoopSecurityLoggerAdapter();

    await expect(adapter.log(createEntry())).resolves.toBeUndefined();
  });
});

function createLoggerMock(): jest.Mocked<LoggerService> {
  return {
    log: jest.fn(),
    error: jest.fn(),
    warn: jest.fn(),
    debug: jest.fn(),
    verbose: jest.fn(),
    fatal: jest.fn(),
    setLogLevels: jest.fn(),
  };
}

function createEntry(overrides: Partial<SecurityLogEntry> = {}): SecurityLogEntry {
  return {
    eventType: 'rate_limit.exceeded',
    severity: 'warn',
    category: 'rate-limit',
    message: 'Rate limit exceeded from IP 203.0.113.10 on POST /auth/login',
    timestamp: '2026-03-23T05:00:00.000Z',
    metadata: {},
    ip: '203.0.113.10',
    method: 'POST',
    path: '/auth/login',
    route: '/auth/login',
    ...overrides,
  };
}
