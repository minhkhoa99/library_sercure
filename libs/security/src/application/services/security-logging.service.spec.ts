import type { SecurityLoggerPort } from '../ports/security-logger.port';
import type { SecurityLogEntry } from '../../types/security-log-entry.types';
import { SecurityLoggingService } from './security-logging.service';

describe('SecurityLoggingService', () => {
  it('filters out entries below configured min level', async () => {
    const logger = createLoggerMock();
    const service = new SecurityLoggingService(logger, {
      enabled: true,
      minLevel: 'warn',
      redactFields: ['authorization'],
      includeHeaders: false,
      includeQueryMetadata: false,
      persistAudit: true,
      verbose: false,
    });

    await service.log(createEntry({ severity: 'debug' }));

    expect(logger.log).not.toHaveBeenCalled();
  });

  it('redacts sensitive fields and keeps attack message with ip method path', async () => {
    const logger = createLoggerMock();
    const service = new SecurityLoggingService(logger, {
      enabled: true,
      minLevel: 'warn',
      redactFields: ['authorization', 'cookie'],
      includeHeaders: true,
      includeQueryMetadata: false,
      persistAudit: true,
      verbose: false,
    });

    await service.log(
      createEntry({
        metadata: {
          headers: {
            authorization: 'Bearer secret',
            cookie: 'sid=secret',
            'x-request-id': 'req-1',
          },
        },
      }),
    );

    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        message: 'Rate limit exceeded from IP 203.0.113.10 on POST /auth/login',
        metadata: {
          headers: {
            authorization: '[REDACTED]',
            cookie: '[REDACTED]',
            'x-request-id': 'req-1',
          },
        },
      }),
    );
  });

  it('drops headers and query metadata unless enabled', async () => {
    const logger = createLoggerMock();
    const service = new SecurityLoggingService(logger, {
      enabled: true,
      minLevel: 'warn',
      redactFields: [],
      includeHeaders: false,
      includeQueryMetadata: false,
      persistAudit: true,
      verbose: false,
    });

    await service.log(
      createEntry({
        metadata: {
          headers: { 'user-agent': 'jest' },
          query: { token: 'abc' },
        },
      }),
    );

    expect(logger.log).toHaveBeenCalledWith(expect.objectContaining({ metadata: {} }));
  });

  it('emits verbose fingerprint event only when verbose mode is enabled', async () => {
    const logger = createLoggerMock();
    const service = new SecurityLoggingService(logger, {
      enabled: true,
      minLevel: 'debug',
      redactFields: [],
      includeHeaders: false,
      includeQueryMetadata: false,
      persistAudit: true,
      verbose: false,
    });

    await service.log(createEntry({ eventType: 'fingerprint.resolved', severity: 'debug' }));

    expect(logger.log).not.toHaveBeenCalled();
  });
});

function createLoggerMock(): jest.Mocked<SecurityLoggerPort> {
  return {
    log: jest.fn().mockResolvedValue(undefined),
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
