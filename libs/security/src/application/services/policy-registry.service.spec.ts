import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import { PolicyRegistryService } from './policy-registry.service';

describe('PolicyRegistryService', () => {
  it('returns default policy by name', () => {
    const service = new PolicyRegistryService(createOptions());

    expect(service.get('public-default')).toMatchObject({
      name: 'public-default',
      keyBy: 'ip',
      limit: 60,
    });
  });

  it('returns custom policy override when provided', () => {
    const service = new PolicyRegistryService(
      createOptions({
        policies: {
          'auth-login': {
            name: 'auth-login',
            keyBy: 'ip-route',
            limit: 3,
            windowMs: 120_000,
          },
        },
      }),
    );

    expect(service.get('auth-login')).toEqual({
      name: 'auth-login',
      keyBy: 'ip-route',
      limit: 3,
      windowMs: 120_000,
    });
  });
});

function createOptions(overrides: Partial<SecurityModuleOptions> = {}): SecurityModuleOptions {
  return {
    trustProxy: false,
    globalRateLimit: { keyBy: 'ip', limit: 60, windowMs: 60_000 },
    blocklist: { enabled: true, baseBlockDurationMs: 900_000 },
    abuseDetection: { enabled: true, scoreTtlMs: 3_600_000 },
    bodyLimits: { jsonBytes: 1024, formBytes: 2048, queryStringMaxLength: 512 },
    timeoutMs: 15_000,
    policies: {
      'public-default': {
        name: 'public-default',
        keyBy: 'ip',
        limit: 60,
        windowMs: 60_000,
      },
      ...overrides.policies,
    },
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
    ...overrides,
  };
}
