import { ModuleMetadata, Provider, Type } from '@nestjs/common';

import { DEFAULT_SECURITY_POLICIES } from '../policies/default-security-policies';
import type { SecurityLoggerPort } from '../application/ports/security-logger.port';
import { RateLimitKeyBy, SecurityPolicy } from '../types/security-policy.types';
import type { SecurityLogSeverity } from '../types/security-log-entry.types';

export interface GlobalRateLimitOptions {
  keyBy: RateLimitKeyBy;
  limit: number;
  windowMs: number;
}

export interface BlocklistOptions {
  enabled: boolean;
  baseBlockDurationMs: number;
}

export interface AbuseDetectionOptions {
  enabled: boolean;
  scoreTtlMs: number;
}

export interface BodyLimitsOptions {
  jsonBytes: number;
  formBytes: number;
  queryStringMaxLength: number;
}

export interface SecurityLoggingOptions {
  enabled: boolean;
  verbose: boolean;
  minLevel: SecurityLogSeverity;
  persistAudit: boolean;
  includeHeaders: boolean;
  includeQueryMetadata: boolean;
  redactFields: string[];
  logger?: SecurityLoggerPort;
}

export interface SecurityModuleOptions {
  trustProxy: boolean;
  globalRateLimit: GlobalRateLimitOptions;
  blocklist: BlocklistOptions;
  abuseDetection: AbuseDetectionOptions;
  bodyLimits: BodyLimitsOptions;
  timeoutMs: number;
  policies: Record<string, SecurityPolicy>;
  suspiciousRoutePatterns: string[];
  skipRoutes: string[];
  logging: SecurityLoggingOptions;
}

export interface SecurityModuleAsyncOptions
  extends Pick<ModuleMetadata, 'imports'> {
  inject?: Array<Type<unknown> | string | symbol>;
  useExisting?: Type<SecurityModuleOptionsFactory>;
  useClass?: Type<SecurityModuleOptionsFactory>;
  useFactory?: (...args: unknown[]) =>
    | Promise<Partial<SecurityModuleOptions>>
    | Partial<SecurityModuleOptions>;
  extraProviders?: Provider[];
}

export interface SecurityModuleOptionsFactory {
  createSecurityModuleOptions:
    | (() => Promise<Partial<SecurityModuleOptions>>)
    | (() => Partial<SecurityModuleOptions>);
}

const DEFAULT_OPTIONS: SecurityModuleOptions = {
  trustProxy: false,
  globalRateLimit: {
    keyBy: 'ip',
    limit: 60,
    windowMs: 60_000,
  },
  blocklist: {
    enabled: true,
    baseBlockDurationMs: 15 * 60_000,
  },
  abuseDetection: {
    enabled: true,
    scoreTtlMs: 60 * 60_000,
  },
  bodyLimits: {
    jsonBytes: 100 * 1024,
    formBytes: 256 * 1024,
    queryStringMaxLength: 2048,
  },
  timeoutMs: 15_000,
  policies: DEFAULT_SECURITY_POLICIES,
  suspiciousRoutePatterns: [
    '/admin',
    '/phpmyadmin',
    '/wp-login',
    '/.env',
    '/server-status',
    '/vendor',
    '/.git',
  ],
  skipRoutes: [],
  logging: {
    enabled: true,
    verbose: false,
    minLevel: 'warn',
    persistAudit: true,
    includeHeaders: false,
    includeQueryMetadata: false,
    redactFields: ['authorization', 'cookie', 'set-cookie', 'x-api-key'],
  },
};

export function createSecurityModuleOptions(
  overrides: Partial<SecurityModuleOptions> = {},
): SecurityModuleOptions {
  return {
    ...DEFAULT_OPTIONS,
    ...overrides,
    globalRateLimit: {
      ...DEFAULT_OPTIONS.globalRateLimit,
      ...overrides.globalRateLimit,
    },
    blocklist: {
      ...DEFAULT_OPTIONS.blocklist,
      ...overrides.blocklist,
    },
    abuseDetection: {
      ...DEFAULT_OPTIONS.abuseDetection,
      ...overrides.abuseDetection,
    },
    bodyLimits: {
      ...DEFAULT_OPTIONS.bodyLimits,
      ...overrides.bodyLimits,
    },
    logging: {
      ...DEFAULT_OPTIONS.logging,
      ...overrides.logging,
    },
    policies: {
      ...DEFAULT_OPTIONS.policies,
      ...overrides.policies,
    },
    suspiciousRoutePatterns:
      overrides.suspiciousRoutePatterns ?? DEFAULT_OPTIONS.suspiciousRoutePatterns,
    skipRoutes: overrides.skipRoutes ?? DEFAULT_OPTIONS.skipRoutes,
  };
}
