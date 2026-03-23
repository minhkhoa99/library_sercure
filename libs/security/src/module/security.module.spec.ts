import { Test } from '@nestjs/testing';

import {
  SECURITY_STORAGE,
  SECURITY_LOGGER,
  SECURITY_MODULE_OPTIONS,
} from '../constants/security.constants';
import { AbuseDetectionService } from '../application/services/abuse-detection.service';
import { BlocklistService } from '../application/services/blocklist.service';
import { SecurityLoggingService } from '../application/services/security-logging.service';
import { PolicyRegistryService } from '../application/services/policy-registry.service';
import { RateLimitService } from '../application/services/rate-limit.service';
import {
  createSecurityModuleOptions,
  type SecurityModuleOptions,
} from '../config/security-module-options.interface';
import { SecurityModule } from './security.module';

describe('SecurityModule', () => {
  it('provides normalized options through forRoot', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        SecurityModule.forRoot({
          trustProxy: true,
          globalRateLimit: {
            keyBy: 'ip',
            limit: 120,
            windowMs: 30_000,
          },
        }),
      ],
    }).compile();

    const options = moduleRef.get<SecurityModuleOptions>(SECURITY_MODULE_OPTIONS);

    expect(options.trustProxy).toBe(true);
    expect(options.globalRateLimit).toEqual({
      keyBy: 'ip',
      limit: 120,
      windowMs: 30_000,
    });
    expect(options.policies['public-default']).toMatchObject({
      limit: 60,
      windowMs: 60_000,
      keyBy: 'ip',
    });
    expect(options.skipRoutes).toEqual([]);
  });

  it('resolves async options through forRootAsync', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        SecurityModule.forRootAsync({
          useFactory: async () => ({
            trustProxy: false,
            logging: {
              enabled: true,
              verbose: false,
              minLevel: 'warn',
              persistAudit: true,
              includeHeaders: false,
              includeQueryMetadata: false,
              redactFields: [],
            },
          }),
        }),
      ],
    }).compile();

    const options = moduleRef.get<SecurityModuleOptions>(SECURITY_MODULE_OPTIONS);

    expect(options).toEqual(
      createSecurityModuleOptions({
        trustProxy: false,
        logging: {
          enabled: true,
          verbose: false,
          minLevel: 'warn',
          persistAudit: true,
          includeHeaders: false,
          includeQueryMetadata: false,
          redactFields: [],
        },
      }),
    );
  });

  it('exports logger token, policy registry, and logging service', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [SecurityModule.forRoot()],
    }).compile();

    expect(moduleRef.get(SECURITY_LOGGER)).toBeDefined();
    expect(moduleRef.get(PolicyRegistryService)).toBeDefined();
    expect(moduleRef.get(SecurityLoggingService)).toBeDefined();
  });

  it('prefers logger from config when no provider override exists', async () => {
    const customLogger = { log: jest.fn().mockResolvedValue(undefined) };
    const moduleRef = await Test.createTestingModule({
      imports: [
        SecurityModule.forRoot({
          logging: {
            enabled: true,
            verbose: false,
            minLevel: 'warn',
            persistAudit: true,
            includeHeaders: false,
            includeQueryMetadata: false,
            redactFields: [],
            logger: customLogger,
          },
        }),
      ],
    }).compile();

    expect(moduleRef.get(SECURITY_LOGGER)).toBe(customLogger);
  });

  it('prefers provider override over config logger', async () => {
    const configLogger = { log: jest.fn().mockResolvedValue(undefined) };
    const providerLogger = { log: jest.fn().mockResolvedValue(undefined) };
    const moduleRef = await Test.createTestingModule({
      imports: [
        SecurityModule.forRoot({
          logging: {
            enabled: true,
            verbose: false,
            minLevel: 'warn',
            persistAudit: true,
            includeHeaders: false,
            includeQueryMetadata: false,
            redactFields: [],
            logger: configLogger,
          },
        }),
      ],
    })
      .overrideProvider(SECURITY_LOGGER)
      .useValue(providerLogger)
      .compile();

    expect(moduleRef.get(SECURITY_LOGGER)).toBe(providerLogger);
  });

  it('resolves core services and storage binding from module configuration', async () => {
    const storage = {
      buildKey: jest.fn(),
      trackSlidingWindow: jest.fn(),
      incrementAbuseScore: jest.fn(),
      setJson: jest.fn(),
      getJson: jest.fn(),
      isHealthy: jest.fn(),
    };

    const moduleRef = await Test.createTestingModule({
      imports: [
        SecurityModule.forRoot({
          storage: storage as never,
        }),
      ],
    }).compile();

    expect(moduleRef.get(SECURITY_STORAGE)).toBe(storage);
    expect(moduleRef.get(RateLimitService)).toBeDefined();
    expect(moduleRef.get(BlocklistService)).toBeDefined();
    expect(moduleRef.get(AbuseDetectionService)).toBeDefined();
  });
});
