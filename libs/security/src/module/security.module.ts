import { DynamicModule, Logger, Module, Provider } from '@nestjs/common';
import { APP_GUARD, Reflector } from '@nestjs/core';

import { SecurityLoggerPort } from '../application/ports/security-logger.port';
import { SecurityStoragePort } from '../application/ports/security-storage.port';
import { PolicyRegistryService } from '../application/services/policy-registry.service';
import { SecurityLoggingService } from '../application/services/security-logging.service';
import { RateLimitService } from '../application/services/rate-limit.service';
import { BlocklistService } from '../application/services/blocklist.service';
import { AbuseDetectionService } from '../application/services/abuse-detection.service';
import { AuditLogService } from '../application/services/audit-log.service';
import { RateLimitGuard } from '../inbound/guards/rate-limit.guard';
import { BlocklistGuard } from '../inbound/guards/blocklist.guard';
import { SECURITY_MODULE_OPTIONS } from '../constants/security.constants';
import { SECURITY_LOGGER } from '../constants/security.constants';
import { SECURITY_STORAGE } from '../constants/security.constants';
import {
  createSecurityModuleOptions,
  SecurityModuleAsyncOptions,
  SecurityModuleOptions,
  SecurityModuleOptionsFactory,
} from '../config/security-module-options.interface';
import { NestSecurityLoggerAdapter } from '../outbound/logging/nest-security-logger.adapter';
import { NoopSecurityLoggerAdapter } from '../outbound/logging/noop-security-logger.adapter';
import { MemoryStorageAdapter } from '../outbound/storage/memory-storage.adapter';

@Module({})
export class SecurityModule {
  static forRoot(options: Partial<SecurityModuleOptions> = {}): DynamicModule {
    const optionsProvider = {
      provide: SECURITY_MODULE_OPTIONS,
      useValue: createSecurityModuleOptions(options),
    };

    return {
      module: SecurityModule,
      providers: [
        optionsProvider,
        this.createSecurityStorageProvider(),
        this.createSecurityLoggerProvider(),
        this.createSecurityLoggingServiceProvider(),
        this.createPolicyRegistryProvider(),
        Reflector,
        RateLimitService,
        BlocklistService,
        AbuseDetectionService,
        AuditLogService,
        {
          provide: APP_GUARD,
          useClass: RateLimitGuard,
        },
        {
          provide: APP_GUARD,
          useClass: BlocklistGuard,
        },
      ],
      exports: [
        SECURITY_MODULE_OPTIONS,
        SECURITY_STORAGE,
        SECURITY_LOGGER,
        SecurityLoggingService,
        PolicyRegistryService,
        RateLimitService,
        BlocklistService,
        AbuseDetectionService,
        AuditLogService,
      ],
      global: true,
    };
  }

  static forRootAsync(options: SecurityModuleAsyncOptions): DynamicModule {
    return {
      module: SecurityModule,
      imports: options.imports,
      providers: [
        ...this.createAsyncProviders(options),
        this.createSecurityStorageProvider(),
        this.createSecurityLoggerProvider(),
        this.createSecurityLoggingServiceProvider(),
        this.createPolicyRegistryProvider(),
        Reflector,
        RateLimitService,
        BlocklistService,
        AbuseDetectionService,
        AuditLogService,
        {
          provide: APP_GUARD,
          useClass: RateLimitGuard,
        },
        {
          provide: APP_GUARD,
          useClass: BlocklistGuard,
        },
        ...(options.extraProviders ?? []),
      ],
      exports: [
        SECURITY_MODULE_OPTIONS,
        SECURITY_STORAGE,
        SECURITY_LOGGER,
        SecurityLoggingService,
        PolicyRegistryService,
        RateLimitService,
        BlocklistService,
        AbuseDetectionService,
        AuditLogService,
      ],
      global: true,
    };
  }

  private static createSecurityLoggerProvider(): Provider {
    return {
      provide: SECURITY_LOGGER,
      useFactory: (moduleOptions: SecurityModuleOptions): SecurityLoggerPort => {
        if (moduleOptions.logging.logger) {
          return moduleOptions.logging.logger;
        }

        if (!moduleOptions.logging.enabled) {
          return new NoopSecurityLoggerAdapter();
        }

        return new NestSecurityLoggerAdapter(new Logger('SecurityLibrary'));
      },
      inject: [SECURITY_MODULE_OPTIONS],
    };
  }

  private static createSecurityStorageProvider(): Provider {
    return {
      provide: SECURITY_STORAGE,
      useFactory: (moduleOptions: SecurityModuleOptions): SecurityStoragePort =>
        moduleOptions.storage ?? new MemoryStorageAdapter(),
      inject: [SECURITY_MODULE_OPTIONS],
    };
  }

  private static createSecurityLoggingServiceProvider(): Provider {
    return {
      provide: SecurityLoggingService,
      useFactory: (
        logger: SecurityLoggerPort,
        moduleOptions: SecurityModuleOptions,
      ) => new SecurityLoggingService(logger, moduleOptions.logging),
      inject: [SECURITY_LOGGER, SECURITY_MODULE_OPTIONS],
    };
  }

  private static createPolicyRegistryProvider(): Provider {
    return {
      provide: PolicyRegistryService,
      useFactory: (moduleOptions: SecurityModuleOptions) =>
        new PolicyRegistryService(moduleOptions),
      inject: [SECURITY_MODULE_OPTIONS],
    };
  }

  private static createAsyncProviders(
    options: SecurityModuleAsyncOptions,
  ): Provider[] {
    if (options.useFactory) {
      return [
        {
          provide: SECURITY_MODULE_OPTIONS,
          useFactory: async (...args: unknown[]) =>
            createSecurityModuleOptions(await options.useFactory!(...args)),
          inject: options.inject ?? [],
        },
      ];
    }

    const inject = [options.useExisting ?? options.useClass].filter(
      (value): value is NonNullable<typeof value> => value !== undefined,
    );

    const asyncOptionsProvider: Provider = {
      provide: SECURITY_MODULE_OPTIONS,
      useFactory: async (factory: SecurityModuleOptionsFactory) =>
        createSecurityModuleOptions(
          await factory.createSecurityModuleOptions(),
        ),
      inject,
    };

    if (options.useClass) {
      return [
        asyncOptionsProvider,
        {
          provide: options.useClass,
          useClass: options.useClass,
        },
      ];
    }

    return [asyncOptionsProvider];
  }
}
