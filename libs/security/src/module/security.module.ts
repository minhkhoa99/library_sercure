import { DynamicModule, Logger, Module, Provider } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { SecurityLoggerPort } from '../application/ports/security-logger.port';
import { PolicyRegistryService } from '../application/services/policy-registry.service';
import { SecurityLoggingService } from '../application/services/security-logging.service';
import { SECURITY_MODULE_OPTIONS } from '../constants/security.constants';
import { SECURITY_LOGGER } from '../constants/security.constants';
import {
  createSecurityModuleOptions,
  SecurityModuleAsyncOptions,
  SecurityModuleOptions,
  SecurityModuleOptionsFactory,
} from '../config/security-module-options.interface';
import { NestSecurityLoggerAdapter } from '../outbound/logging/nest-security-logger.adapter';
import { NoopSecurityLoggerAdapter } from '../outbound/logging/noop-security-logger.adapter';

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
        this.createSecurityLoggerProvider(),
        this.createSecurityLoggingServiceProvider(),
        this.createPolicyRegistryProvider(),
        Reflector,
      ],
      exports: [
        SECURITY_MODULE_OPTIONS,
        SECURITY_LOGGER,
        SecurityLoggingService,
        PolicyRegistryService,
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
        this.createSecurityLoggerProvider(),
        this.createSecurityLoggingServiceProvider(),
        this.createPolicyRegistryProvider(),
        Reflector,
        ...(options.extraProviders ?? []),
      ],
      exports: [
        SECURITY_MODULE_OPTIONS,
        SECURITY_LOGGER,
        SecurityLoggingService,
        PolicyRegistryService,
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
