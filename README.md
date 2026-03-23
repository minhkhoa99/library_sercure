# lib-sercure

Reusable NestJS security library for app-layer protection with a hexagonal architecture split into inbound adapters, application services, and outbound storage.

## What it provides

- request fingerprinting with `trustProxy` support
- Redis-backed sliding window rate limiting
- IP and user blocklist management with TTL
- abuse detection with suspicion scoring and escalation
- request hardening middleware for body/query/header checks
- structured audit events and interceptor-based logging
- developer decorators and centralized policy registry

## Architecture

The library follows a hexagonal NestJS layout under `libs/security/src`:

- `inbound/`: middleware, guards, interceptors
- `application/`: orchestration services and ports
- `outbound/`: Redis adapter
- `decorators/`: route metadata APIs
- `config/`, `constants/`, `types/`, `utils/`: shared contracts and helpers

## Install

```bash
npm install @nestjs/common @nestjs/core reflect-metadata rxjs class-transformer class-validator ioredis
```

## Quick start

```ts
import { Module } from '@nestjs/common';
import { SecurityModule } from '@lib-sercure/security';

@Module({
  imports: [
    SecurityModule.forRoot({
      trustProxy: true,
      globalRateLimit: {
        keyBy: 'ip',
        limit: 60,
        windowMs: 60_000,
      },
      suspiciousRoutePatterns: ['/admin', '/.env', '/wp-login'],
      policies: {
        'auth-login': {
          name: 'auth-login',
          keyBy: 'ip-route',
          limit: 5,
          windowMs: 10 * 60_000,
        },
      },
    }),
  ],
})
export class AppModule {}
```

## Async configuration

```ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SecurityModule } from '@lib-sercure/security';

@Module({
  imports: [
    ConfigModule.forRoot(),
    SecurityModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        trustProxy: configService.get('TRUST_PROXY') === 'true',
        logging: { enabled: true },
      }),
    }),
  ],
})
export class AppModule {}
```

## Decorators

```ts
import {
  RateLimit,
  SecurityPolicy,
  SkipSecurity,
} from '@lib-sercure/security';
import { Controller, Get, Post } from '@nestjs/common';

@Controller()
export class AuthController {
  @Post('/auth/login')
  @RateLimit({
    name: 'auth-login',
    keyBy: 'ip-route',
    limit: 5,
    windowMs: 10 * 60_000,
  })
  login() {
    return { ok: true };
  }

  @Get('/admin/dashboard')
  @SecurityPolicy('admin-default')
  adminDashboard() {
    return { secure: true };
  }

  @Get('/health')
  @SkipSecurity()
  healthcheck() {
    return { status: 'ok' };
  }
}
```

## Security logging

The library now supports structured attack-focused logging with a default Nest logger adapter and custom override support.

```ts
import {
  NestSecurityLoggerAdapter,
  SecurityLoggerPort,
  SecurityModule,
} from '@lib-sercure/security';
import { ConsoleLogger, Module } from '@nestjs/common';

const defaultSecurityLogger = new NestSecurityLoggerAdapter(
  new ConsoleLogger('SecurityLibrary'),
);

@Module({
  imports: [
    SecurityModule.forRoot({
      trustProxy: true,
      logging: {
        enabled: true,
        verbose: false,
        minLevel: 'warn',
        persistAudit: true,
        includeHeaders: false,
        includeQueryMetadata: false,
        redactFields: ['authorization', 'cookie', 'x-api-key'],
        logger: defaultSecurityLogger,
      },
    }),
  ],
})
export class AppModule {}
```

You can also override the logger with your own adapter:

```ts
class AppSecurityLogger implements SecurityLoggerPort {
  async log(entry) {
    // send to Pino, Winston, OpenTelemetry, SIEM, etc.
  }
}
```

Examples of emitted attack logs:

- `Rate limit exceeded from IP 203.0.113.10 on POST /auth/login`
- `Blocked request from IP 198.51.100.8 due to abuse-score escalation`
- `Suspicious path access from IP 192.0.2.4 on GET /.env`

Important attack-triage fields include:

- `ip`
- `requestId`
- `userId`
- `method`
- `path`
- `route`
- `userAgent`
- `policy`
- `score`
- `reason`
- `retryAfterMs`, `current`, `limit`
- `metadata.matchedPattern`, `metadata.proxyChain`, `metadata.blockExpiresAt`

## Default policies

- `public-default`: `60 req / 60 sec / IP`
- `auth-login`: `5 req / 10 min / IP`
- `otp-send`: `3 req / 15 min / user`
- `upload-default`: `10 req / 10 min / user`
- `admin-default`: `10 req / 60 sec / IP`
- `healthcheck`: lightweight/skip profile

## Redis key strategy

- `sec:rl:ip:{ip}:global`
- `sec:rl:ip:{ip}:route:{route}`
- `sec:block:ip:{ip}`
- `sec:block:user:{userId}`
- `sec:abuse:score:ip:{ip}`
- `sec:abuse:404:ip:{ip}`
- `sec:abuse:auth:user:{userId}`
- `sec:audit:{type}:{timestamp}:{ip}`

TTL is cleanup-driven:

- rate-limit windows expire with policy window
- abuse score expires with `abuseDetection.scoreTtlMs`
- block entries expire with configured block duration
- audit entries expire after 24 hours by default

## Security event schema

Each audit event follows `AuditEvent`:

```ts
type AuditEvent = {
  type:
    | 'RATE_LIMIT'
    | 'BLOCK'
    | 'SUSPICIOUS_ROUTE'
    | 'MALFORMED_REQUEST'
    | 'ABUSE_SCORE'
    | 'REQUEST_REJECTED'
    | 'POLICY_APPLIED';
  ip: string;
  userId?: string;
  route: string;
  path: string;
  method: string;
  userAgent: string;
  score?: number;
  policy?: string;
  statusCode: number;
  timestamp: string;
  metadata: Record<string, unknown>;
};
```

## Verification

```bash
npm test
npm run typecheck
npm run build
```

## Production notes

- enable `trustProxy` only when you actually trust the reverse proxy chain
- Redis is required for production-grade counters and block state; in-memory should stay test-only
- choose rate limits per route carefully to reduce false positives
- audit volume can grow quickly on noisy APIs, so plan retention and downstream log shipping
- security logs intentionally surface the client IP and key attack indicators for incident triage
- this library is app-layer protection only; database and private networking still must be secured separately
