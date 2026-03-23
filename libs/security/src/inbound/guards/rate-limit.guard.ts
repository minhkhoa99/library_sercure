import { CanActivate, ExecutionContext, HttpException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { RATE_LIMIT_METADATA } from '../../constants/security.constants';
import { SECURITY_POLICY_METADATA } from '../../constants/security.constants';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { SecurityPolicy } from '../../types/security-policy.types';
import { RateLimitService } from '../../application/services/rate-limit.service';
import { PolicyRegistryService } from '../../application/services/policy-registry.service';
import { SecurityLoggingService } from '../../application/services/security-logging.service';

type RequestWithFingerprint = {
  securityFingerprint: {
    ip: string;
    method: string;
    route: string;
    path: string;
    userAgent: string;
    userId?: string;
    requestId?: string;
  };
};

@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly rateLimitService: RateLimitService,
    private readonly _options: SecurityModuleOptions,
    private readonly policyRegistry?: PolicyRegistryService,
    private readonly securityLoggingService?: SecurityLoggingService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithFingerprint>();
    const inlinePolicy = this.reflector.getAllAndOverride<SecurityPolicy | undefined>(
      RATE_LIMIT_METADATA,
      [context.getHandler(), context.getClass()],
    );
    const namedPolicy = this.reflector.getAllAndOverride<string | undefined>(
      SECURITY_POLICY_METADATA,
      [context.getHandler(), context.getClass()],
    );
    const policy = inlinePolicy ?? (namedPolicy ? this.policyRegistry?.get(namedPolicy) : undefined);
    const decision = await this.rateLimitService.checkLimit(
      request.securityFingerprint,
      policy,
    );

    if (!decision.allowed) {
      await this.securityLoggingService?.log({
        eventType: 'rate_limit.exceeded',
        severity: 'warn',
        category: 'rate-limit',
        message: `Rate limit exceeded from IP ${request.securityFingerprint.ip} on ${request.securityFingerprint.method} ${request.securityFingerprint.path}`,
        timestamp: new Date().toISOString(),
        ip: request.securityFingerprint.ip,
        userId: request.securityFingerprint.userId,
        method: request.securityFingerprint.method,
        path: request.securityFingerprint.path,
        route: request.securityFingerprint.route,
        requestId: request.securityFingerprint.requestId,
        retryAfterMs: decision.retryAfterMs,
        current: decision.current,
        limit: decision.limit,
        policy: decision.scope,
        metadata: {},
      });

      throw new HttpException(
        {
          message: 'Rate limit exceeded',
          limit: decision.limit,
          current: decision.current,
          retryAfterMs: decision.retryAfterMs,
          scope: decision.scope,
        },
        429,
      );
    }

    return true;
  }
}
