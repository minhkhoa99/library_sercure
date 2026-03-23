import { CanActivate, ExecutionContext, HttpException, Injectable } from '@nestjs/common';

import { BlocklistService } from '../../application/services/blocklist.service';
import { SecurityLoggingService } from '../../application/services/security-logging.service';

type RequestWithFingerprint = {
  securityFingerprint: {
    ip: string;
    userId?: string;
  };
};

@Injectable()
export class BlocklistGuard implements CanActivate {
  constructor(
    private readonly blocklistService: BlocklistService,
    private readonly securityLoggingService?: SecurityLoggingService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<RequestWithFingerprint>();
    const entry = await this.blocklistService.findActiveBlock(
      request.securityFingerprint.ip,
      request.securityFingerprint.userId,
    );

    if (entry) {
      await this.securityLoggingService?.log({
        eventType: 'blocklist.rejected',
        severity: 'error',
        category: 'blocklist',
        message: `Blocked request from IP ${request.securityFingerprint.ip} on UNKNOWN / due to ${entry.reason}`,
        timestamp: new Date().toISOString(),
        ip: request.securityFingerprint.ip,
        userId: request.securityFingerprint.userId,
        method: 'UNKNOWN',
        path: '/',
        reason: entry.reason,
        subjectType: entry.subjectType,
        metadata: {
          blockExpiresAt: entry.expiresAt,
        },
      });

      throw new HttpException(
        {
          message: 'Request blocked',
          reason: entry.reason,
          expiresAt: entry.expiresAt,
          subjectType: entry.subjectType,
        },
        403,
      );
    }

    return true;
  }
}
