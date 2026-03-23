import { Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import { SecurityLoggingService } from '../../application/services/security-logging.service';
import { createRequestFingerprint } from '../../utils/request-fingerprint.util';

type RequestWithFingerprint = Request & {
  securityFingerprint?: ReturnType<typeof createRequestFingerprint>;
  user?: {
    id?: string;
  };
};

@Injectable()
export class RequestFingerprintMiddleware implements NestMiddleware {
  constructor(
    private readonly options: Pick<SecurityModuleOptions, 'trustProxy'> = {
      trustProxy: false,
    },
    private readonly securityLoggingService?: SecurityLoggingService,
  ) {}

  use(request: RequestWithFingerprint, _response: Response, next: NextFunction): void {
    request.securityFingerprint = createRequestFingerprint(request, this.options.trustProxy);

    if (this.options.trustProxy && !request.headers['x-forwarded-for'] && !request.headers['x-real-ip']) {
      void this.securityLoggingService?.log({
        eventType: 'fingerprint.proxy-header-missing',
        severity: 'warn',
        category: 'fingerprint',
        message: `Proxy header missing for IP ${request.securityFingerprint.ip} on ${request.securityFingerprint.method} ${request.securityFingerprint.path}`,
        timestamp: new Date().toISOString(),
        ip: request.securityFingerprint.ip,
        method: request.securityFingerprint.method,
        path: request.securityFingerprint.path,
        route: request.securityFingerprint.route,
        requestId: request.securityFingerprint.requestId,
        metadata: {
          proxyChain: [],
        },
      });
    }

    next();
  }
}
