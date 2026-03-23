import {
  BadRequestException,
  Injectable,
  NestMiddleware,
  PayloadTooLargeException,
} from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import { SecurityLoggingService } from '../../application/services/security-logging.service';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';

type RequestLike = Request & {
  headers: Record<string, string | string[] | undefined>;
  originalUrl?: string;
};

@Injectable()
export class BodyLimitMiddleware implements NestMiddleware {
  constructor(
    private readonly options: Pick<SecurityModuleOptions, 'bodyLimits'>,
    private readonly securityLoggingService?: SecurityLoggingService,
  ) {}

  use(request: RequestLike, _response: Response, next: NextFunction): void {
    this.enforceQueryStringLimit(request.originalUrl);
    this.enforceBodyLimit(request);
    next();
  }

  private enforceQueryStringLimit(originalUrl?: string): void {
    const query = originalUrl?.split('?')[1] ?? '';
    if (query.length > this.options.bodyLimits.queryStringMaxLength) {
      throw new BadRequestException('Query string exceeds configured limit');
    }
  }

  private enforceBodyLimit(request: RequestLike): void {
    const contentType = this.readHeader(request.headers['content-type']);
    const contentLength = Number(this.readHeader(request.headers['content-length']) ?? 0);

    if (!Number.isFinite(contentLength) || contentLength <= 0) {
      return;
    }

    if (contentType?.includes('application/json') && contentLength > this.options.bodyLimits.jsonBytes) {
      void this.securityLoggingService?.log({
        eventType: 'request_rejected.body_too_large',
        severity: 'warn',
        category: 'hardening',
        message: `Body too large from IP unknown on POST ${request.originalUrl?.split('?')[0] ?? '/'}`,
        timestamp: new Date().toISOString(),
        method: 'POST',
        path: request.originalUrl?.split('?')[0] ?? '/',
        metadata: {},
      });
      throw new PayloadTooLargeException('JSON body exceeds configured limit');
    }

    if (
      (contentType?.includes('application/x-www-form-urlencoded') ||
        contentType?.includes('multipart/form-data')) &&
      contentLength > this.options.bodyLimits.formBytes
    ) {
      void this.securityLoggingService?.log({
        eventType: 'request_rejected.body_too_large',
        severity: 'warn',
        category: 'hardening',
        message: `Body too large from IP unknown on POST ${request.originalUrl?.split('?')[0] ?? '/'}`,
        timestamp: new Date().toISOString(),
        method: 'POST',
        path: request.originalUrl?.split('?')[0] ?? '/',
        metadata: {},
      });
      throw new PayloadTooLargeException('Form body exceeds configured limit');
    }
  }

  private readHeader(value: string | string[] | undefined): string | undefined {
    if (Array.isArray(value)) {
      return value[0];
    }

    return value;
  }
}
