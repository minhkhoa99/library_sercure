import { BadRequestException, Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import { SecurityLoggingService } from '../../application/services/security-logging.service';

type RequestLike = Request & {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
};

const ALLOWED_CONTENT_TYPES = [
  'application/json',
  'application/x-www-form-urlencoded',
  'multipart/form-data',
  'text/plain',
];

@Injectable()
export class HeaderSanityMiddleware implements NestMiddleware {
  constructor(private readonly securityLoggingService?: SecurityLoggingService) {}

  use(request: RequestLike, _response: Response, next: NextFunction): void {
    const userAgent = this.readHeader(request.headers['user-agent']);
    if (userAgent !== undefined && userAgent.trim().length === 0) {
      void this.securityLoggingService?.log({
        eventType: 'request_rejected.invalid_header',
        severity: 'warn',
        category: 'hardening',
        message: 'Invalid header from IP unknown on GET /',
        timestamp: new Date().toISOString(),
        method: request.method ?? 'GET',
        path: '/',
        metadata: {},
      });
      throw new BadRequestException('User-Agent header must not be empty');
    }

    if ((request.method ?? 'GET') !== 'GET') {
      const contentType = this.readHeader(request.headers['content-type']);
      if (contentType && !ALLOWED_CONTENT_TYPES.some((entry) => contentType.includes(entry))) {
        void this.securityLoggingService?.log({
          eventType: 'request_rejected.invalid_header',
          severity: 'warn',
          category: 'hardening',
          message: `Invalid header from IP unknown on ${request.method ?? 'GET'} /`,
          timestamp: new Date().toISOString(),
          method: request.method ?? 'GET',
          path: '/',
          metadata: {},
        });
        throw new BadRequestException('Unsupported content-type header');
      }
    }

    next();
  }

  private readHeader(value: string | string[] | undefined): string | undefined {
    if (Array.isArray(value)) {
      return value[0];
    }

    return value;
  }
}
