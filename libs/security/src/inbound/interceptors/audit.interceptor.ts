import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';

import { AuditLogService } from '../../application/services/audit-log.service';

type RequestWithFingerprint = {
  securityFingerprint: {
    ip: string;
    userId?: string;
    route: string;
    path: string;
    method: string;
    userAgent: string;
    requestId?: string;
  };
};

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly auditLogService: AuditLogService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<RequestWithFingerprint>();
    const response = context.switchToHttp().getResponse<{ statusCode: number }>();

    return next.handle().pipe(
      tap(() => {
        const fingerprint = request.securityFingerprint;
        void this.auditLogService.record({
          type: 'POLICY_APPLIED',
          ip: fingerprint.ip,
          userId: fingerprint.userId,
          route: fingerprint.route,
          path: fingerprint.path,
          method: fingerprint.method,
          userAgent: fingerprint.userAgent,
          statusCode: response.statusCode,
          timestamp: new Date().toISOString(),
          metadata: {
            requestId: fingerprint.requestId,
          },
        });
      }),
      catchError((error: Error) => {
        const fingerprint = request.securityFingerprint;
        void this.auditLogService.record({
          type: 'REQUEST_REJECTED',
          ip: fingerprint.ip,
          userId: fingerprint.userId,
          route: fingerprint.route,
          path: fingerprint.path,
          method: fingerprint.method,
          userAgent: fingerprint.userAgent,
          statusCode: response.statusCode,
          timestamp: new Date().toISOString(),
          metadata: {
            requestId: fingerprint.requestId,
            error: error.message,
          },
        });

        return throwError(() => error);
      }),
    );
  }
}
