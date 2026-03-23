import { CallHandler, ExecutionContext } from '@nestjs/common';
import { lastValueFrom, of, throwError } from 'rxjs';

import { AuditInterceptor } from './audit.interceptor';

describe('AuditInterceptor', () => {
  it('records structured event from request fingerprint and response status', async () => {
    const auditLogService = {
      record: jest.fn().mockResolvedValue(undefined),
    };
    const interceptor = new AuditInterceptor(auditLogService as never);
    const context = createContext();
    const next: CallHandler = {
      handle: () => of({ ok: true }),
    };

    await lastValueFrom(interceptor.intercept(context, next));

    expect(auditLogService.record).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'POLICY_APPLIED',
        ip: '127.0.0.1',
        route: '/auth/login',
        path: '/auth/login',
        method: 'POST',
        userAgent: 'jest-agent',
        statusCode: 201,
        metadata: {
          requestId: 'req-1',
        },
      }),
    );
  });

  it('records failure event on exception path', async () => {
    const auditLogService = {
      record: jest.fn().mockResolvedValue(undefined),
    };
    const interceptor = new AuditInterceptor(auditLogService as never);
    const context = createContext(429);
    const next: CallHandler = {
      handle: () => throwError(() => new Error('boom')),
    };

    await expect(lastValueFrom(interceptor.intercept(context, next))).rejects.toThrow('boom');
    expect(auditLogService.record).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'REQUEST_REJECTED',
        statusCode: 429,
      }),
    );
  });
});

function createContext(statusCode = 201): ExecutionContext {
  const request = {
    securityFingerprint: {
      ip: '127.0.0.1',
      method: 'POST',
      route: '/auth/login',
      path: '/auth/login',
      userAgent: 'jest-agent',
      requestId: 'req-1',
    },
  };
  const response = {
    statusCode,
  };

  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => response,
      getNext: () => undefined,
    }),
    getHandler: () => () => undefined,
    getClass: () => class TestController {},
    getArgs: () => [],
    getArgByIndex: () => undefined,
    switchToRpc: () => ({ getData: () => undefined, getContext: () => undefined }),
    switchToWs: () => ({ getClient: () => undefined, getData: () => undefined }),
    getType: () => 'http',
  } as unknown as ExecutionContext;
}
