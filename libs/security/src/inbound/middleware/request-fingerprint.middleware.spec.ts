import { RequestFingerprintMiddleware } from './request-fingerprint.middleware';

describe('RequestFingerprintMiddleware', () => {
  it('prefers forwarded headers when trustProxy is enabled', () => {
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const middleware = new RequestFingerprintMiddleware({ trustProxy: true }, logger as never);
    const request = {
      headers: {
        'x-forwarded-for': '198.51.100.10, 10.0.0.2',
        'user-agent': 'jest-agent',
        'x-request-id': 'req-1',
      },
      ip: '10.0.0.2',
      method: 'POST',
      originalUrl: '/auth/login?next=/home',
      route: { path: '/auth/login' },
      user: { id: 'user-1' },
    } as any;

    const next = jest.fn();

    middleware.use(request, {} as never, next);

    expect(request.securityFingerprint).toEqual({
      ip: '198.51.100.10',
      method: 'POST',
      route: '/auth/login',
      path: '/auth/login',
      userAgent: 'jest-agent',
      userId: 'user-1',
      requestId: 'req-1',
    });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it('logs proxy warning when trustProxy is enabled without forwarded headers', () => {
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const middleware = new RequestFingerprintMiddleware({ trustProxy: true }, logger as never);

    middleware.use(
      {
        headers: { 'user-agent': 'jest-agent' },
        ip: '203.0.113.15',
        method: 'GET',
        originalUrl: '/health',
      } as any,
      {} as never,
      jest.fn(),
    );

    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'fingerprint.proxy-header-missing',
        ip: '203.0.113.15',
      }),
    );
  });

  it('falls back to request ip when trustProxy is disabled', () => {
    const middleware = new RequestFingerprintMiddleware({ trustProxy: false });
    const request = {
      headers: {
        'x-forwarded-for': '198.51.100.10',
      },
      ip: '203.0.113.15',
      method: 'GET',
      originalUrl: '/health?full=true',
      route: undefined,
    } as any;

    middleware.use(request, {} as never, jest.fn());

    expect(request.securityFingerprint.ip).toBe('203.0.113.15');
    expect(request.securityFingerprint.path).toBe('/health');
    expect(request.securityFingerprint.route).toBe('/health');
    expect(request.securityFingerprint.userAgent).toBe('unknown');
  });
});
