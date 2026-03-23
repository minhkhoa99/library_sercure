import { ExecutionContext, HttpException } from '@nestjs/common';

import { BlocklistGuard } from './blocklist.guard';

describe('BlocklistGuard', () => {
  it('allows request when no block exists', async () => {
    const service = {
      findActiveBlock: jest.fn().mockResolvedValue(null),
    };
    const guard = new BlocklistGuard(service as never);

    await expect(guard.canActivate(createContext())).resolves.toBe(true);
  });

  it('throws 403 when request fingerprint is blocked', async () => {
    const service = {
      findActiveBlock: jest.fn().mockResolvedValue({
        subject: '127.0.0.1',
        subjectType: 'ip',
        reason: 'abuse',
        expiresAt: '2026-03-23T03:00:00.000Z',
      }),
    };
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const guard = new BlocklistGuard(service as never, logger as never);

    await expect(guard.canActivate(createContext())).rejects.toMatchObject({ status: 403 });
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'blocklist.rejected',
        severity: 'error',
        ip: '127.0.0.1',
        message: expect.stringContaining('IP 127.0.0.1'),
        reason: 'abuse',
        subjectType: 'ip',
      }),
    );
  });
});

function createContext(): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => ({
        securityFingerprint: {
          ip: '127.0.0.1',
          userId: 'user-1',
        },
      }),
      getResponse: () => ({}),
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
