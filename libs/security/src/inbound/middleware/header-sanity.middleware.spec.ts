import { BadRequestException } from '@nestjs/common';

import { HeaderSanityMiddleware } from './header-sanity.middleware';

describe('HeaderSanityMiddleware', () => {
  it('rejects requests with empty user-agent', () => {
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const middleware = new HeaderSanityMiddleware(logger as never);

    expect(() =>
      middleware.use(
        {
          method: 'GET',
          headers: {
            'user-agent': '',
          },
        } as never,
        {} as never,
        jest.fn(),
      ),
    ).toThrow(BadRequestException);
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'request_rejected.invalid_header',
      }),
    );
  });

  it('rejects requests with invalid content-type header', () => {
    const middleware = new HeaderSanityMiddleware();

    expect(() =>
      middleware.use(
        {
          method: 'POST',
          headers: {
            'user-agent': 'jest-agent',
            'content-type': 'application/x-malicious',
          },
        } as never,
        {} as never,
        jest.fn(),
      ),
    ).toThrow(BadRequestException);
  });

  it('allows sane headers', () => {
    const next = jest.fn();
    const middleware = new HeaderSanityMiddleware();

    middleware.use(
      {
        method: 'POST',
        headers: {
          'user-agent': 'jest-agent',
          'content-type': 'application/json',
        },
      } as never,
      {} as never,
      next,
    );

    expect(next).toHaveBeenCalledTimes(1);
  });
});
