import { BadRequestException, PayloadTooLargeException } from '@nestjs/common';

import { BodyLimitMiddleware } from './body-limit.middleware';

describe('BodyLimitMiddleware', () => {
  it('rejects json requests that exceed configured body limit', () => {
    const logger = { log: jest.fn().mockResolvedValue(undefined) };
    const middleware = new BodyLimitMiddleware({
      bodyLimits: {
        jsonBytes: 100,
        formBytes: 200,
        queryStringMaxLength: 50,
      },
    }, logger as never);

    expect(() =>
      middleware.use(
        {
          headers: {
            'content-type': 'application/json',
            'content-length': '101',
          },
          originalUrl: '/upload',
        } as never,
        {} as never,
        jest.fn(),
      ),
    ).toThrow(PayloadTooLargeException);
    expect(logger.log).toHaveBeenCalledWith(
      expect.objectContaining({
        eventType: 'request_rejected.body_too_large',
        message: expect.stringContaining('IP'),
      }),
    );
  });

  it('rejects requests with oversized query string', () => {
    const middleware = new BodyLimitMiddleware({
      bodyLimits: {
        jsonBytes: 100,
        formBytes: 200,
        queryStringMaxLength: 5,
      },
    });

    expect(() =>
      middleware.use(
        {
          headers: {},
          originalUrl: '/health?verbose=true',
        } as never,
        {} as never,
        jest.fn(),
      ),
    ).toThrow(BadRequestException);
  });

  it('passes through when request stays within configured limits', () => {
    const next = jest.fn();
    const middleware = new BodyLimitMiddleware({
      bodyLimits: {
        jsonBytes: 100,
        formBytes: 200,
        queryStringMaxLength: 50,
      },
    });

    middleware.use(
      {
        headers: {
          'content-type': 'application/json',
          'content-length': '99',
        },
        originalUrl: '/health?ok=1',
      } as never,
      {} as never,
      next,
    );

    expect(next).toHaveBeenCalledTimes(1);
  });
});
