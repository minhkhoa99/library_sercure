import 'reflect-metadata';

import {
  RATE_LIMIT_METADATA,
  SECURITY_POLICY_METADATA,
  SKIP_SECURITY_METADATA,
} from '../constants/security.constants';
import { RateLimit } from './rate-limit.decorator';
import { SecurityPolicy } from './security-policy.decorator';
import { SkipSecurity } from './skip-security.decorator';

describe('security decorators', () => {
  it('binds rate limit policy metadata', () => {
    class TestController {
      @RateLimit({
        name: 'auth-login',
        keyBy: 'ip-route',
        limit: 5,
        windowMs: 600_000,
      })
      login(): void {}
    }

    expect(Reflect.getMetadata(RATE_LIMIT_METADATA, TestController.prototype.login)).toEqual({
      name: 'auth-login',
      keyBy: 'ip-route',
      limit: 5,
      windowMs: 600_000,
    });
  });

  it('binds named security policy metadata', () => {
    class TestController {
      @SecurityPolicy('admin-default')
      admin(): void {}
    }

    expect(Reflect.getMetadata(SECURITY_POLICY_METADATA, TestController.prototype.admin)).toBe(
      'admin-default',
    );
  });

  it('binds skip security metadata', () => {
    class TestController {
      @SkipSecurity()
      health(): void {}
    }

    expect(Reflect.getMetadata(SKIP_SECURITY_METADATA, TestController.prototype.health)).toBe(true);
  });
});
