import type { SecurityStoragePort } from '../ports/security-storage.port';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { RequestFingerprint } from '../../types/request-fingerprint.types';
import type { SecurityPolicy } from '../../types/security-policy.types';

export interface RateLimitDecision {
  allowed: boolean;
  current: number;
  limit: number;
  remaining: number;
  retryAfterMs: number;
  scope: string;
}

export class RateLimitService {
  constructor(
    private readonly storage: SecurityStoragePort,
    private readonly options: SecurityModuleOptions,
  ) {}

  async checkLimit(
    fingerprint: RequestFingerprint,
    policy?: SecurityPolicy,
    now = Date.now(),
  ): Promise<RateLimitDecision> {
    const activePolicy = policy ?? {
      name: 'global',
      ...this.options.globalRateLimit,
    };

    const key = this.storage.buildKey('rl', ...this.resolveScopeParts(fingerprint, activePolicy));
    const current = await this.storage.trackSlidingWindow({
      key,
      member: `${now}:${fingerprint.method}:${fingerprint.route}:${fingerprint.requestId ?? 'na'}`,
      now,
      windowMs: activePolicy.windowMs,
    });
    const allowed = current <= activePolicy.limit;

    return {
      allowed,
      current,
      limit: activePolicy.limit,
      remaining: Math.max(activePolicy.limit - current, 0),
      retryAfterMs: allowed ? 0 : activePolicy.windowMs,
      scope: activePolicy.name,
    };
  }

  private resolveScopeParts(
    fingerprint: RequestFingerprint,
    policy: SecurityPolicy,
  ): string[] {
    switch (policy.keyBy) {
      case 'ip':
        return ['ip', fingerprint.ip, policy.name];
      case 'user':
        return ['user', fingerprint.userId ?? 'anonymous', policy.name];
      case 'route':
        return ['route', fingerprint.route];
      case 'ip-route':
        return ['ip', fingerprint.ip, 'route', fingerprint.route];
      case 'user-route':
        return ['user', fingerprint.userId ?? 'anonymous', 'route', fingerprint.route];
      default:
        return ['ip', fingerprint.ip, policy.name];
    }
  }
}
