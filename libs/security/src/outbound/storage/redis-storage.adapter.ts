import type Redis from 'ioredis';

import {
  SecurityStoragePort,
  SlidingWindowRequest,
} from '../../application/ports/security-storage.port';

type RedisLike = Pick<
  Redis,
  'eval' | 'set' | 'get' | 'ping'
>;

const SLIDING_WINDOW_SCRIPT = `
  redis.call("ZADD", KEYS[1], ARGV[1], ARGV[2])
  redis.call("ZREMRANGEBYSCORE", KEYS[1], 0, ARGV[3])
  local count = redis.call("ZCARD", KEYS[1])
  redis.call("PEXPIRE", KEYS[1], ARGV[4])
  return count
`;

const ABUSE_SCORE_INCREMENT_SCRIPT = `
  local score = redis.call("INCRBYFLOAT", KEYS[1], ARGV[1])
  redis.call("PEXPIRE", KEYS[1], ARGV[2])
  return score
`;

export class RedisStorageAdapter implements SecurityStoragePort {
  constructor(private readonly redis: RedisLike) {}

  buildKey(namespace: string, ...parts: string[]): string {
    return ['sec', namespace, ...parts].join(':');
  }

  async trackSlidingWindow(request: SlidingWindowRequest): Promise<number> {
    const cutoff = request.now - request.windowMs;

    return Number(
      await this.redis.eval(
        SLIDING_WINDOW_SCRIPT,
        1,
        request.key,
        request.now,
        request.member,
        cutoff,
        request.windowMs,
      ),
    );
  }

  async incrementAbuseScore(
    key: string,
    delta: number,
    ttlMs: number,
  ): Promise<number> {
    return Number(
      await this.redis.eval(ABUSE_SCORE_INCREMENT_SCRIPT, 1, key, delta, ttlMs),
    );
  }

  async setJson(key: string, value: unknown, ttlMs: number): Promise<void> {
    await this.redis.set(key, JSON.stringify(value), 'PX', ttlMs);
  }

  async getJson<T>(key: string): Promise<T | null> {
    const rawValue = await this.redis.get(key);
    if (!rawValue) {
      return null;
    }

    return JSON.parse(rawValue) as T;
  }

  async isHealthy(): Promise<boolean> {
    return (await this.redis.ping()) === 'PONG';
  }
}
