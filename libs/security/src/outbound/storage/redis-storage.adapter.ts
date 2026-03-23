import type Redis from 'ioredis';

import {
  SecurityStoragePort,
  SlidingWindowRequest,
} from '../../application/ports/security-storage.port';

type RedisLike = Pick<
  Redis,
  'pipeline' | 'set' | 'get' | 'ping'
>;

type PipelineResult = Array<[Error | null, number]>;

export class RedisStorageAdapter implements SecurityStoragePort {
  constructor(private readonly redis: RedisLike) {}

  buildKey(namespace: string, ...parts: string[]): string {
    return ['sec', namespace, ...parts].join(':');
  }

  async trackSlidingWindow(request: SlidingWindowRequest): Promise<number> {
    const pipeline = this.redis.pipeline();
    const cutoff = request.now - request.windowMs;

    pipeline.zadd(request.key, request.now, request.member);
    pipeline.zremrangebyscore(request.key, 0, cutoff);
    pipeline.zcard(request.key);
    pipeline.pexpire(request.key, request.windowMs);

    const result = (await pipeline.exec()) as PipelineResult;
    return result[2]?.[1] ?? 0;
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
