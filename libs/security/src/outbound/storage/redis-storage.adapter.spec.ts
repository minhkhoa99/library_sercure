import { RedisStorageAdapter } from './redis-storage.adapter';

describe('RedisStorageAdapter', () => {
  it('builds namespaced keys consistently', () => {
    const adapter = new RedisStorageAdapter(createRedisMock() as never);

    expect(adapter.buildKey('rl', 'ip', '127.0.0.1', 'global')).toBe(
      'sec:rl:ip:127.0.0.1:global',
    );
    expect(adapter.buildKey('block', 'user', 'u-1')).toBe('sec:block:user:u-1');
  });

  it('tracks sliding window counts through a redis pipeline', async () => {
    const redis = createRedisMock({ execResult: [[null, 1], [null, 0], [null, 3], [null, 1]] });
    const adapter = new RedisStorageAdapter(redis as never);

    const count = await adapter.trackSlidingWindow({
      key: adapter.buildKey('rl', 'ip', '127.0.0.1', 'global'),
      now: 5_000,
      windowMs: 60_000,
      member: 'entry-1',
    });

    expect(count).toBe(3);
    expect(redis.pipelineOps).toEqual([
      ['zadd', 'sec:rl:ip:127.0.0.1:global', 5000, 'entry-1'],
      ['zremrangebyscore', 'sec:rl:ip:127.0.0.1:global', 0, -55000],
      ['zcard', 'sec:rl:ip:127.0.0.1:global'],
      ['pexpire', 'sec:rl:ip:127.0.0.1:global', 60000],
    ]);
  });

  it('stores json state with ttl and reports health', async () => {
    const redis = createRedisMock();
    const adapter = new RedisStorageAdapter(redis as never);

    await adapter.setJson('sec:block:ip:127.0.0.1', { active: true }, 900000);

    expect(redis.setCalls).toEqual([
      ['sec:block:ip:127.0.0.1', JSON.stringify({ active: true }), 'PX', 900000],
    ]);
    await expect(adapter.isHealthy()).resolves.toBe(true);
  });
});

function createRedisMock(options?: { execResult?: Array<[null, number]> }) {
  const pipelineOps: Array<[string, ...Array<string | number>]> = [];
  const setCalls: Array<[string, string, 'PX', number]> = [];

  return {
    pipelineOps,
    setCalls,
    pipeline() {
      return {
        zadd(key: string, score: number, member: string) {
          pipelineOps.push(['zadd', key, score, member]);
          return this;
        },
        zremrangebyscore(key: string, min: number, max: number) {
          pipelineOps.push(['zremrangebyscore', key, min, max]);
          return this;
        },
        zcard(key: string) {
          pipelineOps.push(['zcard', key]);
          return this;
        },
        pexpire(key: string, ttlMs: number) {
          pipelineOps.push(['pexpire', key, ttlMs]);
          return this;
        },
        exec: jest.fn().mockResolvedValue(options?.execResult ?? []),
      };
    },
    set: jest.fn().mockImplementation(async (...args: [string, string, 'PX', number]) => {
      setCalls.push(args);
      return 'OK';
    }),
    ping: jest.fn().mockResolvedValue('PONG'),
  };
}
