import { RedisStorageAdapter } from './redis-storage.adapter';

describe('RedisStorageAdapter', () => {
  it('builds namespaced keys consistently', () => {
    const adapter = new RedisStorageAdapter(createRedisMock() as never);

    expect(adapter.buildKey('rl', 'ip', '127.0.0.1', 'global')).toBe(
      'sec:rl:ip:127.0.0.1:global',
    );
    expect(adapter.buildKey('block', 'user', 'u-1')).toBe('sec:block:user:u-1');
  });

  it('tracks sliding window counts through a redis lua script', async () => {
    const redis = createRedisMock({ evalResult: 3 });
    const adapter = new RedisStorageAdapter(redis as never);

    const count = await adapter.trackSlidingWindow({
      key: adapter.buildKey('rl', 'ip', '127.0.0.1', 'global'),
      now: 5_000,
      windowMs: 60_000,
      member: 'entry-1',
    });

    expect(count).toBe(3);
    expect(redis.evalCalls).toEqual([
      [
        expect.stringContaining('ZADD'),
        1,
        'sec:rl:ip:127.0.0.1:global',
        5000,
        'entry-1',
        -55000,
        60000,
      ],
    ]);
  });

  it('increments abuse score atomically with ttl retention', async () => {
    const redis = createRedisMock({ evalResult: 14 });
    const adapter = new RedisStorageAdapter(redis as never);

    const totalScore = await adapter.incrementAbuseScore(
      'sec:abuse:score:ip:127.0.0.1',
      2,
      3_600_000,
    );

    expect(totalScore).toBe(14);
    expect(redis.evalCalls[0]).toEqual([
      expect.stringContaining('INCRBYFLOAT'),
      1,
      'sec:abuse:score:ip:127.0.0.1',
      2,
      3_600_000,
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

function createRedisMock(options?: { evalResult?: number }) {
  const evalCalls: Array<[string, ...Array<string | number>]> = [];
  const setCalls: Array<[string, string, 'PX', number]> = [];

  return {
    evalCalls,
    setCalls,
    eval: jest.fn().mockImplementation(async (...args: [string, ...Array<string | number>]) => {
      evalCalls.push(args);
      return options?.evalResult ?? 0;
    }),
    set: jest.fn().mockImplementation(async (...args: [string, string, 'PX', number]) => {
      setCalls.push(args);
      return 'OK';
    }),
    ping: jest.fn().mockResolvedValue('PONG'),
  };
}
