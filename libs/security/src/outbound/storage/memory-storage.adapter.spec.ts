import { MemoryStorageAdapter } from './memory-storage.adapter';

describe('MemoryStorageAdapter', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-03-23T06:00:00.000Z'));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('evicts expired json values during cleanup interval', async () => {
    const adapter = new MemoryStorageAdapter({ cleanupIntervalMs: 1000 });

    await adapter.setJson('sec:block:ip:127.0.0.1', { blocked: true }, 500);
    expect(await adapter.getJson('sec:block:ip:127.0.0.1')).toEqual({ blocked: true });

    jest.advanceTimersByTime(1500);

    await expect(adapter.getJson('sec:block:ip:127.0.0.1')).resolves.toBeNull();
    expect(adapter.getInternalSizes()).toEqual({ values: 0, sortedSets: 0 });
    adapter.dispose();
  });

  it('evicts expired sliding window sets after ttl passes', async () => {
    const adapter = new MemoryStorageAdapter({ cleanupIntervalMs: 1000 });

    await adapter.trackSlidingWindow({
      key: 'sec:rl:ip:127.0.0.1:global',
      now: Date.now(),
      windowMs: 500,
      member: 'entry-1',
    });

    expect(adapter.getInternalSizes()).toEqual({ values: 0, sortedSets: 1 });

    jest.advanceTimersByTime(1500);

    await adapter.trackSlidingWindow({
      key: 'sec:rl:ip:127.0.0.2:global',
      now: Date.now(),
      windowMs: 500,
      member: 'entry-2',
    });

    expect(adapter.getInternalSizes()).toEqual({ values: 0, sortedSets: 1 });
    adapter.dispose();
  });
});
