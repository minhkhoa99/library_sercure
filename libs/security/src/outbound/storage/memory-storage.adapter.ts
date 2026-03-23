import {
  SecurityStoragePort,
  SlidingWindowRequest,
} from '../../application/ports/security-storage.port';

interface MemoryStorageAdapterOptions {
  cleanupIntervalMs?: number;
}

export class MemoryStorageAdapter implements SecurityStoragePort {
  private readonly values = new Map<string, string>();
  private readonly sortedSets = new Map<string, Array<{ score: number; member: string }>>();
  private readonly valueExpirations = new Map<string, number>();
  private readonly sortedSetExpirations = new Map<string, number>();
  private readonly cleanupTimer: NodeJS.Timeout;

  constructor(options: MemoryStorageAdapterOptions = {}) {
    const cleanupIntervalMs = options.cleanupIntervalMs ?? 30_000;
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredEntries(Date.now());
    }, cleanupIntervalMs);
    this.cleanupTimer.unref?.();
  }

  buildKey(namespace: string, ...parts: string[]): string {
    return ['sec', namespace, ...parts].join(':');
  }

  async trackSlidingWindow(request: SlidingWindowRequest): Promise<number> {
    this.cleanupExpiredEntries(request.now);
    const current = this.sortedSets.get(request.key) ?? [];
    const cutoff = request.now - request.windowMs;
    const next = current
      .filter((entry) => entry.score > cutoff)
      .concat({ score: request.now, member: request.member });
    this.sortedSets.set(request.key, next);
    this.sortedSetExpirations.set(request.key, request.now + request.windowMs);
    return next.length;
  }

  async incrementAbuseScore(key: string, delta: number, ttlMs: number): Promise<number> {
    this.cleanupExpiredEntries(Date.now());
    const current = Number(this.values.get(key) ?? '0');
    const total = current + delta;
    this.values.set(key, String(total));
    this.valueExpirations.set(key, Date.now() + ttlMs);
    return total;
  }

  async setJson(key: string, value: unknown, ttlMs: number): Promise<void> {
    this.cleanupExpiredEntries(Date.now());
    this.values.set(key, JSON.stringify(value));
    this.valueExpirations.set(key, Date.now() + ttlMs);
  }

  async getJson<T>(key: string): Promise<T | null> {
    this.cleanupExpiredEntries(Date.now());
    const value = this.values.get(key);
    return value ? (JSON.parse(value) as T) : null;
  }

  async isHealthy(): Promise<boolean> {
    return true;
  }

  dispose(): void {
    clearInterval(this.cleanupTimer);
  }

  getInternalSizes(): { values: number; sortedSets: number } {
    return {
      values: this.values.size,
      sortedSets: this.sortedSets.size,
    };
  }

  private cleanupExpiredEntries(now: number): void {
    for (const [key, expiresAt] of this.valueExpirations.entries()) {
      if (expiresAt <= now) {
        this.valueExpirations.delete(key);
        this.values.delete(key);
      }
    }

    for (const [key, expiresAt] of this.sortedSetExpirations.entries()) {
      if (expiresAt <= now) {
        this.sortedSetExpirations.delete(key);
        this.sortedSets.delete(key);
      }
    }
  }
}
