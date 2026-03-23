export interface SlidingWindowRequest {
  key: string;
  now: number;
  windowMs: number;
  member: string;
}

export interface SecurityStoragePort {
  buildKey(namespace: string, ...parts: string[]): string;
  trackSlidingWindow(request: SlidingWindowRequest): Promise<number>;
  incrementAbuseScore(key: string, delta: number, ttlMs: number): Promise<number>;
  setJson(key: string, value: unknown, ttlMs: number): Promise<void>;
  getJson<T>(key: string): Promise<T | null>;
  isHealthy(): Promise<boolean>;
}
