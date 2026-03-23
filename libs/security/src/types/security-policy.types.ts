export type RateLimitKeyBy = 'ip' | 'user' | 'route' | 'ip-route' | 'user-route';

export interface SecurityPolicy {
  name: string;
  keyBy: RateLimitKeyBy;
  limit: number;
  windowMs: number;
  skip?: boolean;
  bodyLimitBytes?: number;
}
