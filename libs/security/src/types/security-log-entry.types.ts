export type SecurityLogSeverity = 'debug' | 'log' | 'warn' | 'error';

export interface SecurityLogEntry {
  eventType: string;
  severity: SecurityLogSeverity;
  category: string;
  message: string;
  timestamp: string;
  metadata: Record<string, unknown>;
  ip?: string;
  userId?: string;
  route?: string;
  path?: string;
  method?: string;
  userAgent?: string;
  requestId?: string;
  statusCode?: number;
  policy?: string;
  score?: number;
  action?: string;
  reason?: string;
  subjectType?: string;
  retryAfterMs?: number;
  current?: number;
  limit?: number;
}
