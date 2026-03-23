export type AuditEventType =
  | 'RATE_LIMIT'
  | 'BLOCK'
  | 'SUSPICIOUS_ROUTE'
  | 'MALFORMED_REQUEST'
  | 'ABUSE_SCORE'
  | 'REQUEST_REJECTED'
  | 'POLICY_APPLIED';

export interface AuditEvent {
  type: AuditEventType;
  ip: string;
  userId?: string;
  route: string;
  path: string;
  method: string;
  userAgent: string;
  score?: number;
  policy?: string;
  statusCode: number;
  timestamp: string;
  metadata: Record<string, unknown>;
}
