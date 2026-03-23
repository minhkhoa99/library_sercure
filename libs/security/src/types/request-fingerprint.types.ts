export interface RequestFingerprint {
  ip: string;
  method: string;
  route: string;
  path: string;
  userAgent: string;
  userId?: string;
  requestId?: string;
}
