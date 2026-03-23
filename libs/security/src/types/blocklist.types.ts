export interface BlockEntry {
  subject: string;
  subjectType: 'ip' | 'user';
  reason: string;
  expiresAt: string;
}
