import type { RequestFingerprint } from './request-fingerprint.types';

export interface AbuseScoreState {
  score: number;
  updatedAt?: string;
}

export interface AbuseDetectionInput {
  fingerprint: RequestFingerprint;
  statusCode: number;
  now?: number;
}

export interface AbuseDetectionResult {
  triggeredRules: string[];
  scoreDelta: number;
  totalScore: number;
  action: 'allow' | 'throttle' | 'block';
}
