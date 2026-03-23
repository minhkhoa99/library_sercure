import { SecurityPolicy } from '../types/security-policy.types';

export const DEFAULT_SECURITY_POLICIES: Record<string, SecurityPolicy> = {
  'public-default': {
    name: 'public-default',
    keyBy: 'ip',
    limit: 60,
    windowMs: 60_000,
  },
  'auth-login': {
    name: 'auth-login',
    keyBy: 'ip',
    limit: 5,
    windowMs: 10 * 60_000,
  },
  'otp-send': {
    name: 'otp-send',
    keyBy: 'user',
    limit: 3,
    windowMs: 15 * 60_000,
  },
  'upload-default': {
    name: 'upload-default',
    keyBy: 'user',
    limit: 10,
    windowMs: 10 * 60_000,
    bodyLimitBytes: 64 * 1024,
  },
  'admin-default': {
    name: 'admin-default',
    keyBy: 'ip',
    limit: 10,
    windowMs: 60_000,
  },
  healthcheck: {
    name: 'healthcheck',
    keyBy: 'ip',
    limit: 300,
    windowMs: 60_000,
    skip: true,
  },
};
