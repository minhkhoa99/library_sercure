import type { RequestFingerprint } from '../types/request-fingerprint.types';

import { resolveClientIp } from './ip.util';

interface RequestLike {
  headers: Record<string, string | string[] | undefined>;
  ip?: string;
  method?: string;
  originalUrl?: string;
  route?: {
    path?: string;
  };
  user?: {
    id?: string;
  };
}

export function createRequestFingerprint(
  request: RequestLike,
  trustProxy: boolean,
): RequestFingerprint {
  const path = normalizePath(request.originalUrl);
  const route = request.route?.path || path;

  return {
    ip: resolveClientIp(request.headers, request.ip, trustProxy),
    method: request.method || 'GET',
    route,
    path,
    userAgent: readHeader(request.headers['user-agent']) || 'unknown',
    userId: request.user?.id,
    requestId: readHeader(request.headers['x-request-id']),
  };
}

function normalizePath(originalUrl: string | undefined): string {
  if (!originalUrl) {
    return '/';
  }

  const [pathname] = originalUrl.split('?');
  return pathname || '/';
}

function readHeader(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}
