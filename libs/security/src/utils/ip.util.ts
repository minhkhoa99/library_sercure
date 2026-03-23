export function resolveClientIp(
  headers: Record<string, string | string[] | undefined>,
  fallbackIp: string | undefined,
  trustProxy: boolean,
): string {
  if (trustProxy) {
    const forwardedFor = readHeader(headers['x-forwarded-for']);
    if (forwardedFor) {
      return forwardedFor.split(',')[0].trim();
    }

    const realIp = readHeader(headers['x-real-ip']);
    if (realIp) {
      return realIp.trim();
    }
  }

  return fallbackIp?.trim() || 'unknown';
}

function readHeader(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}
