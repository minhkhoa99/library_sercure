export function resolveClientIp(
  headers: Record<string, string | string[] | undefined>,
  fallbackIp: string | undefined,
  trustProxy: boolean | number,
): string {
  if (trustProxy) {
    const forwardedFor = readHeader(headers['x-forwarded-for']);
    if (forwardedFor) {
      const forwardedChain = forwardedFor
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => isUsableIp(entry));

      if (forwardedChain.length > 0) {
        return selectTrustedClientIp(forwardedChain, trustProxy);
      }
    }

    const realIp = readHeader(headers['x-real-ip']);
    if (realIp && isUsableIp(realIp.trim())) {
      return realIp.trim();
    }
  }

  return fallbackIp?.trim() || 'unknown';
}

function selectTrustedClientIp(
  forwardedChain: string[],
  trustProxy: boolean | number,
): string {
  if (forwardedChain.length === 1) {
    return forwardedChain[0];
  }

  if (trustProxy === true) {
    return forwardedChain[forwardedChain.length - 1];
  }

  const trustedHopCount = typeof trustProxy === 'number' ? trustProxy : 1;
  const trustedHopIndex = forwardedChain.length - trustedHopCount;
  if (trustedHopIndex >= 0) {
    return forwardedChain[trustedHopIndex];
  }

  return forwardedChain[0];
}

function isUsableIp(value: string): boolean {
  if (!value) {
    return false;
  }

  const normalized = value.trim().toLowerCase();
  return normalized !== 'unknown' && normalized !== 'bad-value';
}

function readHeader(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}
