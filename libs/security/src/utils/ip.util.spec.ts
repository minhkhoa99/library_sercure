import { resolveClientIp } from './ip.util';

describe('resolveClientIp', () => {
  it('uses fallback ip when trustProxy is disabled', () => {
    const ip = resolveClientIp(
      {
        'x-forwarded-for': '1.1.1.1, 8.8.8.8',
      },
      '203.0.113.10',
      false,
    );

    expect(ip).toBe('203.0.113.10');
  });

  it('uses rightmost usable forwarded ip when trustProxy is true', () => {
    const ip = resolveClientIp(
      {
        'x-forwarded-for': '1.1.1.1, 8.8.8.8, 10.0.0.2',
      },
      '10.0.0.2',
      true,
    );

    expect(ip).toBe('10.0.0.2');
  });

  it('supports trusted hop indexing from the right side', () => {
    const ip = resolveClientIp(
      {
        'x-forwarded-for': '8.8.8.8, 1.1.1.1, 172.16.0.1',
      },
      '172.16.0.1',
      2,
    );

    expect(ip).toBe('1.1.1.1');
  });

  it('ignores malformed or empty forwarded chain entries', () => {
    const ip = resolveClientIp(
      {
        'x-forwarded-for': ' , unknown, 1.1.1.1 ',
      },
      '10.0.0.2',
      true,
    );

    expect(ip).toBe('1.1.1.1');
  });

  it('falls back safely when forwarded header is unusable', () => {
    const ip = resolveClientIp(
      {
        'x-forwarded-for': 'unknown, bad-value',
        'x-real-ip': '198.51.100.8',
      },
      '10.0.0.2',
      true,
    );

    expect(ip).toBe('198.51.100.8');
  });

  it('resists simple spoofing when a client injects a fake leftmost ip', () => {
    const ip = resolveClientIp(
      {
        'x-forwarded-for': '8.8.8.8, 172.16.0.1',
      },
      '172.16.0.1',
      true,
    );

    expect(ip).toBe('172.16.0.1');
  });
});
