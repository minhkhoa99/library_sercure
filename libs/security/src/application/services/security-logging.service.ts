import type { SecurityLoggerPort } from '../ports/security-logger.port';
import type { SecurityLoggingOptions } from '../../config/security-module-options.interface';
import type { SecurityLogEntry, SecurityLogSeverity } from '../../types/security-log-entry.types';

const LEVEL_ORDER: Record<SecurityLogSeverity, number> = {
  debug: 10,
  log: 20,
  warn: 30,
  error: 40,
};

export class SecurityLoggingService {
  constructor(
    private readonly logger: SecurityLoggerPort,
    private readonly options: SecurityLoggingOptions,
  ) {}

  async log(entry: SecurityLogEntry): Promise<void> {
    if (!this.options.enabled) {
      return;
    }

    if (entry.eventType === 'fingerprint.resolved' && !this.options.verbose) {
      return;
    }

    if (LEVEL_ORDER[entry.severity] < LEVEL_ORDER[this.options.minLevel]) {
      return;
    }

    const sanitized = this.sanitizeEntry(entry);
    await this.logger.log(sanitized);
  }

  private sanitizeEntry(entry: SecurityLogEntry): SecurityLogEntry {
    const metadata = { ...entry.metadata };

    if (!this.options.includeHeaders) {
      delete metadata.headers;
    } else if (metadata.headers && typeof metadata.headers === 'object') {
      metadata.headers = this.redactRecord(metadata.headers as Record<string, unknown>);
    }

    if (!this.options.includeQueryMetadata) {
      delete metadata.query;
    }

    return {
      ...entry,
      message: this.ensureOperationalMessage(entry.message, entry),
      metadata,
    };
  }

  private redactRecord(record: Record<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(
      Object.entries(record).map(([key, value]) => [
        key,
        this.options.redactFields.includes(key.toLowerCase()) ? '[REDACTED]' : value,
      ]),
    );
  }

  private ensureOperationalMessage(message: string, entry: SecurityLogEntry): string {
    if (!this.isAttackEvent(entry.eventType)) {
      return message;
    }

    const ip = entry.ip ?? 'unknown';
    const method = entry.method ?? 'UNKNOWN';
    const path = entry.path ?? '/';

    if (message.includes(ip) && message.includes(method) && message.includes(path)) {
      return message;
    }

    return `${message} from IP ${ip} on ${method} ${path}`;
  }

  private isAttackEvent(eventType: string): boolean {
    return [
      'rate_limit.exceeded',
      'blocklist.rejected',
      'abuse.rule_triggered',
      'abuse.escalated',
      'request_rejected.body_too_large',
      'request_rejected.invalid_header',
    ].includes(eventType);
  }
}
