import type { SecurityLoggerPort } from '../../application/ports/security-logger.port';
import type { SecurityLogEntry } from '../../types/security-log-entry.types';

export class NoopSecurityLoggerAdapter implements SecurityLoggerPort {
  async log(_entry: SecurityLogEntry): Promise<void> {
    return undefined;
  }
}
