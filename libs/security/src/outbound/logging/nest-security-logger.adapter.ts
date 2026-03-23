import { Logger, type LoggerService } from '@nestjs/common';

import type { SecurityLoggerPort } from '../../application/ports/security-logger.port';
import type { SecurityLogEntry } from '../../types/security-log-entry.types';

export class NestSecurityLoggerAdapter implements SecurityLoggerPort {
  constructor(private readonly logger: LoggerService = new Logger('SecurityLibrary')) {}

  async log(entry: SecurityLogEntry): Promise<void> {
    if (entry.severity === 'error') {
      this.logger.error(entry.message, entry);
      return;
    }

    if (entry.severity === 'warn') {
      this.logger.warn(entry.message, entry);
      return;
    }

    if (entry.severity === 'debug') {
      this.logger.debug?.(entry.message, entry);
      return;
    }

    this.logger.log(entry.message, entry);
  }
}
