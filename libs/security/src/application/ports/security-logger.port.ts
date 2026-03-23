import type { SecurityLogEntry } from '../../types/security-log-entry.types';

export interface SecurityLoggerPort {
  log(entry: SecurityLogEntry): Promise<void>;
}
