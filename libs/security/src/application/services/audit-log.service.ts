import type { SecurityStoragePort } from '../ports/security-storage.port';
import { SecurityLoggingService } from './security-logging.service';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { AuditEvent } from '../../types/audit-event.types';

const AUDIT_TTL_MS = 24 * 60 * 60_000;

export class AuditLogService {
  constructor(
    private readonly storage: SecurityStoragePort,
    private readonly options: SecurityModuleOptions,
    private readonly securityLoggingService?: SecurityLoggingService,
  ) {}

  async record(event: AuditEvent): Promise<void> {
    if (this.options.logging.persistAudit) {
      const key = this.storage.buildKey('audit', event.type, event.timestamp, event.ip);
      await this.storage.setJson(key, event, AUDIT_TTL_MS);
    }

    if (this.options.logging.enabled) {
      await this.securityLoggingService?.log({
        eventType: `audit.${event.type.toLowerCase()}`,
        severity: event.statusCode >= 400 ? 'warn' : 'log',
        category: 'audit',
        message: `${event.type} observed from IP ${event.ip} on ${event.method} ${event.path}`,
        timestamp: event.timestamp,
        ip: event.ip,
        userId: event.userId,
        route: event.route,
        path: event.path,
        method: event.method,
        userAgent: event.userAgent,
        statusCode: event.statusCode,
        policy: event.policy,
        score: event.score,
        requestId: typeof event.metadata.requestId === 'string' ? event.metadata.requestId : undefined,
        metadata: event.metadata,
      });
    }
  }
}
