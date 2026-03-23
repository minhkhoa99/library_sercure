import { Inject, Injectable } from '@nestjs/common';

import { BlocklistService } from './blocklist.service';
import type { SecurityStoragePort } from '../ports/security-storage.port';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import {
  SECURITY_MODULE_OPTIONS,
  SECURITY_STORAGE,
} from '../../constants/security.constants';
import type {
  AbuseDetectionInput,
  AbuseDetectionResult,
  AbuseScoreState,
} from '../../types/abuse-detection.types';
import { SecurityLoggingService } from './security-logging.service';

@Injectable()
export class AbuseDetectionService {
  constructor(
    @Inject(SECURITY_STORAGE) private readonly storage: SecurityStoragePort,
    private readonly blocklistService: BlocklistService,
    @Inject(SECURITY_MODULE_OPTIONS) private readonly options: SecurityModuleOptions,
    private readonly securityLoggingService?: SecurityLoggingService,
  ) {}

  async analyze(input: AbuseDetectionInput): Promise<AbuseDetectionResult> {
    const now = input.now ?? Date.now();
    const triggeredRules: string[] = [];
    let scoreDelta = 0;

    if (this.isSuspiciousPath(input.fingerprint.path)) {
      triggeredRules.push('suspicious-path');
      scoreDelta += 5;
      await this.securityLoggingService?.log({
        eventType: 'abuse.suspicious_path',
        severity: 'warn',
        category: 'abuse-detection',
        message: `Suspicious path access from IP ${input.fingerprint.ip} on ${input.fingerprint.method} ${input.fingerprint.path}`,
        timestamp: new Date(now).toISOString(),
        ip: input.fingerprint.ip,
        method: input.fingerprint.method,
        path: input.fingerprint.path,
        route: input.fingerprint.route,
        requestId: input.fingerprint.requestId,
        metadata: {
          matchedPattern: this.options.suspiciousRoutePatterns.find((pattern) =>
            input.fingerprint.path.startsWith(pattern),
          ),
        },
      });
    }

    if (input.statusCode === 404) {
      const count = await this.storage.trackSlidingWindow({
        key: this.storage.buildKey('abuse', '404', 'ip', input.fingerprint.ip),
        member: `${now}:404:${input.fingerprint.route}:${input.fingerprint.requestId ?? 'na'}`,
        now,
        windowMs: 60_000,
      });

      if (count >= 10) {
        triggeredRules.push('404-burst');
        scoreDelta += 2;
        await this.securityLoggingService?.log({
          eventType: 'abuse.404_burst',
          severity: 'warn',
          category: 'abuse-detection',
          message: `404 burst detected from IP ${input.fingerprint.ip} on ${input.fingerprint.method} ${input.fingerprint.path}`,
          timestamp: new Date(now).toISOString(),
          ip: input.fingerprint.ip,
          method: input.fingerprint.method,
          path: input.fingerprint.path,
          route: input.fingerprint.route,
          requestId: input.fingerprint.requestId,
          metadata: {},
        });
      }
    }

    if (input.statusCode === 401 || input.statusCode === 403) {
      const subjectType = input.fingerprint.userId ? 'user' : 'ip';
      const subject = input.fingerprint.userId ?? input.fingerprint.ip;
      const count = await this.storage.trackSlidingWindow({
        key: this.storage.buildKey('abuse', 'auth', subjectType, subject),
        member: `${now}:${input.statusCode}:${input.fingerprint.route}:${input.fingerprint.requestId ?? 'na'}`,
        now,
        windowMs: 300_000,
      });

      if (count >= 5) {
        triggeredRules.push('401-403-burst');
        scoreDelta += 3;
        await this.securityLoggingService?.log({
          eventType: 'abuse.401_403_burst',
          severity: 'warn',
          category: 'abuse-detection',
          message: `401/403 burst detected from IP ${input.fingerprint.ip} on ${input.fingerprint.method} ${input.fingerprint.path}`,
          timestamp: new Date(now).toISOString(),
          ip: input.fingerprint.ip,
          userId: input.fingerprint.userId,
          method: input.fingerprint.method,
          path: input.fingerprint.path,
          route: input.fingerprint.route,
          requestId: input.fingerprint.requestId,
          metadata: {},
        });
      }
    }

    const scoreKey = this.storage.buildKey('abuse', 'score', 'ip', input.fingerprint.ip);
    const totalScore = await this.storage.incrementAbuseScore(
      scoreKey,
      scoreDelta,
      this.options.abuseDetection.scoreTtlMs,
    );

    let action: AbuseDetectionResult['action'] = 'allow';

    if (totalScore >= 40) {
      action = 'block';
      await this.blocklistService.blockIp(
        input.fingerprint.ip,
        `abuse-score:${totalScore}`,
        60 * 60_000,
      );
      await this.securityLoggingService?.log({
        eventType: 'abuse.escalated',
        severity: 'error',
        category: 'abuse-detection',
        message: `Blocked request source from IP ${input.fingerprint.ip} on ${input.fingerprint.method} ${input.fingerprint.path}`,
        timestamp: new Date(now).toISOString(),
        ip: input.fingerprint.ip,
        method: input.fingerprint.method,
        path: input.fingerprint.path,
        route: input.fingerprint.route,
        requestId: input.fingerprint.requestId,
        score: totalScore,
        action,
        metadata: {},
      });
    } else if (totalScore >= 20) {
      action = 'block';
      await this.blocklistService.blockIp(
        input.fingerprint.ip,
        `abuse-score:${totalScore}`,
        this.options.blocklist.baseBlockDurationMs,
      );
      await this.securityLoggingService?.log({
        eventType: 'abuse.escalated',
        severity: 'error',
        category: 'abuse-detection',
        message: `Blocked request source from IP ${input.fingerprint.ip} on ${input.fingerprint.method} ${input.fingerprint.path}`,
        timestamp: new Date(now).toISOString(),
        ip: input.fingerprint.ip,
        method: input.fingerprint.method,
        path: input.fingerprint.path,
        route: input.fingerprint.route,
        requestId: input.fingerprint.requestId,
        score: totalScore,
        action,
        metadata: {},
      });
    } else if (totalScore >= 10) {
      action = 'throttle';
    }

    return {
      triggeredRules,
      scoreDelta,
      totalScore,
      action,
    };
  }

  private isSuspiciousPath(path: string): boolean {
    return this.options.suspiciousRoutePatterns.some((pattern) => path.startsWith(pattern));
  }
}
