import type { SecurityStoragePort } from '../ports/security-storage.port';
import type { SecurityModuleOptions } from '../../config/security-module-options.interface';
import type { BlockEntry } from '../../types/blocklist.types';

export class BlocklistService {
  constructor(
    private readonly storage: SecurityStoragePort,
    private readonly options: SecurityModuleOptions,
  ) {}

  async blockIp(ip: string, reason: string, ttlMs?: number): Promise<BlockEntry> {
    return this.persistBlock('ip', ip, reason, ttlMs);
  }

  async blockUser(userId: string, reason: string, ttlMs?: number): Promise<BlockEntry> {
    return this.persistBlock('user', userId, reason, ttlMs);
  }

  async findActiveBlock(ip: string, userId?: string): Promise<BlockEntry | null> {
    const ipBlock = await this.storage.getJson<BlockEntry>(
      this.storage.buildKey('block', 'ip', ip),
    );

    if (ipBlock) {
      return ipBlock;
    }

    if (!userId) {
      return null;
    }

    return this.storage.getJson<BlockEntry>(
      this.storage.buildKey('block', 'user', userId),
    );
  }

  private async persistBlock(
    subjectType: BlockEntry['subjectType'],
    subject: string,
    reason: string,
    ttlMs = this.options.blocklist.baseBlockDurationMs,
  ): Promise<BlockEntry> {
    const entry: BlockEntry = {
      subject,
      subjectType,
      reason,
      expiresAt: new Date(Date.now() + ttlMs).toISOString(),
    };

    await this.storage.setJson(
      this.storage.buildKey('block', subjectType, subject),
      entry,
      ttlMs,
    );

    return entry;
  }
}
