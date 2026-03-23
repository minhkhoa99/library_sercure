// src/app.module.ts
import { Module } from '@nestjs/common';
import { SecurityModule, RedisStorageAdapter } from '@lib-sercure/security';
// import { SecurityModule } from '@minhkhoa99/lib-sercure'; // Lúc cài đặt npm thực tế
import Redis from 'ioredis';
import { AppController } from './app.controller';

@Module({
  imports: [
    SecurityModule.forRootAsync({
      useFactory: () => {
        // Khởi tạo Redis thông thường
        const redisClient = new Redis({
          host: process.env.REDIS_HOST || '127.0.0.1',
          port: 6379,
        });

        return {
          // Tin tưởng độ sâu proxy (Nginx). VD: 1 HOP
          trustProxy: 1, 
          storage: new RedisStorageAdapter(redisClient),

          // Tùy chỉnh Blocklist / RateLimit
          globalRateLimit: {
            limit: 50,
            windowMs: 60_000,
            keyBy: 'ip',
          },
          blocklist: {
            enabled: true,
            baseBlockDurationMs: 30 * 60_000, // 30 phút khoá
          },
          abuseDetection: {
            enabled: true,
            scoreTtlMs: 24 * 60 * 60_000,
          },
          logging: {
            enabled: true,
            minLevel: 'debug',
            persistAudit: false,       // In console chứ không lưu CSDL
            includeHeaders: false,     // Chống rò rỉ token
            includeQueryMetadata: true,
            verbose: true,
            redactFields: ['authorization', 'cookie', 'password'],
          },
          suspiciousRoutePatterns: [
            '/admin', '/phpmyadmin', '/wp-admin', '/.env'
          ],
          skipRoutes: ['/healthcheck', '/metrics'],
        };
      },
    }),
  ],
  controllers: [AppController],
})
export class AppModule {}
