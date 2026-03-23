# @minhkhoa99/lib-sercure

Một thư viện chặn IP, Rate-Limit, và Abuse Detection chuẩn Production dành riêng cho Ecosystem **NestJS** nội bộ.

## Tính năng chính (Core Features)
- **Advanced Rate Limiting:** Trượt cửa sổ (Sliding Window) qua Redis an toàn tuyệt đối với C10k.
- **Abuse Detection:** Hệ thống tự động phát hiện hành vi khả nghi (404 Burst, Auth Brute-force, Suspicious Path), tích lũy `Score` và chuyển thành Throttle/Block.
- **Auto Blocklist:** Blocklist tự động theo dõi và cách ly IP/User vi phạm. Bỏ qua database lookup, cache Redis trực tiếp.
- **Resilient Fallback:** Tự động rơi xuống sử dụng Memory (In-Memory Map) nếu Redis không kết nối được hoặc dev quên truyền `storage`. Fix chống Memory Leak.
- **Thread-safe:** Toàn bộ transaction được đóng trong Redis LUAs.

## Cài đặt (Installation)

Thư viện hiện publish trên Private Registry nội bộ của team/công ty.

```bash
npm install @minhkhoa99/lib-sercure ioredis
# Hoặc yarn
yarn add @minhkhoa99/lib-sercure ioredis
```

*(Yêu cầu `peerDependencies`: `@nestjs/core`, `@nestjs/common`, `ioredis`)*.

## Bắt đầu sử dụng (Quick Start)

### 1. Import module

Tại Root `AppModule`, import `SecurityModule.forRoot()`:

```typescript
import { Module } from '@nestjs/common';
import { SecurityModule } from '@minhkhoa99/lib-sercure';
import Redis from 'ioredis';
import { RedisStorageAdapter } from '@minhkhoa99/lib-sercure'; 

@Module({
  imports: [
    SecurityModule.forRootAsync({
      inject: [], // Inject ConfigService nếu cần
      useFactory: () => {
        const redisClient = new Redis('redis://localhost:6379');
        return {
          trustProxy: 1, // Tin tưởng 1 Proxy (ELB/Nginx) chống IP Spoofing
          storage: new RedisStorageAdapter(redisClient), // Hoặc bỏ trống để dùng In-Memory 
          // Custom Rate Limit mặc định:
          globalRateLimit: {
            limit: 100,
            windowMs: 60_000,
            keyBy: 'ip',
          },
          // ...
          logging: {
            enabled: true,
            minLevel: 'warn',
          }
        };
      },
    }),
  ],
})
export class AppModule {}
```

### 2. Sử dụng Decorator cho API

```typescript
import { Controller, Get } from '@nestjs/common';
import { RateLimit, Blockable, SkipSecurity } from '@minhkhoa99/lib-sercure';

@Controller('users')
export class UsersController {
  
  @Get('profile')
  @RateLimit('ip', 5, 10_000) // Chỉ 5 requests / 10s cho riêng route này
  @Blockable() // Theo dõi Abuse detection 
  getProfile() {
    return { ok: true };
  }

  @Get('health')
  @SkipSecurity() // Bỏ qua tất cả bảo mật
  health() {
    return 'OK';
  }
}
```

## Chú ý về Production Configuration

1. **`trustProxy`:** Cấu hình **tuyệt đối quan trọng** để phòng chống IP Spoofing. Truyền vào một cấu hình `number` tuỳ số lượng LB (Load Balancer) mà môi trường Deploy của bạn đi qua. 
   - `0` hoặc KhônG truyền (hoặc `false`): Request nối thẳng.
   - `1`: Yêu cầu NGINX/Alb đẩy vào.
   - `true`: Tin tưởng vào Proxy Cuối Cùng.
2. **Abuse Route Patterns:** Hãy đổi `suspiciousRoutePatterns` nếu bạn có API nhạy cảm riêng biệt.
3. Không expose PostgreSQL port `5432` ngoài Internet, vì thư viện này **KHÔNG** làm thay WAF ở Firewall.

## Documents nội bộ

- [Cấu hình nâng cao](./docs/configuration.md)
- [Quản trị Rate Limit & Blocklist](./docs/blocklist-and-abuse-detection.md)
- [Release Process cho Developer/Maintainer](./RELEASE.md)
