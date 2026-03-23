# Phát triển Thư viện Bảo mật (lib-sercure) cho NestJS

## Phase 1: MVP (Lớp bảo vệ cơ bản)
- [x] Khởi tạo project NestJS library (`libs/security`).
- [x] Xây dựng `SecurityModule` và cấu hình cơ bản.
- [x] Viết tiện ích `RequestFingerprintMiddleware` để phân giải IP thật.
- [x] Cài đặt `RedisStorageAdapter` để kết nối Redis.
- [x] Cài đặt `RateLimitService` & `RateLimitGuard` (Global và Route-specific).
- [x] Cài đặt `BlocklistService` & `BlocklistGuard`.
- [x] Viết Unit Test cơ bản cho MVP.

## Phase 2: Abuse detection
- [x] Cài đặt `AbuseDetectionService`.
- [x] Phát hiện 404 burst, 401/403 burst, suspicious paths.
- [x] Tính toán suspicion score và kết nối với Blocklist.

## Phase 3: Hardening + Audit
- [x] Cài đặt `BodyLimitMiddleware` và `HeaderSanityMiddleware`.
- [x] Cài đặt `AuditInterceptor` và `AuditLogService`.
- [x] Định nghĩa schema structured event cho audit log.

## Phase 4: Developer experience (DX)
- [x] Xây dựng decorators: `@SecurityPolicy()`, `@RateLimit()`, `@SkipSecurity()`.
- [x] Tích hợp policy registry.
- [x] Viết README, config/import examples.
