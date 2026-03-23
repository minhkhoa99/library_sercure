# Implementation Plan: Thư viện bảo mật NestJS (lib-sercure)

Tài liệu này mô tả kế hoạch triển khai thư viện bảo mật dùng chung cho các ứng dụng NestJS, tập trung vào Rate Limit, Audit Log, Abuse Detection, và Request Hardening sử dụng Redis.

## User Review Required
> [!IMPORTANT]
> - Framework sẽ được khởi tạo dưới dạng một standard NestJS Library sử dụng Nest CLI. Xin hãy xác nhận nếu bạn muốn khởi tạo project bằng một tool/framework khác (ví dụ: Nx workspace hay pnpm workspaces).
> - Thư viện yêu cầu cài đặt `ioredis`, `class-validator`, `class-transformer` và các dependencies của NestJS.
> - Xin xác nhận bạn đã tải repository `superpowers` thành công và xem liệu có cần chúng tôi sử dụng công cụ hoặc skill cụ thể nào trong thư mục đó không.

## Proposed Changes

Thư viện sẽ được chia thành cấu trúc module như sau (tại `libs/security/`):

### Core Module (`libs/security/src/module/`)
- Mạch sống của thư viện:
  - `SecurityModule`: Root module hỗ trợ `.forRoot()` và `.forRootAsync()` để nhận cấu hình ứng dụng từ môi trường sử dụng.

### Config (`libs/security/src/config/`)
- Giao diện định nghĩa cấu hình bảo mật `SecurityModuleOptions` hỗ trợ các thiết lập cho: `trustProxy`, `globalRateLimit`, `blocklist`, `abuseDetection`, `bodyLimits`, `policies`.

### Adapters (`libs/security/src/storage/`)
- `RedisStorageAdapter`: Lớp trừu tượng hóa giao tiếp với Redis (sử dụng `ioredis`), xử lý lưu trữ các counters, block TTL, scores... Hỗ trợ key pattern chuẩn: `sec:rl:`, `sec:block:`, `sec:abuse:`, `sec:audit:`.

### Middleware & Interceptors
- `RequestFingerprintMiddleware`: Phân tích request để lấy client IP thực từ `x-forwarded-for` hoặc `x-real-ip`, kết hợp với `user-agent`, `method` và `path`.
- `BodyLimitMiddleware` & `HeaderSanityMiddleware`: Siết chặt request (chặn JSON/Form body vượt kích thước, kiểm tra headers hợp lệ).
- `AuditInterceptor`: Chặn và ghi nhận kết quả của các request tới endpoint để phục vụ cho logging.

### Services (`libs/security/src/services/`)
- `RateLimitService`: Logic kiểm tra giới hạn (áp dụng sliding window với Redis Sorted Set).
- `BlocklistService`: Quản lý danh sách tài khoản/IP bị cấm tạm thời (TTL block 5 phút, 15 phút, v.v.).
- `AbuseDetectionService`: Thuật toán scoring heurustic cho các hành vi dò quét route, 404/401/403 burst, hoặc empty user-agent.
- `AuditLogService`: Quản lý việc ghi sự kiện bảo mật thành log có cấu trúc chuẩn.

### Guards (`libs/security/src/guards/`)
- `RateLimitGuard`: Trả về 429 nếu vi phạm rate limit.
- `BlocklistGuard`: Trả về 403 hoặc 429 nếu user/IP nằm trong danh sách cấm.

### Decorators (`libs/security/src/decorators/`)
- Tạo các wrapper decorators cho dev dễ sử dụng: `@SecurityPolicy()`, `@RateLimit()`, `@SkipSecurity()`.

## Verification Plan

### Automated Tests
- Viết unit tests sử dụng component testing tools của NestJS (`@nestjs/testing`) kết hợp với Jest.
- Mock cho `RedisStorageAdapter` sẽ được tạo ra nhằm đảm bảo không phụ thuộc vào kết nối Redis server thật trong quá trình chạy Unit Tests.
- Lên lịch test cho: global rate limit, route rate limit, IP/user block TTL, 404 burst scoring, decorator metadata binding, behavior của Trust proxy IP.

### Manual Verification
1. Sau khi hoàn thiện tính năng, tạo một project app NestJS demo nhỏ (`demo-app`).
2. Cấu hình import `SecurityModule` vào ứng dụng demo.
3. Chờ người dùng khởi chạy local Redis (ví dụ: `docker run -d -p 6379:6379 redis`).
4. Chạy `npm run start:dev` ứng dụng demo.
5. Gọi các endpoint bằng Postman hoặc `curl` để kiểm tra các hành động: gọi quá tải sẽ sinh lỗi 429, dò quét linh tinh gây 404 sẽ tự động tăng score bị block (403). Mọi hoạt động sẽ in ra structured log.
