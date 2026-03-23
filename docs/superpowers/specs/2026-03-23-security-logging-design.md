# Security Logging Design

## Goal

Mở rộng `lib-sercure` để toàn bộ thư viện phát ra security logs rõ ràng, có cấu trúc, và dễ tích hợp vào logger stack của ứng dụng NestJS khi phát hiện hoặc xử lý hành vi tấn công.

Ưu tiên hiển thị rõ `IP truy cập` và các thông tin điều tra quan trọng để khi bị tấn công, đội vận hành có thể nhanh chóng xác định nguồn, kiểu tấn công, endpoint bị nhắm tới, mức độ nghiêm trọng, và hành động đã áp dụng.

## Scope

Thiết kế này bổ sung một logging subsystem dùng chung cho các thành phần security hiện có:

- `RequestFingerprintMiddleware`
- `BodyLimitMiddleware`
- `HeaderSanityMiddleware`
- `RateLimitGuard`
- `BlocklistGuard`
- `AbuseDetectionService`
- `AuditInterceptor`
- `AuditLogService`
- `SecurityModule`

Không thay đổi mục tiêu app-layer protection của thư viện. Logging mới phải hỗ trợ quan sát (observability), triage, và forensic cơ bản nhưng không log lộ dữ liệu nhạy cảm.

## Design Summary

Thư viện sẽ dùng mô hình hybrid logger:

1. **Application port:** `SecurityLoggerPort`
2. **Default outbound adapter:** `NestSecurityLoggerAdapter` bọc `LoggerService` của Nest và xuất structured JSON
3. **Override support:** ứng dụng tích hợp có thể truyền custom logger adapter qua config hoặc provider để dùng `Pino`, `Winston`, `OpenTelemetry`, hoặc logger nội bộ khác

Mọi component bảo mật sẽ log qua `SecurityLoggingService`/`SecurityLoggerPort`, không tự gọi `console`, không gọi `Logger` trực tiếp lung tung. `AuditLogService` tiếp tục là nơi chuẩn hóa audit event, nhưng sẽ đồng thời forward event đã chuẩn hóa sang logger pipeline nếu logging bật.

## Provider Graph

Module sẽ có provider/token rõ ràng:

- `SECURITY_LOGGER`: injection token cho `SecurityLoggerPort`
- `SECURITY_MODULE_OPTIONS`: options chuẩn hóa toàn module
- `SecurityLoggingService`: facade nội bộ để filter level, redact và forward
- `NestSecurityLoggerAdapter`: default outbound adapter

Precedence rule:

1. nếu app đăng ký provider override cho `SECURITY_LOGGER` thì dùng provider đó
2. nếu không có provider override nhưng `logging.logger` được truyền trong config thì module bind token này vào instance đó
3. nếu `logging.enabled=false` thì module bind token này vào `NoopSecurityLoggerAdapter`
4. nếu không có các điều kiện trên thì fallback sang `NestSecurityLoggerAdapter`

`SecurityModule` phải register/export ít nhất:

- `SECURITY_LOGGER`
- `SecurityLoggingService`
- `PolicyRegistryService`

để app tích hợp có thể reuse hoặc override.

## Architecture

### Application Layer

- `libs/security/src/application/ports/security-logger.port.ts`
  - Định nghĩa interface logger độc lập framework
- `libs/security/src/application/services/security-logging.service.ts`
  - Entry point chung để chuẩn hóa severity, redaction, và dispatch event
- `libs/security/src/application/services/audit-log.service.ts`
  - Ghi audit event vào storage và forward sang security logger

### Outbound Layer

- `libs/security/src/outbound/logging/nest-security-logger.adapter.ts`
  - Adapter mặc định dùng `LoggerService`
- `libs/security/src/outbound/logging/noop-security-logger.adapter.ts`
  - Adapter fallback nếu logging bị disable hoàn toàn

### Inbound Integration Points

- `RequestFingerprintMiddleware`
  - debug/warn khi resolve IP bất thường hoặc thiếu user-agent
- `BodyLimitMiddleware`
  - warn khi reject vì body/query vượt ngưỡng
- `HeaderSanityMiddleware`
  - warn khi reject vì content-type/header không hợp lệ
- `RateLimitGuard`
  - warn cho mỗi lần rate limit hit, kèm policy/scope
- `BlocklistGuard`
  - error khi block request do IP/user đang bị chặn
- `AuditInterceptor`
  - log decision cuối cùng theo structured event
- `AbuseDetectionService`
  - warn cho triggered rules, error khi escalation thành block

## Event Model

Sẽ thêm một structured log payload riêng cho runtime logging, tương thích nhưng không phụ thuộc hoàn toàn vào `AuditEvent`.

`AuditEvent` vẫn giữ vai trò schema audit domain. `SecurityLogEntry` là schema vận chuyển canonical cho logger runtime. `AuditLogService` sẽ chuyển đổi `AuditEvent -> SecurityLogEntry` khi forward log.

Canonical `SecurityLogEntry` field set:

- required: `eventType`, `severity`, `category`, `message`, `timestamp`, `metadata`
- optional: `ip`, `userId`, `route`, `path`, `method`, `userAgent`, `requestId`, `statusCode`, `policy`, `score`, `action`, `reason`, `subjectType`, `retryAfterMs`, `current`, `limit`

### Attack triage fields

Khi event liên quan tới tấn công hoặc abuse, logger phải cố gắng đưa ra đầy đủ các trường sau nếu có sẵn:

- `ip`: bắt buộc ưu tiên hiển thị rõ ràng trong message và payload
- `requestId`
- `userId`
- `method`
- `path`
- `route`
- `userAgent`
- `statusCode`
- `policy`
- `score`
- `action`
- `reason`
- `subjectType`
- `retryAfterMs`, `current`, `limit`
- `metadata.attackIndicators`
- `metadata.proxyChain` khi `trustProxy=true`
- `metadata.matchedPattern` cho suspicious route
- `metadata.blockExpiresAt` khi có blocklist/escalation

Với event mức `warn` hoặc `error`, message nên luôn có dạng dễ đọc cho người vận hành, ví dụ:

- `Rate limit exceeded from IP 203.0.113.10 on POST /auth/login`
- `Blocked request from IP 198.51.100.8 due to abuse-score escalation`
- `Suspicious path access from IP 192.0.2.4 targeting /.env`

### Required fields in `SecurityLogEntry`

- `eventType`
- `severity`
- `category`
- `message`
- `timestamp`
- `metadata`

### Optional fields in `SecurityLogEntry`

- `ip`
- `route`
- `path`
- `method`
- `userAgent`
- `requestId`
- `userId`
- `statusCode`
- `policy`
- `score`
- `action`
- `reason`
- `subjectType`
- `retryAfterMs`
- `current`
- `limit`

`AuditEvent -> SecurityLogEntry` mapping phải giữ nguyên dữ liệu triage quan trọng. Không được làm mất `userAgent`, block `reason`, `subjectType`, hoặc rate-limit state (`retryAfterMs/current/limit`) nếu producer đang có.

## Severity Rules

- `debug`
  - fingerprint resolution detail
  - skip-security decision
  - policy applied ở chế độ verbose
- `log`
  - startup/wiring success
  - health diagnostics không bất thường
- `warn`
  - rate limit exceeded
  - malformed request
  - suspicious path hit
  - empty user-agent
  - 404 / 401 / 403 burst detection
- `error`
  - request blocked
  - abuse score escalation
  - security processing/storage failure

## Configuration Changes

Mở rộng `SecurityModuleOptions.logging`:

- `enabled: boolean`
- `verbose?: boolean`
- `minLevel?: 'debug' | 'log' | 'warn' | 'error'`
- `persistAudit?: boolean`
- `includeHeaders?: boolean`
- `includeQueryMetadata?: boolean`
- `redactFields?: string[]`
- `logger?: SecurityLoggerPort`

Default behavior:

- `enabled: true`
- `verbose: false`
- `minLevel: 'warn'`
- `persistAudit: true`
- `includeHeaders: false`
- `includeQueryMetadata: false`
- `redactFields: ['authorization', 'cookie', 'set-cookie', 'x-api-key']`

Nếu người dùng truyền `logger`, module sẽ dùng adapter đó. Nếu không, module sẽ inject `NestSecurityLoggerAdapter` mặc định.

### Config semantics

- `logging.enabled`: có emit runtime structured logs hay không
- `logging.persistAudit`: có ghi audit event vào storage hay không

Truth table:

- `enabled=true`, `persistAudit=true`: emit logs + persist audit
- `enabled=true`, `persistAudit=false`: emit logs only
- `enabled=false`, `persistAudit=true`: persist audit only, không emit runtime logs
- `enabled=false`, `persistAudit=false`: disable cả hai

Backward-compat behavior mới cần tách rời hai trách nhiệm này; `AuditLogService.record()` không còn được dùng `logging.enabled` để quyết định audit persistence.

Producer behavior:

- khi `logging.enabled=false`, producers vẫn có thể tạo event payload nội bộ nhưng `SecurityLoggingService` sẽ route sang `NoopSecurityLoggerAdapter`
- khi `persistAudit=false`, `AuditLogService` bỏ qua storage write nhưng vẫn có thể forward runtime log nếu `enabled=true`
- khi cả hai cùng `false`, không có emit runtime log và không có audit persistence

### Operational logging rule

Đối với event tấn công thực tế (`rate_limit.exceeded`, `blocklist.rejected`, `abuse.rule_triggered`, `abuse.escalated`, `request_rejected.*`), logger mặc định phải:

- luôn đưa `ip` lên top-level payload
- luôn đưa `ip`, `method`, `path` vào human-readable message
- đưa thêm `requestId`, `userId`, `policy`, `score`, `reason` nếu có
- không ẩn hoặc chỉ để IP trong nested metadata

## Data Safety

Để tránh log dữ liệu nhạy cảm:

- không log raw body
- không log raw authorization/cookie/token
- header allowlist hoặc redaction trước khi emit
- query string chỉ log path đã normalize, metadata query chỉ log khi explicit enable và đã sanitize

## Request Flow Impact

Flow xử lý sau khi thêm logger:

1. resolve fingerprint
2. nếu có anomaly ở fingerprint -> emit debug/warn log
3. check blocklist -> nếu block thì log error và reject
4. apply global/route limit -> nếu exceed thì log warn
5. hardening middleware reject sớm -> log warn
6. business logic chạy
7. `AuditInterceptor` capture status code
8. `AbuseDetectionService` tính score -> log warn/error theo rule/escalation
9. `AuditLogService` persist audit nếu bật
10. `SecurityLoggingService` forward structured log tới configured adapter

## Concrete Producers

- `RequestFingerprintMiddleware`
  - emit `fingerprint.resolved` ở `debug` khi `verbose=true`
  - emit `fingerprint.proxy-header-missing` ở `warn` nếu `trustProxy=true` nhưng không có header proxy kỳ vọng
- `BodyLimitMiddleware`
  - emit `request_rejected.body_too_large` ở `warn`
- `HeaderSanityMiddleware`
  - emit `request_rejected.invalid_header` ở `warn`
- `RateLimitGuard`
  - emit `rate_limit.exceeded` ở `warn` với `policy`, `current`, `limit`, `retryAfterMs`
- `BlocklistGuard`
  - emit `blocklist.rejected` ở `error` với `reason`, `subjectType`, `expiresAt`
- `AbuseDetectionService`
  - emit `abuse.rule_triggered` ở `warn` cho từng rule hit
  - emit `abuse.escalated` ở `error` khi chuyển sang block
  - là owner cho các event `abuse.suspicious_path`, `abuse.404_burst`, `abuse.401_403_burst`
- `SecurityLoggingService`
  - chịu trách nhiệm enrich event với `ip`, `requestId`, `policy`, `score`, `reason`, `matchedPattern`, `proxyChain` nếu producer cung cấp
  - build human-readable message ngắn gọn, ưu tiên làm nổi bật IP và hành động bảo vệ đã áp dụng
- `AuditInterceptor`
  - phải capture cả success lẫn exception path
  - dùng `tap` cho success và `catchError` hoặc `finalize` + response status cho reject/error path
  - emit `audit.request_completed` hoặc `audit.request_failed` tương ứng
- `SecurityModule`
  - chỉ emit startup/wiring log ở `debug` khi `verbose=true`; không coi đây là yêu cầu bắt buộc cho MVP logging extension

## Files To Add Or Update

### New Files

- `libs/security/src/application/ports/security-logger.port.ts`
- `libs/security/src/application/services/security-logging.service.ts`
- `libs/security/src/outbound/logging/nest-security-logger.adapter.ts`
- `libs/security/src/outbound/logging/noop-security-logger.adapter.ts`
- `libs/security/src/types/security-log-entry.types.ts`
- `libs/security/src/outbound/logging/*.spec.ts`
- `libs/security/src/application/services/security-logging.service.spec.ts`

### Modified Files

- `libs/security/src/config/security-module-options.interface.ts`
- `libs/security/src/module/security.module.ts`
- `libs/security/src/application/services/audit-log.service.ts`
- `libs/security/src/application/services/abuse-detection.service.ts`
- `libs/security/src/inbound/guards/rate-limit.guard.ts`
- `libs/security/src/inbound/guards/blocklist.guard.ts`
- `libs/security/src/inbound/middleware/body-limit.middleware.ts`
- `libs/security/src/inbound/middleware/header-sanity.middleware.ts`
- `libs/security/src/inbound/middleware/request-fingerprint.middleware.ts`
- `libs/security/src/inbound/interceptors/audit.interceptor.ts`
- `README.md`

## Testing Strategy

- TDD cho từng bước
- unit test cho adapter mặc định và redaction
- unit test cho `SecurityLoggingService` với severity threshold
- integration-level unit tests xác nhận guards/middleware/services gọi logger đúng event payload
- verify `AuditLogService` không log double hoặc drop event khi `persistAudit` bật/tắt

## Trade-offs

### Chọn hybrid logger thay vì hardcode Nest logger

Ưu điểm:

- dùng ngay được trong mọi app Nest
- dễ thay logger backend ở app tích hợp
- giảm coupling giữa domain security và công cụ logging cụ thể

Nhược điểm:

- thêm một lớp port/service/adapter
- cần config rõ hơn trong `SecurityModule`

### Tách `SecurityLogEntry` khỏi `AuditEvent`

Ưu điểm:

- audit domain và runtime logging không bị ép chung một schema
- dễ evolve logger mà không phá audit persistence

Nhược điểm:

- thêm logic mapping

## Success Criteria

- mọi security decision quan trọng đều phát structured log nhất quán
- app tích hợp có log rõ ràng khi bị rate limit, blocklist, suspicious route, malformed request, abuse escalation
- không lộ dữ liệu nhạy cảm mặc định
- có default adapter dùng ngay, nhưng override được dễ dàng
- toàn bộ test, typecheck, build vẫn pass
