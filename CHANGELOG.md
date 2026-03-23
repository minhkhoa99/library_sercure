# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-23
### Added
- Thư mục `docs/` và `examples/basic-app/`.
- Ready build-test-publish scripts cho CI/CD process.
- Fallback in-memory storage cho SecurityStorage (hỗ trợ `cleanupTimer` garbage collection).
- `trustProxy` (Hops indexing) chống IP spoof logic.

### Changed
- Refactor `SecurityModule` để export toàn bộ Guard và Service (cung cấp API công khai cho Client của Node Package).
- Tối ưu `trackSlidingWindow` bằng Redis LUA Scripts cho khả năng chịu tải siêu lớn (C100k concurrency testing).
- Đổi mô hình score cập nhật (read-modify-write sang `INCRBYFLOAT` atomic).

### Security
- [CRITICAL] Fixed x-forwarded-for spoofing bypass khi `trustProxy = true`. Lấy hop cuối cùng đáng tin cậy.
- [HIGH] Chống Race Condition Blocklist và Score Increment ghi đè.
