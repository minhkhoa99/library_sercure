# Tham Chiếu Nâng Cấp Hệ Thống (MIGRATION.md)

Lưu ý: Mọi sự thay đổi (Breaking Changes) qua từng Major Version sẽ được hướng dẫn Mapping ở đây để Dev dễ dàng thay đổi Module Root của Project.

---

## Upgrade từ V0.x.x Lên V1.0.0

- Khởi tạo DI Module bây giờ đi qua cấu hình tiêu chuẩn có `trustProxy` number (không dùng boolean ngầm dễ bị IP Spoofing như beta cũ).
- Cần Import ít nhất `ioredis` Client ngoài, hoặc thư viện sẽ lấy Fallback Adapter của JS. Không ép buộc Inject. (Xem `docs/configuration.md`).

**Old code (0.x.x):**
```typescript
SecurityModule.forRoot({
  trustProxy: true
})
```

**New code (1.0.0):**
```typescript
SecurityModule.forRoot({
  trustProxy: 1 // hoặc 2, 3 tuỳ theo môi trường Reverse Proxy
})
```

---

## Các hàm thay đổi khác:
1. `resolveClientIp` không chạy thuần trong Controller Request, nó được nhúng thẳng trong `RequestFingerprintMiddleware`. Team cần gắn Custom Config `skipRoutes` nếu muốn bypass middleware này. (Bản Beta cũ gọi thủ công).
2. Xoá mọi Log Config thủ công liên quan đến Winstone hoặc NestLogger nội sinh, thay bằng interface `SecurityLoggerPort`.
