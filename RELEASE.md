# Release Process (Maintainer Guide)

Bất kỳ Engineer nào khi làm Maintainer của gói thư viện `@minhkhoa99/lib-sercure` phải tuân thủ nghiêm ngặt quy trình Release trên branch `main`. Thư viện cấu trúc theo Semantic Versioning.

## 1. Versioning Rules (SemVer)
- **Hành động `PATCH` (1.0.1, 1.0.2):** Sửa lỗi nhỏ, hot-fixes (không thêm chức năng mới, không thay đổi interface Config hiện tại).
- **Hành động `MINOR` (1.1.0, 1.2.0):** Thêm tính năng như Service hoặc Options mới nhưng KHÔNG loại bỏ/đổi tên các config cũ (Tương thích ngược).
- **Hành động `MAJOR` (2.0.0, 3.0.0):** Đổi cổng DI, đổi tên tham số Global Options (vd rate limit object name), hoặc thay behavior của Fallback Storage (Breaking Changes). Bạn *phải* cập nhật file [MIGRATION.md](MIGRATION.md).

## 2. Pre-Release Checklist (Cần thực hiện trước khi tạo tag)
1. Chạy tất cả test linter: `npm run lint` & `npm run format`.
2. Kiểm tra type check: `npm run typecheck`
3. Chờ cho CI Pass mọi Unittest: `npm run test:unit`.
4. Cập nhật `CHANGELOG.md` cho đúng Version Target. Nêu rõ [Added], [Fixed], hoặc [Changed].
5. Chạy lệnh: `npm version [patch|minor|major]`

## 3. Quá trình Publish
Package đã được setup script `prepublishOnly`, nhờ vậy lệnh `npm publish` sẽ:
- Tự động chạy `npm run clean && npm run typecheck && npm run test && npm run build`.
- Bất kỳ lỗi Code nào cũng làm Cancel quá trình.

Chạy:
```bash
npm publish
```
Vì cấu hình `publishConfig.registry` đã được điều chỉnh là internal registry của team, phiên bản NPM Package mới sẽ được đẩy lưu chuyển nội bộ.

### Rollback (Triển khai lỗi)
NPM không cho phép overwrite (push đè) một số định danh đã publish, bạn hãy:
- Publish hotfix với patch mới `1.0.X` ngay trong 5-10 phút.
- Gắn thẻ tag `@deprecated "Do lỗi ..."` cho version bị lỗi nếu cần thiết trong NPM để Dev khác né ra.
