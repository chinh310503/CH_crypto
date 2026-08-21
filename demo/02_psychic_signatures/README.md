# Demo 2 — Psychic Signatures (CVE-2022-21449)

**Nhóm D — Lỗi triển khai** · Lý thuyết: [docs/04-loi-trien-khai.md §1](../../docs/04-loi-trien-khai.md)

## Kịch bản
Một thư viện xác minh ECDSA **quên kiểm tra** điều kiện `r, s ∈ [1, n−1]` — đúng
lỗi trong **Java/OpenJDK 15–18** do Neil Madden phát hiện năm 2022. Kẻ tấn công
gửi chữ ký **rỗng `(r=0, s=0)`** và được chấp nhận là hợp lệ cho **bất kỳ** thông
điệp nào, **mà không cần biết khóa bí mật**.

## Cơ chế
Xác minh ECDSA tính `w = s⁻¹`, `u1 = z·w`, `u2 = r·w`, rồi điểm
`P = u1·G + u2·Q`, và chấp nhận nếu `r ≡ x(P)`. Với `(r, s) = (0, 0)`:

- Phép tính suy biến cho ra **điểm vô cực `O`**;
- Cài đặt lỗi coi `x(O) = 0`, nên so sánh `r == x(P)` trở thành `0 == 0` → **luôn đúng**.

Chỉ cần **một dòng kiểm tra** `r, s ∈ [1, n−1]` là chặn được ngay từ đầu.

## Điểm nhấn của demo
File `ecc_core/ecdsa.py` cung cấp **hai** hàm xác minh để so sánh trực tiếp:
- `verify()` — đúng chuẩn, **có** bước kiểm tra biên → từ chối `(0,0)`.
- `verify_insecure()` — **bỏ** bước đó (mô phỏng lỗi Java) → chấp nhận `(0,0)`.

## Chạy
```bash
python attack.py
```

## Kết quả mong đợi
Bảng đối chiếu trên nhiều thông điệp: hàm **an toàn từ chối tất cả**, hàm **có lỗi
chấp nhận tất cả** chữ ký rỗng `(0,0)`.

## Phòng chống
Luôn kiểm tra `r, s ∈ [1, n−1]` khi xác minh; dùng thư viện đã vá. Xem
[docs/06-phong-chong.md §3](../../docs/06-phong-chong.md).
