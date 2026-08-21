# Demo 1 — Tấn công dùng lại nonce (Nonce Reuse)

**Nhóm A** · Lý thuyết: [docs/01-tan-cong-nonce.md §1](../../docs/01-tan-cong-nonce.md)

## Kịch bản
"Nạn nhân" lỡ dùng **cùng một nonce `k`** để ký hai thông điệp khác nhau — đúng
như sự cố **Sony PS3 (2010)** dùng nonce tĩnh, và **ví Bitcoin trên Android
(2013)** khi `SecureRandom` hỏng khiến nonce trùng. Chỉ từ **hai chữ ký công
khai**, kẻ tấn công khôi phục trọn vẹn khóa bí mật.

## Cơ chế toán học
Hai chữ ký cùng `k` sẽ có **cùng `r`** (vì `r` chỉ phụ thuộc `k`):

```
s1 = k⁻¹(z1 + r·d)          s2 = k⁻¹(z2 + r·d)      (mod n)
```

Giải hệ hai phương trình tuyến tính hai ẩn `(k, d)`:

```
k = (z1 − z2) / (s1 − s2)   (mod n)
d = (s1·k − z1) / r         (mod n)
```

→ Khôi phục tức thời, không cần sức mạnh tính toán.

## Chạy
```bash
python attack.py
```

## Kết quả mong đợi
- Bước [2] cho thấy `r1 == r2` (dấu hiệu nonce trùng trên dữ liệu công khai).
- Bước [3]–[4] khôi phục đúng `k`, đúng khóa bí mật `d`, và **giả mạo** một chữ ký
  mới được chính khóa công khai của nạn nhân chấp nhận.

## Phòng chống
Sinh nonce **tất định theo RFC 6979** (`k = HMAC-DRBG(d, H(m))`) — loại bỏ hoàn
toàn khả năng trùng/đoán nonce. Xem [docs/06-phong-chong.md §1](../../docs/06-phong-chong.md).
