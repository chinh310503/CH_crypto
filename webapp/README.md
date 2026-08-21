# CryptoBank — Web demo tấn công ECDSA

Một ứng dụng web *"giống thật"* (ngân hàng số) dùng chữ ký ECDSA, được **cài cắm
3 lỗ hổng** đúng với ba tấn công đã nghiên cứu, kèm **Attacker Console** để khai
thác trực tiếp và trình diễn impact.

Tái sử dụng thư viện lõi [`../demo/ecc_core`](../demo/README.md).

## Yêu cầu & chạy

```bash
pip install flask          # (đã cài trong môi trường này)
python webapp/app.py       # rồi mở http://127.0.0.1:5000
```

Hai giao diện:
- **Ngân hàng** (nạn nhân): `/login` → `/dashboard`
- **Attacker Console**: `/attacker`

## Tài khoản demo

| Tài khoản | Mật khẩu | Vai trò | Số dư |
|-----------|----------|---------|-------|
| alice | `alice123` | user | 5.000 |
| bob | `bob123` | user (kẻ tấn công nhận tiền) | 1.500 |
| carol | `carol123` | user | 3.200 |
| admin | *(không công bố)* | admin | 100.000 |
| megacorp | — | enterprise | 5.000.000 |

> `admin` cố tình **không có mật khẩu công khai** — chỉ có thể vào bằng tấn công
> Psychic Signatures.

## Ba lỗ hổng & vị trí trong mã

| # | Tấn công | Lỗ hổng cài trong code | Impact |
|---|----------|------------------------|--------|
| 1 | **Nonce reuse** | [`vault.py`](vault.py) `BrokenRNG` — hồ nonce nhỏ, lặp vòng khi ký giao dịch | Khôi phục **khóa master** → rút sạch tài khoản |
| 2 | **Psychic Signatures** | [`vault.py`](vault.py) `verify_token()` dùng `verify_insecure` | **Chiếm admin** không cần mật khẩu |
| 3 | **Pohlig–Hellman** | [`vault.py`](vault.py) khóa enterprise trên đường cong bậc trơn | Khôi phục **khóa riêng** → rút sạch MegaCorp |

Logic tấn công (chỉ dùng dữ liệu công khai): [`attacks.py`](attacks.py).

## Kịch bản trình diễn "impact tối đa"

1. **Mở ngân hàng, đăng nhập `alice`** (`alice123`) → cho thấy số dư **5.000 CBC** thật.
2. **Mở Attacker Console** (`/attacker`) — bảng số dư mọi tài khoản hiển thị trực tiếp.
3. **Bấm "Khai thác" ở thẻ 1 (Nonce Reuse):** console in từng bước — phát hiện nonce
   trùng, khôi phục khóa master — rồi số dư **alice tụt về 0** (nhấp nháy đỏ), **bob tăng vọt**.
4. **Bấm thẻ 2 (Psychic):** chế tạo token `(0,0)`, **chiếm admin**, bung bảng toàn bộ tài khoản.
5. **Bấm thẻ 3 (Pohlig–Hellman):** khôi phục khóa enterprise, **MegaCorp 5.000.000 → 0**.
6. **Quay lại ngân hàng, đăng nhập `alice`** → số dư giờ là **0**: impact có thật, không phải mô phỏng rời rạc.
7. Bấm **"Reset hệ thống"** để diễn lại.

## Vì sao impact "thật"

- Các tấn công **chỉ dùng dữ liệu công khai** của hệ thống (lịch sử chữ ký ở
  `/api/transactions`, khóa công khai ở `/api/enterprise/pubkey`) — đúng như kẻ tấn
  công ngoài đời.
- Sau khi chiếm khóa, chúng **gọi chính các API thật** của ngân hàng (`/api/clear`,
  rút enterprise) để dịch chuyển tiền — nên số dư thay đổi thật.

## Phòng chống

Mỗi lỗ hổng có cách vá tương ứng trong [`../docs/06-phong-chong.md`](../docs/06-phong-chong.md):
RFC 6979 (nonce tất định), kiểm tra `r,s ∈ [1,n-1]`, chọn đường cong bậc nguyên tố.
Đối chứng: `vault.py` có sẵn `verify_token_secure()` (bản vá) để so sánh.

## Cấu trúc

```
webapp/
├── ecc_bridge.py   # nạp thư viện lõi ecc_core từ ../demo
├── vault.py        # két mật mã — nơi cài 3 lỗ hổng
├── bank.py         # trạng thái & nghiệp vụ ngân hàng
├── attacks.py      # 3 tấn công (chỉ dùng dữ liệu công khai)
├── app.py          # Flask routes
├── templates/      # login / dashboard / attacker
└── static/style.css
```
