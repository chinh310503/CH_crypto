# CryptoBank — bản AN TOÀN (không còn khai thác được ECDSA)

Cùng giao diện/endpoint với [`../webapp`](../webapp/README.md) nhưng **loại bỏ cả 3
lỗ hổng** bằng cách thay mọi mật mã tự cài bằng **thư viện đã kiểm định** và **đường
cong chuẩn**. Chạy song song với bản cũ để đối chứng — cùng bộ
[`../attack_client`](../attack_client/README.md) sẽ **thất bại** ở đây.

## Chạy

```bash
pip install flask cryptography PyJWT
python webapp_secure/app.py       # http://127.0.0.1:5000
```

(Đăng nhập demo: `alice/alice123`, `bob/bob123`, `carlos/carlos123`, `admin/admin123`.)

## Ngăn xếp mật mã

| Thành phần | Thư viện | Ghi chú |
|---|---|---|
| Ký/xác minh giao dịch (server) | **`cryptography`** (pyca/OpenSSL) | ECDSA **NIST P-256**, tự validate điểm & từ chối chữ ký sai |
| Ký giao dịch (trình duyệt) | **WebCrypto** `crypto.subtle` | ECDSA P-256, nonce an toàn do trình duyệt sinh (non-custodial, import JWK non-extractable) |
| Token phiên đăng nhập | **PyJWT** (`ES256`) | Pin thuật toán; chữ ký `(0,0)`/sai bị từ chối ngay |

Chỉ dùng **một** đường cong duy nhất — P-256 (bậc nguyên tố ~2²⁵⁶). Không có đường
cong tùy chọn, không có RNG hỏng, không bỏ bước kiểm tra.

## Ba lỗ hổng cũ → vì sao vô hiệu

| Tấn công cũ | Vì sao thất bại ở bản này |
|---|---|
| **Nonce reuse** | WebCrypto/`cryptography` sinh nonce từ CSPRNG → không hai chữ ký nào trùng `r` → không khôi phục được khóa |
| **Psychic (0,0)** | Token phiên verify bằng PyJWT `ES256` → chữ ký rỗng bị từ chối (`403`) |
| **Đường cong yếu** | Mọi tài khoản trên P-256 (bậc nguyên tố) → Pohlig-Hellman/rho ~2¹²⁸, bất khả thi |

## Kiểm chứng

```bash
# cửa sổ 1
python webapp_secure/app.py
# cửa sổ 2 — cả ba tấn công đều thất bại
python attack_client/run_all.py
```

Kết quả mong đợi: nonce reuse *không tìm thấy ví lặp nonce*; psychic *HTTP 403*;
đường cong yếu *n bậc nguyên tố → không phá được*. Trong khi đó chuyển tiền hợp lệ
(đăng nhập → Ký & Gửi) vẫn chạy bình thường.

## So khớp với lý thuyết

Đúng thông điệp [`../docs/06-phong-chong.md`](../docs/06-phong-chong.md): an toàn của
ECDSA nằm ở **cài đặt đúng** (nonce an toàn, xác minh đầy đủ `r,s∈[1,n-1]`, đường cong
chuẩn bậc nguyên tố, dùng thư viện được kiểm định) — **không** phải ở việc đổi thuật toán.

## Cấu trúc

```
webapp_secure/
├── crypto.py       # bọc cryptography (P-256) + PyJWT — KHÔNG tự cài toán EC
├── bank.py         # tài khoản (keypair P-256), giao dịch ký an toàn, sổ cái
├── app.py          # Flask routes (giống webapp)
├── templates/      # login / dashboard (WebCrypto) / monitor / explorer
└── static/style.css
```
