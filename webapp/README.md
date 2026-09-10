# CryptoBank — Web app demo (mô hình ví/sàn, toàn bộ ECDSA)

Ứng dụng web mô phỏng một sàn/ví tiền số: **mỗi tài khoản có cặp khóa ECDSA riêng**,
**chuyển tiền = giao dịch được ký ECDSA** và server xác minh chữ ký trước khi thực
thi. Được **cài cắm 3 lỗ hổng**; web app chỉ đóng vai "nạn nhân", còn tấn công do
các script trong [`../attack_client`](../attack_client/README.md) thực hiện qua HTTP
bằng **đúng các API công khai** của trang (không có API ẩn).

Thư mục **tự chứa** — thư viện ECDSA nằm trong `webapp/ecc_core/`.

## Chạy

```bash
pip install flask
python webapp/app.py       # http://127.0.0.1:5000
```

Bốn trang: **/login → /dashboard** (đăng nhập, chuyển tiền), **/monitor** (theo dõi
số dư trực tiếp), **/explorer** (sổ cái chữ ký + danh bạ khóa công khai — bề mặt tấn công).

## Mô hình giao dịch (không còn API ẩn)

- `POST /api/tx/submit` — **con đường DUY NHẤT để tiền dịch chuyển**: nộp một giao
  dịch đã ký ECDSA; server xác minh chữ ký của người gửi rồi thực thi (giống broadcast
  của blockchain). **Form chuyển tiền trên web tự ký ECDSA ngay trong trình duyệt**
  (JS secp256k1) rồi gọi đúng endpoint này — hệt như script tấn công. **Không có
  endpoint ký hộ**; mọi giao dịch (bình thường lẫn tấn công) đi qua đúng một con đường.
- `GET /api/wallet` — (đã đăng nhập) nạp "ví" vào trình duyệt: khóa riêng + tham số
  đường cong, để trình duyệt tự ký (mô hình ví non-custodial). Ví dùng RNG hỏng nên
  chính giao dịch bạn tạo cũng lặp nonce → có thể bị lộ khóa.
- `GET /api/transactions` — sổ cái công khai (mỗi giao dịch kèm `r,s`).
- `GET /api/accounts` — danh bạ khóa công khai + tham số đường cong của từng tài khoản.

## Ba lỗ hổng (tất cả ECDSA, khai thác chức năng thật)

| # | Tấn công | Lỗ hổng trong code | Bề mặt thật bị khai thác |
|---|----------|--------------------|--------------------------|
| 1 | **Nonce reuse** | Ví mỗi người dùng có RNG hỏng khi ký ([vault.py](vault.py) `BrokenRNG`) | Sổ cái `GET /api/transactions` → `POST /api/tx/submit` |
| 2 | **Psychic Signatures** | `verify_token` bỏ kiểm tra `r,s∈[1,n-1]` ([vault.py](vault.py)) | `GET /api/admin/users` + cookie token `(0,0)` |
| 3 | **Đường cong yếu** | `megacorp` dùng đường cong bậc điểm sinh quá nhỏ (~2³⁷), field 256-bit | `GET /api/accounts` → Pollard's rho → `POST /api/tx/submit` |

> Xác minh giao dịch (`/api/tx/submit`) dùng ECDSA **đúng chuẩn** — chữ ký `(0,0)`
> bị từ chối. Lỗ hổng psychic chỉ nằm ở khâu xác minh **token phiên**, nên ba tấn
> công độc lập nhau.

## Dữ liệu

20 tài khoản (5 cố định + 15 khách phát sinh, kèm PII giả), mỗi tài khoản một cặp
khóa ECDSA; `megacorp` trên đường cong yếu. ~57 giao dịch đã ký (trong đó ví lỗi RNG
làm lặp nonce → lộ trên sổ cái).

| Tài khoản | Mật khẩu | Vai trò | Số dư | Đường cong |
|-----------|----------|---------|-------|------------|
| alice | `alice123` | user | 5.000 | secp256k1 |
| bob | `bob123` | user (kẻ tấn công nhận tiền) | 1.500 | secp256k1 |
| carol | `carol123` | user | 3.200 | secp256k1 |
| admin | *(không công bố)* | admin | 100.000 | secp256k1 |
| megacorp | — | enterprise | 5.000.000 | **enterprise-weak** |

## Kịch bản demo

1. Chạy web app; mở **`/monitor`** (và **`/explorer`** để thấy các chữ ký cùng `r`).
2. Terminal khác: `python attack_client/run_all.py`.
3. Nhìn Monitor: số dư từng ví tụt về 0, dồn về `bob`; MegaCorp 5.000.000 → 0.
4. Gõ **`/reset`** để diễn lại.

## Đường cong yếu (tấn công 3)

`ecc_core/weak_curve.py` (sinh bởi `tools/gen_weak_curve.py`): supersingular
`y²=x³+x` trên `F_p` với **p là số nguyên tố ~256 bit** (trông như đường cong thật)
nhưng **bậc điểm sinh chỉ ~2³⁷** (cofactor khổng lồ). ECDSA vẫn chạy (bậc nguyên tố),
nhưng Pollard's rho khôi phục khóa riêng trong ~15-25 giây. Đây là lỗi thực tế "tự
chế đường cong / điểm sinh bậc quá nhỏ".

> **Vì sao không dùng đường cong 256-bit đầy đủ?** ECDSA cần bậc nhóm **nguyên tố**;
> mà bậc nguyên tố 256-bit thì ECDLP là **bất khả thi** (đó chính là lý do nó an
> toàn). Muốn phá được trong demo, bậc phải nhỏ (~2³⁷) — nên đây là đánh đổi bắt buộc.

## Phòng chống

Xem [`../docs/06-phong-chong.md`](../docs/06-phong-chong.md): RFC 6979 (nonce tất
định), kiểm tra `r,s∈[1,n-1]`, chọn đường cong chuẩn có bậc nguyên tố **lớn**
(≥256-bit). `vault.py` có sẵn `verify_token_secure()` (bản vá đối chứng).

## Cấu trúc

```
webapp/                 # tự chứa
├── ecc_core/           # thư viện ECDSA (curve, ký/xác minh, đường cong yếu)
├── vault.py            # mật mã: khóa token + ký/xác minh giao dịch (nơi cài lỗ hổng)
├── bank.py             # tài khoản (có khóa), giao dịch ký, sổ cái
├── app.py              # Flask routes
├── tools/gen_weak_curve.py   # sinh lại đường cong yếu
├── templates/          # login / dashboard / monitor / explorer
└── static/style.css
```
