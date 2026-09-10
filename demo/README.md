# Demo tấn công ECDSA (Python thuần)

Bộ ba demo minh họa các cuộc tấn công vào chữ ký số ECDSA, đi kèm phần lý thuyết
trong thư mục [`../docs`](../docs/README.md). Toàn bộ viết bằng **Python thuần**
(không cần thư viện ngoài), dùng chung một thư viện lõi `ecc_core`.

## Yêu cầu

- **Python ≥ 3.8** (dùng `pow(k, -1, m)` để nghịch đảo modulo). Đã kiểm thử với 3.11.
- Không cần cài `pip` package nào.

## Ba kịch bản

| # | Demo | Nhóm | Điểm yếu bị khai thác | Kết quả |
|---|------|------|-----------------------|---------|
| 1 | [Nonce reuse](01_nonce_reuse/) | A — Nonce | Dùng lại nonce `k` | Khôi phục **khóa bí mật** từ 2 chữ ký |
| 2 | [Psychic Signatures](02_psychic_signatures/) | D — Triển khai | Bỏ kiểm tra `r,s ∈ [1,n-1]` | Giả mạo chữ ký **(0,0)** cho mọi thông điệp |
| 3 | [Pohlig–Hellman](03_pohlig_hellman/) | C — Đường cong yếu | Bậc `n` **trơn** | Giải ECDLP, khôi phục khóa qua CRT |

Ba demo thuộc **ba nhóm tấn công khác nhau** (A / D / C) nhưng dùng chung khung.

## Cách chạy

```bash
# chạy từng demo
python 01_nonce_reuse/attack.py
python 02_psychic_signatures/attack.py
python 03_pohlig_hellman/attack.py

# hoặc chạy cả ba
python run_all.py

# kiểm tra tính đúng đắn của thư viện lõi
python tools/selftest.py
```

> Mỗi `attack.py` tự thêm thư mục gốc `demo/` vào `sys.path`, nên có thể chạy từ
> bất kỳ thư mục nào.

## Cấu trúc

```
demo/
├── ecc_core/                 ← THƯ VIỆN LÕI (dùng chung cho cả 3 demo)
│   ├── curve.py              # EllipticCurve, Point: cộng/nhân điểm, nghịch đảo mod
│   ├── curves.py             # secp256k1 (đường cong thật)
│   ├── weak_curve.py         # đường cong supersingular ~256 bit, bậc trơn (sinh tự động)
│   ├── factor.py             # is_prime + factorize (trial + Miller-Rabin + Pollard rho)
│   ├── ecdsa.py              # keygen, sign, verify, verify_insecure
│   └── io.py                 # tiện ích in ấn (tự bật UTF-8)
├── 01_nonce_reuse/attack.py
├── 02_psychic_signatures/attack.py
├── 03_pohlig_hellman/attack.py
├── tools/
│   ├── gen_weak_curve.py     # sinh lại đường cong yếu (supersingular, bậc trơn) cho demo 3
│   └── selftest.py           # kiểm tra nhanh ecc_core
└── run_all.py
```

## Khung chung của mỗi demo

Mọi `attack.py` được tổ chức theo **bốn bước** để trình bày nhất quán:

```
[1] SETUP   — "nạn nhân" sinh khóa / chữ ký (dùng ecc_core)
[2] FLAW    — kích hoạt điểm yếu (nonce trùng / bỏ kiểm tra / bậc trơn)
[3] ATTACK  — "kẻ tấn công" chỉ dùng dữ liệu công khai để khai thác
[4] PROOF   — chứng minh: khóa khôi phục == khóa thật, hoặc chữ ký giả được chấp nhận
```

Điểm khác nhau giữa ba demo **chỉ nằm ở bước [2] và [3]** — toàn bộ số học đường
cong và ECDSA đều tái sử dụng từ `ecc_core`.

## Lưu ý

- Mục đích **giáo dục**: đường cong secp256k1 là thật, nhưng khóa/nonce/thông điệp
  đều do demo tự sinh; đường cong ở demo 3 là đường cong **supersingular ~256 bit**
  cố tình có bậc nhóm trơn (demo 3 chạy mất vài giây do phải giải ECDLP).
- Các hàm được viết ưu tiên **dễ đọc**, không phải mã production (ví dụ ký/xác
  minh không chống kênh bên). Với hệ thống thật, xem khuyến nghị ở
  [docs/06-phong-chong.md](../docs/06-phong-chong.md).
