# attack_client — Bộ script tấn công CryptoBank (từ bên ngoài, qua HTTP)

Ba script Python **độc lập**, tấn công web app CryptoBank qua HTTP đúng như kẻ tấn
công thật: chỉ dùng **các API công khai thật** của trang (sổ cái chữ ký, danh bạ
khóa công khai) để khôi phục khóa, rồi **nộp giao dịch đã ký qua đúng endpoint mà
form chuyển tiền dùng** (`/api/tx/submit`). Không có API ẩn.

Toán học ECDSA tái sử dụng [`../demo/ecc_core`](../demo/README.md).

## Chuẩn bị

```bash
python webapp/app.py        # cửa sổ 1: chạy web (http://127.0.0.1:5000)
```
Mở **http://127.0.0.1:5000/monitor** (và `/explorer`) để xem trực tiếp.

## Chạy tấn công (cửa sổ 2)

```bash
python attack_client/attack_nonce_reuse.py   # khôi phục khóa mọi ví → rút sạch
python attack_client/attack_psychic.py       # token (0,0) → chiếm admin, lộ PII
python attack_client/attack_weakcurve.py     # Pohlig-Hellman → rút sạch OmniCorp
python attack_client/run_all.py              # chạy cả ba
```

Trỏ máy chủ khác: `TARGET=http://host:5000 python attack_client/run_all.py`

## Mỗi script khai thác gì

| Script | Đọc (công khai) | Kỹ thuật | Gửi | Impact |
|--------|-----------------|----------|-----|--------|
| `attack_nonce_reuse.py` | `/api/transactions`, `/api/accounts`, `/api/state` | Giải hệ phương trình từ 2 chữ ký cùng `r` của cùng người gửi | `/api/tx/submit` (chữ ký tự tạo) | Khôi phục khóa mọi ví → rút sạch về `bob` |
| `attack_psychic.py` | — | Token JWT với chữ ký `(0,0)` | `/api/admin/users` + cookie | Chiếm admin, lộ CCCD/SĐT/email 20 khách |
| `attack_weakcurve.py` | `/api/accounts` | **Pohlig-Hellman** giải ECDLP (bậc 256-bit nhưng TRƠN) | `/api/tx/submit` | Khôi phục khóa OmniCorp → rút 5.000.000 |

> `attack_weakcurve.py` mất **~10-15 giây** (Pohlig-Hellman + BSGS thật). Đường cong của
> OmniCorp trông y như thật (dạng `y²=x³+b` như secp256k1, `p` và `n` đều ~256 bit),
> nhưng khi **phân tích thừa số `n`** mới lộ ra `n` là số **trơn** → ECDLP sụp đổ.

## Khôi phục sau demo

Gõ **http://127.0.0.1:5000/reset**.

## Cấu trúc

```
attack_client/
├── common.py               # HTTP + ECDSA + Pollard's rho + Pohlig-Hellman + in ấn (dùng chung)
├── attack_nonce_reuse.py
├── attack_psychic.py
├── attack_weakcurve.py
└── run_all.py
```

> Chỉ dùng thư viện chuẩn Python (`urllib`) + `ecc_core`, không cần cài thêm.
