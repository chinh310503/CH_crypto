# Demo 3 — Tấn công Pohlig–Hellman

**Nhóm C — Đường cong/tham số yếu** · Lý thuyết: [docs/03-tan-cong-toan-hoc.md, Phần I §3](../../docs/03-tan-cong-toan-hoc.md)

## Kịch bản
Một hệ thống dùng đường cong **trông rất "thật"** — trường nguyên tố **~256 bit**,
bậc nhóm cũng **~256 bit**, nhìn không khác gì secp256k1 nên tưởng an toàn. Nhưng
**bậc nhóm là số TRƠN**: thừa số nguyên tố lớn nhất chỉ **~2³⁴**. Kẻ tấn công phân
tích thừa số bậc nhóm rồi giải ECDLP bằng Pohlig–Hellman → khôi phục khóa bí mật.

> Đây là cạm bẫy thực tế: người ta kiểm tra kích thước `p` và `n` (thấy 256-bit →
> yên tâm) nhưng **quên kiểm tra `n` có phải số nguyên tố / có thừa số lớn không**.

## Đường cong dùng trong demo
`ecc_core/weak_curve.py` (sinh bằng `tools/gen_weak_curve.py`):

```
E: y² = x³ + x  trên F_p,  p ≡ 3 (mod 4),  p ~ 257 bit
→ supersingular ⇒ #E(F_p) = p + 1  (không cần thuật toán đếm điểm Schoof)
p + 1 = 2² · 3 · (nhiều nguyên tố nhỏ < 500) · q,  với q ~ 2³⁴ là thừa số lớn nhất
```

Vì `#E = p+1` được chọn TRƠN, thừa số lớn nhất chỉ ~2³⁴ → Pohlig–Hellman + BSGS phá
được ECDLP chỉ với ~2¹⁷ phép toán (thay vì √n ≈ 2¹²⁷).

Muốn sinh đường cong khác:
```bash
python ../tools/gen_weak_curve.py
```

## Cơ chế
Nếu `n = ∏ pᵢ^eᵢ` thì (Pohlig–Hellman):
1. Với mỗi `pᵢ^eᵢ`, chiếu về **nhóm con bậc nhỏ**, giải `d mod pᵢ^eᵢ` bằng
   **Baby-step Giant-step** (lũy thừa nguyên tố thì giải theo từng "chữ số").
2. **Ghép CRT** các `d mod pᵢ^eᵢ` để thu `d`.

Chi phí giảm từ `~√n ≈ 2¹²⁷` xuống `~√q ≈ 2¹⁷`.

## Chạy
```bash
python attack.py
```
Mất **vài giây** (BSGS trên nhóm con bậc `q ~ 2³⁴`).

## Kết quả mong đợi
- Phân tích bậc nhóm 256-bit ra 23 thừa số, lớn nhất `q ~ 2³⁴`.
- Khôi phục đúng khóa bí mật `d`.
- Đối chiếu chi phí: `2¹²⁷` (nếu bậc nguyên tố) so với `~131.000 bước` (thực tế).

## Phòng chống
Chọn đường cong chuẩn có **bậc `n` nguyên tố** (hoặc nguyên tố lớn × cofactor nhỏ),
và **tránh đường cong supersingular** (còn dính cả MOV attack). Xem
[docs/03-tan-cong-toan-hoc.md, Phần II §4](../../docs/03-tan-cong-toan-hoc.md).
