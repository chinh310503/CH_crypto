# Demo 3 — Tấn công Pohlig–Hellman

**Nhóm C — Đường cong/tham số yếu** · Lý thuyết: [docs/03-tan-cong-toan-hoc.md, Phần I §3](../../docs/03-tan-cong-toan-hoc.md)

## Kịch bản
Một hệ thống chọn nhầm đường cong mà **bậc `n` của điểm sinh là số "trơn"
(smooth)** — chỉ gồm các thừa số nguyên tố nhỏ. Khi đó bài toán ECDLP `Q = d·G`
bị "chẻ nhỏ" theo từng thừa số rồi ghép lại bằng **Định lý Số dư Trung Hoa
(CRT)**, khiến việc tìm khóa bí mật `d` trở nên dễ dàng.

## Cơ chế
Nếu `n = ∏ pᵢ^eᵢ` thì (theo Pohlig–Hellman):

1. Với mỗi thừa số `pᵢ^eᵢ`, chiếu bài toán về **nhóm con bậc nhỏ** và giải
   `d mod pᵢ^eᵢ` bằng **Baby-step Giant-step** (với lũy thừa nguyên tố thì giải
   theo từng "chữ số" cơ số `pᵢ`).
2. **Ghép CRT** các `d mod pᵢ^eᵢ` để thu `d mod n`.

Chi phí giảm từ `~√n` (Pollard rho toàn cục) xuống `~Σ eᵢ·√pᵢ`.

## Đường cong dùng trong demo
`ecc_core/toy_curve.py` (sinh sẵn bằng `tools/gen_smooth_curve.py`):

```
y² = x³ + 1  (mod 1000003)
bậc điểm sinh n = 499002 = 2 · 3 · 7 · 109²
```

Order này có **4 thừa số phân biệt** và một **lũy thừa nguyên tố** (109²) để minh
họa đầy đủ cả bước "chữ số hóa" lẫn CRT. Muốn sinh đường cong khác:

```bash
python ../tools/gen_smooth_curve.py
```

## Chạy
```bash
python attack.py
```

## Kết quả mong đợi
- Bảng `d mod pᵢ^eᵢ` cho từng thừa số, rồi **ghép CRT** ra đúng `d`.
- Đối chiếu chi phí: `√n ≈ 706` bước (toàn cục) so với `≈ 29` bước (Pohlig–Hellman).

> **Ý nghĩa:** với đường cong 256-bit có `n` **nguyên tố**, `√n ≈ 2¹²⁸` là bất khả
> thi. Nhưng nếu `n` **trơn**, tấn công chỉ tốn `~√(thừa số lớn nhất)` → sụp đổ.

## Phòng chống
Chọn đường cong chuẩn có **bậc `n` nguyên tố** (hoặc nguyên tố lớn × cofactor
nhỏ). Xem [docs/03-tan-cong-toan-hoc.md, Phần II §4](../../docs/03-tan-cong-toan-hoc.md).
