# Các phương pháp tấn công vào chữ ký số ECDSA

Tập tài liệu này là phần **"Các phương pháp tấn công vào ECDSA"** thuộc đề tài
*"Tìm hiểu chữ ký số ECDSA và các phương pháp tấn công vào ECDSA"*. Nội dung được
tổng hợp từ các **nguồn học thuật** (IACR ePrint, USENIX, Springer/LNCS, IEEE, ACM,
RFC) và các **sự cố tấn công thực tế** đã được ghi nhận (kèm CVE).

## Tóm tắt điều hành

> **Thông điệp cốt lõi:** ECDSA với đường cong chuẩn (P-256, secp256k1…) **chưa bao
> giờ bị phá bằng tấn công toán học vào đường cong** trong thực tế. Mọi vụ mất khóa
> đều bắt nguồn từ **lỗi triển khai**: nonce yếu/trùng lặp, rò rỉ kênh bên, hoặc
> thiếu kiểm tra đầu vào. Vì vậy trọng tâm phòng chống là **cài đặt đúng**
> (deterministic nonce theo RFC 6979, constant-time, validation), không phải chọn
> đường cong "mạnh hơn".

Điểm yếu trung tâm là **nonce `k`**: phương trình ký $s = k^{-1}(z + rd) \bmod n$
liên hệ tuyến tính `k` với khóa bí mật `d`, nên chỉ cần lộ vài bit của `k` (qua
nhiều chữ ký) là đủ khôi phục toàn bộ khóa.

## Cấu trúc tài liệu

| Tài liệu | Nội dung |
|---|---|
| [00 — Tổng quan và phân loại](00-tong-quan-va-phan-loai.md) | Nhắc lại ECDSA, vì sao nonce là mắt xích yếu, **cây phân loại 5 nhóm tấn công** |
| [01 — Tấn công dựa trên nonce](01-tan-cong-nonce.md) | Dùng lại nonce, nonce lệch, Hidden Number Problem, tấn công lưới (LLL/BKZ), RNG yếu |
| [02 — Tấn công kênh bên](02-tan-cong-kenh-ben.md) | Timing, cache, điện năng, EM, fault; Minerva, LadderLeak, TPM-Fail |
| [03 — Tấn công toán học & đường cong yếu](03-tan-cong-toan-hoc.md) | ECDLP, MOV/Frey-Rück, Smart, invalid curve, twist, Dual_EC_DRBG |
| [04 — Lỗi triển khai](04-loi-trien-khai.md) | Psychic Signatures (CVE-2022-21449), malleability, thiếu validation |
| [05 — Sự cố tấn công thực tế](05-tan-cong-thuc-te.md) | Dòng thời gian & bảng tổng hợp: PS3, Bitcoin/Android, EUCLEAK… |
| [06 — Biện pháp phòng chống](06-phong-chong.md) | RFC 6979, constant-time, validation, hedged, EdDSA, hậu lượng tử |
| [07 — Tài liệu tham khảo](07-tai-lieu-tham-khao.md) | Danh mục nguồn học thuật & thực tế, phân theo chủ đề |

## Bản đồ nhanh 5 nhóm tấn công

| Nhóm | Bản chất | Sự cố tiêu biểu | Mức nguy hiểm thực tế |
|---|---|---|---|
| **A. Nonce** | Nonce trùng/lệch/đoán được | PS3 (2010), Bitcoin Android (2013) | ★★★★★ Cao nhất |
| **B. Kênh bên** | Rò rỉ vật lý/vi kiến trúc | Minerva, TPM-Fail, EUCLEAK | ★★★★ |
| **C. Toán học/đường cong** | Đường cong/tham số yếu | Juniper (Dual_EC), CurveBall | ★★ (chủ yếu lý thuyết) |
| **D. Triển khai** | Bỏ kiểm tra đầu vào | Psychic Signatures (2022) | ★★★★ |
| **E. Lượng tử** | Thuật toán Shor | (tương lai) | ★ (dài hạn) |

## Gợi ý cách đọc

- **Đọc tuần tự** 00 → 07 để nắm toàn cảnh có hệ thống.
- Cần **cơ chế toán học cốt lõi**: xem [chương 01 §1.1](01-tan-cong-nonce.md#11-cơ-chế-toán-học)
  (khôi phục khóa từ nonce reuse) và [§3](01-tan-cong-nonce.md#3-nonce-lệch--rò-rỉ-một-phần-và-bài-toán-số-ẩn-hnp)
  (Hidden Number Problem).
- Cần **ví dụ thực tế để trình bày**: xem [chương 05](05-tan-cong-thuc-te.md).
- Cần **phần khuyến nghị/kết luận**: xem [chương 06](06-phong-chong.md).

---
*Tài liệu phục vụ mục đích học tập và nghiên cứu về an toàn thông tin.*
