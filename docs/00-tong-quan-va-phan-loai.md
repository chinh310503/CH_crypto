# Tổng quan và phân loại các phương pháp tấn công vào ECDSA

> Tài liệu này là phần "Các phương pháp tấn công vào ECDSA" trong đề tài
> *"Tìm hiểu chữ ký số ECDSA và các phương pháp tấn công vào ECDSA"*.
> Phần trình bày cơ chế ký/xác minh của ECDSA được giả định đã hoàn thiện ở
> chương trước; ở đây chỉ nhắc lại các ký hiệu và công thức cần thiết để phân
> tích các điểm yếu.

## Mục lục toàn bộ tài liệu

| STT | Tài liệu | Nội dung chính |
|-----|----------|----------------|
| 00 | [Tổng quan và phân loại](00-tong-quan-va-phan-loai.md) | Nhắc lại ECDSA, cây phân loại tấn công |
| 01 | [Tấn công dựa trên nonce](01-tan-cong-nonce.md) | Dùng lại nonce, nonce lệch, HNP, tấn công lưới |
| 02 | [Tấn công kênh bên](02-tan-cong-kenh-ben.md) | Timing, cache, điện năng, Minerva, LadderLeak, TPM-Fail |
| 03 | [Tấn công toán học & đường cong yếu](03-tan-cong-toan-hoc.md) | ECDLP, MOV, Smart, invalid curve, Dual_EC_DRBG |
| 04 | [Lỗi triển khai](04-loi-trien-khai.md) | Psychic Signatures, malleability, thiếu kiểm tra |
| 05 | [Sự cố tấn công thực tế](05-tan-cong-thuc-te.md) | PS3, ví Bitcoin/Android, trộm blockchain |
| 06 | [Biện pháp phòng chống](06-phong-chong.md) | RFC 6979, constant-time, EdDSA |
| 07 | [Tài liệu tham khảo](07-tai-lieu-tham-khao.md) | Danh mục nguồn học thuật và thực tế |

---

## 1. Nhắc lại lược đồ ECDSA và các ký hiệu

### 1.1. Tham số miền (domain parameters)

- Đường cong elliptic $E$ trên trường hữu hạn $\mathbb{F}_p$.
- Điểm sinh (base point) $G \in E$ có bậc là số nguyên tố $n$.
- Cofactor $h = \#E(\mathbb{F}_p) / n$.

### 1.2. Cặp khóa

- **Khóa bí mật:** số nguyên $d \in [1, n-1]$ chọn ngẫu nhiên.
- **Khóa công khai:** điểm $Q = d \cdot G$.

Độ an toàn dựa trên **bài toán logarit rời rạc trên đường cong elliptic
(ECDLP)**: biết $Q$ và $G$, tìm $d$ là bài toán khó.

### 1.3. Thuật toán ký thông điệp $m$

1. Tính giá trị băm $z = H(m)$ (lấy $L_n$ bit trái, với $L_n$ là độ dài bit của $n$).
2. Chọn **nonce** $k \in [1, n-1]$ ngẫu nhiên (bí mật, dùng một lần).
3. Tính $R = k \cdot G = (x_R, y_R)$ và đặt $r = x_R \bmod n$. Nếu $r = 0$, chọn lại $k$.
4. Tính

$$s = k^{-1}\,(z + r\,d) \bmod n.$$

   Nếu $s = 0$, chọn lại $k$.
5. Chữ ký là cặp $(r, s)$.

### 1.4. Thuật toán xác minh chữ ký $(r, s)$ trên $m$

1. Kiểm tra $r, s \in [1, n-1]$. Nếu không, **từ chối**.
2. Tính $z = H(m)$, rồi $u_1 = z\,s^{-1} \bmod n$ và $u_2 = r\,s^{-1} \bmod n$.
3. Tính điểm $P = u_1 G + u_2 Q = (x_P, y_P)$.
4. Chữ ký hợp lệ khi và chỉ khi $r \equiv x_P \pmod{n}$.

> **Ghi chú quan trọng cho phần tấn công:** phương trình ký
> $s = k^{-1}(z + r d) \bmod n$ chứa **hai** đại lượng bí mật là $k$ và $d$.
> Nếu kẻ tấn công biết (hoặc đoán được) $k$ của **một** chữ ký, hắn suy ra ngay:
>
> $$d = r^{-1}\,(s\,k - z) \bmod n.$$
>
> Đây là lý do vì sao **nonce $k$ là mắt xích yếu nhất và là mục tiêu chính**
> của phần lớn các cuộc tấn công thực tế vào ECDSA.

---

## 2. Cây phân loại các phương pháp tấn công

Có nhiều cách phân loại; tài liệu này chia theo **bản chất của điểm yếu bị khai thác**:

```
TẤN CÔNG VÀO ECDSA
│
├── A. TẤN CÔNG VÀO NONCE k  (chương 01) ── nguy hiểm & phổ biến nhất
│   ├── A1. Dùng lại nonce (nonce reuse / static nonce)
│   ├── A2. Nonce lệch / rò rỉ một phần (biased / partial nonce)
│   │        → Hidden Number Problem → tấn công lưới (LLL/BKZ), Bleichenbacher
│   └── A3. Bộ sinh ngẫu nhiên yếu / dự đoán được (weak RNG)
│
├── B. TẤN CÔNG KÊNH BÊN  (chương 02) ── khai thác rò rỉ vật lý/vi kiến trúc
│   ├── B1. Tấn công thời gian (timing)
│   ├── B2. Tấn công bộ nhớ đệm (cache: Flush+Reload, Prime+Probe)
│   ├── B3. Phân tích điện năng (SPA/DPA) và điện từ (EM)
│   ├── B4. Tấn công tiêm lỗi (fault injection)
│   └── B5. Các tấn công có tên: Minerva, LadderLeak, TPM-Fail…
│        (phần lớn hội tụ về A2: làm lộ vài bit của nonce)
│
├── C. TẤN CÔNG TOÁN HỌC & ĐƯỜNG CONG YẾU  (chương 03)
│   ├── C1. Giải ECDLP tổng quát (Pollard's rho, BSGS, Pohlig-Hellman)
│   ├── C2. Đường cong yếu: MOV/Frey-Rück (pairing), Smart (đường cong dị thường)
│   ├── C3. Invalid curve / twist / small-subgroup attack (thiếu kiểm tra điểm)
│   └── C4. Tham số nghi ngờ cửa hậu: Dual_EC_DRBG, tranh luận đường cong NIST
│
├── D. LỖI TRIỂN KHAI  (chương 04)
│   ├── D1. Psychic Signatures — CVE-2022-21449 (chấp nhận r=s=0)
│   ├── D2. Signature malleability ((r, -s) cũng hợp lệ)
│   └── D3. Thiếu kiểm tra đầu vào (r, s ngoài khoảng; khóa công khai không hợp lệ)
│
└── E. TẤN CÔNG LƯỢNG TỬ  (tương lai) ── thuật toán Shor phá ECDLP
```

Ba nhóm A, B, D là nguyên nhân của **hầu hết** các vụ mất khóa/mất tiền trong
thực tế; điểm chung của chúng thường không phải là bẻ gãy toán học của ECDSA mà
là **khai thác lỗi trong khâu sinh nonce hoặc khâu kiểm tra đầu vào**. Nhóm C
mang tính lý thuyết nhiều hơn, chỉ nguy hiểm khi lựa chọn tham số đường cong sai.
Nhóm E là mối đe dọa dài hạn khi máy tính lượng tử đủ mạnh xuất hiện.

Các chương tiếp theo phân tích chi tiết từng nhóm kèm cơ chế toán học, nguồn học
thuật và các sự cố thực tế tương ứng.
