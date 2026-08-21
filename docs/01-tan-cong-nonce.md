# Chương 01 — Tấn công dựa trên nonce (giá trị `k`)

> Thuộc nhóm **A** trong [cây phân loại](00-tong-quan-va-phan-loai.md). Đây là
> nhóm tấn công **nguy hiểm và phổ biến nhất** trong thực tế: phần lớn các vụ mất
> khóa/mất tiền liên quan đến ECDSA đều bắt nguồn từ lỗi sinh nonce, **không** phải
> từ việc bẻ gãy toán học của đường cong.

## 0. Vai trò sống còn của nonce `k`

Nhắc lại phương trình ký:

$$s = k^{-1}\,(h + r\,d) \bmod n, \qquad h = H(m),\quad r = (kG).x \bmod n.$$

Nonce `k` phải đồng thời thỏa **bốn** tính chất:

1. **Ngẫu nhiên đều** (uniform) trên $[1, n-1]$;
2. **Bí mật** (không lộ ra ngoài);
3. **Dùng một lần** (unique — không lặp lại giữa các chữ ký);
4. **Không đoán được** (unpredictable).

Vi phạm **bất kỳ** tính chất nào cũng làm lộ khóa bí mật `d`, vì `k` liên hệ
**tuyến tính** với `d` trong phương trình ký. Đây là "gót chân Achilles" của ECDSA.
Chương này phân tích ba kiểu vi phạm: **dùng lại nonce** (A1), **nonce lệch/rò rỉ
một phần** (A2), và **RNG yếu** (A3).

---

## 1. Nonce reuse — Dùng lại nonce (thảm họa tức thì)

### 1.1. Cơ chế toán học

Giả sử cùng một `k` được dùng để ký **hai** thông điệp khác nhau $h_1 \neq h_2$.
Vì $r = (kG).x$ **chỉ phụ thuộc `k`**, cả hai chữ ký có **cùng giá trị `r`** —
đây chính là dấu hiệu nhận biết nonce reuse trên dữ liệu công khai. Ta có hệ:

$$s_1 = k^{-1}(h_1 + r d) \bmod n, \qquad s_2 = k^{-1}(h_2 + r d) \bmod n.$$

**Bước 1 — khôi phục `k`.** Trừ hai phương trình: $s_1 - s_2 = k^{-1}(h_1 - h_2)$, suy ra

$$k = \frac{h_1 - h_2}{s_1 - s_2} \bmod n.$$

**Bước 2 — khôi phục khóa bí mật `d`.** Từ $s_1 k = h_1 + r d$:

$$d = \frac{s_1 k - h_1}{r} \bmod n.$$

Thay `k` vào, ta có công thức khép kín **chỉ từ dữ liệu chữ ký công khai**:

$$d = \frac{s_2 h_1 - s_1 h_2}{r\,(s_1 - s_2)} \bmod n.$$

Đây chỉ là giải một hệ hai phương trình tuyến tính hai ẩn $(k, d)$ trên $\mathbb{Z}_n$
— thực hiện **tức thời**, không cần sức mạnh tính toán. **Chỉ hai chữ ký** chung `k`
là đủ để lộ hoàn toàn khóa.

> **Mở rộng:** ngay cả khi hai nonce không bằng nhau mà chỉ có **quan hệ tuyến
> tính/affine** đã biết (ví dụ $k_2 = a k_1 + b$), kẻ tấn công vẫn lập được hệ
> phương trình và khôi phục khóa. Nói cách khác, chỉ cần các nonce **không độc
> lập** là đã nguy hiểm.

### 1.2. Công cụ minh họa
Có nhiều thư viện mã nguồn mở hiện thực sẵn tấn công này để kiểm thử, ví dụ
`tintinweb/ecdsa-private-key-recovery` và `pcaversaccio/ecdsa-nonce-reuse-attack`
trên GitHub — cho thấy rào cản kỹ thuật để khai thác gần như bằng không.

---

## 2. Nonce reuse trong thực tế

### 2.1. Sony PlayStation 3 (2010) — nonce tĩnh

- **Sự kiện:** tại hội nghị **27C3** (27th Chaos Communication Congress), Berlin,
  **tháng 12/2010**, nhóm **fail0verflow** trình bày bài *"Console Hacking 2010 —
  PS3 Epic Fail"*.
- **Lỗi cốt lõi:** Sony ký firmware/phần mềm PS3 bằng ECDSA nhưng **không sinh `k`
  ngẫu nhiên** — họ dùng một **hằng số cố định (static nonce)** trong **mọi** chữ
  ký. Hệ quả: mọi chữ ký có cùng `r`, và chỉ cần hai tệp đã ký là khôi phục được
  `k`, từ đó suy ra **khóa ký riêng của Sony**.
- **Hậu quả:** cho phép ký code tùy ý, phá vỡ hoàn toàn chuỗi tin cậy (chain of
  trust) của máy; khóa **không thể thu hồi** mà không thay đổi phần cứng. Sự cố
  dẫn đến vụ kiện của Sony với George Hotz (geohot) và fail0verflow đầu năm 2011
  (sau đó dàn xếp). Đây là ví dụ kinh điển nhất về hậu quả của việc dùng `k` tĩnh.

### 2.2. Bitcoin / ví Android (tháng 8/2013) — RNG hỏng gây trùng nonce

- **Lỗi cốt lõi:** lớp `SecureRandom` của Java trên Android (bản hiện thực
  SHA1PRNG dựa trên Apache Harmony) **không được seed đủ entropy**, khiến bộ sinh
  số trả về giá trị **lặp lại hoặc đoán được**.
- **Cơ chế mất tiền:** ví Bitcoin trên Android ký giao dịch bằng ECDSA. Với RNG
  hỏng, nhiều chữ ký dùng **cùng `k`** → **cùng `r`** hiển thị công khai trên
  blockchain. Kẻ tấn công quét blockchain tìm các giao dịch có `r` trùng, áp dụng
  công thức mục 1.1 để lấy `d`, rồi rút sạch ví.
- **Phát hiện:** **Mike Hearn** (nhà phát triển thư viện `bitcoinj`) xác định thủ
  phạm là `SecureRandom` của Android; cảnh báo chính thức đăng tại **bitcoin.org
  ngày 11/08/2013**. Định danh **CVE-2013-7372**.
- **Hậu quả & khắc phục:** các báo cáo công bố thiệt hại **khoảng 55,82 BTC**; các
  ví bị ảnh hưởng gồm Bitcoin Wallet, blockchain.info, BitcoinSpinner, Mycelium.
  Bản vá seed PRNG đúng cách (đọc `/dev/urandom`); người dùng phải **xoay khóa**
  (tạo địa chỉ mới và chuyển toàn bộ tiền sang).

> Chi tiết mở rộng về các sự cố blockchain (nghiên cứu *Biased Nonce Sense* quét
> toàn chuỗi) được trình bày ở [chương 05](05-tan-cong-thuc-te.md).

---

## 3. Nonce lệch / rò rỉ một phần và Bài toán Số Ẩn (HNP)

Đây là lớp tấn công tinh vi hơn: kẻ tấn công **không** biết trọn `k`, mà chỉ biết
**một vài bit** của mỗi `k` (vài bit cao hoặc thấp), hoặc biết `k` **thiên lệch**
(biased — không phân bố đều). Chỉ cần rò rỉ rất ít bit trên **nhiều** chữ ký là đủ
khôi phục `d`.

### 3.1. Bài toán Số Ẩn — Hidden Number Problem (HNP)
- **Nguồn gốc:** Dan Boneh & Ramarathnam Venkatesan, *Hardness of Computing the
  Most Significant Bits of Secret Keys in Diffie-Hellman and Related Schemes*
  (CRYPTO 1996).
- **Phát biểu:** có một số ẩn $\alpha$ modulo số nguyên tố; cho nhiều cặp
  $(t_i,\ \text{MSB của } t_i \alpha \bmod p)$ với $t_i$ ngẫu nhiên đã biết, hãy
  khôi phục $\alpha$. Boneh–Venkatesan chỉ ra bài toán này quy về **Closest Vector
  Problem (CVP)** trên **lưới**, giải bằng **LLL** + thuật toán mặt phẳng gần nhất
  của **Babai**.

### 3.2. Quy ECDSA (biased nonce) về HNP
Từ phương trình ký, với mỗi chữ ký $i$:

$$k_i = (s_i^{-1} r_i)\,d + (s_i^{-1} h_i) \bmod n.$$

Đặt $A_i = s_i^{-1} r_i \bmod n$ và $B_i = s_i^{-1} h_i \bmod n$ (đều tính được từ
chữ ký công khai), ta có quan hệ tuyến tính:

$$k_i \equiv A_i\, d + B_i \pmod{n}.$$

`d` đóng vai trò **số ẩn** $\alpha$. Nếu mỗi $k_i$ thiên lệch — ví dụ $\ell$ bit
cao bằng 0, tức $k_i < n/2^{\ell}$ — thì ta biết một **xấp xỉ** của $A_i d \bmod n$.
Đó chính là một thể hiện của HNP. Gom nhiều quan hệ thành một **lưới**, vector ngắn
nhất/gần nhất sẽ tiết lộ đồng thời các $k_i$ nhỏ và do đó là `d`.

### 3.3. Dòng nghiên cứu tấn công lưới
- **Howgrave-Graham & Smart (2001)** — *Lattice Attacks on Digital Signature
  Schemes* (Designs, Codes and Cryptography): công trình **khởi xướng**, tấn công
  lưới (heuristic) đầu tiên lên DSA khi biết một phần bit của nonce.
- **Nguyen & Shparlinski (2002, DSA; 2003, ECDSA)** — *The Insecurity of the
  (Elliptic Curve) Digital Signature Algorithm with Partially Known Nonces*: nâng
  cấp thành thuật toán **thời gian đa thức có chứng minh**, khôi phục `d` khi biết
  vài bit liên tiếp của `k` trên số chữ ký chỉ tuyến tính theo $\log n$.

**Ngưỡng thực nghiệm điển hình** (số bit nonce cần rò rỉ để tấn công lưới thành công):

| Độ dài khóa | Số bit nonce cần biết |
|---|---|
| 160-bit | ~2 bit |
| 256-bit | ~3 bit |
| 384-bit | ~4 bit |

Con số cực nhỏ này giải thích vì sao các rò rỉ kênh bên "tưởng như vô hại" (chương 02)
lại đủ để phá khóa.

### 3.4. Kỹ thuật LLL, BKZ, CVP/SVP
- **LLL** (Lenstra–Lenstra–Lovász, 1982): rút gọn cơ sở lưới thời gian đa thức,
  nền tảng để tìm vector ngắn/gần nhất; hiệu quả ở chiều thấp–trung bình.
- **BKZ** (Block Korkine–Zolotarev, Schnorr–Euchner 1994): rút gọn mạnh hơn, cần
  khi chiều lưới lớn hoặc bias nhỏ; đánh đổi thời gian lấy chất lượng.
- Bài toán thường được đóng khung dưới dạng **CVP** hoặc nhúng thành **SVP** (kỹ
  thuật embedding của Kannan), rồi giải bằng LLL/BKZ + Babai.

### 3.5. Hướng phân tích Fourier / Bleichenbacher
- **Bleichenbacher (2000):** đề xuất cách tiếp cận **thống kê/phân tích Fourier**
  cho HNP, khác hoàn toàn với lưới. Ưu điểm: khai thác được **bias cực nhỏ (dưới 1
  bit)** và **chịu nhiễu** — nơi lattice thất bại — nhưng cần **rất nhiều** chữ ký.
- **De Mulder, Hutter, Marson & Pearson (CHES 2013):** áp dụng Bleichenbacher để
  tấn công rò rỉ nonce trên ECDSA 384-bit.
- **LadderLeak (CCS 2020):** đỉnh cao hướng Fourier, phá ECDSA chỉ với **dưới 1
  bit** rò rỉ nonce (chi tiết ở [chương 02](02-tan-cong-kenh-ben.md#52-ladderleak-2020)).
- **ASIACRYPT 2024:** *Attacking ECDSA with Nonce Leakage by Lattice Sieving* —
  kết hợp lattice sieving với phân tích Fourier, thu hẹp khoảng cách giữa hai hướng.

### 3.6. Nguồn rò rỉ một phần trong thực tế
Rò rỉ vài bit nonce thường đến từ **kênh bên** rồi mới dùng lưới/Fourier: **Minerva**
(rò rỉ độ dài bit qua thời gian) và **TPM-Fail** (timing hộp đen trên TPM 2.0) là
hai ví dụ tiêu biểu — phân tích chi tiết ở [chương 02](02-tan-cong-kenh-ben.md#5-các-tấn-công-có-tên-riêng-nổi-tiếng).

---

## 4. RNG yếu / dự đoán được

Nguồn gốc chung của cả nonce reuse lẫn biased nonce là **bộ sinh số ngẫu nhiên
(RNG/PRNG) kém**:

- **Nguyên lý:** nếu PRNG có entropy thấp, bị seed cố định, hoặc trạng thái đoán
  được, thì `k` trở nên đoán được. Chỉ cần đoán đúng `k` của **một** chữ ký, khóa
  lộ ngay qua $d = (s k - h) r^{-1} \bmod n$. Nếu `k` sinh từ PRNG có cấu trúc
  (ví dụ LCG), kẻ tấn công dựng quan hệ giữa các `k` liên tiếp và tấn công lưới.
- **Nghịch lý ngày sinh:** với RNG tốt cần cỡ $2^{n/2}$ chữ ký mới có xác suất va
  chạm nonce đáng kể; RNG hỏng khiến va chạm xảy ra chỉ sau **vài** chữ ký — chính
  là kịch bản Android 2013 (mục 2.2).

---

## 5. Tóm tắt & biện pháp phòng chống

| Kiểu vi phạm | Hệ quả | Đối phó chính |
|---|---|---|
| Dùng lại nonce (A1) | Lộ khóa từ **2** chữ ký | Nonce tất định **RFC 6979** |
| Nonce lệch/rò rỉ một phần (A2) | Lộ khóa qua HNP + lưới | Nhân vô hướng thời gian hằng số + RFC 6979 |
| RNG yếu (A3) | Trùng/đoán được nonce | RFC 6979, hedged nonce, nguồn entropy tốt |

**Biện pháp then chốt — RFC 6979** (Thomas Pornin, 2013, *Deterministic Usage of
DSA and ECDSA*): sinh `k` **tất định** từ khóa bí mật `d` và giá trị băm thông điệp
qua HMAC-DRBG, **loại bỏ hoàn toàn** sự phụ thuộc vào RNG lúc ký, chống cả reuse
lẫn bias. Các lựa chọn hiện đại: **EdDSA/Ed25519** (nonce tất định theo thiết kế)
và **hedged nonce** (trộn entropy hệ thống với giá trị tất định để chống thêm tấn
công tiêm lỗi — xem [chương 02 §6](02-tan-cong-kenh-ben.md#6-tấn-công-tiêm-lỗi-fault-injection)).

Chi tiết đầy đủ xem [chương 06 — Biện pháp phòng chống](06-phong-chong.md).
Nguồn trích dẫn đầy đủ xem [chương 07 — Tài liệu tham khảo](07-tai-lieu-tham-khao.md).

---

### Dòng thời gian học thuật của tấn công nonce

```
1996  Boneh–Venkatesan: Hidden Number Problem (CRYPTO)
2000  Bleichenbacher: hướng phân tích Fourier cho HNP
2001  Howgrave-Graham–Smart: tấn công lưới heuristic lên DSA
2002  Nguyen–Shparlinski: DSA với nonce biết một phần (provable)
2003  Nguyen–Shparlinski: mở rộng cho ECDSA
2010  Sony PS3: nonce tĩnh → lộ khóa ký (27C3)
2013  Android SecureRandom: trùng nonce → mất Bitcoin (CVE-2013-7372)
2013  De Mulder và cộng sự: Bleichenbacher trên ECDSA 384-bit (CHES)
2019  Biased Nonce Sense (Breitner–Heninger): quét blockchain
2020  Minerva, TPM-Fail, LadderLeak: rò rỉ ≤ 1 bit qua kênh bên
2024  Lattice sieving + Fourier (ASIACRYPT)
```
