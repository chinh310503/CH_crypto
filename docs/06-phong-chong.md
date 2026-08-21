# Chương 06 — Biện pháp phòng chống

> Chương này tổng hợp các biện pháp đối phó với toàn bộ các nhóm tấn công đã phân
> tích. Nguyên tắc bao trùm: **an ninh thực tế của ECDSA nằm ở khâu triển khai**,
> nên phần lớn biện pháp nhằm vào cách sinh nonce, cách tính toán, và cách kiểm tra
> đầu vào — chứ không phải vào việc chọn đường cong "mạnh hơn".

## 1. Sinh nonce tất định — RFC 6979

**RFC 6979** (*Deterministic Usage of DSA and ECDSA*, Thomas Pornin, 8/2013) sinh
nonce `k` một cách **tất định** như hàm giả ngẫu nhiên của **khóa bí mật `d`** và
**băm thông điệp**, thường qua **HMAC-DRBG**:

$$k = \text{HMAC-DRBG}(d,\ H(m)).$$

**Ưu điểm:**
- **Loại bỏ hoàn toàn phụ thuộc vào RNG lúc ký** → chống hỏng TRNG, cạn entropy,
  PRNG lệch — tức là chặn tận gốc các sự cố PS3 (2010), Android Bitcoin (2013), và
  phần "biased nonce" trong Biased Nonce Sense (2019).
- Thông điệp khác nhau → nonce khác nhau (chống **reuse**); khóa khác nhau → nonce
  khác nhau cho cùng thông điệp.
- **Tương thích ngược:** chữ ký tạo ra vẫn được mọi trình xác minh chuẩn chấp nhận.

> **Cảnh báo:** nonce tất định "thuần" lại **dễ bị tấn công tiêm lỗi** (xem
> [chương 02 §6](02-tan-cong-kenh-ben.md#6-tấn-công-tiêm-lỗi-fault-injection)). Lời
> giải là **hedged signatures** (mục 4).

## 2. Triển khai hằng thời gian (Constant-time)

Chống trực tiếp toàn bộ nhóm kênh bên (Minerva, TPM-Fail, LadderLeak, EUCLEAK).
Nguyên tắc: **không** để thời gian thực thi, rẽ nhánh, hay mẫu truy cập bộ nhớ phụ
thuộc dữ liệu bí mật (nonce, khóa).

| Thành phần | Yêu cầu |
|---|---|
| Nhân vô hướng $k \cdot G$ | Số vòng lặp **cố định** (đệm nonce lên đúng độ dài); Montgomery ladder đầy đủ |
| Cộng điểm | **Công thức cộng hoàn chỉnh (complete addition formulas)** — không có trường hợp đặc biệt lộ thông tin |
| Nghịch đảo modulo $k^{-1}, s^{-1}$ | Hằng thời gian: định lý Fermat nhỏ, hoặc **safegcd** (Bernstein–Yang) — **không** dùng Euclid mở rộng phụ thuộc dữ liệu (bài học EUCLEAK) |
| Tra bảng cửa sổ | Truy cập **mọi** phần tử bảng (che mẫu truy cập) |

## 3. Kiểm tra tham số & điểm đầu vào

Chống Psychic Signatures, invalid curve, twist, small subgroup, CurveBall.

- **Khi xác minh chữ ký:** bắt buộc kiểm tra $r, s \in [1, n-1]$ **trước** mọi tính
  toán (bài học [Psychic Signatures](04-loi-trien-khai.md#1-psychic-signatures--cve-2022-21449)).
- **Xác thực khóa công khai `Q`:** $Q \neq O$; tọa độ trong trường hợp lệ; $Q$ thỏa
  phương trình đường cong; $n Q = O$ (đúng bậc nhóm con).
- **Xác thực tham số miền:** kiểm tra cả **điểm sinh `G`** và các tham số đường cong
  đúng như chuẩn (bài học [CurveBall](03-tan-cong-toan-hoc.md#2-sự-cố-thực-tế--curveball-cve-2020-0601)).
- **Đường cong an toàn:** bậc $n$ nguyên tố, embedding degree lớn, không dị thường,
  cofactor nhỏ (xem [chương 03 Phần II](03-tan-cong-toan-hoc.md#4-điều-kiện-đường-cong-an-toàn-tổng-hợp)).

## 4. Chữ ký "phòng bị kép" — Hedged signatures

Kết hợp nonce tất định **với** một lượng ngẫu nhiên tươi mới:

$$k = H(d,\ m,\ \text{random}).$$

**Lý do:** lấy đồng thời ưu điểm của hai thế giới —
- Chống **hỏng RNG** (như nonce tất định), vì vẫn phụ thuộc `d` và `m`;
- Chống **tấn công tiêm lỗi** (khác nonce tất định thuần), vì thành phần ngẫu nhiên
  khiến hai lần ký cùng thông điệp không cho cùng nonce, phá vỡ điều kiện mà tấn
  công lattice-fault cần (đã chứng minh với Ed25519 — Romailler & Pelissier, FDTC
  2017).

## 5. Chuyển sang EdDSA / Ed25519

**EdDSA** (Bernstein, Duif, Lange, Schwabe, Yang, 2011; chuẩn hóa **RFC 8032**) là
lựa chọn hiện đại thay thế ECDSA, khắc phục nhiều lớp lỗi ngay từ thiết kế:

| Đặc tính EdDSA | Chống được lỗi gì của ECDSA |
|---|---|
| **Nonce tất định theo thiết kế** $k = H(\text{prefix} \| M)$ | Reuse/biased nonce (nhóm A) mà không cần RNG tốt |
| **Công thức cộng điểm đầy đủ** (đường cong Edwards) | Lỗi biên/trường hợp đặc biệt |
| **Thuận cho constant-time** (không rẽ nhánh theo bí mật) | Kênh bên (nhóm B) |
| Đường cong minh bạch, **twist-secure** (Curve25519) | Cửa hậu tham số, twist attack |

> **Lưu ý cân bằng:** EdDSA tất định vẫn **dễ bị tiêm lỗi** (nên có biến thể hedged
> như XEdDSA); và cần thống nhất quy tắc xác minh (RFC 8032 so với ZIP-215) để tránh
> uốn nắn chữ ký/vấn đề cofactor — đúng như sự cố
> [libolm](05-tan-cong-thuc-te.md#5-sự-cố-thư-viện-e2ee--libolm--matrix-2024) cho thấy.
> EdDSA **giảm mạnh** nhưng không **triệt tiêu** mọi rủi ro triển khai.

## 6. Mối đe dọa dài hạn — máy tính lượng tử

- **Thuật toán Shor** giải ECDLP (và bài toán phân tích thừa số) trong **thời gian
  đa thức** trên máy tính lượng tử đủ lớn → **phá vỡ hoàn toàn** ECDSA/EdDSA khi
  phần cứng lượng tử đạt quy mô cần thiết. Đây là điểm khác biệt căn bản với các
  tấn công cổ điển ở [chương 03](03-tan-cong-toan-hoc.md) (vốn chỉ $O(\sqrt{n})$).
- **Đối phó:** chuyển sang **mật mã hậu lượng tử (PQC)**. NIST đã chuẩn hóa các lược
  đồ chữ ký hậu lượng tử — **ML-DSA** (FIPS 204, dựa trên CRYSTALS-Dilithium) và
  **SLH-DSA** (FIPS 205, dựa trên SPHINCS+) — làm phương án thay thế/kết hợp
  (hybrid) cho ECDSA trong dài hạn.

## 7. Bảng ánh xạ: tấn công → phòng chống

| Nhóm tấn công | Biện pháp chính |
|---|---|
| A. Nonce reuse/biased/RNG yếu | **RFC 6979** + hedged; entropy tốt |
| B. Kênh bên (timing/cache/power/EM) | **Constant-time** toàn diện; blinding (Coron); xác minh trước khi xuất (chống fault) |
| C1–C3. ECDLP / đường cong yếu / invalid curve | Chọn **đường cong chuẩn an toàn**; **xác thực điểm & tham số miền** |
| C4. Cửa hậu tham số | Dùng đường cong **minh bạch** (Curve25519/Ed25519, SafeCurves) |
| D. Lỗi triển khai (Psychic, malleability) | Kiểm tra $r,s$; bắt buộc **low-S**; kiểm thử chuẩn tắc |
| E. Lượng tử | Chuyển sang **PQC** (ML-DSA/SLH-DSA), triển khai hybrid |

## 8. Danh sách kiểm tra (checklist) triển khai ECDSA an toàn

- [ ] Sinh nonce bằng **RFC 6979** (hoặc hedged), **không** dựa vào RNG hệ thống một cách trần trụi.
- [ ] Nhân vô hướng và nghịch đảo modulo **hằng thời gian**; công thức cộng hoàn chỉnh.
- [ ] Kiểm tra $r, s \in [1, n-1]$ khi xác minh; bắt buộc **low-S** nếu cần chống malleability.
- [ ] Xác thực đầy đủ khóa công khai (trên đường cong, đúng bậc, khác $O$) và tham số miền (kể cả `G`).
- [ ] Dùng **đường cong chuẩn, minh bạch** (P-256/secp256k1 khi bắt buộc; ưu tiên Ed25519/X25519 cho hệ thống mới).
- [ ] Với thiết bị vật lý: chống **kênh bên** (blinding, che chắn EM) và **tiêm lỗi** (xác minh chữ ký trước khi xuất).
- [ ] Lập kế hoạch **chuyển đổi hậu lượng tử** cho dữ liệu cần bảo mật lâu dài.

Nguồn trích dẫn đầy đủ xem [chương 07 — Tài liệu tham khảo](07-tai-lieu-tham-khao.md).
