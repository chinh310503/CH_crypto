# Chương 02 — Tấn công kênh bên (Side-Channel Attacks)

> Thuộc nhóm **B** trong [cây phân loại](00-tong-quan-va-phan-loai.md). Đây là
> nhóm tấn công **không** bẻ gãy toán học của ECDSA mà khai thác **rò rỉ vật lý
> hoặc vi kiến trúc** trong quá trình cài đặt để lấy thông tin về nonce `k`.

## 0. Vì sao ECDSA dễ tổn thương với kênh bên

Toàn bộ các tấn công trong chương này đều nhắm vào **nonce `k`**. Nhắc lại phương
trình ký:

$$s = k^{-1}\,(z + r\,d) \bmod n, \qquad z = H(m).$$

Nếu kẻ tấn công thu được **dù chỉ vài bit** thông tin về `k` (vài bit cao nhất,
độ dài bit, hoặc vài bit thấp) qua **nhiều** chữ ký, bài toán khôi phục khóa `d`
quy về **Bài toán Số Ẩn (Hidden Number Problem — HNP)** và giải được bằng **rút
gọn lưới (LLL/BKZ)** hoặc phương pháp Fourier/thống kê (Bleichenbacher). Chi tiết
HNP và tấn công lưới xem [chương 01](01-tan-cong-nonce.md); chương này tập trung
vào **cơ chế rò rỉ** cung cấp số bit đó.

**Nguồn rò rỉ cốt lõi** là phép **nhân vô hướng điểm** $k \cdot G$. Nếu phép này
_không chạy thời gian hằng số_ (số vòng lặp phụ thuộc độ dài bit của `k`, hoặc có
nhánh rẽ/tra bảng phụ thuộc bit của `k`) thì nonce bị lộ qua thời gian, cache,
điện năng hoặc bức xạ điện từ.

Nền tảng lý thuyết cho việc "vài bit → toàn bộ khóa": Boneh & Venkatesan
(CRYPTO 1996); Nguyen & Shparlinski, *The Insecurity of the Elliptic Curve
Digital Signature Algorithm with Partially Known Nonces* (J. Cryptology, 2003).

---

## 1. Tấn công thời gian (Timing Attacks)

### Cơ chế
Kẻ tấn công đo **thời gian thực thi** phép ký. Khi cài đặt không phải thời gian
hằng số, thời gian tương quan với **độ dài bit hiệu dụng của nonce** (số vòng lặp
trong `double-and-add`/Montgomery ladder tỉ lệ với $\lceil \log_2 k \rceil$) hoặc
**trọng số Hamming/vị trí bit** của `k`. Từ tập thời gian đo được, kẻ tấn công lọc
ra các chữ ký có nonce ngắn bất thường (các bit cao bằng 0) rồi dựng lưới HNP.

### Các mốc quan trọng
- **Kocher (1996)** — *Timing Attacks on Implementations of Diffie-Hellman, RSA,
  DSS, and Other Systems* (CRYPTO 1996): công trình khai sinh khái niệm tấn công
  thời gian.
- **Brumley & Tuveri (2011)** — *Remote Timing Attacks Are Still Practical*
  (ESORICS 2011): tấn công thời gian **từ xa qua mạng** đầu tiên khôi phục khóa
  ECDSA của một máy chủ TLS. Khai thác cài đặt **Montgomery ladder cho đường cong
  nhị phân trong OpenSSL** — dù ladder có vẻ "đều", số vòng lặp vẫn tỉ lệ độ dài
  bit của `k`. Định danh **CVE-2011-1945**. Biện pháp khắc phục do nhóm đề xuất:
  **đệm nonce (nonce padding)** để cố định số bit.

---

## 2. Tấn công bộ nhớ đệm (Cache Attacks)

Kẻ tấn công chạy chung máy vật lý (cùng CPU/last-level cache) với nạn nhân, theo
dõi **dấu vết truy cập bộ nhớ** của phép nhân vô hướng để suy ra chuỗi thao tác
(add/double) hoặc chỉ số cửa sổ (window digit), từ đó suy ra bit của nonce.

### 2.1. Flush+Reload — "Just a Little Bit" (CHES 2014)
- **Benger, van de Pol, Smart, Yarom** — *"Ooh Aah… Just a Little Bit": A Small
  Amount of Side Channel Can Go a Long Way* (CHES 2014).
- **Cơ chế:** kỹ thuật **Flush+Reload** theo dõi cache hit/miss để phân biệt lệnh
  `add` với `double`, trích **một lượng nhỏ bit** của nonce trong thao tác ký
  ECDSA của OpenSSL, rồi dùng lưới khôi phục khóa.
- **Kết quả:** chỉ cần khoảng **200 chữ ký** trên đường cong 256-bit
  **secp256k1** (đường cong của Bitcoin) để đạt tỉ lệ thành công hợp lý.

### 2.2. Prime+Probe và cache-timing template
- **Brumley & Hakala (2009)** — *Cache-Timing Template Attacks* (ASIACRYPT 2009):
  dùng **Prime+Probe** dựng "template" cache để khôi phục nonce ECDSA của OpenSSL
  — một trong các tấn công cache đầu tiên nhằm vào ECDSA.
- **Keegan Ryan (2019)** — *Return of the Hidden Number Problem* (TCHES 2019, số
  1): PoC hoàn chỉnh nhằm vào mẫu cài đặt phổ biến (khoảng một nửa số thư viện
  khảo sát có mẫu dễ tổn thương). Trích rò rỉ từ phép nhân vô hướng cửa sổ
  (windowed/sliding-window) và tra bảng; khôi phục khóa ECDSA 256-bit của OpenSSL
  chỉ sau **vài nghìn chữ ký**.

### 2.3. CacheBleed (CHES 2016) — biến thể liên quan
- **Yarom, Genkin, Heninger** — *CacheBleed: A Timing Attack on OpenSSL
  Constant-Time RSA* (CHES 2016). Khai thác **xung đột cache-bank** trên vi kiến
  trúc Intel Sandy Bridge — tấn công cache đầu tiên khai thác kênh này. Định danh
  **CVE-2016-0702**, vá trong OpenSSL 1.0.2g.
- **Phạm vi:** CacheBleed nhắm **RSA** (lũy thừa mô-đun), **không** trực tiếp vào
  ECDSA. Tuy nhiên nó thuộc cùng họ tấn công vi kiến trúc và minh họa rằng nhãn
  "constant-time" chưa đủ nếu vẫn còn xung đột cache-bank — nên thường được nhắc
  kèm khi bàn về kênh bên của OpenSSL.

---

## 3. Phân tích điện năng (Power Analysis)

Yêu cầu truy cập vật lý (thẻ thông minh, thiết bị nhúng, HSM), đo **mức tiêu thụ
điện năng** trong lúc thực hiện $k \cdot G$.

### 3.1. SPA — Simple Power Analysis
Quan sát **một** (hoặc vài) vết điện năng. Phép **cộng điểm** và **nhân đôi điểm**
có hình dạng vết điện năng khác nhau rõ rệt; với thuật toán `double-and-add` đơn
giản, chuỗi double/add tiết lộ **trực tiếp** từng bit của `k`.

### 3.2. DPA/CPA — Differential/Correlation Power Analysis
- **Kocher, Jaffe, Jun (1999)** — *Differential Power Analysis* (CRYPTO 1999):
  nền tảng DPA, dùng thống kê trên **nhiều** vết để lọc nhiễu và trích bit khóa.
- **CPA:** dùng hệ số tương quan giữa vết đo và mô hình rò rỉ (thường là mô hình
  trọng số Hamming) để khôi phục bit của scalar.

### 3.3. Tấn công template và Online Template Attack (OTA)
- **Medwed & Oswald (2008)** — *Template Attacks on ECDSA* (WISA 2008): xây dựng
  khuôn mẫu thống kê cho từng thao tác rồi so khớp trên vết mục tiêu; có thể vượt
  một số cài đặt "kháng SPA".
- **Online Template Attacks (OTA)** — Batina và cộng sự (INDOCRYPT 2014): chỉ cần
  **một** vết của phép nhân vô hướng trên thiết bị mục tiêu cộng với một vết
  template cho mỗi bit; áp dụng cho hầu hết thuật toán nhân vô hướng, kể cả ECDSA.

### 3.4. Biện pháp đối phó kinh điển (Coron, CHES 1999)
Coron — *Resistance against Differential Power Analysis for Elliptic Curve
Cryptosystems* (CHES 1999) — đề xuất 3 biện pháp: (1) ngẫu nhiên hóa scalar,
(2) làm mù điểm (point blinding), (3) ngẫu nhiên hóa tọa độ xạ ảnh. Lưu ý: tấn
công template dựa trên SPA vẫn có thể vượt một phần các cơ chế này.

---

## 4. Phân tích điện từ (Electromagnetic — EM)

Tương tự phân tích điện năng nhưng đo **bức xạ điện từ** phát ra khi thiết bị tính
toán — thường **không xâm nhập**, chỉ cần đầu dò từ đặt gần thiết bị.

- **Genkin, Pachmanov, Pipman, Tromer, Yarom (2016)** — *ECDSA Key Extraction
  from Mobile Devices via Nonintrusive Physical Side Channels* (CCS 2016).
  - **Kết quả:** trích **toàn bộ** khóa ký ECDSA từ **OpenSSL và CoreBitcoin trên
    iOS**; rò rỉ **một phần** khóa từ OpenSSL trên Android và CommonCrypto của iOS.
  - **Phương pháp:** đầu dò từ đặt gần điện thoại (hoặc đầu dò điện năng trên cáp
    USB), băng thông chỉ vài trăm kHz — có thể thực hiện rẻ tiền bằng card âm
    thanh + đầu dò tự chế. Phân tích vết để đếm **số bit 0 thấp nhất của nonce**,
    rồi dựng lưới HNP.
- Các nghiên cứu tiếp theo (2024–2025) tiếp tục khảo sát tính khả thi của tấn công
  EM vào ECDSA trên điện thoại thông minh hiện đại, cho thấy đây vẫn là hướng
  nghiên cứu sống động.

---

## 5. Các tấn công có tên riêng nổi tiếng

Ba tấn công dưới đây đều **hội tụ về cùng một ý tưởng**: dùng kênh bên (timing)
làm lộ **độ dài bit / bit cao nhất của nonce**, rồi khôi phục khóa bằng lưới —
minh họa trực tiếp mối liên hệ giữa chương này và [chương 01](01-tan-cong-nonce.md).

### 5.1. Minerva (2019)
- **Jancar, Sedláček, Švenda, Sýs** (CRoCS, ĐH Masaryk) — *Minerva: The curse of
  ECDSA nonces* (TCHES 2020; trình bày CHES 2020; ePrint 2020/728).
- **Cơ chế:** tấn công **thời gian** vào **độ dài bit của nonce** — thời gian ký
  phụ thuộc tuyến tính vào $\lceil \log_2 k \rceil$. Rò rỉ "nhiễu" này được đưa
  vào tấn công lưới.
- **Hiệu quả:** ~**500** chữ ký (mô phỏng), ~**1.200** (thư viện thực), ~**2.100**
  (thẻ thông minh) để khôi phục khóa 256-bit.
- **Đối tượng bị ảnh hưởng và CVE:**

  | Sản phẩm | CVE | Ghi chú |
  |---|---|---|
  | Thẻ Athena IDProtect (chip Inside Secure AT90SC) | CVE-2019-15809 | Có chứng nhận FIPS 140-2 L3 / CC vẫn dính |
  | libgcrypt | CVE-2019-13627 | ≤ 1.8.4, vá ở 1.8.5 |
  | wolfSSL / wolfCrypt | CVE-2019-13628 | ≤ 4.0.0, vá ở 4.1.0 |
  | MatrixSSL | CVE-2019-13629 | ≤ 4.2.1 |
  | SunEC / OpenJDK | CVE-2019-2894 | ≤ JDK 12 |
  | Crypto++ | CVE-2019-14318 | ≤ 8.2.0 |

  > **OpenSSL không bị Minerva** vì đã dùng nhân vô hướng thời gian hằng số cho
  > ECDSA. Đáng chú ý: một thẻ đạt chứng nhận bảo mật cao vẫn dính lỗi.

### 5.2. LadderLeak (2020)
- **Aranha, Novaes, Takahashi, Tibouchi, Yarom** — *LadderLeak: Breaking ECDSA
  with Less than One Bit of Nonce Leakage* (CCS 2020; ePrint 2020/615).
- **Cơ chế:** khai thác rò rỉ **cache-timing ở vòng lặp đầu của Montgomery
  ladder** trong OpenSSL (và bộ RELIC), làm lộ **bit cao nhất (MSB)** của nonce
  nhưng với xác suất $< 1$ — tức "**ít hơn 1 bit**" thông tin. Đóng góp mật mã
  cốt lõi: cải tiến thuật toán Bleichenbacher/Fourier để phá ECDSA/SM2 chỉ với
  **< 1 bit** thiên lệch nonce, trong khi các tấn công lưới trước cần $\geq 2$ bit.
- **Đối tượng:** một số phiên bản OpenSSL (nhánh 1.0.2, 1.1.0) dùng đường cong nhị
  phân; RELIC. Phá được ECDSA ở mức an ninh 160-bit (sect163r1) và 192-bit.

### 5.3. TPM-Fail (2019)
- **Moghimi, Sunar, Eisenbarth, Heninger** — *TPM-FAIL: TPM meets Timing and
  Lattice Attacks* (USENIX Security 2020; công bố 11/2019).
- **Cơ chế:** phân tích thời gian **hộp đen** các thiết bị **TPM 2.0**; thời gian
  tạo chữ ký ECDSA/ECSchnorr **phụ thuộc nonce**, dùng lưới khôi phục khóa 256-bit.
- **Đối tượng và CVE:**
  - **Intel fTPM** (firmware TPM): **CVE-2019-11090** — khôi phục khóa sau ~**1.300
    quan sát**, dưới **2 phút**.
  - **STMicroelectronics TPM** (chip phần cứng, chứng nhận **Common Criteria EAL
    4+**): **CVE-2019-16863** — khôi phục sau **< 40.000 quan sát**.
  - **Tấn công từ xa:** với VPN IPsec dùng StrongSwan, khôi phục khóa xác thực của
    máy chủ bằng cách đo thời gian ~**45.000** lượt bắt tay qua mạng.

---

## 6. Tấn công tiêm lỗi (Fault Injection)

Khác với các tấn công **bị động** ở trên, đây là tấn công **chủ động**: kẻ tấn
công gây lỗi tính toán (xung điện, xung clock, laser, nhiễu EM, Rowhammer…) trong
lúc ký, rồi so sánh chữ ký lỗi với chữ ký đúng để khôi phục khóa — cùng triết lý
với tấn công **Bellcore** (Boneh–DeMillo–Lipton) trên RSA-CRT, mở rộng sang ECC.

- **Naccache, Nguyen, Tunstall, Whelan (2005)** — *Experimenting with Faults,
  Lattices and the DSA* (PKC 2005): gây lỗi làm lộ/ép một phần bit của nonce, kết
  hợp lưới để khôi phục khóa (EC)DSA.
- **Schmidt & Medwed (2009)** — *A Fault Attack on ECDSA* (FDTC 2009).
- **Nghịch lý của chữ ký tất định:** *Lattice-Based Fault Attacks on Deterministic
  Signature Schemes of ECDSA and EdDSA* (CT-RSA 2022; ePrint 2020/803). Với
  deterministic ECDSA (RFC 6979), cùng thông điệp cho **cùng** nonce, nên chỉ cần
  một chữ ký đúng + vài chữ ký lỗi trên cùng thông điệp là dựng được instance
  SVP/CVP để khôi phục khóa. **Nghịch lý:** chữ ký tất định — vốn được thiết kế để
  loại bỏ rủi ro nonce ngẫu nhiên yếu (chương 01) — lại **dễ tổn thương hơn**
  trước tiêm lỗi. Đây là lý do các cài đặt hiện đại thường dùng **hedged
  signatures** (xem [chương 06](06-phong-chong.md)).

---

## 7. Tóm tắt biện pháp đối phó

| Rò rỉ | Đối phó |
|---|---|
| Timing / cache | Nhân vô hướng **thời gian hằng số**, cố định số vòng lặp (đệm nonce), Montgomery ladder đầy đủ, công thức cộng điểm hoàn chỉnh (complete addition) |
| Thiên lệch nonce | Nonce tất định **RFC 6979** hoặc **hedged** |
| Điện năng / EM | Scalar blinding, point blinding, ngẫu nhiên hóa tọa độ xạ ảnh (Coron); che chắn EM |
| Tiêm lỗi | **Xác minh chữ ký trước khi xuất**; hedged thay cho tất định thuần |

Chi tiết đầy đủ về các biện pháp này xem [chương 06 — Biện pháp phòng chống](06-phong-chong.md).
Nguồn trích dẫn đầy đủ xem [chương 07 — Tài liệu tham khảo](07-tai-lieu-tham-khao.md).
