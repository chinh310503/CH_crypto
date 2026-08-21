# Chương 04 — Lỗi triển khai (Implementation Bugs)

> Thuộc nhóm **D** trong [cây phân loại](00-tong-quan-va-phan-loai.md). Đây là các
> lỗi nằm trong **mã nguồn** của thư viện/ứng dụng — không phải điểm yếu toán học
> của ECDSA, cũng không phải rò rỉ vật lý (chương 02). Chúng đặc biệt nguy hiểm vì
> một dòng kiểm tra bị bỏ sót có thể vô hiệu hóa toàn bộ an ninh của lược đồ.

## 1. Psychic Signatures — CVE-2022-21449

### Bản chất
Lỗi trong quy trình **xác minh** chữ ký ECDSA của thư viện chuẩn Java. Khi Oracle
viết lại nhà cung cấp mật mã `SunEC` từ mã C gốc sang thuần Java (bắt đầu JDK 15),
bước kiểm tra tính hợp lệ của `r` và `s` bị **bỏ sót**.

### Cơ chế
Quy trình xác minh ECDSA đúng chuẩn bắt buộc **bước đầu tiên**: từ chối nếu `r` hoặc
`s` **không** nằm trong $[1, n-1]$. Vì thiếu bước này, chữ ký $(r=0, s=0)$ sẽ được
xử lý như sau: $w = s^{-1}$, $u_1 = h w$, $u_2 = r w$, rồi điểm
$P = u_1 G + u_2 Q$. Với $r = s = 0$ các số hạng bị triệt tiêu, phương trình xác
minh suy biến thành

$$0 \equiv 0 \pmod n,$$

**luôn đúng** với *bất kỳ* thông điệp và *bất kỳ* khóa công khai nào. Kẻ tấn công
chỉ cần gửi một chữ ký "toàn số 0" là được chấp nhận.

> **Tên gọi:** *Psychic Signatures* mượn hình ảnh "psychic paper" trong Doctor Who
> — tờ giấy trắng hiển thị bất cứ thông tin xác thực nào người xem mong đợi. Ở đây
> một chữ ký trống được chấp nhận là hợp lệ cho mọi thứ.

### Chi tiết
- **Người phát hiện:** Neil Madden (ForgeRock). Báo cáo cho Oracle **11/11/2021**,
  công bố blog **19/04/2022** trùng bản vá Oracle CPU tháng 4/2022.
- **Phiên bản khai thác được:** OpenJDK/Java SE **15, 16, 17, 18** (Java ≤ 14 dùng
  mã C cũ, không bị lỗi).
- **Hậu quả:** giả mạo chữ ký ECDSA một cách tầm thường, phá vỡ mọi thứ dựa trên
  ECDSA trong Java: chứng chỉ TLS, WebAuthn/FIDO, **JWT/JWS** (ES256/384/512), xác
  nhận SAML, ID token OpenID Connect, JAR ký số → **vượt qua xác thực, giả mạo
  token**. Oracle chấm CVSS 7.5 nhưng nhiều chuyên gia cho rằng nghiêm trọng hơn
  vì cho phép giả mạo hoàn toàn.

> **Bài học:** đây là minh chứng trực tiếp cho tầm quan trọng của bước kiểm tra
> $r, s \in [1, n-1]$ (mục 3). Một dòng `if` bị thiếu ⇒ sập toàn bộ.

---

## 2. Signature malleability (tính dễ uốn nắn của chữ ký)

### Cơ chế
Với một chữ ký ECDSA hợp lệ $(r, s)$, thì $(r,\ n - s)$ **cũng hợp lệ** với cùng
thông điệp và khóa. Lý do: `s` và $-s \equiv n - s \pmod n$ cho ra cùng tọa độ `x`
(bằng `r`) khi xác minh — phép lấy đối chỉ lật dấu tọa độ `y` của điểm $R$, còn
tọa độ `x` (thứ được so với `r`) không đổi.

Điều quan trọng: **bất kỳ ai** (không cần khóa riêng) đều tạo được chữ ký thứ hai
hợp lệ. Điều này **không** cho phép giả mạo trên thông điệp *mới*, nhưng làm **thay
đổi biểu diễn byte** của chữ ký — đủ để gây hại ở các hệ thống dùng hash của chữ
ký làm định danh.

### Tác động đến Bitcoin — Transaction Malleability
Trong Bitcoin, mã định danh giao dịch (`txid`) là hàm băm của **toàn bộ** giao
dịch, bao gồm cả chữ ký. Do chữ ký dễ uốn nắn (cùng nhiều nguồn khác: mã hóa DER
không chuẩn tắc…), một nút chuyển tiếp có thể sửa `txid` mà giao dịch vẫn hợp lệ,
làm các giao dịch con chưa xác nhận trỏ vào `txid` cũ bị vô hiệu.

### Sự kiện Mt. Gox (2/2014) — và một đính chính học thuật
Sàn **Mt. Gox** ngừng rút Bitcoin và **đổ lỗi cho transaction malleability**, rồi
tuyên bố phá sản 28/02/2014 với ~**850.000 BTC** bị mất.

> **Đính chính quan trọng (tránh quan niệm sai phổ biến):** nghiên cứu độc lập của
> **Decker & Wattenhofer** — *Bitcoin Transaction Malleability and MtGox*
> (ESORICS 2014) — phân tích blockchain và kết luận các cuộc tấn công malleability
> **không thể giải thích** phần lớn số coin bị mất; hầu hết vụ malleability quan
> sát được xảy ra *sau* thông báo của Mt. Gox. Nói cách khác, malleability phần
> lớn là **cái cớ**, không phải nguyên nhân chính gây thất thoát.

### Biện pháp khắc phục trong Bitcoin (yêu cầu low-S)
- **BIP-62** *"Dealing with malleability"* (Pieter Wuille, 2014): đưa ra quy tắc
  **low-S** — yêu cầu $s \leq n/2$ (chuẩn hóa `s` về nửa dưới). BIP-62 sau đó bị
  hoãn/rút vì khó xử lý mọi vector ở tầng đồng thuận.
- **BIP-66** (2015): bắt buộc mã hóa DER nghiêm ngặt.
- **BIP-146** *"Dealing with signature encoding malleability"* (Johnson Lau &
  Pieter Wuille): định nghĩa `LOW_S` và `NULLDUMMY`.
- **SegWit** (BIP-141/144, kích hoạt 2017): giải pháp căn cơ — tách phần "nhân
  chứng" (chữ ký) khỏi phép tính `txid`, nên uốn nắn chữ ký không còn ảnh hưởng
  `txid`. Thư viện `libsecp256k1` chỉ tạo chữ ký low-S.

> **Lưu ý:** EdDSA/Ed25519 cũng có thể mắc lỗi uốn nắn chữ ký nếu thiếu kiểm tra
> chuẩn tắc (điển hình là sự cố **libolm** của Matrix, 2024 — xem
> [chương 05](05-tan-cong-thuc-te.md)).

---

## 3. Thiếu kiểm tra đầu vào (Input Validation)

### a) Không kiểm tra $r, s \in [1, n-1]$
Chính là gốc rễ của Psychic Signatures (mục 1). Ngoài $r, s \neq 0$, còn phải kiểm
tra $s < n$ — nếu không cũng mở đường cho một dạng uốn nắn.

### b) Không kiểm tra điểm khóa công khai hợp lệ
Nếu bên nhận không kiểm tra rằng $Q$ thực sự nằm trên đường cong dự kiến và có đúng
bậc nhóm con, kẻ tấn công có thể gửi điểm nằm trên một đường cong **khác** (yếu
hơn) để dần khôi phục khóa bí mật — **invalid curve attack**, đặc biệt nguy hiểm
với ECDH. Kiểm tra khóa công khai đầy đủ cần đảm bảo: $Q \neq O$; các tọa độ trong
trường hợp lệ; $Q$ thỏa phương trình đường cong; và $n Q = O$ (đúng bậc nhóm con).

Cơ chế toán học của invalid curve attack, twist attack, cùng sự cố thực tế
**CurveBall (CVE-2020-0601)** — nơi Windows CryptoAPI quên kiểm tra **điểm sinh
`G`** của tham số đường cong — được trình bày ở
[chương 03 §3 — Tấn công triển khai liên quan đến đường cong](03-tan-cong-toan-hoc.md).

---

## 4. Tổng kết chương

| Lỗi | Định danh | Nguyên nhân gốc | Đối phó |
|---|---|---|---|
| Psychic Signatures | CVE-2022-21449 | Bỏ kiểm tra $r,s \in [1,n-1]$ | Kiểm tra biên `r,s` khi xác minh |
| Signature malleability | BIP-62/146 | $(r, n-s)$ cũng hợp lệ | Bắt buộc **low-S**, SegWit |
| Thiếu validation điểm | (xem ch.03) | Không kiểm tra $Q$/`G` hợp lệ | Xác thực đầy đủ khóa công khai & tham số miền |

Điểm chung của cả ba: **an ninh của ECDSA phụ thuộc vào việc kiểm tra đầy đủ đầu
vào**, không chỉ vào độ khó của ECDLP. Chi tiết phòng chống xem
[chương 06](06-phong-chong.md); dòng thời gian sự cố xem
[chương 05](05-tan-cong-thuc-te.md).
