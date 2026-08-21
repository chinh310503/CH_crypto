# Chương 05 — Các sự cố tấn công ECDSA trong thực tế

> Chương này **tổng hợp theo dòng thời gian** những sự cố nổi bật nhất liên quan
> đến ECDSA/chữ ký trên đường cong elliptic, liên kết mỗi vụ với nhóm tấn công đã
> phân tích ở các chương kỹ thuật. Mục tiêu: cho thấy các điểm yếu lý thuyết đã gây
> hậu quả **thật** như thế nào, và loại lỗi nào tái diễn nhiều nhất.

## 1. Dòng thời gian tổng hợp

```
2010  PS3 — nonce tĩnh          → lộ khóa ký firmware        [nhóm A: nonce]
2013  Android Bitcoin           → RNG hỏng, trùng nonce, mất BTC   [A]
2015  Juniper ScreenOS          → cửa hậu Dual_EC bị chiếm dụng     [C: backdoor]
2019  Biased Nonce Sense        → quét blockchain, khôi phục khóa   [A]
2019  Minerva                   → timing lộ độ dài nonce            [B: kênh bên]
2019  TPM-Fail                  → timing trên TPM 2.0               [B]
2020  CurveBall (CVE-2020-0601) → giả mạo chứng chỉ Windows         [C/D: validation]
2020  LadderLeak                → phá ECDSA với < 1 bit rò rỉ       [B]
2021  Google Titan clone        → EM side-channel, nhân bản FIDO    [B]
2022  Psychic Signatures        → Java chấp nhận chữ ký (0,0)       [D: triển khai]
2024  EUCLEAK (YubiKey)         → EM side-channel, nhân bản FIDO    [B]
2024  libolm/Matrix deprecate   → Ed25519 malleability & timing     [D]
```

## 2. Bảng tổng hợp sự cố

| Năm | Sự cố | Nhóm lỗi | Nguyên nhân gốc | Hậu quả | Chương |
|---|---|---|---|---|---|
| 2010 | **Sony PS3** | Nonce (A1) | Dùng `k` **tĩnh** | Lộ khóa ký, jailbreak toàn hệ | [01](01-tan-cong-nonce.md#21-sony-playstation-3-2010--nonce-tĩnh) |
| 2013 | **Ví Bitcoin Android** | Nonce (A3) | `SecureRandom` thiếu entropy → trùng nonce | Mất ~55,82 BTC (CVE-2013-7372) | [01](01-tan-cong-nonce.md#22-bitcoin--ví-android-tháng-82013--rng-hỏng-gây-trùng-nonce) |
| 2015 | **Juniper ScreenOS** | Backdoor (C4) | Dual_EC + $Q$ bị đổi | Giải mã VPN (CVE-2015-7755/56) | [03](03-tan-cong-toan-hoc.md#2-sự-cố-juniper-screenos-2015) |
| 2019 | **Biased Nonce Sense** | Nonce (A2) | Nonce lệch/trùng trên blockchain | Khôi phục hàng trăm khóa | [01](01-tan-cong-nonce.md#36-nguồn-rò-rỉ-một-phần-trong-thực-tế) |
| 2019 | **Minerva** | Kênh bên (B1) | Timing lộ độ dài bit nonce | Khôi phục khóa thẻ & thư viện | [02](02-tan-cong-kenh-ben.md#51-minerva-2019) |
| 2019 | **TPM-Fail** | Kênh bên (B1) | Timing phụ thuộc nonce trên TPM | Khôi phục khóa TPM (CVE-2019-11090/16863) | [02](02-tan-cong-kenh-ben.md#53-tpm-fail-2019) |
| 2020 | **CurveBall** | Validation (D3/C3) | Không kiểm tra điểm sinh `G` | Giả mạo chứng chỉ (CVE-2020-0601) | [03](03-tan-cong-toan-hoc.md#2-sự-cố-thực-tế--curveball-cve-2020-0601) |
| 2020 | **LadderLeak** | Kênh bên (B2) | Cache-timing Montgomery ladder | Phá ECDSA với < 1 bit rò rỉ | [02](02-tan-cong-kenh-ben.md#52-ladderleak-2020) |
| 2021 | **Google Titan** | Kênh bên (B3) | EM side-channel chip NXP | Nhân bản khóa FIDO | mục 4 dưới |
| 2022 | **Psychic Signatures** | Triển khai (D1) | Bỏ kiểm tra $r,s \in [1,n-1]$ | Giả mạo mọi chữ ký (CVE-2022-21449) | [04](04-loi-trien-khai.md#1-psychic-signatures--cve-2022-21449) |
| 2024 | **EUCLEAK** | Kênh bên (B3) | Nghịch đảo modulo không hằng thời gian | Nhân bản YubiKey 5 (< 5.7) | mục 4 dưới |
| 2024 | **libolm/Matrix** | Triển khai (D2) | Ed25519 malleability + timing | Ngừng dùng libolm | mục 5 dưới |

## 3. Ba "kinh điển" đáng nhớ nhất

### 3.1. Sony PlayStation 3 (2010) — bài học "đừng bao giờ dùng nonce tĩnh"
Nhóm **fail0verflow** (27C3, 12/2010) chỉ ra Sony dùng **cùng một `k`** cho mọi chữ
ký firmware. Chỉ với hai tệp đã ký, khóa ký riêng của Sony bị khôi phục, phá vỡ
hoàn toàn chuỗi tin cậy của máy. Khóa **không thể thu hồi** mà không đổi phần cứng.
Đây là minh họa sạch sẽ nhất cho toán học ở [chương 01 §1.1](01-tan-cong-nonce.md#11-cơ-chế-toán-học).

### 3.2. Ví Bitcoin trên Android (2013) — RNG hỏng = mất tiền
Lỗi `SecureRandom` của Android khiến nhiều giao dịch dùng **cùng nonce** → **cùng
`r`** hiển thị công khai trên blockchain. Kẻ tấn công quét chuỗi, tìm `r` trùng,
khôi phục khóa và rút ví. Thiệt hại công bố ~**55,82 BTC**; buộc người dùng xoay
khóa. **CVE-2013-7372**.

### 3.3. Psychic Signatures (2022) — một dòng `if` bị thiếu
Java (JDK 15–18) quên kiểm tra $r, s \in [1, n-1]$, khiến chữ ký $(0, 0)$ được chấp
nhận là hợp lệ cho **mọi** thông điệp và **mọi** khóa. Ảnh hưởng JWT, SAML, WebAuthn,
TLS trên nền Java. Do Neil Madden phát hiện. **CVE-2022-21449**.

## 4. Nhóm sự cố phần cứng / FIDO (side-channel vật lý)

- **Google Titan (2021):** Thomas Roche & Victor Lomné (NinjaLab) dùng **kênh bên
  điện từ** trên chip NXP để **nhân bản** khóa FIDO của khóa bảo mật Google Titan —
  đòi hỏi tiếp cận vật lý và mở thiết bị.
- **EUCLEAK (2024):** Thomas Roche (NinjaLab) phát hiện lỗi trong thư viện mật mã
  **Infineon** (vi điều khiển bảo mật) do **nghịch đảo modulo không hằng thời gian**.
  Cho phép trích khóa riêng ECDSA và **nhân bản thiết bị FIDO** — ví dụ **YubiKey 5
  Series firmware < 5.7** — qua vài phút đo kênh bên EM khi tiếp cận vật lý. Lỗi tồn
  tại **~14 năm**, vượt qua ~80 lần đánh giá chứng nhận Common Criteria cấp cao mà
  không bị phát hiện. Công bố 03/09/2024 (ePrint 2024/1380); Yubico vá bằng firmware
  5.7. **Bài học:** chứng nhận bảo mật cao **không** đảm bảo miễn nhiễm kênh bên.

## 5. Sự cố thư viện E2EE — libolm / Matrix (2024)

`libolm` (thư viện mã hóa đầu-cuối gốc của Matrix, dùng **Ed25519/Curve25519**) bị
**ngừng hỗ trợ** tháng 8/2024, chuyển sang `vodozemac` (Rust, dùng bộ `dalek` hằng
thời gian). Đợt rà soát (nhà nghiên cứu **Soatok**) công bố nhiều CVE:
**CVE-2024-45191** (AES cache-timing), **CVE-2024-45192** (timing trong ECDH),
**CVE-2024-45193** (rò rỉ timing/base64 + **tính uốn nắn của chữ ký Ed25519**).
**Ý nghĩa:** ngay cả **EdDSA/Ed25519** — vốn tất định và an toàn về thiết kế — vẫn
có thể triển khai sai (không hằng thời gian, cho phép uốn nắn) nếu thiếu kiểm tra
chuẩn tắc và bảo vệ kênh bên.

## 6. Nhận xét: loại lỗi nào tái diễn nhiều nhất?

| Nhóm lỗi | Số sự cố tiêu biểu ở trên | Ghi chú |
|---|---|---|
| Nonce (A) | 3 (PS3, Android, Biased Nonce Sense) | Gây mất mát trực tiếp, dễ khai thác nhất |
| Kênh bên (B) | 5 (Minerva, TPM-Fail, LadderLeak, Titan, EUCLEAK) | Phổ biến trên thẻ/token/TPM; ngưỡng rò rỉ cực thấp |
| Triển khai (D) | 3 (Psychic, CurveBall, libolm) | "Một dòng kiểm tra" quyết định an ninh |
| Backdoor (C4) | 1 (Juniper) | Hiếm nhưng hậu quả chiến lược |
| Toán học thuần (C1–C3) | 0 | **Chưa** có vụ phá đường cong chuẩn 256-bit thực tế |

> **Kết luận quan trọng của toàn đề tài:** trong thực tế, ECDSA **hầu như không bao
> giờ bị phá bằng cách tấn công toán học vào đường cong**. Mọi thất bại đều đến từ
> **nonce yếu, rò rỉ kênh bên, hoặc thiếu kiểm tra đầu vào** — tức là **lỗi ở khâu
> triển khai và sinh ngẫu nhiên**, không phải ở nền tảng lý thuyết. Đây chính là lý
> do các biện pháp ở [chương 06](06-phong-chong.md) tập trung vào cài đặt đúng
> (deterministic nonce, constant-time, validation) hơn là vào chọn đường cong mạnh
> hơn.

Nguồn trích dẫn đầy đủ xem [chương 07 — Tài liệu tham khảo](07-tai-lieu-tham-khao.md).
