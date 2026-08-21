# Chương 03 — Tấn công toán học & đường cong yếu

> Thuộc nhóm **C** trong [cây phân loại](00-tong-quan-va-phan-loai.md). Khác với
> các chương trước (khai thác lỗi cài đặt/rò rỉ), chương này bàn về **bản thân
> nền tảng toán học** của ECDSA: khi nào bài toán ECDLP thực sự khó, và những
> **họ đường cong / tham số** khiến nó sụp đổ.
>
> **Thông điệp xuyên suốt:** với đường cong chuẩn được chọn đúng, tấn công toán
> học vào ECDLP là **bất khả thi trên thực tế** (kỷ lục công khai mới ~112-bit).
> Rủi ro thật nằm ở **lựa chọn tham số sai** (đường cong yếu, cửa hậu) và **thiếu
> kiểm tra điểm** (invalid curve) — không phải ở độ khó nội tại của ECDLP.

---

## Phần I. Tấn công tổng quát vào ECDLP

**Bài toán ECDLP:** cho đường cong $E$, điểm cơ sở $P$ bậc $n$, và $Q = kP$; tìm
$k$. Với đường cong chọn tốt, thuật toán tốt nhất đã biết vẫn là **hàm mũ**
$O(\sqrt{n})$ — đây là lý do ECC dùng khóa ngắn hơn nhiều so với RSA (256-bit ECC
≈ 3072-bit RSA về mức an toàn).

### 1. Baby-step Giant-step (Shanks, 1971)
- **Cơ chế:** đặt $m = \lceil\sqrt{n}\rceil$, viết $k = im + j$ với $0 \le i,j < m$.
  Lập bảng "baby steps" $\{jP\}$ rồi duyệt "giant steps" $Q - i(mP)$ để tìm trùng
  khớp; khi trùng, $k = im + j$.
- **Độ phức tạp:** thời gian $O(\sqrt{n})$ **và bộ nhớ $O(\sqrt{n})$**. Chính nhu
  cầu lưu trữ khổng lồ khiến nó không thực dụng ở quy mô mật mã. Thuật toán **tất
  định**.

### 2. Pollard's rho và song song hóa (van Oorschot–Wiener)
- **Cơ chế:** dùng "bước đi giả ngẫu nhiên" trên nhóm $\langle P \rangle$, dạng
  $X_{i+1} = f(X_i)$ với $X_i = a_i P + b_i Q$. Theo nghịch lý ngày sinh, sẽ xuất
  hiện va chạm $a_1 P + b_1 Q = a_2 P + b_2 Q$, từ đó
  $k = (a_1 - a_2)(b_2 - b_1)^{-1} \bmod n$.
- **Độ phức tạp:** kỳ vọng $\sqrt{\pi n / 2} \approx 0{,}886\sqrt{n}$ phép toán
  nhóm, **bộ nhớ không đáng kể** (phát hiện chu trình Floyd/Brent). Đây là **vũ
  khí thực dụng số một** chống ECDLP hiện nay.
- **Song song hóa (đóng góp then chốt):** van Oorschot–Wiener (J. Cryptology 1999)
  dùng **phương pháp điểm phân biệt (distinguished points)** — mỗi máy chạy walk
  riêng, chỉ lưu các điểm có tính chất đặc biệt vào danh sách chung; va chạm được
  phát hiện khi một điểm phân biệt xuất hiện lần hai. Cho **tăng tốc tuyến tính**:
  với $m$ máy, thời gian $\approx \sqrt{\pi n/2}/m$. Đây là nền tảng của mọi kỷ lục
  giải ECDLP.

### 3. Pohlig–Hellman (1978)
- **Cơ chế:** nếu $n = \prod_i p_i^{e_i}$, ECDLP trong nhóm bậc $n$ được **phân rã
  qua CRT** thành các ECDLP con trong nhóm con bậc $p_i^{e_i}$; mỗi bài con giải
  bằng BSGS/rho với chi phí $\sim \sqrt{p_i}$.
- **Hệ quả:** độ an toàn thực tế **chỉ bằng $\sqrt{p_{\max}}$** với $p_{\max}$ là
  thừa số nguyên tố lớn nhất của $n$. Nếu $n$ "trơn" (chỉ gồm thừa số nhỏ), ECDLP
  sụp đổ.
- **Đối phó:** chọn đường cong có **bậc $n$ là số nguyên tố** (hoặc nguyên tố lớn
  nhân cofactor nhỏ). Đây là lý do các chuẩn NIST/SEC đều yêu cầu bậc nguyên tố.

### 4. Vì sao Index Calculus KHÔNG hiệu quả với đường cong tổng quát
Trong trường hữu hạn $\mathbb{F}_p^*$, index calculus đạt **dưới mũ** nhờ khái niệm
"phần tử trơn" để dựng **factor base**. Trên đường cong elliptic **không có khái
niệm tự nhiên về độ trơn** — các điểm không "phân tích" thành điểm nhỏ hơn — nên
không có factor base hiển nhiên. Semaev (2004) đề xuất **đa thức tổng (summation
polynomials)**; Gaudry và Diem mở rộng cho **trường mở rộng** $\mathbb{F}_{q^n}$,
nhưng với **trường nguyên tố** $\mathbb{F}_p$ (P-256, secp256k1…) các kỹ thuật này
**vẫn không cho lời giải dưới mũ thực dụng**. Đây chính là cơ sở giữ vững an toàn
của ECDLP.

### 5. Kỷ lục giải ECDLP (Certicom ECC Challenges)
- **ECCp-109** (109-bit, trường nguyên tố): giải **2002** bởi nhóm Chris Monico,
  dùng Pollard rho song song trên hàng nghìn máy trong nhiều tháng.
- **secp112r1** (112-bit): Bos, Kaihara, Kleinjung, Lenstra, Montgomery (2009) giải
  trên cụm **~200 máy PlayStation 3** tại EPFL trong ~3,5 tháng.
- **ECC2K-130** (131-bit, Koblitz): mục tiêu của chiến dịch phân tán lớn dùng CPU,
  PS3, GPU, FPGA — các thử thách mức 131-bit về cơ bản vẫn **ngoài tầm với**.
- **Kết luận:** kỷ lục công khai mới ở mức ~112–113 bit. Đường cong 256-bit
  (P-256, secp256k1) có biên an toàn **cực lớn** trước tấn công cổ điển.

---

## Phần II. Tấn công vào đường cong đặc biệt / yếu

Ý tưởng chung: **quy giản** ECDLP về một bài toán DLP dễ hơn trong cấu trúc khác.

### 1. MOV attack (Menezes–Okamoto–Vanstone, 1993) — Weil pairing
- **Cơ chế:** dùng **cặp Weil** $e_n: E[n] \times E[n] \to \mathbb{F}_{q^k}^*$ để
  **nhúng** $\langle P \rangle$ vào nhóm nhân $\mathbb{F}_{q^k}^*$ của trường mở
  rộng. ECDLP $Q = kP$ biến thành DLP thông thường
  $e_n(Q, R) = e_n(P, R)^k$ trong $\mathbb{F}_{q^k}^*$, nơi áp dụng được index
  calculus dưới mũ.
- **Điều kiện yếu:** **bậc nhúng (embedding degree)** $k$ — số nhỏ nhất sao cho
  $n \mid q^k - 1$ — phải **nhỏ**. Đường cong **siêu kỳ dị (supersingular)** có
  $k \le 6$ → cực kỳ nguy hiểm.
- **Đối phó:** yêu cầu bậc nhúng $k$ **đủ lớn**. Nghịch lý thú vị: chính thuộc tính
  "bậc nhúng nhỏ" lại được khai thác **có chủ đích** trong mật mã dựa trên pairing
  (IBE Boneh–Franklin, chữ ký BLS).

### 2. Frey–Rück (1994) — Tate pairing
- **Cơ chế:** tương tự MOV nhưng dùng **cặp Tate**, **tổng quát và hiệu quả tính
  toán hơn** — áp dụng được cả cho **đường cong thường (ordinary)** miễn là bậc
  nhúng nhỏ.
- **Ví dụ:** *Solving Discrete Logarithms on a 170-bit MNT Curve by Pairing
  Reduction* (2017) minh họa phá một đường cong MNT bậc nhúng nhỏ ~170-bit.

### 3. Smart's attack (1999) — đường cong dị thường (anomalous)
- **Cơ chế:** đường cong **dị thường** có **số điểm bằng đúng $p$**, tức
  $\#E(\mathbb{F}_p) = p$ (vết Frobenius $t = 1$). Qua **nâng $p$-adic** lên
  $\mathbb{Q}_p$ và dùng **logarithm elliptic $p$-adic**, ECDLP quy về một phép chia
  trong **nhóm cộng $\mathbb{F}_p$** — giải được trong **thời gian đa thức** (gần
  tuyến tính). Đường cong 256-bit dị thường có thể bị phá gần như tức thời.
- **Phát hiện độc lập gần đồng thời:** Smart (1999); Satoh–Araki (1998);
  Semaev (1998).
- **Đối phó:** kiểm tra $\#E(\mathbb{F}_p) \neq p$.

### 4. Điều kiện "đường cong an toàn" (tổng hợp)
Một đường cong dùng cho ECDSA cần **đồng thời**:

| # | Điều kiện | Chống tấn công |
|---|---|---|
| 1 | Bậc $n$ nguyên tố (cofactor nhỏ) | Pohlig–Hellman |
| 2 | Bậc nhúng $k$ lớn | MOV / Frey–Rück |
| 3 | Không dị thường ($\#E(\mathbb{F}_p) \neq p$) | Smart |
| 4 | $n$ đủ lớn (≥ ~256-bit) | Pollard's rho |

---

## Phần III. Tấn công triển khai liên quan đến đường cong

Nhóm này **không phá toán học của đường cong hợp lệ**, mà khai thác **thiếu kiểm
tra điểm đầu vào** (point validation) — nằm ở ranh giới với [chương 04](04-loi-trien-khai.md).

### 1. Invalid Curve Attack (đường cong không hợp lệ)
- **Cơ chế:** công thức cộng điểm trên Weierstrass $y^2 = x^3 + ax + b$ **không dùng
  đến tham số $b$**. Kẻ tấn công gửi "điểm" $P'$ nằm trên đường cong **khác**
  $E': y^2 = x^3 + ax + b'$ (chọn $b'$ để $E'$ có nhóm con bậc nhỏ). Nếu nạn nhân
  không kiểm tra $P'$ có thuộc đường cong hợp lệ, phép nhân $d \cdot P'$ diễn ra
  trên $E'$, làm **rò rỉ $d \bmod r$** với $r$ nhỏ. Lặp với nhiều $E'$ rồi ghép
  bằng **CRT** để khôi phục toàn bộ $d$. Đặc biệt nguy hiểm với ECDH.
- **Mốc quan trọng:**
  - Biehl, Meyer, Müller — *Differential Fault Attacks on Elliptic Curve
    Cryptosystems* (CRYPTO 2000): nền tảng ý tưởng.
  - Antipa, Brown, Menezes, Struik, Vanstone — *Validation of Elliptic Curve Public
    Keys* (PKC 2003): hình thức hóa + biện pháp kiểm tra khóa công khai.
  - Jager, Schwenk, Somorovsky — *Practical Invalid Curve Attacks on TLS-ECDH*
    (**ESORICS 2015**): tấn công **thực tế** — khảo sát 8 thư viện, phát hiện
    **Oracle JSSE (SunEC)** và **Bouncy Castle** không kiểm tra điểm → **trích xuất
    khóa riêng dài hạn** từ máy chủ TLS-ECDH.
- **Đối phó:** luôn kiểm tra điểm nhận được thỏa phương trình đường cong hợp lệ và
  nằm trong nhóm con đúng.

### 2. Sự cố thực tế — CurveBall (CVE-2020-0601)
Lỗ hổng trong **Windows CryptoAPI** (`crypt32.dll`) khi xác thực chứng chỉ ECC: nó
kiểm tra khóa công khai của chứng chỉ khớp với khóa của một CA tin cậy **nhưng
không kiểm tra điểm sinh `G`** của tham số đường cong. Kẻ tấn công chọn một `G'`
tùy biến sao cho chứng chỉ giả vẫn "khớp" CA gốc → **giả mạo chứng chỉ ký mã hoặc
TLS**. **Do NSA phát hiện và báo cáo**, công bố **14/01/2020**. Đây là ví dụ điển
hình của lỗi **thiếu kiểm tra đầy đủ tham số miền** (cụ thể là điểm sinh).

### 3. Twist Attack (đường cong xoắn)
- **Cơ chế:** trong triển khai chỉ dùng **tọa độ $x$** (Montgomery ladder, ví dụ
  X25519), một giá trị $x$ tùy ý có thể tương ứng điểm trên **đường cong xoắn bậc
  hai** $E'$. Nếu bậc của twist $E'$ có thừa số nhỏ, kẻ tấn công gửi $x$ thuộc
  twist để thực hiện small-subgroup attack trên twist, rò rỉ khóa.
- **Đối phó — "twist security":** chọn đường cong sao cho cả bậc của $E$ lẫn twist
  $E'$ đều gần nguyên tố. **Curve25519 được thiết kế twist-secure** nên miễn nhiễm.

### 4. Small Subgroup Attack
- **Cơ chế:** khi cofactor $h > 1$, tồn tại nhóm con bậc nhỏ. Kẻ tấn công gửi điểm
  bậc nhỏ $r$; kết quả bị giới hạn trong nhóm con bậc $r$, làm lộ khóa $\bmod\ r$.
  Ghép nhiều $r$ qua CRT.
- **Mốc:** Lim–Lee (CRYPTO 1997, bối cảnh DH); đo lường thực tế bởi Valenta và cộng
  sự (NDSS 2017).
- **Đối phó:** nhân cofactor / kiểm tra bậc điểm; hoặc dùng đường cong cofactor $h=1$.

---

## Phần IV. Đường cong / tham số bị nghi ngờ cài cửa hậu (Backdoor)

### 1. Dual_EC_DRBG — bộ sinh số ngẫu nhiên có cửa hậu
- **Bản chất:** Dual_EC_DRBG (chuẩn hóa trong **NIST SP 800-90A**) là bộ sinh bit
  ngẫu nhiên tất định dựa trên ECC, dùng **hai điểm $P, Q$** trên NIST P-256.
- **Cửa hậu toán học:** nếu tồn tại $d$ sao cho $P = dQ$ (kẻ dựng biết log rời rạc
  giữa $P$ và $Q$), thì chỉ cần quan sát **~30 byte đầu ra** là **khôi phục được
  trạng thái nội bộ và tiên đoán toàn bộ đầu ra tương lai**. Giá trị $Q$ mặc định
  do **NSA** cung cấp mà không giải thích cách tạo.
- **Mốc thời gian:**
  - **2007:** Shumow & Ferguson (Microsoft) nêu khả năng cửa hậu tại rump session
    CRYPTO 2007.
  - **2013:** rò rỉ Snowden (chiến dịch **BULLRUN**) củng cố nghi ngờ; RSA BSAFE bị
    cho là đặt Dual_EC làm mặc định.
  - **2014:** **NIST rút Dual_EC_DRBG** khỏi khuyến nghị.
  - Checkoway và cộng sự — *On the Practical Exploitability of Dual EC in TLS
    Implementations* (USENIX Security 2014).

### 2. Sự cố Juniper ScreenOS (2015)
Tháng 12/2015 Juniper công bố phát hiện **"mã trái phép"** trong ScreenOS (thiết bị
NetScreen VPN) — **CVE-2015-7755** và **CVE-2015-7756**. ScreenOS dùng Dual_EC
(đáng lẽ được "vô hiệu" bằng lớp PRNG ANSI X9.31), nhưng: (a) một khiếm khuyết làm
**đầu ra Dual_EC thô bị lộ**, và (b) **một bên không rõ danh tính đã đổi giá trị
$Q$** thành hằng số riêng của họ (~2012) → biến cửa hậu "của NSA" thành cửa hậu của
**chính kẻ tấn công**, cho phép **giải mã lưu lượng VPN**.
- **Phân tích:** Checkoway, Maskiewicz, Garman, Fried, Cohney, Green, Heninger,
  Weinmann, Rescorla, Shacham — *A Systematic Analysis of the Juniper Dual EC
  Incident* (**ACM CCS 2016**). Minh chứng thực tế rằng cửa hậu trong tham số có
  thể bị lợi dụng ngoài đời thực.

### 3. "Nothing-up-my-sleeve" và sự ra đời của Curve25519
- **Vấn đề với NIST P-curves:** các đường cong P-192/224/256… sinh từ **SHA-1 của
  một "seed" không được giải thích**. Vì seed tùy ý và không minh bạch, nếu tồn tại
  lớp đường cong yếu bí mật, về lý thuyết người sinh tham số có thể **dò seed** cho
  ra đường cong nằm trong lớp yếu đó — không ai kiểm chứng được. Sự cố Dual_EC làm
  dấy lên nghi ngờ tương tự với niềm tin vào tham số NIST.
- **"Nothing-up-my-sleeve numbers":** chọn hằng số từ nguồn **hiển nhiên, không thể
  giả mạo** (chữ số của $\pi$, "số nhỏ nhất thỏa điều kiện") để chứng minh không
  giấu cửa hậu.
- **Curve25519 (Bernstein, PKC 2006):** mọi hằng số đều minh bạch, kiểm chứng được:
  trường $p = 2^{255} - 19$; đường cong Montgomery $y^2 = x^3 + 486662x^2 + x$ với
  $A = 486662$ là giá trị **nhỏ nhất** thỏa điều kiện an toàn/hiệu năng; điểm cơ sở
  $x = 9$. **Twist-secure**, cofactor nhỏ, tránh mọi suy biến.
- **SafeCurves (Bernstein & Lange, 2013+):** bộ tiêu chí công khai đánh giá độ an
  toàn đường cong, gồm khái niệm **"rigidity"** (độ minh bạch của quá trình sinh
  tham số). Ed25519 (chữ ký) và X25519 (trao đổi khóa) nay được dùng rộng rãi
  (TLS 1.3, SSH, Signal…).

---

## Tổng kết chương

- **ECDLP với đường cong chuẩn:** an toàn vững chắc; tấn công tổng quát tốt nhất là
  Pollard's rho $O(\sqrt{n})$, kỷ lục mới ~112-bit ⇒ đường cong 256-bit an toàn.
- **Đường cong yếu** (supersingular/bậc nhúng nhỏ, dị thường, bậc trơn): bị phá bởi
  MOV/Frey–Rück, Smart, Pohlig–Hellman ⇒ **phải chọn tham số đúng chuẩn**.
- **Lỗi thiếu kiểm tra điểm** (invalid curve/twist/small subgroup, CurveBall):
  nguy hiểm thực tế cao ⇒ **luôn xác thực điểm & tham số miền**.
- **Cửa hậu tham số** (Dual_EC, nghi ngờ NIST): thúc đẩy xu hướng chuyển sang các
  đường cong minh bạch (Curve25519/Ed25519).

Mối đe dọa dài hạn — **thuật toán Shor** trên máy tính lượng tử phá ECDLP trong
thời gian đa thức — được đề cập ở [chương 06 §5](06-phong-chong.md).
Nguồn trích dẫn đầy đủ xem [chương 07](07-tai-lieu-tham-khao.md).
