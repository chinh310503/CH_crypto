"""Đường cong OMNICORP cố tình yếu cho web demo (ECDSA thật).

TRÔNG NHƯ ĐƯỜNG CONG THẬT: cùng dạng với secp256k1  y^2 = x^3 + b  (a = 0),
trường nguyên tố p ~256 bit, bậc điểm sinh n ~256 bit. Nhìn tham số công khai
(a, b, p, n, G) gần như không phân biệt được với một đường cong chuẩn.

ĐIỂM YẾU ẨN: chọn p ≡ 2 (mod 3) nên đường cong là SUPERSINGULAR và #E = p + 1;
p được chọn sao cho p + 1 là số TRƠN (mọi thừa số nguyên tố ≤ ~2^36). Vì vậy dù
n ~256 bit, chỉ cần PHÂN TÍCH THỪA SỐ n là thấy nó trơn → Pohlig–Hellman + BSGS
khôi phục khóa riêng trong ~10-15s (thay vì ~2^128 như đường cong chuẩn).

Sinh tự động bởi tools/gen_weak_curve.py — KHÔNG chỉnh tay.
"""
from .curve import EllipticCurve

WEAK_CURVE = EllipticCurve(
    a=0,
    b=95629663359382215948757156568554414388821931397123170840157877963107147559091,
    p=317898947492701219360988861516335550838944457830666552289487817265977313526139,
    n=317898947492701219360988861516335550838944457830666552289487817265977313526140,
    Gx=268939492648433334770647888188866705849585133214072461260505837474016950346746,
    Gy=90685332260530970562115753546813157094563931595113825120097259427727924053297,
    name='omnicorp-256')
