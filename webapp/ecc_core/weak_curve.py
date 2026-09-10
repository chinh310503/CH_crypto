"""Đường cong ENTERPRISE cố tình yếu cho web demo (ECDSA thật).

Supersingular y^2 = x^3 + x trên F_p, p ~256 bit (trông như đường cong thật),
nhưng bậc điểm sinh chỉ là số nguyên tố q ~2^37 (cofactor ~2^219).
ECDSA chạy bình thường (q nguyên tố), nhưng Pollard's rho khôi phục khóa
riêng trong ~14s vì bậc quá nhỏ. Sinh bởi tools/gen_weak_curve.py.
"""
from .curve import EllipticCurve

WEAK_CURVE = EllipticCurve(
    a=1, b=0,
    p=92339102413839164430941710841035394235292725518804378605133442342442346410139,
    n=129455956997,
    Gx=78455472786888793278109395733552936536300000499639334694383516465603145772422,
    Gy=50464120003148375186728890165161897106825681000151195592321697721467778327350,
    name='enterprise-weak')
