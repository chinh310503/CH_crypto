"""Đường cong đồ chơi bậc TRƠN cho demo Pohlig-Hellman.
Sinh tự động bởi tools/gen_smooth_curve.py — KHÔNG chỉnh tay.
"""
from .curve import EllipticCurve

# y^2 = x^3 + 0x + 1  (mod 1000003)
# bậc nhóm #E = 998004 = {2: 2, 3: 1, 7: 1, 109: 2}
# bậc điểm sinh n = 499002 = {2: 1, 3: 1, 7: 1, 109: 2}
TOY_SMOOTH = EllipticCurve(a=0, b=1, p=1000003, n=499002,
                           Gx=5, Gy=276697, name='toy-smooth')
