"""Đường cong ENTERPRISE cố tình yếu cho demo Pohlig-Hellman.

Supersingular  y^2 = x^3 + x  trên F_p (p ≡ 3 mod 4) ⇒ #E = p + 1.
Trường ~256 bit nên TRÔNG an toàn, nhưng bậc nhóm lại TRƠN:
    #E = p+1 = 2^2 * 3 * 23 * 61 * 71 * 103 * 127^2 * 131 * 149 * 167^2 * 239 * 263^2 * 293 * 307^3 * 337 * 359 * 379 * 409 * 419 * 421^2 * 433 * 479 * 491 * 499 * 17179870819
Thừa số nguyên tố lớn nhất chỉ ~2^34 ⇒ Pohlig-Hellman phá được.
Sinh tự động bởi tools/gen_weak_curve.py — KHÔNG chỉnh tay.
"""
from .curve import EllipticCurve

WEAK_CURVE = EllipticCurve(
    a=1, b=0,
    p=184210765362223284900631179355377792325086599802998802172720921610366430059891,
    n=15350897113518607075052598279614816027090549983583233514393410134197202504991,
    Gx=68730364934624542280813202225456790068153066925008984355286335369360741402352,
    Gy=22062019645145943788975788091531110840002164296750817101821233732330039809681,
    name='enterprise-weak')
