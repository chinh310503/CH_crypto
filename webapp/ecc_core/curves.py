"""Tham số các đường cong dùng trong CryptoBank.

- Các đường cong CHUẨN, AN TOÀN (secp256k1 + họ NIST P-192/224/256): mỗi tài khoản
  được gán ngẫu nhiên một trong số này, nên danh bạ khóa công khai trông đa dạng
  như hệ thống thật. Tất cả đều có bậc nhóm nguyên tố lớn → nonce reuse vẫn là con
  đường tấn công (không phải do đường cong yếu).
- Đường cong ENTERPRISE cố tình yếu (supersingular ~256 bit, bậc nhóm TRƠN) cho
  tấn công Pohlig-Hellman / Pollard's rho, nạp từ `weak_curve.py`.
"""
from __future__ import annotations
from .curve import EllipticCurve

# ---------------------------------------------------------------------------
# secp256k1 — y^2 = x^3 + 7 (Bitcoin/Ethereum)
# ---------------------------------------------------------------------------
SECP256K1 = EllipticCurve(
    a=0, b=7,
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    name="secp256k1")

# ---------------------------------------------------------------------------
# Họ NIST (a = -3): P-256 / P-224 / P-192 — đều an toàn, bậc n nguyên tố
# ---------------------------------------------------------------------------
SECP256R1 = EllipticCurve(  # NIST P-256
    a=-3, b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    Gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    Gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    name="secp256r1")

SECP224R1 = EllipticCurve(  # NIST P-224
    a=-3, b=0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
    p=0xffffffffffffffffffffffffffffffff000000000000000000000001,
    n=0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
    Gx=0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
    Gy=0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
    name="secp224r1")

SECP192R1 = EllipticCurve(  # NIST P-192
    a=-3, b=0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
    p=0xfffffffffffffffffffffffffffffffeffffffffffffffff,
    n=0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
    Gx=0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
    Gy=0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811,
    name="secp192r1")

# Nhóm đường cong chuẩn để gán ngẫu nhiên cho các tài khoản người dùng thường.
STANDARD_CURVES = [SECP256K1, SECP256R1, SECP224R1, SECP192R1]


def load_weak_curve():
    """Nạp đường cong enterprise cố tình yếu (supersingular ~256 bit, bậc trơn)
    cho demo Pohlig-Hellman. Import trễ để hai demo còn lại không phụ thuộc vào
    file sinh sẵn.
    """
    from .weak_curve import WEAK_CURVE
    return WEAK_CURVE
