"""Tham số các đường cong dùng trong demo.

- SECP256K1: đường cong thật (dùng trong Bitcoin/Ethereum) cho demo nonce reuse
  và psychic signatures.
- Đường cong "đồ chơi" có bậc TRƠN (smooth) cho demo Pohlig-Hellman được nạp từ
  file `toy_curve.py` (sinh sẵn bằng script `tools/gen_smooth_curve.py`).
"""
from __future__ import annotations
from .curve import EllipticCurve

# ---------------------------------------------------------------------------
# secp256k1 — đường cong thật, y^2 = x^3 + 7
# ---------------------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

SECP256K1 = EllipticCurve(a=0, b=7, p=_P, n=_N, Gx=_GX, Gy=_GY, name="secp256k1")


def load_toy_smooth():
    """Nạp đường cong đồ chơi bậc trơn cho demo Pohlig-Hellman.

    Trả về đối tượng EllipticCurve đã gắn G và n. Import trễ để hai demo còn lại
    không phụ thuộc vào file sinh sẵn.
    """
    from .toy_curve import TOY_SMOOTH
    return TOY_SMOOTH
