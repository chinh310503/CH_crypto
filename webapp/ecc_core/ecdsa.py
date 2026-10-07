from __future__ import annotations
import hashlib
import secrets
from math import gcd

from .curve import EllipticCurve, Point, inverse_mod


def _hash_to_int(msg: bytes, n: int) -> int:
    digest = hashlib.sha256(msg).digest()
    e = int.from_bytes(digest, "big")

    bits_excess = e.bit_length() - n.bit_length()
    if bits_excess > 0:
        e >>= bits_excess
    return e % n


def keygen(curve: EllipticCurve):
    d = secrets.randbelow(curve.n - 1) + 1
    Q = curve.mul(d, curve.G)
    return d, Q


def sign(curve: EllipticCurve, d: int, msg: bytes, k: int | None = None):
    n = curve.n
    z = _hash_to_int(msg, n)
    
    if k is None and gcd(gcd(d, z), n) != 1:
        raise ValueError("thông điệp không ký được trên đường cong bậc hợp số "
                         "(gcd(d, z, n) > 1) — hãy đổi thông điệp")
    for _ in range(4096):
        k_use = secrets.randbelow(n - 1) + 1 if k is None else k
        if gcd(k_use, n) != 1:
            if k is not None:
                raise ValueError("k không khả nghịch modulo n, hãy chọn k khác")
            continue
        R = curve.mul(k_use, curve.G)
        r = R.x % n
        if r == 0:
            if k is not None:
                raise ValueError("k cố định cho ra r = 0, hãy chọn k khác")
            continue
        s = (inverse_mod(k_use, n) * (z + r * d)) % n
        if s == 0 or gcd(s, n) != 1:
            if k is not None:
                raise ValueError("k cố định cho ra s không hợp lệ, hãy chọn k khác")
            continue
        return r, s, z
    raise ValueError("không sinh được nonce hợp lệ sau nhiều lần thử")


def verify(curve: EllipticCurve, Q: Point, msg: bytes, r: int, s: int) -> bool:
    n = curve.n

    if not (1 <= r <= n - 1):
        return False
    if not (1 <= s <= n - 1):
        return False
    z = _hash_to_int(msg, n)
    try:
        w = inverse_mod(s, n)
    except ZeroDivisionError:
        return False
    u1 = (z * w) % n
    u2 = (r * w) % n
    P = curve.add(curve.mul(u1, curve.G), curve.mul(u2, Q))
    if P.is_infinity():
        return False
    return (P.x % n) == (r % n)


def verify_insecure(curve: EllipticCurve, Q: Point, msg: bytes, r: int, s: int) -> bool:
    n = curve.n
    
    z = _hash_to_int(msg, n)
    if s % n == 0:

        P = curve.O
    else:
        w = inverse_mod(s, n)
        u1 = (z * w) % n
        u2 = (r * w) % n
        P = curve.add(curve.mul(u1, curve.G), curve.mul(u2, Q))
    x = 0 if P.is_infinity() else (P.x % n)
    return x == (r % n)
