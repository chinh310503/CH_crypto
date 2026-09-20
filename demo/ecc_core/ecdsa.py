"""Lược đồ chữ ký số ECDSA — bản cài đặt tối giản cho mục đích giáo dục.

Cung cấp cả bản xác minh AN TOÀN (`verify`) lẫn bản CÓ LỖI (`verify_insecure`)
để phục vụ demo CVE-2022-21449 (Psychic Signatures).
"""
from __future__ import annotations
import hashlib
import secrets
from math import gcd

from .curve import EllipticCurve, Point, inverse_mod


def _hash_to_int(msg: bytes, n: int) -> int:
    """z = H(m), lấy đúng số bit của n (theo đặc tả ECDSA)."""
    digest = hashlib.sha256(msg).digest()
    e = int.from_bytes(digest, "big")
    # cắt bớt cho khớp độ dài bit của n
    bits_excess = e.bit_length() - n.bit_length()
    if bits_excess > 0:
        e >>= bits_excess
    return e % n


def keygen(curve: EllipticCurve):
    """Sinh cặp khóa (d, Q) với d bí mật, Q = d*G công khai."""
    d = secrets.randbelow(curve.n - 1) + 1
    Q = curve.mul(d, curve.G)
    return d, Q


def sign(curve: EllipticCurve, d: int, msg: bytes, k: int | None = None):
    """Ký thông điệp. Cho phép truyền k để MÔ PHỎNG lỗi nonce (reuse/biased).

    Trả về (r, s, z) — kèm z để tiện cho demo (z vốn tính được công khai).
    """
    n = curve.n
    z = _hash_to_int(msg, n)
    # Bậc n hợp số (đường cong yếu) có thể khiến (d, z) không ký được → báo sớm, tránh treo.
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
    """Xác minh ĐÚNG CHUẨN — có bước kiểm tra biên r, s ∈ [1, n-1]."""
    n = curve.n
    # [BƯỚC BẢO VỆ] — chính bước này bị thiếu trong CVE-2022-21449
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
    """Xác minh CÓ LỖI — mô phỏng cơ chế CVE-2022-21449 (Psychic Signatures).

    Bỏ bước kiểm tra r, s ∈ [1, n-1]. Với chữ ký (r=0, s=0), phép tính suy biến
    cho ra điểm vô cực, và cài đặt lỗi coi hoành độ của điểm vô cực bằng 0 nên
    phép so sánh r == x trở thành 0 == 0 → luôn hợp lệ.
    """
    n = curve.n
    # (KHÔNG có bước kiểm tra biên — đây chính là lỗ hổng)
    z = _hash_to_int(msg, n)
    if s % n == 0:
        # inverse(0) không tồn tại; cài đặt lỗi không xử lý ngoại lệ này mà để
        # phép nhân điểm suy biến về O.
        P = curve.O
    else:
        w = inverse_mod(s, n)
        u1 = (z * w) % n
        u2 = (r * w) % n
        P = curve.add(curve.mul(u1, curve.G), curve.mul(u2, Q))
    x = 0 if P.is_infinity() else (P.x % n)   # <-- lỗi: coi x(O) = 0
    return x == (r % n)
