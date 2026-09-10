"""Số học cần cho tấn công: kiểm tra nguyên tố (Miller-Rabin) và phân tích thừa số
(trial division + Pollard rho). Đủ nhanh để factor một bậc nhóm 256-bit *trơn*
(mọi thừa số nguyên tố tương đối nhỏ) — chính là điều khiến Pohlig-Hellman khả thi.
"""
from __future__ import annotations
import math
import random

_SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in _SMALL:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in _SMALL:                       # đủ mạnh cho phạm vi demo
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _pollard_rho(n: int) -> int:
    if n % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, n)
        y, c, d = x, random.randrange(1, n), 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factorize(n: int, small_bound: int = 100_000) -> dict:
    """Trả về {prime: exponent}. Chia thử tới `small_bound`, phần còn lại xử lý
    bằng kiểm tra nguyên tố + Pollard rho."""
    factors: dict[int, int] = {}
    d = 2
    while d <= small_bound and d * d <= n:
        while n % d == 0:
            factors[d] = factors.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n == 1:
        return factors
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if is_prime(m):
            factors[m] = factors.get(m, 0) + 1
            continue
        f = _pollard_rho(m)
        stack.append(f)
        stack.append(m // f)
    return factors
