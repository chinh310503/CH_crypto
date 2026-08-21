"""Sinh một đường cong elliptic đồ chơi có BẬC TRƠN (smooth order) cho demo
Pohlig-Hellman, rồi ghi kết quả ra ecc_core/toy_curve.py.

Ý tưởng: chọn p nguyên tố nhỏ (đủ nhỏ để đếm điểm bằng vét cạn), duyệt các
(a, b) đến khi tìm được đường cong mà #E(F_p) chỉ gồm các thừa số nguyên tố nhỏ
và có NHIỀU thừa số phân biệt (để phần ghép CRT trong demo sinh động).

Chạy:  python tools/gen_smooth_curve.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core.curve import EllipticCurve  # noqa: E402


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for q in small:
        if n % q == 0:
            return n == q
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in small:
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


def factorize(n: int) -> dict:
    f = {}
    d = 2
    while d * d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f


def find_prime_3mod4(around: int) -> int:
    """Tìm số nguyên tố p ≡ 3 (mod 4) gần `around` (để khai căn mod p dễ)."""
    p = around | 1
    while not (p % 4 == 3 and is_prime(p)):
        p += 2
    return p


def build_qr_set(p: int) -> set:
    """Tập các thặng dư bậc hai khác 0 modulo p."""
    qr = set()
    for i in range(1, (p + 1) // 2):
        qr.add(i * i % p)
    return qr


def curve_order(a: int, b: int, p: int, qr: set) -> int:
    total = 1  # điểm vô cực
    for x in range(p):
        t = (x * x * x + a * x + b) % p
        if t == 0:
            total += 1
        elif t in qr:
            total += 2
    return total


def sqrt_mod_3mod4(t: int, p: int) -> int:
    return pow(t, (p + 1) // 4, p)


def point_order(curve: EllipticCurve, P, N: int, factors: dict) -> int:
    """Tính bậc của điểm P, biết bậc nhóm N và phân tích thừa số của N."""
    o = N
    for q, e in factors.items():
        o //= q ** e
        Q = curve.mul(o, P)
        while not Q.is_infinity():
            Q = curve.mul(q, Q)
            o *= q
    return o


def main():
    around = 1_000_003            # p ~ 10^6
    p = find_prime_3mod4(around)
    print(f"[*] Chọn p = {p}  (p ≡ 3 mod 4, nguyên tố)")

    print("[*] Tiền tính tập thặng dư bậc hai (QR)…")
    qr = build_qr_set(p)

    SMOOTH_BOUND = 2500           # mọi thừa số nguyên tố phải <= bound này
    MIN_DISTINCT = 4              # cần ít nhất chừng này thừa số phân biệt
    best = None

    print("[*] Duyệt (a, b) tìm đường cong bậc trơn…")
    count = 0
    for b in range(1, 400):
        for a in (0, 1, 2, 3, 5, 7):
            # tránh đường cong suy biến: 4a^3 + 27b^2 != 0
            if (4 * a * a * a + 27 * b * b) % p == 0:
                continue
            count += 1
            N = curve_order(a, b, p, qr)
            fac = factorize(N)
            maxf = max(fac)
            distinct = len(fac)
            if maxf <= SMOOTH_BOUND and distinct >= MIN_DISTINCT:
                print(f"    -> a={a}, b={b}, N={N}, factors={fac}")
                best = (a, b, N, fac)
                break
            if count % 25 == 0:
                print(f"    …đã thử {count} đường cong")
        if best:
            break

    if not best:
        print("!!! Không tìm thấy. Hãy nới SMOOTH_BOUND hoặc giảm MIN_DISTINCT.")
        sys.exit(1)

    a, b, N, fac = best
    curve = EllipticCurve(a=a, b=b, p=p, n=N, name="toy-smooth")

    # tìm điểm sinh có bậc lớn nhất (lý tưởng = N nếu nhóm cyclic)
    print("[*] Tìm điểm sinh G…")
    G = None
    best_ord = 0
    for x in range(2, p):
        t = (x * x * x + a * x + b) % p
        if t == 0 or t not in qr:
            continue
        y = sqrt_mod_3mod4(t, p)
        P = curve.point(x, y)
        ordP = point_order(curve, P, N, fac)
        if ordP > best_ord:
            best_ord, G = ordP, P
        if best_ord == N:
            break

    n = best_ord
    nfac = factorize(n)
    print(f"[*] G = ({G.x}, {G.y}), bậc n = {n}, factors = {nfac}")

    out = os.path.join(os.path.dirname(__file__), "..", "ecc_core", "toy_curve.py")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write('"""Đường cong đồ chơi bậc TRƠN cho demo Pohlig-Hellman.\n')
        fh.write("Sinh tự động bởi tools/gen_smooth_curve.py — KHÔNG chỉnh tay.\n")
        fh.write('"""\n')
        fh.write("from .curve import EllipticCurve\n\n")
        fh.write(f"# y^2 = x^3 + {a}x + {b}  (mod {p})\n")
        fh.write(f"# bậc nhóm #E = {N} = {fac}\n")
        fh.write(f"# bậc điểm sinh n = {n} = {nfac}\n")
        fh.write(f"TOY_SMOOTH = EllipticCurve(a={a}, b={b}, p={p}, n={n},\n")
        fh.write(f"                           Gx={G.x}, Gy={G.y}, name='toy-smooth')\n")
    print(f"[*] Đã ghi {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
