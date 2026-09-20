"""Sinh đường cong supersingular (y²=x³+x, p ≡ 3 mod 4 ⇒ #E = p+1) trông ~256 bit
nhưng BẬC NHÓM TRƠN (thừa số lớn nhất ~2^34) → phá bằng Pohlig-Hellman. Chi tiết
cơ chế: xem demo/03_pohlig_hellman/README.md.

Chạy:  python tools/gen_weak_curve.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core.curve import EllipticCurve          # noqa: E402
from ecc_core.factor import is_prime               # noqa: E402

P_BITS = 256          # kích thước trường (trông như secp256k1)
Q_BITS = 34           # thừa số nguyên tố lớn nhất của bậc nhóm (điểm yếu ẩn)
MAX_SMALL = 500       # các thừa số của phần "trơn" đều < ngưỡng này


def build_smooth(target_bits, rng):
    """Dựng s ≡ 0 (mod 4), tích các số nguyên tố < MAX_SMALL, độ dài ~target_bits."""
    primes = [p for p in range(3, MAX_SMALL) if is_prime(p)]
    s, facs = 4, {2: 2}                            # đảm bảo 4 | s → p = q·s-1 ≡ 3 (mod 4)
    while s.bit_length() < target_bits:
        p = rng.choice(primes)
        s *= p
        facs[p] = facs.get(p, 0) + 1
    return s, facs


def find_curve(rng):
    while True:
        s, sfac = build_smooth(P_BITS - Q_BITS, rng)
        q = (1 << Q_BITS) | 1
        for _ in range(400_000):
            if is_prime(q):
                p = q * s - 1
                if abs(p.bit_length() - P_BITS) <= 6 and is_prime(p):
                    fac = dict(sfac)
                    fac[q] = 1
                    return p, q, s, fac
            q += 2
        # nếu không tìm được trong dải q, dựng lại s


def point_order(curve, P, N, fac):
    o = N
    for pr, e in fac.items():
        o //= pr ** e
        Q = curve.mul(o, P)
        while not Q.is_infinity():
            Q = curve.mul(pr, Q)
            o *= pr
    return o


def main():
    rng = random.Random(0xECD5A)
    print(f"[*] Tìm p ~{P_BITS} bit, q ~2^{Q_BITS} …")
    p, q, s, fac = find_curve(rng)
    N = p + 1                                       # = #E = q · s
    print(f"[*] p = {p}  ({p.bit_length()} bit)")
    print(f"[*] #E = p+1 = {N}")
    print(f"[*] thừa số nguyên tố lớn nhất q = {q}  (2^{q.bit_length()-1}+)")

    curve = EllipticCurve(a=1, b=0, p=p, n=N, name="weak")

    # tìm điểm sinh G có bậc chia hết cho q (để Pohlig-Hellman khôi phục được d)
    print("[*] Tìm điểm sinh G …")
    G, n = None, None
    for _ in range(500):
        x = rng.randrange(2, p)
        t = (x * x * x + x) % p
        if t == 0:
            continue
        y = pow(t, (p + 1) // 4, p)                 # căn bậc hai (p ≡ 3 mod 4)
        if (y * y) % p != t:
            continue
        P = curve.point(x, y)
        o = point_order(curve, P, N, fac)
        if o % q == 0:
            G, n = P, o
            break
    if G is None:
        print("!!! Không tìm được G phù hợp, chạy lại.")
        sys.exit(1)

    print(f"[*] G = ({G.x}, {G.y})")
    print(f"[*] bậc n của G = {n}  (n == #E: {n == N})")

    out = os.path.join(os.path.dirname(__file__), "..", "ecc_core", "weak_curve.py")
    fac_str = " * ".join(f"{pr}^{e}" if e > 1 else str(pr) for pr, e in sorted(fac.items()))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write('"""Đường cong ENTERPRISE cố tình yếu cho demo Pohlig-Hellman.\n\n')
        fh.write("Supersingular  y^2 = x^3 + x  trên F_p (p ≡ 3 mod 4) ⇒ #E = p + 1.\n")
        fh.write("Trường ~256 bit nên TRÔNG an toàn, nhưng bậc nhóm lại TRƠN:\n")
        fh.write(f"    #E = p+1 = {fac_str}\n")
        fh.write(f"Thừa số nguyên tố lớn nhất chỉ ~2^{q.bit_length()-1} ⇒ Pohlig-Hellman phá được.\n")
        fh.write("Sinh tự động bởi tools/gen_weak_curve.py — KHÔNG chỉnh tay.\n")
        fh.write('"""\n')
        fh.write("from .curve import EllipticCurve\n\n")
        fh.write(f"WEAK_CURVE = EllipticCurve(\n")
        fh.write(f"    a=1, b=0,\n")
        fh.write(f"    p={p},\n")
        fh.write(f"    n={n},\n")
        fh.write(f"    Gx={G.x},\n")
        fh.write(f"    Gy={G.y},\n")
        fh.write(f"    name='enterprise-weak')\n")
    print(f"[*] Đã ghi {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
