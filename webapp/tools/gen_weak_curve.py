import os
import random
import sys
import time
from math import gcd, isqrt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core.curve import EllipticCurve
from ecc_core.factor import is_prime, factorize

P_BITS = 256
Q_BITS = 36
MAX_SMALL = 500


def build_smooth(target_bits, rng):
    primes = [p for p in range(5, MAX_SMALL) if is_prime(p)]
    S, facs = 12, {2: 2, 3: 1}
    while S.bit_length() < target_bits:
        p = rng.choice(primes)
        S *= p
        facs[p] = facs.get(p, 0) + 1
    return S, facs


def find_curve(rng):
    while True:
        S, sfac = build_smooth(P_BITS - Q_BITS, rng)
        q = (1 << Q_BITS) | 1
        for _ in range(400_000):
            if is_prime(q):
                p = q * S - 1
                if abs(p.bit_length() - P_BITS) <= 4 and p % 4 == 3 and p % 3 == 2 and is_prime(p):
                    fac = dict(sfac)
                    fac[q] = 1
                    return p, q, fac
            q += 2


def point_order(curve, Pt, N, fac):
    o = N
    for pr, e in fac.items():
        o //= pr ** e
        Q = curve.mul(o, Pt)
        while not Q.is_infinity():
            Q = curve.mul(pr, Q)
            o *= pr
    return o


def _bsgs(curve, P, Q, order):
    m = isqrt(order) + 1
    table, cur = {}, curve.O
    for j in range(m):
        table.setdefault("O" if cur.is_infinity() else (cur.x, cur.y), j)
        cur = curve.add(cur, P)
    neg = -curve.mul(m, P)
    g = Q
    for i in range(m + 1):
        hit = table.get("O" if g.is_infinity() else (g.x, g.y))
        if hit is not None:
            return (i * m + hit) % order
        g = curve.add(g, neg)
    raise ValueError("bsgs fail")


def pohlig_hellman(curve, G, Q, n, fac):
    from ecc_core.curve import inverse_mod
    res, mod = [], []
    for p, e in sorted(fac.items()):
        g0 = curve.mul(n // p, G)
        x = 0
        for k in range(e):
            diff = curve.add(Q, -curve.mul(x, G))
            ak = _bsgs(curve, g0, curve.mul(n // (p ** (k + 1)), diff), p)
            x += ak * (p ** k)
        res.append(x)
        mod.append(p ** e)
    N = 1
    for m in mod:
        N *= m
    out = 0
    for r, m in zip(res, mod):
        Ni = N // m
        out += r * Ni * inverse_mod(Ni, m)
    return out % N


def main():
    rng = random.Random()
    print(f"[*] Tìm p ~{P_BITS} bit (p≡3 mod4, ≡2 mod3), p+1 trơn, thừa số lớn nhất ~2^{Q_BITS} …")
    p, q, fac = find_curve(rng)
    N = p + 1
    b = rng.randrange(2, p)
    curve = EllipticCurve(a=0, b=b, p=p, n=N, name="carlos-256")
    print(f"    p = {p}  ({p.bit_length()} bit)")
    print(f"    #E = p+1 gồm {len(fac)} thừa số nguyên tố, lớn nhất q = {q} (~2^{q.bit_length()-1})")

    print("[*] Tìm điểm sinh G bậc đầy đủ = p+1 …")
    G = None
    for _ in range(3000):
        x = rng.randrange(2, p)
        t = (x * x * x + b) % p
        if t == 0 or pow(t, (p - 1) // 2, p) != 1:
            continue
        y = pow(t, (p + 1) // 4, p)
        Pt = curve.point(x, y)
        if point_order(curve, Pt, N, fac) == N:
            G = Pt
            break
    if G is None:
        print("!!! Không tìm được G bậc đầy đủ, chạy lại."); sys.exit(1)
    curve.G = G
    print(f"    G = ({G.x}, {G.y})")

    print("[*] Tự kiểm chứng bằng Pohlig-Hellman …")
    d = rng.randrange(1, N)
    while gcd(d, N) != 1:
        d = rng.randrange(1, N)
    Q = curve.mul(d, G)
    t0 = time.time()
    d_rec = pohlig_hellman(curve, G, Q, N, fac)
    dt = time.time() - t0
    print(f"    Pohlig-Hellman {dt:.1f}s, khôi phục đúng khóa = {d_rec == d}")
    if d_rec != d:
        print("!!! Kiểm chứng thất bại, chạy lại."); sys.exit(1)

    out = os.path.join(os.path.dirname(__file__), "..", "ecc_core", "weak_curve.py")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("from .curve import EllipticCurve\n\n")
        fh.write("WEAK_CURVE = EllipticCurve(\n")
        fh.write("    a=0,\n")
        fh.write(f"    b={b},\n")
        fh.write(f"    p={p},\n")
        fh.write(f"    n={N},\n")
        fh.write(f"    Gx={G.x},\n")
        fh.write(f"    Gy={G.y},\n")
        fh.write("    name='carlos-256')\n")
    print(f"[*] Đã ghi {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
