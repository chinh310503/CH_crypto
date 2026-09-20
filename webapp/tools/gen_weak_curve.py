"""Sinh đường cong 'carlos' cố tình yếu cho web: a=0, b ngẫu nhiên, supersingular
(p ≡ 2 mod 3 ⇒ #E = p+1), bậc nhóm n ~256 bit nhưng TRƠN → phá bằng Pohlig-Hellman.
Nhìn tham số công khai gần như không phân biệt được đường cong chuẩn; điểm yếu chỉ
lộ khi phân tích thừa số n. Chi tiết cơ chế: xem webapp/README.md.

Chạy:  python tools/gen_weak_curve.py
"""
import os
import random
import sys
import time
from math import gcd, isqrt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core.curve import EllipticCurve            # noqa: E402
from ecc_core.factor import is_prime, factorize      # noqa: E402

P_BITS = 256      # kích thước trường (trông như đường cong thật)
Q_BITS = 36       # thừa số nguyên tố lớn nhất của bậc nhóm → công sức tấn công ~2^18 (~10-15s)
MAX_SMALL = 500   # phần "trơn" ghép từ các nguyên tố < ngưỡng này


def build_smooth(target_bits, rng):
    """Dựng phần trơn S: bắt đầu 2²·3 (⇒ 4|S để p≡3 mod4, 3|S để p≡2 mod3)."""
    primes = [p for p in range(5, MAX_SMALL) if is_prime(p)]
    S, facs = 12, {2: 2, 3: 1}
    while S.bit_length() < target_bits:
        p = rng.choice(primes)
        S *= p
        facs[p] = facs.get(p, 0) + 1
    return S, facs


def find_curve(rng):
    """Tìm p ~256 bit, p ≡ 3 (mod4) & ≡ 2 (mod3), với p+1 = q·S trơn."""
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
    """Bậc chính xác của điểm Pt (biết N = #E và phân tích thừa số của N)."""
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
    b = rng.randrange(2, p)                          # b NGẪU NHIÊN ⇒ trông như đường cong thật
    curve = EllipticCurve(a=0, b=b, p=p, n=N, name="carlos-256")
    print(f"    p = {p}  ({p.bit_length()} bit)")
    print(f"    #E = p+1 gồm {len(fac)} thừa số nguyên tố, lớn nhất q = {q} (~2^{q.bit_length()-1})")

    print("[*] Tìm điểm sinh G bậc đầy đủ = p+1 …")
    G = None
    for _ in range(3000):
        x = rng.randrange(2, p)
        t = (x * x * x + b) % p
        if t == 0 or pow(t, (p - 1) // 2, p) != 1:   # phải là thặng dư bậc hai
            continue
        y = pow(t, (p + 1) // 4, p)                   # căn bậc hai (p ≡ 3 mod 4)
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
        fh.write('"""Đường cong CARLOS cố tình yếu cho web demo (ECDSA thật).\n\n')
        fh.write("TRÔNG NHƯ ĐƯỜNG CONG THẬT: cùng dạng với secp256k1  y^2 = x^3 + b  (a = 0),\n")
        fh.write("trường nguyên tố p ~256 bit, bậc điểm sinh n ~256 bit. Nhìn tham số công khai\n")
        fh.write("(a, b, p, n, G) gần như không phân biệt được với một đường cong chuẩn.\n\n")
        fh.write("ĐIỂM YẾU ẨN: chọn p ≡ 2 (mod 3) nên đường cong là SUPERSINGULAR và #E = p + 1;\n")
        fh.write(f"p được chọn sao cho p + 1 là số TRƠN (mọi thừa số nguyên tố ≤ ~2^{Q_BITS}). Vì vậy dù\n")
        fh.write("n ~256 bit, chỉ cần PHÂN TÍCH THỪA SỐ n là thấy nó trơn → Pohlig–Hellman + BSGS\n")
        fh.write(f"khôi phục khóa riêng trong ~{dt:.0f}s (thay vì ~2^128 như đường cong chuẩn).\n\n")
        fh.write("Sinh tự động bởi tools/gen_weak_curve.py — KHÔNG chỉnh tay.\n")
        fh.write('"""\n')
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
