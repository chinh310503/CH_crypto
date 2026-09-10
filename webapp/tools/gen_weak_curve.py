"""Sinh đường cong ENTERPRISE cố tình yếu cho web (ECDSA thật, phá được bằng rho).

Chiến lược "trông thật nhưng bậc điểm sinh quá nhỏ":
  - Trường F_p với p là số nguyên tố ~256 bit (nhìn y như secp256k1) và p ≡ 3 (mod 4)
    ⇒ đường cong supersingular y² = x³ + x có #E = p + 1 (biết bậc, khỏi cần Schoof).
  - Chọn trước một số nguyên tố q ~2³⁷ rồi ép q | (p+1); điểm sinh G lấy bậc đúng = q.
  - ECDSA chạy bình thường (q nguyên tố ⇒ tính được s⁻¹ mod q), NHƯNG bậc điểm sinh
    chỉ ~2³⁷ nên Pollard's rho khôi phục khóa riêng trong ~20 giây.

Đây là lỗi thực tế: đường cong tự chế / điểm sinh có bậc quá nhỏ (cofactor khổng lồ).

Chạy:  python tools/gen_weak_curve.py
"""
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core.curve import EllipticCurve, inverse_mod   # noqa: E402
from ecc_core.factor import is_prime                     # noqa: E402

Q_BITS = 37       # bậc điểm sinh (điểm yếu ẩn) ~2^37 → rho ~20s
P_BITS = 256      # kích thước trường (trông như đường cong thật)


def rand_prime(bits, rng):
    while True:
        x = rng.randrange(1 << (bits - 1), 1 << bits) | 1
        if is_prime(x):
            return x


def find_p(q, rng):
    """Tìm p ~256 bit: p ≡ 3 (mod 4) và p ≡ -1 (mod q), p nguyên tố."""
    # CRT: p ≡ 3 (mod 4), p ≡ q-1 (mod q)
    inv_q_4 = pow(q % 4, -1, 4)
    inv_4_q = pow(4 % q, -1, q)
    base = (3 * q * inv_q_4 + (q - 1) * 4 * inv_4_q) % (4 * q)
    step = 4 * q
    while True:
        t = rng.randrange((1 << (P_BITS - 1)) // step, (1 << P_BITS) // step)
        p = base + step * t
        if p % 4 == 3 and (p + 1) % q == 0 and is_prime(p):
            return p


def rho_dlog(curve, G, Q, n):
    """Pollard's rho tìm d sao cho Q = d·G (dùng để tự kiểm chứng)."""
    def f(X, a, b):
        s = 0 if X.is_infinity() else X.x % 3
        if s == 0:
            return curve.add(X, G), (a + 1) % n, b
        if s == 1:
            return curve.add(X, X), (2 * a) % n, (2 * b) % n
        return curve.add(X, Q), a, (b + 1) % n
    X, a1, b1 = curve.O, 0, 0
    Y, a2, b2 = curve.O, 0, 0
    while True:
        X, a1, b1 = f(X, a1, b1)
        Y, a2, b2 = f(*f(Y, a2, b2))
        if X == Y:
            r = (b1 - b2) % n
            if r == 0:
                X, a1, b1 = curve.O, 0, 0
                Y, a2, b2 = curve.O, 0, 0
                continue
            return ((a2 - a1) * inverse_mod(r, n)) % n


def main():
    rng = secrets.SystemRandom()
    print(f"[*] Chọn q nguyên tố ~2^{Q_BITS} …")
    q = rand_prime(Q_BITS, rng)
    print(f"    q = {q}")
    print(f"[*] Tìm p ~{P_BITS} bit với p ≡ 3 (mod 4) và q | (p+1) …")
    p = find_p(q, rng)
    print(f"    p = {p}  ({p.bit_length()} bit)")

    curve = EllipticCurve(a=1, b=0, p=p, n=q, name="enterprise-weak")
    cofactor = (p + 1) // q

    print("[*] Tìm điểm sinh G bậc đúng = q …")
    while True:
        x = rng.randrange(2, p)
        t = (x * x * x + x) % p
        y = pow(t, (p + 1) // 4, p)          # căn bậc hai (p ≡ 3 mod 4)
        if (y * y) % p != t:
            continue
        G = curve.mul(cofactor, curve.point(x, y))
        if not G.is_infinity() and curve.mul(q, G).is_infinity():
            break
    print(f"    G = ({G.x}, {G.y})")

    # tự kiểm chứng: rho khôi phục một khóa ngẫu nhiên
    print("[*] Tự kiểm chứng bằng Pollard's rho …")
    d = rng.randrange(1, q)
    Q = curve.mul(d, G)
    t0 = time.time()
    d_rec = rho_dlog(curve, G, Q, q)
    dt = time.time() - t0
    print(f"    rho {dt:.1f}s, đúng = {d_rec == d}")

    out = os.path.join(os.path.dirname(__file__), "..", "ecc_core", "weak_curve.py")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write('"""Đường cong ENTERPRISE cố tình yếu cho web demo (ECDSA thật).\n\n')
        fh.write("Supersingular y^2 = x^3 + x trên F_p, p ~256 bit (trông như đường cong thật),\n")
        fh.write(f"nhưng bậc điểm sinh chỉ là số nguyên tố q ~2^{Q_BITS} (cofactor ~2^{cofactor.bit_length()}).\n")
        fh.write("ECDSA chạy bình thường (q nguyên tố), nhưng Pollard's rho khôi phục khóa\n")
        fh.write(f"riêng trong ~{dt:.0f}s vì bậc quá nhỏ. Sinh bởi tools/gen_weak_curve.py.\n")
        fh.write('"""\n')
        fh.write("from .curve import EllipticCurve\n\n")
        fh.write("WEAK_CURVE = EllipticCurve(\n")
        fh.write("    a=1, b=0,\n")
        fh.write(f"    p={p},\n")
        fh.write(f"    n={q},\n")
        fh.write(f"    Gx={G.x},\n")
        fh.write(f"    Gy={G.y},\n")
        fh.write("    name='enterprise-weak')\n")
    print(f"[*] Đã ghi {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
