"""DEMO 3 — TẤN CÔNG POHLIG–HELLMAN   [nhóm C — đường cong/tham số yếu]

Kịch bản: một hệ thống chọn nhầm đường cong mà BẬC của điểm sinh (n) là một số
"trơn" (smooth) — chỉ gồm các thừa số nguyên tố nhỏ. Khi đó bài toán ECDLP
Q = d*G bị "chẻ nhỏ" theo từng thừa số nguyên tố rồi ghép lại bằng Định lý Số dư
Trung Hoa (CRT), khiến việc tìm khóa bí mật d trở nên dễ dàng — thay vì tốn ~√n
như trên đường cong tốt.

Cơ sở lý thuyết: docs/03-tan-cong-toan-hoc.md, Phần I §3
Chạy:  python attack.py
"""
import os
import sys
from math import isqrt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core import load_toy_smooth, inverse_mod
from ecc_core import io
import secrets


# --------------------------------------------------------------------------
# Các thuật toán phụ trợ
# --------------------------------------------------------------------------
def factorize(n: int) -> dict:
    f, d = {}, 2
    while d * d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f


def _key(P):
    return "O" if P.is_infinity() else (P.x, P.y)


def bsgs(curve, P, Q, order):
    """Baby-step Giant-step: tìm k ∈ [0, order) sao cho k*P = Q."""
    m = isqrt(order) + 1
    table, cur = {}, curve.O
    for j in range(m):                     # baby steps: j*P
        table.setdefault(_key(cur), j)
        cur = curve.add(cur, P)
    neg_mP = -curve.mul(m, P)               # -m*P
    gamma = Q
    for i in range(m + 1):                  # giant steps: Q - i*m*P
        hit = table.get(_key(gamma))
        if hit is not None:
            return (i * m + hit) % order
        gamma = curve.add(gamma, neg_mP)
    raise ValueError("BSGS thất bại (P không sinh nhóm bậc `order`?)")


def solve_prime_power(curve, G, Q, n, p, e):
    """Tìm d mod p^e bằng phương pháp 'chữ số' theo cơ số p."""
    g0 = curve.mul(n // p, G)               # phần tử bậc p
    x = 0
    for k in range(e):
        exp = n // (p ** (k + 1))
        diff = curve.add(Q, -curve.mul(x, G))   # Q - x*G
        tk = curve.mul(exp, diff)               # = a_k * g0
        ak = bsgs(curve, g0, tk, p)
        x += ak * (p ** k)
    return x                                 # d mod p^e


def crt(residues, moduli):
    """Ghép nghiệm bằng Định lý Số dư Trung Hoa."""
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r, m in zip(residues, moduli):
        Ni = N // m
        x += r * Ni * inverse_mod(Ni, m)
    return x % N


# --------------------------------------------------------------------------
def main():
    io.banner("DEMO 3 — TẤN CÔNG POHLIG–HELLMAN (đường cong bậc trơn)")
    curve = load_toy_smooth()
    G, n = curve.G, curve.n

    # ------------------------------------------------------------------ [1]
    io.step(1, "SETUP — nạn nhân sinh khóa trên đường cong đồ chơi")
    print(f"    {curve}")
    d = secrets.randbelow(n - 1) + 1
    Q = curve.mul(d, G)
    io.info("Điểm sinh G", f"({G.x}, {G.y})")
    io.info("Bậc của G: n", n)
    io.info("Khóa bí mật d (giữ kín)", d)
    io.info("Khóa công khai Q = d*G", f"({Q.x}, {Q.y})")

    # ------------------------------------------------------------------ [2]
    io.step(2, "FLAW — bậc n là số TRƠN (chỉ gồm thừa số nguyên tố nhỏ)")
    factors = factorize(n)
    io.info("Phân tích n", " × ".join(f"{p}^{e}" if e > 1 else f"{p}"
                                       for p, e in factors.items()))
    io.info("Thừa số nguyên tố lớn nhất", max(factors))

    # ------------------------------------------------------------------ [3]
    io.step(3, "ATTACK — Pohlig–Hellman: giải ECDLP theo từng thừa số rồi CRT")
    print(f"\n    {'Thừa số p^e':<14}{'d mod p^e':<14}{'(giải bằng BSGS trong nhóm bậc nhỏ)'}")
    print("    " + "-" * 66)
    residues, moduli = [], []
    for p, e in factors.items():
        dm = solve_prime_power(curve, G, Q, n, p, e)
        pe = p ** e
        residues.append(dm)
        moduli.append(pe)
        print(f"    {str(pe):<14}{str(dm):<14}d ≡ {dm} (mod {pe})")

    d_rec = crt(residues, moduli)
    print()
    io.info("Ghép CRT → d", d_rec)

    # ------------------------------------------------------------------ [4]
    io.step(4, "PROOF — so khớp khóa và đối chiếu chi phí")
    ok = io.compare_keys(d_rec, d)

    cost_global = isqrt(n)
    cost_ph = sum(e * (isqrt(p) + 1) for p, e in factors.items())
    print()
    io.info("Chi phí ~ Pollard rho toàn cục", f"≈ √n ≈ {cost_global} bước")
    io.info("Chi phí ~ Pohlig–Hellman", f"≈ Σ eᵢ·√pᵢ ≈ {cost_ph} bước")
    print("\n    → Với đường cong 256-bit có n NGUYÊN TỐ, √n ≈ 2^128 là bất khả thi.")
    print("      Nhưng khi n TRƠN, tấn công chỉ tốn ~√(thừa số lớn nhất) → sụp đổ hoàn toàn.")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
