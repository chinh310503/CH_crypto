"""DEMO 3 — TẤN CÔNG POHLIG–HELLMAN   [nhóm C — đường cong/tham số yếu]

Kịch bản: một hệ thống dùng đường cong TRÔNG rất "thật" — trường nguyên tố ~256 bit,
bậc nhóm cũng ~256 bit — nên tưởng an toàn như secp256k1. Nhưng bậc nhóm lại là số
TRƠN (thừa số nguyên tố lớn nhất chỉ ~2^34). Kẻ tấn công phân tích thừa số bậc nhóm,
rồi "chẻ nhỏ" ECDLP theo từng thừa số và ghép bằng CRT — khôi phục khóa bí mật dễ
dàng, thay vì tốn ~√n ≈ 2^128 như trên đường cong tốt.

Cơ sở lý thuyết: docs/03-tan-cong-toan-hoc.md, Phần I §3
Chạy:  python attack.py
"""
import os
import secrets
import sys
from math import isqrt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core import load_weak_curve, inverse_mod, factorize, io


def _key(P):
    return "O" if P.is_infinity() else (P.x, P.y)


def bsgs(curve, P, Q, order):
    """Baby-step Giant-step: tìm k ∈ [0, order) sao cho k*P = Q."""
    m = isqrt(order) + 1
    table, cur = {}, curve.O
    for j in range(m):                         # baby steps: j*P
        table.setdefault(_key(cur), j)
        cur = curve.add(cur, P)
    neg_mP = -curve.mul(m, P)                   # -m*P
    gamma = Q
    for i in range(m + 1):                      # giant steps: Q - i*m*P
        hit = table.get(_key(gamma))
        if hit is not None:
            return (i * m + hit) % order
        gamma = curve.add(gamma, neg_mP)
    raise ValueError("BSGS thất bại")


def solve_prime_power(curve, G, Q, n, p, e):
    """Tìm d mod p^e bằng phương pháp 'chữ số' theo cơ số p."""
    g0 = curve.mul(n // p, G)                   # phần tử bậc p
    x = 0
    for k in range(e):
        exp = n // (p ** (k + 1))
        diff = curve.add(Q, -curve.mul(x, G))   # Q - x*G
        tk = curve.mul(exp, diff)               # = a_k * g0
        ak = bsgs(curve, g0, tk, p)
        x += ak * (p ** k)
    return x                                     # d mod p^e


def crt(residues, moduli):
    N = 1
    for m in moduli:
        N *= m
    x = 0
    for r, m in zip(residues, moduli):
        Ni = N // m
        x += r * Ni * inverse_mod(Ni, m)
    return x % N


def main():
    io.banner("DEMO 3 — TẤN CÔNG POHLIG–HELLMAN (đường cong ~256 bit, bậc TRƠN)")
    curve = load_weak_curve()
    G, n = curve.G, curve.n

    # ------------------------------------------------------------------ [1]
    io.step(1, "SETUP — nạn nhân sinh khóa trên đường cong 'enterprise'")
    io.info("Trường F_p", f"p ~ {curve.p.bit_length()} bit ({io.short(curve.p)})")
    io.info("Bậc nhóm n", f"~ {n.bit_length()} bit ({io.short(n)})")
    d = secrets.randbelow(n - 1) + 1
    Q = curve.mul(d, G)
    io.info("Khóa bí mật d (giữ kín)", io.short(d))
    io.info("Khóa công khai Q = d*G", f"({io.short(Q.x)}, {io.short(Q.y)})")

    # ------------------------------------------------------------------ [2]
    io.step(2, "FLAW — phân tích thừa số bậc nhóm (điều gần như không ai kiểm tra)")
    factors = factorize(n)
    q = max(factors)
    io.info("Số thừa số nguyên tố", len(factors))
    io.info("Thừa số lớn nhất q", f"{q}  (~2^{q.bit_length() - 1})")
    io.result(True, "Bậc nhóm 256-bit nhưng TRƠN → Pohlig–Hellman áp dụng được")

    # ------------------------------------------------------------------ [3]
    io.step(3, "ATTACK — giải ECDLP theo từng thừa số (BSGS) rồi ghép CRT")
    residues, moduli = [], []
    for p, e in sorted(factors.items()):
        dm = solve_prime_power(curve, G, Q, n, p, e)
        residues.append(dm)
        moduli.append(p ** e)
    io.info("Đã giải xong", f"{len(factors)} nhóm con (nhóm bậc q ~2^{q.bit_length()-1} tốn nhất)")
    d_rec = crt(residues, moduli)
    io.info("Ghép CRT → d", io.short(d_rec))

    # ------------------------------------------------------------------ [4]
    io.step(4, "PROOF — so khớp khóa và đối chiếu chi phí")
    ok = io.compare_keys(d_rec, d)
    cost_ph = sum(e * (isqrt(p) + 1) for p, e in factors.items())
    print()
    io.info("Chi phí nếu n NGUYÊN TỐ (√n)", f"≈ 2^{n.bit_length() // 2}  (bất khả thi)")
    io.info("Chi phí Pohlig–Hellman thực tế", f"≈ {cost_ph:,} bước".replace(",", "."))
    print("\n    → Cùng một đường cong 256-bit: nếu bậc nhóm NGUYÊN TỐ thì an toàn tuyệt đối,")
    print("      nhưng vì bậc nhóm TRƠN nên chỉ tốn ~√(thừa số lớn nhất) → sụp đổ hoàn toàn.")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
