"""Kiểm tra nhanh tính đúng đắn của thư viện lõi ecc_core.

Chạy:  python tools/selftest.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core import (SECP256K1, load_weak_curve, keygen, sign, verify,
                      verify_insecure, factorize)


def check(name, cond):
    print(f"  [{'OK ' if cond else 'FAIL'}] {name}")
    assert cond, name


def main():
    print("== secp256k1 ==")
    G = SECP256K1.G
    check("G nằm trên đường cong", SECP256K1.contains(G))
    check("n*G = O", SECP256K1.mul(SECP256K1.n, G).is_infinity())

    d, Q = keygen(SECP256K1)
    check("Q = d*G nằm trên đường cong", SECP256K1.contains(Q))

    r, s, z = sign(SECP256K1, d, b"hello world")
    check("verify chữ ký hợp lệ -> True", verify(SECP256K1, Q, b"hello world", r, s))
    check("verify sai thông điệp -> False", not verify(SECP256K1, Q, b"tampered", r, s))
    check("verify sai r -> False", not verify(SECP256K1, Q, b"hello world", (r + 1) % SECP256K1.n, s))

    print("== Psychic Signatures (0,0) ==")
    check("verify AN TOÀN từ chối (0,0)", not verify(SECP256K1, Q, b"forge", 0, 0))
    check("verify CÓ LỖI chấp nhận (0,0)", verify_insecure(SECP256K1, Q, b"forge", 0, 0))

    print("== đường cong enterprise yếu (supersingular ~256 bit) ==")
    T = load_weak_curve()
    check("G nằm trên đường cong", T.contains(T.G))
    check("n*G = O", T.mul(T.n, T.G).is_infinity())
    q = max(factorize(T.n))
    check(f"thừa số nguyên tố lớn nhất của bậc nhóm nhỏ (~2^{q.bit_length()-1})",
          q.bit_length() <= 40)
    check("(n//q)*G != O — G có bậc chia hết q", not T.mul(T.n // q, T.G).is_infinity())

    print("\nTất cả kiểm tra PASS ✔")


if __name__ == "__main__":
    main()
