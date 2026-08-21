"""DEMO 1 — TẤN CÔNG DÙNG LẠI NONCE (Nonce Reuse)   [nhóm A]

Kịch bản: "nạn nhân" lỡ dùng cùng một nonce k để ký hai thông điệp khác nhau
(do bộ sinh ngẫu nhiên hỏng — đúng như sự cố Sony PS3 2010 và ví Bitcoin trên
Android 2013). Chỉ từ hai chữ ký công khai, "kẻ tấn công" khôi phục trọn vẹn
khóa bí mật.

Cơ sở lý thuyết: docs/01-tan-cong-nonce.md §1
Chạy:  python attack.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core import SECP256K1, keygen, sign, verify, inverse_mod
from ecc_core.ecdsa import _hash_to_int
from ecc_core import io


def recover_private_key(n, r, s1, z1, s2, z2):
    """Khôi phục (k, d) từ hai chữ ký dùng chung nonce.

        s1 = k^-1 (z1 + r d),  s2 = k^-1 (z2 + r d)
        =>  k = (z1 - z2) / (s1 - s2)         (mod n)
        =>  d = (s1 k - z1) / r               (mod n)
    """
    k = (z1 - z2) * inverse_mod((s1 - s2) % n, n) % n
    d = (s1 * k - z1) * inverse_mod(r, n) % n
    return k, d


def main():
    io.banner("DEMO 1 — TẤN CÔNG DÙNG LẠI NONCE (secp256k1)")
    curve = SECP256K1
    n = curve.n

    # ------------------------------------------------------------------ [1]
    io.step(1, "SETUP — nạn nhân tạo khóa và công bố khóa công khai Q")
    d, Q = keygen(curve)
    io.info("Khóa bí mật d (nạn nhân giữ kín)", io.short(d))
    io.info("Khóa công khai Q = d*G", f"({io.short(Q.x)}, {io.short(Q.y)})")

    # ------------------------------------------------------------------ [2]
    io.step(2, "FLAW — RNG hỏng: cùng một nonce k dùng cho hai thông điệp")
    m1 = b"Chuyen 10 BTC cho Alice"
    m2 = b"Chuyen 20 BTC cho Bob"
    k_reused = 0x1337C0FFEE1234567890ABCDEF  # nonce bí mật lẽ ra phải ngẫu nhiên mỗi lần
    r1, s1, z1 = sign(curve, d, m1, k=k_reused)
    r2, s2, z2 = sign(curve, d, m2, k=k_reused)

    io.info("Thông điệp 1", m1.decode())
    io.info("  chữ ký (r1, s1)", f"({io.short(r1)}, {io.short(s1)})")
    io.info("Thông điệp 2", m2.decode())
    io.info("  chữ ký (r2, s2)", f"({io.short(r2)}, {io.short(s2)})")
    print()
    io.info("Nhận xét của kẻ tấn công", "r1 == r2 ?  " + ("CÓ → lộ nonce trùng!"
                                                          if r1 == r2 else "không"))

    # ------------------------------------------------------------------ [3]
    io.step(3, "ATTACK — chỉ dùng dữ liệu công khai (r, s1, s2, z1, z2)")
    assert r1 == r2, "nonce không trùng — tấn công không áp dụng"
    k_rec, d_rec = recover_private_key(n, r1, s1, z1, s2, z2)
    io.info("Nonce k khôi phục", io.short(k_rec))
    io.info("So với k thật", "khớp" if k_rec == k_reused else "SAI")

    # ------------------------------------------------------------------ [4]
    io.step(4, "PROOF — so khớp khóa và giả mạo một chữ ký mới")
    ok = io.compare_keys(d_rec, d)

    # kẻ tấn công giờ ký được thông điệp tùy ý như thể là nạn nhân
    forged = b"Chuyen 1000 BTC cho Ke tan cong"
    fr, fs, _ = sign(curve, d_rec, forged)
    accepted = verify(curve, Q, forged, fr, fs)
    print()
    io.info("Giả mạo thông điệp", forged.decode())
    io.result(accepted, "Chữ ký giả mạo được KHÓA CÔNG KHAI của nạn nhân chấp nhận!"
              if accepted else "Không giả mạo được.")

    sys.exit(0 if (ok and accepted) else 1)


if __name__ == "__main__":
    main()
