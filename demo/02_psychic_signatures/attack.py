"""DEMO 2 — PSYCHIC SIGNATURES / CVE-2022-21449   [nhóm D — lỗi triển khai]

Kịch bản: một thư viện xác minh ECDSA quên kiểm tra điều kiện r, s ∈ [1, n-1]
(đúng như lỗi trong Java/OpenJDK 15–18). Kẻ tấn công gửi chữ ký "rỗng"
(r = 0, s = 0) và được chấp nhận là hợp lệ cho BẤT KỲ thông điệp nào — mà
KHÔNG cần biết khóa bí mật.

Cơ sở lý thuyết: docs/04-loi-trien-khai.md §1
Chạy:  python attack.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ecc_core import SECP256K1, keygen, verify, verify_insecure
from ecc_core import io


def main():
    io.banner("DEMO 2 — PSYCHIC SIGNATURES (CVE-2022-21449)")
    curve = SECP256K1

    io.step(1, "SETUP — nạn nhân có khóa; kẻ tấn công CHỈ biết khóa công khai Q")
    d, Q = keygen(curve)
    io.info("Khóa bí mật d (nạn nhân)", io.short(d))
    io.info("Khóa công khai Q", f"({io.short(Q.x)}, {io.short(Q.y)})")
    io.info("Kẻ tấn công biết d ?", "KHÔNG — hắn không hề có khóa bí mật")

    io.step(2, "FLAW — hệ thống dùng hàm xác minh THIẾU kiểm tra biên r, s")
    print("    • verify()          : ĐÚNG CHUẨN — có kiểm tra r, s ∈ [1, n-1]")
    print("    • verify_insecure() : CÓ LỖI    — bỏ bước kiểm tra đó (giống Java)")

    io.step(3, "ATTACK — chế tạo chữ ký rỗng (r = 0, s = 0), không cần khóa")
    forged_r, forged_s = 0, 0
    io.info("Chữ ký giả mạo (r, s)", f"({forged_r}, {forged_s})")

    io.step(4, "PROOF — thử chữ ký (0,0) trên nhiều thông điệp khác nhau")
    messages = [
        b"Toi la quan tri vien",
        b"Chuyen toan bo tai san",
        b"Dang nhap voi quyen root",
    ]
    print(f"\n    {'Thông điệp':<32}{'verify (an toàn)':<20}{'verify_insecure (lỗi)'}")
    print("    " + "-" * 70)
    all_bypassed = True
    for m in messages:
        safe = verify(curve, Q, m, forged_r, forged_s)
        buggy = verify_insecure(curve, Q, m, forged_r, forged_s)
        all_bypassed = all_bypassed and buggy and (not safe)
        print(f"    {m.decode():<32}{('CHẤP NHẬN' if safe else 'từ chối'):<20}"
              f"{'CHẤP NHẬN' if buggy else 'từ chối'}")

    print()
    io.result(all_bypassed,
              "Chữ ký rỗng (0,0) bị hàm CÓ LỖI chấp nhận cho MỌI thông điệp, "
              "trong khi hàm an toàn từ chối tất cả.")
    print("\n    Vì sao? Khi s = 0, phép tính suy biến cho ra điểm vô cực O; cài đặt")
    print("    lỗi coi hoành độ x(O) = 0, nên phép so sánh r == x thành 0 == 0 (luôn đúng).")
    print("    Bước kiểm tra r, s ∈ [1, n-1] — nếu có — sẽ chặn ngay từ đầu.")

    sys.exit(0 if all_bypassed else 1)


if __name__ == "__main__":
    main()
