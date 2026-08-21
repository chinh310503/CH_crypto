"""Chạy lần lượt cả ba demo tấn công ECDSA.

Chạy:  python run_all.py
"""
import os
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Ép tiến trình con dùng UTF-8 (phòng khi console mặc định là cp1252)
_ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

HERE = os.path.dirname(os.path.abspath(__file__))
DEMOS = [
    ("01_nonce_reuse", "Dùng lại nonce"),
    ("02_psychic_signatures", "Psychic Signatures (CVE-2022-21449)"),
    ("03_pohlig_hellman", "Pohlig–Hellman (đường cong bậc trơn)"),
]


def main():
    fails = 0
    for folder, name in DEMOS:
        path = os.path.join(HERE, folder, "attack.py")
        rc = subprocess.run([sys.executable, path], env=_ENV).returncode
        if rc != 0:
            fails += 1
            print(f"\n!!! Demo '{folder}' trả về mã lỗi {rc}")
    print("\n" + "=" * 70)
    print(f"  Hoàn tất: {len(DEMOS) - fails}/{len(DEMOS)} demo chạy THÀNH CÔNG.")
    print("=" * 70)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
