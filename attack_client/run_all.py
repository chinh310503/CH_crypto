"""Chạy lần lượt cả ba tấn công vào CryptoBank.

    python run_all.py

Mẹo: mở http://127.0.0.1:5000/monitor để xem số dư đổi trực tiếp khi tấn công.
"""
import attack_nonce_reuse
import attack_psychic
import attack_weakcurve
from common import get, money


def main():
    attack_nonce_reuse.main()
    print()
    attack_psychic.main()
    print()
    attack_weakcurve.main()
    print()

    _, state = get("/api/state")
    bob = next((a for a in state["accounts"] if a["user"] == "bob"), None)
    if bob:
        print(f"Xong. Tài khoản 'bob' (kẻ tấn công) hiện có {money(bob['balance'])} CBC.")
    print("Gõ http://127.0.0.1:5000/reset để khôi phục trạng thái ban đầu.")


if __name__ == "__main__":
    main()
