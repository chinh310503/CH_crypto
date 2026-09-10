"""Chạy lần lượt cả ba tấn công vào CryptoBank.

    python run_all.py

Mẹo: mở http://127.0.0.1:5000/monitor để xem số dư đổi trực tiếp khi tấn công.
"""
import attack_nonce_reuse
import attack_psychic
import attack_weakcurve
from common import banner, money, get


def main():
    attack_nonce_reuse.main()
    attack_psychic.main()
    attack_weakcurve.main()

    _, state = get("/api/state")
    bob = next((a for a in state["accounts"] if a["user"] == "bob"), None)
    banner("HOÀN TẤT — ba tấn công đã khai thác xong")
    if bob:
        print(f"  Tài khoản 'bob' (kẻ tấn công) hiện có: {money(bob['balance'])} CBC")
    print("  Gõ http://127.0.0.1:5000/reset để khôi phục trạng thái ban đầu.\n")


if __name__ == "__main__":
    main()
