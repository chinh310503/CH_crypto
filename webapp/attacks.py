"""Ba tấn công thực hiện phía server — CHỈ dùng dữ liệu CÔNG KHAI của hệ thống
(lịch sử chữ ký, khóa công khai, tham số đường cong). Mỗi hàm trả về danh sách
các bước và phần "impact" để bảng điều khiển tấn công hiển thị.
"""
import hashlib
import json
import secrets
from math import isqrt

from ecc_bridge import (SECP256K1, EllipticCurve, inverse_mod, sign,
                        _hash_to_int)
from bank import tx_bytes
from vault import b64u


# ==========================================================================
#  Tiện ích cho Pohlig–Hellman
# ==========================================================================
def factorize(n):
    f, d = {}, 2
    while d * d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f


def _key(P):
    return "O" if P.is_infinity() else (P.x, P.y)


def _bsgs(curve, P, Q, order):
    m = isqrt(order) + 1
    table, cur = {}, curve.O
    for j in range(m):
        table.setdefault(_key(cur), j)
        cur = curve.add(cur, P)
    neg_mP = -curve.mul(m, P)
    g = Q
    for i in range(m + 1):
        hit = table.get(_key(g))
        if hit is not None:
            return (i * m + hit) % order
        g = curve.add(g, neg_mP)
    raise ValueError("BSGS thất bại")


def _solve_pp(curve, G, Q, n, p, e):
    g0 = curve.mul(n // p, G)
    x = 0
    for k in range(e):
        exp = n // (p ** (k + 1))
        diff = curve.add(Q, -curve.mul(x, G))
        tk = curve.mul(exp, diff)
        ak = _bsgs(curve, g0, tk, p)
        x += ak * (p ** k)
    return x


def _crt(res, mod):
    N = 1
    for m in mod:
        N *= m
    x = 0
    for r, m in zip(res, mod):
        Ni = N // m
        x += r * Ni * inverse_mod(Ni, m)
    return x % N


def pohlig_hellman(curve, G, Q, n):
    fac = factorize(n)
    res, mod = [], []
    for p, e in fac.items():
        res.append(_solve_pp(curve, G, Q, n, p, e))
        mod.append(p ** e)
    return _crt(res, mod), fac


# ==========================================================================
#  Tấn công 1 — Nonce reuse → chiếm khóa ký master → rút sạch tài khoản
# ==========================================================================
def attack_nonce_reuse(bank):
    steps = []
    n = SECP256K1.n
    txs = bank.public_transactions()
    steps.append(f"Thu thập {len(txs)} chữ ký giao dịch CÔNG KHAI từ /api/transactions")

    # tìm hai giao dịch cùng r (dấu hiệu nonce trùng)
    seen, pair = {}, None
    for t in txs:
        if t["r"] in seen:
            pair = (seen[t["r"]], t)
            break
        seen[t["r"]] = t
    if not pair:
        return {"ok": False, "steps": steps + ["Không tìm thấy nonce trùng."]}

    t1, t2 = pair
    steps.append(f"⚠ Phát hiện NONCE TRÙNG: giao dịch #{t1['id']} và #{t2['id']} có cùng r")

    r = int(t1["r"])
    s1, s2 = int(t1["s"]), int(t2["s"])
    z1 = _hash_to_int(tx_bytes(t1), n)
    z2 = _hash_to_int(tx_bytes(t2), n)

    k = (z1 - z2) * inverse_mod((s1 - s2) % n, n) % n
    d = (s1 * k - z1) * inverse_mod(r, n) % n
    steps.append(f"Giải hệ phương trình → nonce k = {hex(k)[:18]}…")
    steps.append(f"Khôi phục KHÓA KÝ MASTER của ngân hàng: d = {hex(d)[:18]}…")

    verified = SECP256K1.mul(d, SECP256K1.G) == bank.vault.Q_bank
    steps.append("Đối chiếu d·G với khóa công khai ngân hàng: "
                 + ("KHỚP ✔" if verified else "SAI ✗"))

    # dùng khóa vừa chiếm để giả mạo giao dịch rút sạch tài khoản alice → bob
    victim, attacker = "alice", "bob"
    amount = bank.users[victim]["balance"]
    forged = {"id": 9000 + len(txs), "from": victim, "to": attacker, "amount": amount}
    fr, fs, _ = sign(SECP256K1, d, tx_bytes(forged))
    before = {"alice": bank.users["alice"]["balance"], "bob": bank.users["bob"]["balance"]}
    ok, msg = bank.execute_clearing(forged, fr, fs)
    after = {"alice": bank.users["alice"]["balance"], "bob": bank.users["bob"]["balance"]}
    steps.append(f"Giả mạo giao dịch alice→bob {amount} CBC và nộp lên /api/clear: {msg}")

    return {"ok": ok and verified, "steps": steps,
            "recovered_key": hex(d),
            "impact": {"before": before, "after": after, "stolen": amount,
                       "victim": victim, "attacker": attacker}}


# ==========================================================================
#  Tấn công 2 — Psychic Signatures → chiếm quyền admin, KHÔNG cần mật khẩu
# ==========================================================================
def attack_psychic(bank):
    steps = []
    steps.append("Mục tiêu: /api/admin/users (chỉ admin xem được)")

    # chế tạo token admin với chữ ký RỖNG (0,0)
    header = {"alg": "ES256", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u(b"\x00" * 64)                      # r = s = 0
    token = f"{h}.{p}.{sig}"
    steps.append("Chế tạo token với payload role=admin và chữ ký RỖNG (r=0, s=0)")

    ok_insecure = bank.vault.verify_token(token) is not None
    ok_secure = bank.vault.verify_token_secure(token) is not None
    steps.append(f"Hàm xác minh CÓ LỖI (đang chạy) chấp nhận token: {ok_insecure}")
    steps.append(f"Hàm xác minh ĐÃ VÁ (đối chứng) chấp nhận token: {ok_secure}")

    leaked = bank.all_accounts() if ok_insecure else None
    if ok_insecure:
        steps.append("→ Đăng nhập admin thành công, trích xuất toàn bộ bảng tài khoản")

    return {"ok": ok_insecure and not ok_secure, "steps": steps, "token": token,
            "impact": {"admin_access": ok_insecure, "leaked_accounts": leaked}}


# ==========================================================================
#  Tấn công 3 — Pohlig–Hellman → khôi phục khóa enterprise → rút sạch MegaCorp
# ==========================================================================
def attack_pohlig(bank):
    steps = []
    info = bank.vault.enterprise_pubinfo()
    curve = EllipticCurve(a=info["a"], b=info["b"], p=info["p"], n=info["n"],
                          Gx=info["Gx"], Gy=info["Gy"], name="enterprise")
    Q = curve.point(info["Qx"], info["Qy"])
    steps.append("Lấy tham số đường cong + khóa công khai enterprise từ /api/enterprise/pubkey")
    steps.append(f"Bậc n = {info['n']} = " + " × ".join(
        f"{p}^{e}" if e > 1 else str(p) for p, e in factorize(info["n"]).items())
        + "  → TRƠN!")

    d, _ = pohlig_hellman(curve, curve.G, Q, info["n"])
    steps.append(f"Pohlig–Hellman khôi phục khóa riêng enterprise: d = {d}")
    verified = curve.mul(d, curve.G) == Q
    steps.append("Đối chiếu d·G với khóa công khai: " + ("KHỚP ✔" if verified else "SAI ✗"))

    to = "bob"
    amount = bank.users["megacorp"]["balance"]
    msg = f"WITHDRAW:{amount}:TO:{to}".encode()
    # Ký Schnorr lệnh rút bằng khóa riêng vừa khôi phục
    k = secrets.randbelow(curve.n - 1) + 1
    R = curve.mul(k, curve.G)
    e = int.from_bytes(hashlib.sha256(f"{R.x},{R.y}".encode() + b"|" + msg).digest(),
                       "big") % curve.n
    s = (k + e * d) % curve.n
    before = {"megacorp": bank.users["megacorp"]["balance"], "bob": bank.users["bob"]["balance"]}
    ok, m = bank.enterprise_withdraw(to, amount, R.x, R.y, s)
    after = {"megacorp": bank.users["megacorp"]["balance"], "bob": bank.users["bob"]["balance"]}
    steps.append(f"Ký lệnh rút {amount} CBC bằng khóa vừa khôi phục: {m}")

    return {"ok": ok and verified, "steps": steps, "recovered_key": d,
            "impact": {"before": before, "after": after, "stolen": amount,
                       "victim": "megacorp", "attacker": to}}
