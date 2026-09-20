"""Tiện ích dùng chung cho các script tấn công CryptoBank từ BÊN NGOÀI.

Mỗi script chỉ giao tiếp với web app qua HTTP bằng các API CÔNG KHAI thật của trang
(không có API ẩn): /api/transactions, /api/accounts, /api/tx/submit, /api/admin/users.
Toán học ECDSA tái sử dụng thư viện lõi ../demo/ecc_core.

Đặt biến môi trường TARGET để trỏ máy chủ khác (mặc định http://127.0.0.1:5000).
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from math import isqrt

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


_DEMO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo")
if _DEMO not in sys.path:
    sys.path.insert(0, _DEMO)
from ecc_core import SECP256K1, EllipticCurve, inverse_mod, sign, factorize   # noqa: E402
from ecc_core.ecdsa import _hash_to_int as hash_to_int            # noqa: E402

BASE = os.environ.get("TARGET", "http://127.0.0.1:5000").rstrip("/")


def _http(method, path, body=None, cookie=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            ct = r.headers.get_content_type()
            return r.status, (json.loads(raw) if raw and "json" in ct else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except urllib.error.URLError as e:
        die(f"Không kết nối được {BASE} — web app đã chạy chưa? ({e.reason})")


def get(path, cookie=None):
    return _http("GET", path, cookie=cookie)


def post(path, body, cookie=None):
    return _http("POST", path, body, cookie=cookie)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def tx_bytes(tx: dict) -> bytes:
    """Phải KHỚP TUYỆT ĐỐI với bank.tx_bytes phía server."""
    return json.dumps(
        {"id": tx["id"], "from": tx["from"], "to": tx["to"], "amount": tx["amount"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()


def curve_from_info(info: dict) -> EllipticCurve:
    """Dựng lại đối tượng đường cong từ dữ liệu /api/accounts."""
    return EllipticCurve(a=int(info["a"]), b=int(info["b"]), p=int(info["p"]),
                         n=int(info["n"]), Gx=int(info["Gx"]), Gy=int(info["Gy"]),
                         name=info["name"])


def sign_transfer(curve, d, frm, to, amount, tx_id):
    """Ký một giao dịch chuyển tiền bằng khóa riêng d (kẻ tấn công đã chiếm được)."""
    tx = {"id": tx_id, "from": frm, "to": to, "amount": amount}
    r, s, _ = sign(curve, d, tx_bytes(tx))
    return tx, r, s


def rho_dlog(curve, G, Q, n):
    """Pollard's rho: tìm d sao cho Q = d·G (dùng cho đường cong bậc nhỏ)."""
    def f(X, a, b):
        s = 0 if X.is_infinity() else X.x % 3
        if s == 0:
            return curve.add(X, G), (a + 1) % n, b
        if s == 1:
            return curve.add(X, X), (2 * a) % n, (2 * b) % n
        return curve.add(X, Q), a, (b + 1) % n
    X, a1, b1 = curve.O, 0, 0
    Y, a2, b2 = curve.O, 0, 0
    while True:
        X, a1, b1 = f(X, a1, b1)
        Y, a2, b2 = f(*f(Y, a2, b2))
        if X == Y:
            r = (b1 - b2) % n
            if r == 0:
                X, a1, b1 = curve.O, 0, 0
                Y, a2, b2 = curve.O, 0, 0
                continue
            return ((a2 - a1) * inverse_mod(r, n)) % n


def _bsgs(curve, P, Q, order):
    """Baby-step Giant-step: tìm k ∈ [0, order) sao cho k·P = Q."""
    m = isqrt(order) + 1
    table, cur = {}, curve.O
    for j in range(m):
        table.setdefault("O" if cur.is_infinity() else (cur.x, cur.y), j)
        cur = curve.add(cur, P)
    neg = -curve.mul(m, P)
    g = Q
    for i in range(m + 1):
        hit = table.get("O" if g.is_infinity() else (g.x, g.y))
        if hit is not None:
            return (i * m + hit) % order
        g = curve.add(g, neg)
    raise ValueError("BSGS thất bại")


def pohlig_hellman_dlog(curve, G, Q, n, factors=None):
    """Giải ECDLP Q = d·G khi bậc n TRƠN: chẻ nhỏ theo từng thừa số nguyên tố
    (BSGS trên mỗi nhóm con) rồi ghép bằng CRT. Trả về (d, factors)."""
    if factors is None:
        factors = factorize(n)
    residues, moduli = [], []
    for p, e in sorted(factors.items()):
        g0 = curve.mul(n // p, G)                 # phần tử bậc p
        x = 0
        for k in range(e):                        # giải theo từng "chữ số" cơ số p
            diff = curve.add(Q, -curve.mul(x, G))
            ak = _bsgs(curve, g0, curve.mul(n // (p ** (k + 1)), diff), p)
            x += ak * (p ** k)
        residues.append(x)
        moduli.append(p ** e)
    N = 1
    for m in moduli:
        N *= m
    d = 0
    for r, m in zip(residues, moduli):
        Ni = N // m
        d += r * Ni * inverse_mod(Ni, m)
    return d % N, factors


def money(x):
    """Định dạng số tiền cho dễ đọc: 5000000 -> 5.000.000"""
    return f"{int(x):,}".replace(",", ".")


def die(msg):
    print(f"LỖI: {msg}")
    sys.exit(1)
