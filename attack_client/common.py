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

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
os.system("")   # bật mã màu ANSI trên Windows 10+


class C:
    R = "\033[31m"; G = "\033[32m"; Y = "\033[33m"; CY = "\033[36m"
    B = "\033[1m"; D = "\033[2m"; X = "\033[0m"


_DEMO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo")
if _DEMO not in sys.path:
    sys.path.insert(0, _DEMO)
from ecc_core import SECP256K1, EllipticCurve, inverse_mod, sign   # noqa: E402
from ecc_core.ecdsa import _hash_to_int as hash_to_int            # noqa: E402

BASE = os.environ.get("TARGET", "http://127.0.0.1:5000").rstrip("/")


# ======================= HTTP =======================
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


# ======================= tiện ích ECDSA =======================
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


# ======================= in ấn =======================
def banner(t):
    print(f"\n{C.B}{'=' * 68}{C.X}\n{C.B}  {t}{C.X}\n{C.B}{'=' * 68}{C.X}")


def step(n, t):
    print(f"\n{C.Y}[{n}]{C.X} {C.B}{t}{C.X}")


def info(k, v):
    print(f"    {C.D}{k:<30}{C.X}: {v}")


def ok(t):
    print(f"    {C.G}✔{C.X} {t}")


def bad(t):
    print(f"    {C.R}✗{C.X} {t}")


def impact(t):
    print(f"\n{C.R}{C.B}  ⛔ IMPACT: {t}{C.X}\n")


def money(x):
    return f"{int(x):,}".replace(",", ".")


def die(msg):
    print(f"{C.R}LỖI: {msg}{C.X}")
    sys.exit(1)
