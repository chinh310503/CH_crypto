"""Trạng thái & nghiệp vụ CryptoBank theo mô hình ví/sàn giao dịch.

- Mỗi tài khoản có cặp khóa ECDSA riêng (người dùng thường trên secp256k1; tài khoản
  enterprise 'omnicorp' trên đường cong yếu).
- Chuyển tiền = giao dịch được KÝ ECDSA bằng khóa người gửi; server XÁC MINH chữ ký
  với khóa công khai của người gửi rồi mới thực thi (qua /api/tx/submit).
- Ví người dùng dùng RNG hỏng khi ký → nonce trùng lặp lộ trên sổ cái công khai.
"""
import json
import random

from ecc_core import STANDARD_CURVES, load_weak_curve
from vault import Vault, BrokenRNG, sign_tx, verify_tx, new_keypair

CURRENCY = "CBC"
WEAK = load_weak_curve()


def tx_bytes(tx: dict) -> bytes:
    """Chuẩn hóa giao dịch thành bytes để ký/xác minh (phải khớp tuyệt đối)."""
    return json.dumps(
        {"id": tx["id"], "from": tx["from"], "to": tx["to"], "amount": tx["amount"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()


def _curve_info(curve) -> dict:
    """Mô tả tham số đường cong. TẤT CẢ số để dạng chuỗi: a, b của họ NIST là số
    ~256 bit (a ≡ -3 mod p), nếu để dạng số JSON sẽ mất chính xác khi JavaScript
    parse (double) → hệ số a sai → ký trong trình duyệt hỏng."""
    return {"name": curve.name, "a": str(curve.a), "b": str(curve.b),
            "p": str(curve.p), "n": str(curve.n),
            "Gx": str(curve.G.x), "Gy": str(curve.G.y)}


_PEOPLE = [
    ("nguyenvana", "Nguyễn Văn An"),   ("tranthib", "Trần Thị Bình"),
    ("levanc", "Lê Văn Cường"),        ("phamthid", "Phạm Thị Dung"),
    ("hoangvane", "Hoàng Văn Em"),     ("vothif", "Võ Thị Phượng"),
    ("dangvang", "Đặng Văn Giang"),    ("buithih", "Bùi Thị Hoa"),
    ("dovank", "Đỗ Văn Khoa"),         ("ngothil", "Ngô Thị Lan"),
    ("duongvanm", "Dương Văn Minh"),   ("lythin", "Lý Thị Nga"),
    ("phanvano", "Phan Văn Oanh"),     ("huynhthip", "Huỳnh Thị Phúc"),
    ("truongvanq", "Trương Văn Quân"),
]


class Bank:
    def __init__(self):
        self.vault = Vault()
        rnd = random.Random(20260908)
        self.users = {}

        def add(u, name, role, bal, curve, pw=None):
            d, Q = new_keypair(curve)
            self.users[u] = {
                "name": name, "password": pw, "role": role, "balance": bal,
                "curve": curve, "d": d, "Q": Q,
                "rng": BrokenRNG(curve.n, pool_size=2),   # ví lỗi RNG
                "email": f"{u}@cryptobank.vn",
                "cccd": "".join(str(rnd.randint(0, 9)) for _ in range(12)),
                "phone": "09" + "".join(str(rnd.randint(0, 9)) for _ in range(8)),
            }

        # Mỗi tài khoản thường được gán NGẪU NHIÊN một đường cong chuẩn (secp256k1
        # hoặc họ NIST P-192/224/256) → danh bạ khóa công khai trông đa dạng như thật.
        pick = lambda: rnd.choice(STANDARD_CURVES)
        add("alice", "Nguyễn Alice", "user", 5000, pick(), "alice123")
        add("bob", "Trần Bob", "user", 1500, pick(), "bob123")
        add("carol", "Lê Carol", "user", 3200, pick(), "carol123")
        add("admin", "Quản Trị Viên", "admin", 100000, pick(), "S3cr3t!" + str(rnd.randint(1000, 9999)))
        add("omnicorp", "Tập Đoàn OmniCorp", "enterprise", 5000000, WEAK)  # đường cong yếu
        for u, name in _PEOPLE:
            add(u, name, "user", rnd.randint(80, 400) * 100, pick())

        self.transactions = []
        self.used_ids = set()
        self._next_id = 1
        self._seed_history(rnd)

    # ------------------------------------------------------------------
    def _seed_history(self, rnd):
        """Mỗi ví (trừ omnicorp) gửi vài giao dịch nhỏ → sổ cái + nonce trùng."""
        senders = [u for u in self.users if u != "omnicorp"]
        others = list(senders)
        for u in senders:
            for _ in range(3):                       # 3 giao dịch → chắc chắn lặp nonce
                to = rnd.choice([x for x in others if x != u])
                self._logged_in_transfer(u, to, rnd.randint(10, 90))

    # ------------------------------------------------------------------
    def _do_transfer(self, frm, to, amount):
        self.users[frm]["balance"] -= amount
        self.users[to]["balance"] += amount

    def _append(self, tx, r, s):
        rec = {"id": tx["id"], "from": tx["from"], "to": tx["to"],
               "amount": tx["amount"], "r": r, "s": s}
        self.transactions.append(rec)
        self.used_ids.add(tx["id"])
        # Bộ đếm số thứ tự luôn tiến qua id vừa dùng → mọi giao dịch (seed, web, tấn
        # công) đánh số tuần tự chung một dãy.
        self._next_id = max(self._next_id, tx["id"] + 1)

    def _logged_in_transfer(self, frm, to, amount):
        """Tạo giao dịch, KÝ bằng khóa người gửi (RNG ví), rồi nộp như mọi giao dịch."""
        acct = self.users[frm]
        tx = {"id": self._next_id, "from": frm, "to": to, "amount": amount}
        self._next_id += 1
        r, s = sign_tx(acct["curve"], acct["d"], tx_bytes(tx), acct["rng"])
        return self.submit_tx(tx, r, s)

    # ---- API nghiệp vụ ----
    def submit_tx(self, tx, r, s):
        """Nộp một giao dịch đã ký (broadcast). Xác minh chữ ký ECDSA của NGƯỜI GỬI
        với khóa công khai của họ, rồi thực thi. Đây là con đường DUY NHẤT để tiền
        dịch chuyển — dùng chung bởi form chuyển tiền lẫn kẻ tấn công."""
        frm, to = tx.get("from"), tx.get("to")
        if frm not in self.users or to not in self.users:
            return False, "Tài khoản không tồn tại"
        if tx["id"] in self.used_ids:
            return False, "Mã giao dịch đã dùng"
        if tx["amount"] <= 0:
            return False, "Số tiền không hợp lệ"
        acct = self.users[frm]
        if not verify_tx(acct["curve"], acct["Q"], tx_bytes(tx), r, s):
            return False, "Chữ ký KHÔNG hợp lệ"
        if acct["balance"] < tx["amount"]:
            return False, "Số dư không đủ"
        self._do_transfer(frm, to, tx["amount"])
        self._append(tx, r, s)
        return True, "Giao dịch thành công"

    def next_id(self):
        return self._next_id

    # ---- auth ----
    def authenticate(self, user, pw):
        u = self.users.get(user)
        if u and u["password"] is not None and u["password"] == pw:
            return {"user": user, "role": u["role"]}
        return None

    # ---- truy vấn công khai ----
    def public_transactions(self):
        return [{"id": t["id"], "from": t["from"], "to": t["to"], "amount": t["amount"],
                 "r": str(t["r"]), "s": str(t["s"])} for t in self.transactions]

    def account_keys(self):
        """Danh bạ khóa công khai + tham số đường cong (bề mặt cho tấn công)."""
        out = []
        for k, v in self.users.items():
            out.append({"user": k, "name": v["name"], "curve": _curve_info(v["curve"]),
                        "pub": {"x": str(v["Q"].x), "y": str(v["Q"].y)}})
        return out

    def public_accounts(self):
        return [{"user": k, "name": v["name"], "balance": v["balance"]}
                for k, v in self.users.items()]

    def all_accounts(self):
        return [{"user": k, "name": v["name"], "role": v["role"], "balance": v["balance"],
                 "email": v["email"], "cccd": v["cccd"], "phone": v["phone"]}
                for k, v in self.users.items()]

    def account(self, user):
        u = self.users.get(user)
        if not u:
            return None
        hist = [t for t in self.transactions if t["from"] == user or t["to"] == user]
        return {"user": user, "name": u["name"], "role": u["role"], "balance": u["balance"],
                "pub": {"x": str(u["Q"].x), "y": str(u["Q"].y)}, "next_id": self._next_id,
                "history": [{"id": t["id"], "from": t["from"], "to": t["to"],
                             "amount": t["amount"]} for t in hist[-12:]]}

    def wallet(self, user):
        """Nạp 'ví' của người dùng vào trình duyệt: khóa riêng + tham số đường cong,
        để trình duyệt TỰ KÝ giao dịch (giống ví non-custodial). Chỉ trả cho chính
        chủ tài khoản (đã đăng nhập)."""
        u = self.users.get(user)
        if not u:
            return None
        return {"user": user, "d": str(u["d"]), "curve": _curve_info(u["curve"]),
                "pub": {"x": str(u["Q"].x), "y": str(u["Q"].y)},
                "next_id": self._next_id}

    def totals(self):
        return {"assets": sum(v["balance"] for v in self.users.values()),
                "transactions": len(self.transactions)}
