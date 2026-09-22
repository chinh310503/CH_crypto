"""Trạng thái & nghiệp vụ CryptoBank — BẢN AN TOÀN.

Mọi tài khoản dùng ECDSA NIST P-256; ký/xác minh giao dịch và token phiên đều qua
thư viện (`cryptography`, PyJWT). KHÔNG có RNG hỏng, KHÔNG đường cong yếu, KHÔNG bỏ
bước kiểm tra — nên ba tấn công vào bản cũ (nonce reuse, psychic, đường cong yếu)
đều vô hiệu.
"""
import json
import random

import crypto

CURRENCY = "CBC"


def tx_bytes(tx: dict) -> bytes:
    """Chuẩn hóa giao dịch thành bytes để ký/xác minh (phải khớp tuyệt đối với client)."""
    return json.dumps(
        {"id": tx["id"], "from": tx["from"], "to": tx["to"], "amount": tx["amount"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()


_PEOPLE = [
    ("an", "Nguyễn Văn An"),       ("binh", "Trần Thị Bình"),
    ("cuong", "Lê Văn Cường"),     ("dung", "Phạm Thị Dung"),
    ("em", "Hoàng Văn Em"),        ("phuong", "Võ Thị Phượng"),
    ("giang", "Đặng Văn Giang"),   ("hoa", "Bùi Thị Hoa"),
    ("khoa", "Đỗ Văn Khoa"),       ("lan", "Ngô Thị Lan"),
    ("minh", "Dương Văn Minh"),    ("nga", "Lý Thị Nga"),
    ("oanh", "Phan Văn Oanh"),     ("phuc", "Huỳnh Thị Phúc"),
    ("quan", "Trương Văn Quân"),
]


class Bank:
    def __init__(self):
        self._tok_priv, self._tok_pub = crypto.server_keypair_pem()
        rnd = random.Random(20260908)
        self.users = {}

        def add(u, name, role, bal, pw=None):
            priv, pub = crypto.new_keypair()
            self.users[u] = {
                "name": name, "password": pw, "role": role, "balance": bal,
                "priv": priv, "pub": pub,
                "email": f"{u}@cryptobank.vn",
                "cccd": "".join(str(rnd.randint(0, 9)) for _ in range(12)),
                "phone": "09" + "".join(str(rnd.randint(0, 9)) for _ in range(8)),
            }

        # 4 tài khoản demo (mật khẩu tên:tên123) + các khách hàng nền — TẤT CẢ P-256.
        add("alice", "Alice", "user", 5000, "alice123")
        add("bob", "Bob", "user", 1500, "bob123")
        add("carlos", "Carlos", "enterprise", 5000000, "carlos123")
        add("admin", "Quản Trị Viên", "admin", 100000, "admin123")
        for u, name in _PEOPLE:
            add(u, name, "user", rnd.randint(80, 400) * 100)

        self.transactions = []
        self.used_ids = set()
        self._next_id = 1
        self._seed_history(rnd)

    def issue_token(self, payload):
        return crypto.issue_token(self._tok_priv, payload)

    def verify_token(self, token):
        return crypto.verify_token(self._tok_pub, token)

    def _seed_history(self, rnd):
        """Vài giao dịch bình thường mỗi ví — đều ký an toàn, nonce không lặp."""
        senders = list(self.users)
        for u in senders:
            for _ in range(rnd.randint(1, 3)):
                to = rnd.choice([x for x in senders if x != u])
                self._logged_in_transfer(u, to, rnd.randint(10, 90))

    def _logged_in_transfer(self, frm, to, amount):
        acct = self.users[frm]
        tx = {"id": self._next_id, "from": frm, "to": to, "amount": amount}
        self._next_id += 1
        r, s = crypto.sign_tx(acct["priv"], tx_bytes(tx))
        return self.submit_tx(tx, r, s)

    def submit_tx(self, tx, r, s):
        """Con đường DUY NHẤT để tiền dịch chuyển: xác minh chữ ký ECDSA của người gửi
        (qua thư viện) rồi thực thi."""
        frm, to = tx.get("from"), tx.get("to")
        if frm not in self.users or to not in self.users:
            return False, "Tài khoản không tồn tại"
        if tx["id"] in self.used_ids:
            return False, "Mã giao dịch đã dùng"
        if tx["amount"] <= 0:
            return False, "Số tiền không hợp lệ"
        acct = self.users[frm]
        if not crypto.verify_tx(acct["pub"], tx_bytes(tx), r, s):
            return False, "Chữ ký KHÔNG hợp lệ"
        if acct["balance"] < tx["amount"]:
            return False, "Số dư không đủ"
        self.users[frm]["balance"] -= tx["amount"]
        self.users[to]["balance"] += tx["amount"]
        self.transactions.append({"id": tx["id"], "from": frm, "to": to,
                                  "amount": tx["amount"], "r": r, "s": s})
        self.used_ids.add(tx["id"])
        self._next_id = max(self._next_id, tx["id"] + 1)
        return True, "Giao dịch thành công"

    def next_id(self):
        return self._next_id

    def authenticate(self, user, pw):
        u = self.users.get(user)
        if u and u["password"] is not None and u["password"] == pw:
            return {"user": user, "role": u["role"]}
        return None

    def _pub_xy(self, u):
        x, y = crypto.public_xy(self.users[u]["pub"])
        return {"x": str(x), "y": str(y)}

    def public_transactions(self):
        return [{"id": t["id"], "from": t["from"], "to": t["to"], "amount": t["amount"],
                 "r": str(t["r"]), "s": str(t["s"])} for t in self.transactions]

    def account_keys(self):
        return [{"user": k, "name": v["name"], "curve": crypto.P256_PARAMS,
                 "pub": self._pub_xy(k)} for k, v in self.users.items()]

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
                "pub": self._pub_xy(user), "next_id": self._next_id,
                "history": [{"id": t["id"], "from": t["from"], "to": t["to"],
                             "amount": t["amount"]} for t in hist[-12:]]}

    def wallet(self, user):
        """Nạp ví vào trình duyệt: khóa riêng dạng JWK để WebCrypto import (non-custodial)."""
        u = self.users.get(user)
        if not u:
            return None
        return {"user": user, "jwk": crypto.private_jwk(u["priv"]),
                "curve": crypto.P256_PARAMS, "next_id": self._next_id}

    def totals(self):
        return {"assets": sum(v["balance"] for v in self.users.values()),
                "transactions": len(self.transactions)}
