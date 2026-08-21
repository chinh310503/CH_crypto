"""Trạng thái & nghiệp vụ của CryptoBank (lưu trong bộ nhớ, đủ cho demo)."""
import json
import time

from vault import Vault

CURRENCY = "CBC"


def tx_bytes(tx: dict) -> bytes:
    """Chuẩn hóa giao dịch thành bytes để ký/xác minh (phải khớp tuyệt đối)."""
    return json.dumps(
        {"id": tx["id"], "from": tx["from"], "to": tx["to"], "amount": tx["amount"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()


class Bank:
    def __init__(self):
        self.vault = Vault()
        self.users = {
            "alice":    {"password": "alice123", "role": "user",       "balance": 5000},
            "bob":      {"password": "bob123",   "role": "user",       "balance": 1500},
            "carol":    {"password": "carol123", "role": "user",       "balance": 3200},
            "admin":    {"password": "S3cr3t!" + str(int(time.time())),
                         "role": "admin", "balance": 100000},
            "megacorp": {"password": None, "role": "enterprise", "balance": 5000000},
        }
        self.transactions = []
        self._next_id = 1
        self._seed_history()

    # ------------------------------------------------------------------
    def _record(self, frm, to, amount):
        tx = {"id": self._next_id, "from": frm, "to": to, "amount": amount}
        self._next_id += 1
        r, s = self.vault.sign_transaction(tx_bytes(tx))
        tx["r"], tx["s"] = r, s
        self.transactions.append(tx)
        return tx

    def _seed_history(self):
        # Lịch sử chữ ký mẫu — chính là bề mặt để lộ nonce trùng.
        seeds = [("alice", "carol", 120), ("bob", "alice", 75),
                 ("carol", "bob", 200), ("alice", "bob", 50),
                 ("carol", "alice", 300), ("bob", "carol", 25),
                 ("alice", "carol", 90), ("carol", "bob", 140)]
        for frm, to, amt in seeds:
            self._record(frm, to, amt)

    # ---- auth ----
    def authenticate(self, user, pw):
        u = self.users.get(user)
        if u and u["password"] is not None and u["password"] == pw:
            return {"user": user, "role": u["role"]}
        return None

    # ---- truy vấn ----
    def public_transactions(self):
        # r, s trả về dạng CHUỖI để tránh mất chính xác số lớn trong JavaScript.
        return [{"id": t["id"], "from": t["from"], "to": t["to"],
                 "amount": t["amount"], "r": str(t["r"]), "s": str(t["s"])}
                for t in self.transactions]

    def account(self, user):
        u = self.users.get(user)
        if not u:
            return None
        hist = [t for t in self.transactions if t["from"] == user or t["to"] == user]
        return {"user": user, "role": u["role"], "balance": u["balance"],
                "history": [{"id": t["id"], "from": t["from"], "to": t["to"],
                             "amount": t["amount"]} for t in hist[-10:]]}

    def all_accounts(self):
        return [{"user": k, "role": v["role"], "balance": v["balance"]}
                for k, v in self.users.items()]

    # ---- nghiệp vụ ----
    def transfer(self, frm, to, amount):
        if frm not in self.users or to not in self.users:
            return False, "Tài khoản không tồn tại"
        if amount <= 0:
            return False, "Số tiền không hợp lệ"
        if self.users[frm]["balance"] < amount:
            return False, "Số dư không đủ"
        self.users[frm]["balance"] -= amount
        self.users[to]["balance"] += amount
        self._record(frm, to, amount)
        return True, "Chuyển tiền thành công"

    def execute_clearing(self, tx, r, s):
        """Thực hiện giao dịch được KÝ bởi ngân hàng, KHÔNG cần đăng nhập.

        Chỉ chấp nhận nếu chữ ký master hợp lệ — bình thường chỉ ngân hàng ký
        được. Đây là điểm khiến việc lộ khóa master trở thành thảm họa.
        """
        if not self.vault.verify_transaction(tx_bytes(tx), r, s):
            return False, "Chữ ký ngân hàng KHÔNG hợp lệ"
        frm, to, amount = tx["from"], tx["to"], tx["amount"]
        if self.users[frm]["balance"] < amount:
            return False, "Số dư không đủ"
        self.users[frm]["balance"] -= amount
        self.users[to]["balance"] += amount
        rec = dict(tx)
        rec["r"], rec["s"] = r, s
        self.transactions.append(rec)
        return True, "Đã thanh toán"

    def enterprise_withdraw(self, to, amount, Rx, Ry, s):
        """Rút tiền tài khoản enterprise — cần chữ ký Schnorr khóa enterprise."""
        msg = f"WITHDRAW:{amount}:TO:{to}".encode()
        if not self.vault.verify_enterprise(msg, Rx, Ry, s):
            return False, "Chữ ký enterprise KHÔNG hợp lệ"
        if self.users["megacorp"]["balance"] < amount:
            return False, "Số dư không đủ"
        self.users["megacorp"]["balance"] -= amount
        self.users[to]["balance"] += amount
        return True, "Đã rút tiền enterprise"
