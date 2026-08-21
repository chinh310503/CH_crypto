"""Két mật mã của CryptoBank — CỐ TÌNH cài cắm 3 lỗ hổng ECDSA để demo.

    (1) Nonce reuse    : bộ sinh ngẫu nhiên hỏng (chu kỳ cực ngắn) khi ký giao dịch
                         → nonce lặp lại → lộ khóa ký master.
    (2) Psychic sigs   : verify_token dùng verify_insecure (bỏ kiểm tra r,s∈[1,n-1])
                         → chấp nhận chữ ký rỗng (0,0).
    (3) Đường cong yếu : khóa "enterprise" đặt trên đường cong bậc TRƠN
                         → Pohlig–Hellman khôi phục khóa riêng.

Các khóa bí mật (d_bank, d_token, d_ent) KHÔNG bao giờ được lộ ra ngoài; mọi tấn
công chỉ dùng dữ liệu công khai.
"""
import base64
import hashlib
import json
import secrets

from ecc_bridge import (SECP256K1, sign, verify, verify_insecure,
                        load_toy_smooth)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class BrokenRNG:
    """PRNG hỏng: chỉ có một 'hồ' nonce nhỏ và lặp vòng → nonce trùng lặp.

    Mô phỏng đúng bản chất sự cố ví Bitcoin trên Android 2013 (SecureRandom cạn
    entropy) và Sony PS3 2010 (nonce tĩnh).
    """

    def __init__(self, n: int, pool_size: int = 3):
        self.pool = [secrets.randbelow(n - 1) + 1 for _ in range(pool_size)]
        self.i = 0

    def next(self) -> int:
        k = self.pool[self.i % len(self.pool)]
        self.i += 1
        return k


class Vault:
    def __init__(self):
        n = SECP256K1.n
        # Khóa ký GIAO DỊCH (master) — bị ký bằng nonce yếu
        self.d_bank = secrets.randbelow(n - 1) + 1
        self.Q_bank = SECP256K1.mul(self.d_bank, SECP256K1.G)
        # Khóa ký TOKEN phiên đăng nhập
        self.d_token = secrets.randbelow(n - 1) + 1
        self.Q_token = SECP256K1.mul(self.d_token, SECP256K1.G)
        self._rng = BrokenRNG(n, pool_size=3)          # (1)
        # (3) Khóa ENTERPRISE trên đường cong bậc trơn
        self.toy = load_toy_smooth()
        self.d_ent = secrets.randbelow(self.toy.n - 1) + 1
        self.Q_ent = self.toy.mul(self.d_ent, self.toy.G)

    # ------------------------------------------------------------------
    # Giao dịch — ký bằng master key với NONCE YẾU  (lỗ hổng 1)
    # ------------------------------------------------------------------
    def sign_transaction(self, tx_bytes: bytes):
        k = self._rng.next()
        r, s, _ = sign(SECP256K1, self.d_bank, tx_bytes, k=k)
        return r, s

    def verify_transaction(self, tx_bytes: bytes, r: int, s: int) -> bool:
        return verify(SECP256K1, self.Q_bank, tx_bytes, r, s)

    # ------------------------------------------------------------------
    # Token phiên — XÁC MINH có lỗ hổng psychic  (lỗ hổng 2)
    # ------------------------------------------------------------------
    def issue_token(self, payload: dict) -> str:
        header = {"alg": "ES256", "typ": "JWT"}
        h = b64u(json.dumps(header, separators=(",", ":")).encode())
        p = b64u(json.dumps(payload, separators=(",", ":")).encode())
        r, s, _ = sign(SECP256K1, self.d_token, f"{h}.{p}".encode())
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{h}.{p}.{b64u(sig)}"

    def _parse_token(self, token: str):
        h, p, sg = token.split(".")
        sig = ub64u(sg)
        if len(sig) < 64:
            sig = sig.rjust(64, b"\x00")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:64], "big")
        return f"{h}.{p}".encode(), p, r, s

    def verify_token(self, token: str):
        """LỖ HỔNG: dùng verify_insecure → chấp nhận (r,s)=(0,0)."""
        try:
            msg, p, r, s = self._parse_token(token)
        except Exception:
            return None
        if verify_insecure(SECP256K1, self.Q_token, msg, r, s):
            return json.loads(ub64u(p))
        return None

    def verify_token_secure(self, token: str):
        """Bản VÁ (đối chứng) — dùng verify đúng chuẩn, sẽ từ chối (0,0)."""
        try:
            msg, p, r, s = self._parse_token(token)
        except Exception:
            return None
        if verify(SECP256K1, self.Q_token, msg, r, s):
            return json.loads(ub64u(p))
        return None

    # ------------------------------------------------------------------
    # Enterprise — đường cong bậc trơn  (lỗ hổng 3)
    #
    # Dùng chữ ký kiểu Schnorr (s·G = R + e·Q) vì nó hợp lệ với mọi bậc n,
    # kể cả n hợp số như đường cong trơn này (ECDSA đòi hỏi n nguyên tố). Điểm
    # yếu KHÔNG nằm ở sơ đồ ký mà ở chỗ n trơn → Pohlig–Hellman khôi phục được
    # khóa riêng chỉ từ khóa công khai Q_ent và tham số đường cong.
    # ------------------------------------------------------------------
    def enterprise_pubinfo(self) -> dict:
        t = self.toy
        return {"a": t.a, "b": t.b, "p": t.p, "n": t.n,
                "Gx": t.G.x, "Gy": t.G.y, "Qx": self.Q_ent.x, "Qy": self.Q_ent.y}

    @staticmethod
    def schnorr_challenge(curve, R, msg_bytes: bytes) -> int:
        data = f"{R.x},{R.y}".encode() + b"|" + msg_bytes
        return int.from_bytes(hashlib.sha256(data).digest(), "big") % curve.n

    def verify_enterprise(self, msg_bytes: bytes, Rx: int, Ry: int, s: int) -> bool:
        t = self.toy
        R = t.point(Rx, Ry)
        e = self.schnorr_challenge(t, R, msg_bytes)
        # kiểm tra s·G == R + e·Q_ent
        return t.mul(s, t.G) == t.add(R, t.mul(e, self.Q_ent))
