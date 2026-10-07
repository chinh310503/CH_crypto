import base64
import json
import secrets

from ecc_core import SECP256K1, sign, verify, verify_insecure


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def ub64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class BrokenRNG:

    def __init__(self, n: int, pool_size: int = 2):
        self.pool = [secrets.randbelow(n - 1) + 1 for _ in range(pool_size)]
        self.i = 0

    def next(self) -> int:
        k = self.pool[self.i % len(self.pool)]
        self.i += 1
        return k


class SafeRNG:

    def __init__(self, n: int):
        self.n = n

    def next(self) -> int:
        return secrets.randbelow(self.n - 1) + 1


def sign_tx(curve, d: int, tx_bytes: bytes, rng: BrokenRNG):
    for _ in range(8):
        k = rng.next()
        try:
            r, s, _ = sign(curve, d, tx_bytes, k=k)
            return r, s
        except ValueError:
            continue
    raise RuntimeError("không ký được giao dịch")


def verify_tx(curve, Q, tx_bytes: bytes, r: int, s: int) -> bool:
    return verify(curve, Q, tx_bytes, r, s)


def new_keypair(curve):
    d = secrets.randbelow(curve.n - 1) + 1
    return d, curve.mul(d, curve.G)


class Vault:
    def __init__(self):
        n = SECP256K1.n
        self.d_token = secrets.randbelow(n - 1) + 1
        self.Q_token = SECP256K1.mul(self.d_token, SECP256K1.G)

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
        try:
            msg, p, r, s = self._parse_token(token)
        except Exception:
            return None
        if verify_insecure(SECP256K1, self.Q_token, msg, r, s):
            return json.loads(ub64u(p))
        return None

    def verify_token_secure(self, token: str):
        try:
            msg, p, r, s = self._parse_token(token)
        except Exception:
            return None
        if verify(SECP256K1, self.Q_token, msg, r, s):
            return json.loads(ub64u(p))
        return None
