"""Cầu nối: thêm thư mục demo/ vào sys.path để tái dùng thư viện lõi ecc_core
(không nhân bản code). Toàn bộ web app import mật mã ECDSA qua đây.
"""
import os
import sys

_DEMO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "demo")
if _DEMO not in sys.path:
    sys.path.insert(0, _DEMO)

from ecc_core import (                       # noqa: E402
    SECP256K1, EllipticCurve, Point, inverse_mod,
    keygen, sign, verify, verify_insecure, load_toy_smooth,
)
from ecc_core.ecdsa import _hash_to_int      # noqa: E402

__all__ = [
    "SECP256K1", "EllipticCurve", "Point", "inverse_mod",
    "keygen", "sign", "verify", "verify_insecure", "load_toy_smooth",
    "_hash_to_int",
]
