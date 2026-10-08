import base64

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

CURVE = ec.SECP256R1()

P256_PARAMS = {
    "name": "secp256r1",
    "a": str(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc),
    "b": str(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b),
    "p": str(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff),
    "n": str(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    "Gx": str(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296),
    "Gy": str(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def new_keypair():
    priv = ec.generate_private_key(CURVE)
    return priv, priv.public_key()


def public_xy(pub):
    n = pub.public_numbers()
    return n.x, n.y


def private_jwk(priv) -> dict:
    n = priv.private_numbers()
    p = n.public_numbers
    return {"kty": "EC", "crv": "P-256",
            "x": _b64u(p.x.to_bytes(32, "big")),
            "y": _b64u(p.y.to_bytes(32, "big")),
            "d": _b64u(n.private_value.to_bytes(32, "big")),
            "key_ops": ["sign"], "ext": True}


def sign_tx(priv, message: bytes):
    return decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))


N = int(P256_PARAMS["n"])


def verify_tx(pub, message: bytes, r: int, s: int) -> bool:
    if not isinstance(r, int) or not isinstance(s, int):
        return False
    if not (0 < r < N and 0 < s < N):
        return False
    try:
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def server_keypair_pem():
    priv = ec.generate_private_key(CURVE)
    priv_pem = priv.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def issue_token(priv_pem, payload: dict) -> str:
    return jwt.encode(payload, priv_pem, algorithm="ES256")


def verify_token(pub_pem, token: str):
    try:
        return jwt.decode(token, pub_pem, algorithms=["ES256"])
    except jwt.InvalidTokenError:
        return None
