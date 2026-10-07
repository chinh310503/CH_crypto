from __future__ import annotations


def inverse_mod(k: int, m: int) -> int:
    if k % m == 0:
        raise ZeroDivisionError(f"{k} không khả nghịch modulo {m}")
    return pow(k % m, -1, m)


class Point:

    def __init__(self, curve: "EllipticCurve", x, y, infinity: bool = False):
        self.curve = curve
        self.x = x
        self.y = y
        self.infinity = infinity

    def is_infinity(self) -> bool:
        return self.infinity

    def __eq__(self, other) -> bool:
        if not isinstance(other, Point):
            return NotImplemented
        if self.infinity or other.infinity:
            return self.infinity and other.infinity
        return self.x == other.x and self.y == other.y

    def __neg__(self) -> "Point":
        if self.infinity:
            return self
        return Point(self.curve, self.x, (-self.y) % self.curve.p)

    def __add__(self, other: "Point") -> "Point":
        return self.curve.add(self, other)

    def __rmul__(self, k: int) -> "Point":
        return self.curve.mul(k, self)

    def __mul__(self, k: int) -> "Point":
        return self.curve.mul(k, self)

    def __repr__(self) -> str:
        if self.infinity:
            return "O(điểm vô cực)"
        return f"({self.x}, {self.y})"


class EllipticCurve:

    def __init__(self, a: int, b: int, p: int, n: int | None = None,
                 Gx: int | None = None, Gy: int | None = None, name: str = ""):
        self.a = a % p
        self.b = b % p
        self.p = p
        self.n = n
        self.name = name
        self.G = self.point(Gx, Gy) if Gx is not None else None

    def point(self, x: int, y: int) -> Point:
        return Point(self, x % self.p, y % self.p)

    @property
    def O(self) -> Point:
        return Point(self, None, None, infinity=True)

    def contains(self, P: Point) -> bool:
        if P.is_infinity():
            return True
        lhs = (P.y * P.y) % self.p
        rhs = (P.x ** 3 + self.a * P.x + self.b) % self.p
        return lhs == rhs

    def add(self, P: Point, Q: Point) -> Point:
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return self.O
        if P.x == Q.x and P.y == Q.y:
            m = (3 * P.x * P.x + self.a) * inverse_mod(2 * P.y, self.p) % self.p
        else:
            m = (Q.y - P.y) * inverse_mod((Q.x - P.x) % self.p, self.p) % self.p
        x3 = (m * m - P.x - Q.x) % self.p
        y3 = (m * (P.x - x3) - P.y) % self.p
        return Point(self, x3, y3)

    def mul(self, k: int, P: Point) -> Point:
        if P.is_infinity() or k == 0:
            return self.O
        if k < 0:
            k, P = -k, -P
        result = self.O
        addend = P
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result

    def __repr__(self) -> str:
        tag = f" [{self.name}]" if self.name else ""
        return f"EllipticCurve{tag}: y^2 = x^3 + {self.a}x + {self.b}  (mod {self.p})"
