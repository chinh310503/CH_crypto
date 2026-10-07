from __future__ import annotations
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def banner(title: str) -> None:
    line = "=" * 70
    print(f"\n{line}\n  {title}\n{line}")


def step(number, text: str) -> None:
    print(f"\n[{number}] {text}")


def info(label: str, value) -> None:
    print(f"    {label:<30}: {value}")


def short(x, head: int = 12, tail: int = 8) -> str:
    if isinstance(x, int) and x.bit_length() <= 44:
        return str(x)
    s = hex(x) if isinstance(x, int) else str(x)
    if len(s) <= head + tail + 1:
        return s
    return f"{s[:head]}…{s[-tail:]}"


def result(ok: bool, text: str) -> None:
    mark = "✔ THÀNH CÔNG" if ok else "✗ THẤT BẠI"
    print(f"\n    >>> {mark}: {text}")


def compare_keys(recovered: int, real: int) -> bool:
    ok = recovered == real
    print()
    info("Khóa bí mật THẬT (nạn nhân)", short(real))
    info("Khóa bí mật KHÔI PHỤC (tấn công)", short(recovered))
    result(ok, "Khôi phục đúng khóa bí mật!" if ok else "Khóa không khớp.")
    return ok
