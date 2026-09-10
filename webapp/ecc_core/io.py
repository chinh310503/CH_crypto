"""Tiện ích in ấn cho demo — giúp mọi kịch bản có định dạng đầu ra nhất quán.

Import module này cũng tự động chuyển stdout sang UTF-8, nhờ đó tiếng Việt và
các ký hiệu (✔ ✗ …) hiển thị đúng trên console Windows (mặc định cp1252).
"""
from __future__ import annotations
import sys

# Đảm bảo in được tiếng Việt trên mọi terminal (Windows cmd dùng cp1252).
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
    """Rút gọn số để in cho gọn.

    Số nhỏ (<= 44 bit) in ở dạng thập phân cho dễ đọc; số lớn (khóa 256-bit)
    in dạng hex rút gọn 0x1234…abcd.
    """
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
