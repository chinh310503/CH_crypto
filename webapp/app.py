"""CryptoBank — web app demo có 3 lỗ hổng ECDSA + bảng điều khiển tấn công.

Chạy:  python app.py    rồi mở http://127.0.0.1:5000
"""
from flask import (Flask, request, jsonify, render_template, redirect,
                   make_response)

import attacks
from bank import Bank, CURRENCY

app = Flask(__name__)
BANK = Bank()


def current_user():
    """Lấy ngữ cảnh người dùng từ cookie token — dùng verify_token CÓ LỖI
    (chính là bề mặt của tấn công Psychic Signatures)."""
    tok = request.cookies.get("session_token")
    if not tok:
        return None
    return BANK.vault.verify_token(tok)


# --------------------------------------------------------------------------
#  Giao diện ngân hàng (nạn nhân)
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect("/dashboard" if current_user() else "/login")


@app.route("/login")
def login_page():
    return render_template("login.html",
                           demo_accounts=[("alice", "alice123"),
                                          ("bob", "bob123"),
                                          ("carol", "carol123")])


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    ctx = BANK.authenticate(data.get("user"), data.get("password"))
    if not ctx:
        return jsonify({"ok": False, "error": "Sai tài khoản hoặc mật khẩu"}), 401
    token = BANK.vault.issue_token(ctx)
    resp = make_response(jsonify({"ok": True, "user": ctx}))
    resp.set_cookie("session_token", token, httponly=True, samesite="Lax")
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("session_token")
    return resp


@app.route("/dashboard")
def dashboard():
    u = current_user()
    if not u:
        return redirect("/login")
    return render_template("dashboard.html", user=u, currency=CURRENCY)


@app.route("/api/account")
def api_account():
    u = current_user()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(BANK.account(u["user"]))


@app.route("/api/transactions")
def api_transactions():
    # CÔNG KHAI — sổ cái chữ ký (bề mặt lộ nonce trùng)
    return jsonify(BANK.public_transactions())


@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    u = current_user()
    if not u:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    d = request.get_json(force=True)
    try:
        amount = int(d.get("amount", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "message": "Số tiền không hợp lệ"})
    ok, msg = BANK.transfer(u["user"], d.get("to"), amount)
    return jsonify({"ok": ok, "message": msg, "account": BANK.account(u["user"])})


@app.route("/api/admin/users")
def api_admin_users():
    u = current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "forbidden — chỉ admin"}), 403
    return jsonify({"accounts": BANK.all_accounts()})


@app.route("/api/enterprise/pubkey")
def api_enterprise_pubkey():
    return jsonify(BANK.vault.enterprise_pubinfo())


# --------------------------------------------------------------------------
#  Bảng điều khiển tấn công
# --------------------------------------------------------------------------
@app.route("/attacker")
def attacker_page():
    return render_template("attacker.html")


@app.route("/attack/nonce_reuse", methods=["POST"])
def atk_nonce_reuse():
    return jsonify(attacks.attack_nonce_reuse(BANK))


@app.route("/attack/psychic", methods=["POST"])
def atk_psychic():
    return jsonify(attacks.attack_psychic(BANK))


@app.route("/attack/pohlig", methods=["POST"])
def atk_pohlig():
    return jsonify(attacks.attack_pohlig(BANK))


@app.route("/api/state")
def api_state():
    """Trạng thái số dư mọi tài khoản — để bảng tấn công vẽ before/after."""
    return jsonify({"accounts": BANK.all_accounts(), "currency": CURRENCY})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    global BANK
    BANK = Bank()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True, port=5000, use_reloader=False)
