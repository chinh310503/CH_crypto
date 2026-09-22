"""CryptoBank — BẢN AN TOÀN (không còn lỗ hổng ECDSA).

Cùng giao diện/endpoint với bản cũ nhưng mọi mật mã dùng thư viện đã kiểm định:
ECDSA P-256 (`cryptography` + WebCrypto), token phiên ES256 (PyJWT). Chạy song song
với bản `webapp/` (có lỗ hổng) để đối chứng — cùng bộ `attack_client` sẽ thất bại ở đây.

Chạy:  python app.py    rồi mở http://127.0.0.1:5000
"""
from flask import (Flask, request, jsonify, render_template, redirect,
                   make_response)

from bank import Bank, CURRENCY

app = Flask(__name__)
BANK = Bank()


def current_user():
    tok = request.cookies.get("session_token")
    if not tok:
        return None
    return BANK.verify_token(tok)          # PyJWT ES256 — từ chối token sai/(0,0)


@app.route("/")
def index():
    return redirect("/dashboard" if current_user() else "/login")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True)
    ctx = BANK.authenticate(data.get("user"), data.get("password"))
    if not ctx:
        return jsonify({"ok": False, "error": "Sai tài khoản hoặc mật khẩu"}), 401
    resp = make_response(jsonify({"ok": True, "user": ctx}))
    resp.set_cookie("session_token", BANK.issue_token(ctx), httponly=True, samesite="Lax")
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


@app.route("/monitor")
def monitor():
    return render_template("monitor.html", currency=CURRENCY)


@app.route("/explorer")
def explorer():
    return render_template("explorer.html", currency=CURRENCY)


@app.route("/api/transactions")
def api_transactions():
    return jsonify(BANK.public_transactions())


@app.route("/api/accounts")
def api_accounts():
    return jsonify(BANK.account_keys())


@app.route("/api/state")
def api_state():
    t = BANK.totals()
    return jsonify({"accounts": BANK.public_accounts(), "currency": CURRENCY,
                    "assets": t["assets"], "tx_count": t["transactions"],
                    "next_id": BANK.next_id()})


@app.route("/api/tx/submit", methods=["POST"])
def api_tx_submit():
    d = request.get_json(force=True)
    try:
        tx = {"id": int(d["id"]), "from": d["from"], "to": d["to"],
              "amount": int(d["amount"])}
        r, s = int(d["r"]), int(d["s"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"ok": False, "message": "Dữ liệu không hợp lệ"}), 400
    ok, msg = BANK.submit_tx(tx, r, s)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/account")
def api_account():
    u = current_user()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(BANK.account(u["user"]))


@app.route("/api/wallet")
def api_wallet():
    u = current_user()
    if not u:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(BANK.wallet(u["user"]))


@app.route("/api/admin/users")
def api_admin_users():
    u = current_user()
    if not u or u.get("role") != "admin":
        return jsonify({"error": "forbidden — chỉ admin"}), 403
    return jsonify({"accounts": BANK.all_accounts()})


@app.route("/reset")
def reset_demo():
    global BANK
    BANK = Bank()
    resp = make_response(redirect("/login"))
    resp.delete_cookie("session_token")
    return resp


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=True, port=port, use_reloader=False)
