from flask import (Flask, request, jsonify, render_template, redirect,
                   make_response)

from bank import Bank, CURRENCY

app = Flask(__name__)
BANK = Bank()


def current_user():
    tok = request.cookies.get("session_token")
    if not tok:
        return None
    return BANK.verify_token(tok)


@app.route("/")
def index():
    return redirect("/dashboard" if current_user() else "/login")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Dữ liệu JSON không hợp lệ"}), 400
    user = data.get("user")
    password = data.get("password")
    if not isinstance(user, str) or not isinstance(password, str):
        return jsonify({"ok": False, "error": "Tài khoản và mật khẩu phải là chuỗi"}), 400
    if len(user) == 0 or len(user) > 64:
        return jsonify({"ok": False, "error": "Tên tài khoản không hợp lệ"}), 400
    if len(password) == 0 or len(password) > 128:
        return jsonify({"ok": False, "error": "Mật khẩu không hợp lệ"}), 400
    ctx = BANK.authenticate(user, password)
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
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify({"ok": False, "message": "Dữ liệu JSON không hợp lệ"}), 400
    required = ("id", "from", "to", "amount", "r", "s")
    missing = [k for k in required if k not in d]
    if missing:
        return jsonify({"ok": False,
                        "message": f"Thiếu tham số: {', '.join(missing)}"}), 400
    try:
        tx_id = int(d["id"])
        amount = int(d["amount"])
        r, s = int(d["r"]), int(d["s"])
    except (TypeError, ValueError):
        return jsonify({"ok": False,
                        "message": "id, amount, r, s phải là số nguyên"}), 400
    frm, to = d["from"], d["to"]
    if not isinstance(frm, str) or not isinstance(to, str):
        return jsonify({"ok": False,
                        "message": "from và to phải là chuỗi"}), 400
    if len(frm) == 0 or len(frm) > 64 or len(to) == 0 or len(to) > 64:
        return jsonify({"ok": False,
                        "message": "Tên tài khoản không hợp lệ"}), 400
    if tx_id <= 0:
        return jsonify({"ok": False, "message": "Mã giao dịch phải > 0"}), 400
    if amount <= 0:
        return jsonify({"ok": False, "message": "Số tiền phải > 0"}), 400
    if r <= 0 or s <= 0:
        return jsonify({"ok": False,
                        "message": "Chữ ký (r, s) phải là số dương"}), 400
    tx = {"id": tx_id, "from": frm, "to": to, "amount": amount}
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
