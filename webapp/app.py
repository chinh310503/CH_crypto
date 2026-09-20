"""CryptoBank — web app demo (mô hình ví/sàn) có 3 lỗ hổng ECDSA.

Web app chỉ là "nạn nhân". Tấn công do các script trong ../attack_client thực hiện
qua HTTP, dùng đúng các API công khai của trang (không có API ẩn):
  - POST /api/tx/submit  : nộp (broadcast) giao dịch đã ký ECDSA
  - GET  /api/transactions: sổ cái chữ ký công khai
  - GET  /api/accounts   : danh bạ khóa công khai + tham số đường cong
  - GET  /api/admin/users: (cần token admin) hồ sơ PII

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
    return BANK.vault.verify_token(tok)          # verify có lỗ hổng psychic


#  Giao diện
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


@app.route("/monitor")
def monitor():
    return render_template("monitor.html", currency=CURRENCY)


@app.route("/explorer")
def explorer():
    return render_template("explorer.html", currency=CURRENCY)


#  API công khai (bề mặt tấn công đều là chức năng thật)
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
    """Nộp một giao dịch đã ký ECDSA. Server xác minh chữ ký của người gửi rồi thực
    thi. Đây là con đường DUY NHẤT để tiền dịch chuyển (giống broadcast blockchain)."""
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
    """Nạp 'ví' vào trình duyệt của chính chủ tài khoản (đã đăng nhập): khóa riêng +
    tham số đường cong. Trình duyệt dùng khóa này để TỰ KÝ giao dịch rồi broadcast
    qua /api/tx/submit — giống ví non-custodial (MetaMask). KHÔNG có endpoint ký hộ:
    chuyển tiền bình thường và tấn công đều đi qua đúng một con đường /api/tx/submit."""
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


#  Tiện ích demo
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
