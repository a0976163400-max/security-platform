from flask import Flask, request, redirect, session, Response, jsonify
import sqlite3
import os
import socket
import ssl
import time
import csv
import io
import secrets
import stripe
from datetime import datetime
from html import escape as html_escape
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import requests
except Exception:
    requests = None


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY")

DB = os.environ.get("DB_PATH", "business_saas.db")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "123456")


# =========================
# 基本工具
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def esc(v):
    return html_escape(str(v if v is not None else ""))


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default


def add_column_if_missing(cursor, table, column, col_type):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except Exception:
        pass


# =========================
# 資料庫
# =========================

def init_db():
    conn = db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        plan TEXT DEFAULT 'Free',
        api_key TEXT,
        stripe_subscription_id TEXT,
        expire_date TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS websites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        client_id INTEGER,
        name TEXT,
        url TEXT,
        note TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        website_name TEXT,
        url TEXT,
        ip TEXT,
        status TEXT,
        response_time TEXT,
        server TEXT,
        ssl_expire TEXT,
        ssl_days INTEGER,
        score INTEGER,
        risk TEXT,
        alert TEXT,
        report TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        email TEXT,
        phone TEXT,
        note TEXT,
        created_at TEXT
    )
    """)

    # 保險：舊資料庫缺欄位時自動補
    add_column_if_missing(c, "users", "plan", "TEXT DEFAULT 'Free'")
    add_column_if_missing(c, "users", "api_key", "TEXT")
    add_column_if_missing(c, "users", "stripe_subscription_id", "TEXT")
    add_column_if_missing(c, "users", "expire_date", "TEXT")
    add_column_if_missing(c, "users", "created_at", "TEXT")

    add_column_if_missing(c, "websites", "user_id", "INTEGER")
    add_column_if_missing(c, "websites", "client_id", "INTEGER")
    add_column_if_missing(c, "websites", "name", "TEXT")
    add_column_if_missing(c, "websites", "url", "TEXT")
    add_column_if_missing(c, "websites", "note", "TEXT")
    add_column_if_missing(c, "websites", "created_at", "TEXT")

    add_column_if_missing(c, "reports", "user_id", "INTEGER")
    add_column_if_missing(c, "reports", "website_name", "TEXT")
    add_column_if_missing(c, "reports", "url", "TEXT")
    add_column_if_missing(c, "reports", "ip", "TEXT")
    add_column_if_missing(c, "reports", "status", "TEXT")
    add_column_if_missing(c, "reports", "response_time", "TEXT")
    add_column_if_missing(c, "reports", "server", "TEXT")
    add_column_if_missing(c, "reports", "ssl_expire", "TEXT")
    add_column_if_missing(c, "reports", "ssl_days", "INTEGER")
    add_column_if_missing(c, "reports", "score", "INTEGER")
    add_column_if_missing(c, "reports", "risk", "TEXT")
    add_column_if_missing(c, "reports", "alert", "TEXT")
    add_column_if_missing(c, "reports", "report", "TEXT")
    add_column_if_missing(c, "reports", "created_at", "TEXT")

    add_column_if_missing(c, "clients", "user_id", "INTEGER")
    add_column_if_missing(c, "clients", "name", "TEXT")
    add_column_if_missing(c, "clients", "email", "TEXT")
    add_column_if_missing(c, "clients", "phone", "TEXT")
    add_column_if_missing(c, "clients", "note", "TEXT")
    add_column_if_missing(c, "clients", "created_at", "TEXT")

    c.execute("""
    INSERT OR IGNORE INTO users
    (username, password_hash, plan, api_key, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        ADMIN_USER,
        generate_password_hash(ADMIN_PASS),
        "Business",
        "admin-key",
        now()
    ))

    conn.commit()
    conn.close()


init_db()


# =========================
# 方案限制
# =========================

def plan_limit(plan):
    plan = (plan or "Free").lower()
    if plan == "business":
        return 50
    if plan == "pro":
        return 5
    return 1


# =========================
# 使用者
# =========================

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (uid,))
    user = c.fetchone()
    conn.close()
    return user


def require_login():
    if not session.get("user_id"):
        return False
    return True


# =========================
# HTML 樣板
# =========================

def layout(title, content):
    user = current_user()

    nav = ""
    if user:
        nav = f"""
        <a href="/">首頁</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/export">匯出CSV</a>
        <a href="/logout">登出</a>
        """
    else:
        nav = """
        <a href="/">首頁</a>
        <a href="/register">免費註冊</a>
        <a href="/login">登入</a>
        """

    html = f"""
    <!doctype html>
    <html lang="zh-Hant">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{esc(title)}</title>
        <style>
            body {{
                margin: 0;
                font-family: Arial, "Microsoft JhengHei", sans-serif;
                background: #030712;
                color: #f9fafb;
                font-size: 18px;
            }}
            .wrap {{
                padding: 34px;
            }}
            h1 {{
                font-size: 38px;
                margin: 0 0 24px 0;
            }}
            h2 {{
                font-size: 28px;
                margin-top: 0;
            }}
            h3 {{
                font-size: 24px;
            }}
            p, li {{
                line-height: 1.7;
            }}
            a {{
                color: #93c5fd;
                text-decoration: none;
                font-weight: bold;
                margin-right: 16px;
            }}
            .nav {{
                margin-bottom: 28px;
            }}
            .card {{
                background: #111827;
                border: 1px solid #253044;
                border-radius: 18px;
                padding: 24px;
                margin-bottom: 22px;
            }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
                gap: 18px;
            }}
            .box {{
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 14px;
                padding: 18px;
            }}
            input, textarea, select {{
                width: 100%;
                padding: 14px;
                border-radius: 12px;
                border: 1px solid #475569;
                font-size: 17px;
                box-sizing: border-box;
                margin: 8px 0 16px 0;
            }}
            button, .btn {{
                background: #22c55e;
                color: #02120a;
                border: 0;
                border-radius: 12px;
                padding: 14px 22px;
                font-size: 17px;
                font-weight: bold;
                cursor: pointer;
                display: inline-block;
            }}
            .btn-red {{
                background: #ef4444;
                color: white;
            }}
            .muted {{
                color: #cbd5e1;
            }}
            .danger {{
                color: #fca5a5;
                font-weight: bold;
            }}
            .warn {{
                color: #facc15;
                font-weight: bold;
            }}
            .good {{
                color: #86efac;
                font-weight: bold;
            }}
            pre {{
                white-space: pre-wrap;
                background: #020617;
                border: 1px solid #334155;
                padding: 18px;
                border-radius: 14px;
                overflow-x: auto;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
            }}
            th, td {{
                border-bottom: 1px solid #334155;
                padding: 10px;
                text-align: left;
            }}
            th {{
                color: #bfdbfe;
            }}
        </style>
    </head>
    <body>
        <div class="wrap">
            <div class="nav">{nav}</div>
            {content}
        </div>
    </body>
    </html>
    """
    return html


# =========================
# 首頁
# =========================

@app.route("/")
def home():
    content = """
    <h1>🛡️ Security SaaS 網站防禦健檢平台</h1>

    <div class="card">
        <h2>幫客戶檢查網站 SSL、Header、Cookie、回應速度與風險分數</h2>
        <p>適合網站維護、接案、WordPress、電商網站、企業形象站。</p>
        <a class="btn" href="/register">免費註冊</a>
        <a class="btn" href="/login">登入</a>
    </div>

    <div class="card">
        <h2>方案價格</h2>
        <div class="grid">
            <div class="box">
                <h2>Free</h2>
                <p>1 個網站</p>
                <h2>NT$0</h2>
                <a class="btn" href="/register">免費開始</a>
            </div>

            <div class="box">
                <h2>Pro</h2>
                <p>5 個網站</p>
                <h2>NT$299/月</h2>
                <a href="/create-checkout/pro">
                    <button>立即訂閱</button>
                </a>
            </div>

            <div class="box">
                <h2>Business</h2>
                <p>50 個網站</p>
                <h2>NT$999/月</h2>
                <a href="/create-checkout/business">
                    <button>立即訂閱</button>
                </a>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>商業功能</h2>
        <p>✅ 會員系統</p>
        <p>✅ 方案限制</p>
        <p>✅ Stripe 訂閱跳轉</p>
        <p>✅ 網站健檢掃描</p>
        <p>✅ SSL 到期檢查</p>
        <p>✅ HTTP 狀態碼</p>
        <p>✅ Server Header</p>
        <p>✅ 安全分數</p>
        <p>✅ AI 風險建議</p>
        <p>✅ 掃描報告保存</p>
        <p>✅ CSV 匯出</p>
    </div>
    """
    return layout("Security SaaS", content)


# =========================
# 註冊
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            msg = "<p class='danger'>帳號與密碼都要填。</p>"
        else:
            try:
                conn = db()
                c = conn.cursor()
                c.execute("""
                INSERT INTO users
                (username, password_hash, plan, api_key, created_at)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    username,
                    generate_password_hash(password),
                    "Free",
                    secrets.token_hex(16),
                    now()
                ))
                conn.commit()
                conn.close()
                return redirect("/login")
            except Exception:
                msg = "<p class='danger'>這個帳號已經存在，請換一個。</p>"

    content = f"""
    <h1>免費註冊</h1>
    <div class="card">
        {msg}
        <form method="post">
            <label>帳號</label>
            <input name="username" placeholder="輸入帳號">

            <label>密碼</label>
            <input name="password" type="password" placeholder="輸入密碼">

            <button type="submit">建立帳號</button>
        </form>
    </div>
    """
    return layout("免費註冊", content)


# =========================
# 登入
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect("/dashboard")
        else:
            msg = "<p class='danger'>帳號或密碼錯誤。</p>"

    content = f"""
    <h1>登入</h1>
    <div class="card">
        {msg}
        <form method="post">
            <label>帳號</label>
            <input name="username" placeholder="admin">

            <label>密碼</label>
            <input name="password" type="password" placeholder="123456">

            <button type="submit">登入</button>
        </form>
        <p class="muted">預設管理員：admin / 123456</p>
    </div>
    """
    return layout("登入", content)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =========================
# Stripe Checkout 跳轉
# =========================

@app.route("/create-checkout/<plan>")
def create_checkout(plan):
    if "user_id" not in session:
        return redirect("/login")

    plan = plan.lower().strip()

    if plan == "pro":
        price_id = os.environ.get("STRIPE_PRO_PRICE_ID")
    elif plan == "business":
        price_id = os.environ.get("STRIPE_BUSINESS_PRICE_ID")
    else:
        return "方案不存在", 404

    if not stripe.api_key:
        return "Stripe Secret Key 尚未設定：請到 Render 環境變數確認 STRIPE_SECRET_KEY", 500

    if not price_id:
        return f"Stripe Price ID 尚未設定：請到 Render 環境變數確認 {plan} 的 PRICE_ID", 500

    domain = request.host_url.rstrip("/")

    checkout_session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[
            {
                "price": price_id,
                "quantity": 1,
            }
        ],
        success_url=domain + "/dashboard?payment=success",
        cancel_url=domain + "/?payment=cancel",
        metadata={
            "user_id": str(session.get("user_id")),
            "plan": plan,
        },
    )

    return redirect(checkout_session.url, code=303)


@app.route("/scan", methods=["POST"])
def scan():
    if not require_login():
        return redirect("/login")

    user = current_user()
    uid = user["id"]
    plan = user["plan"]
    limit = plan_limit(plan)

    conn = db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS total FROM reports WHERE user_id = ?", (uid,))
    total = c.fetchone()["total"]

    if total >= limit:
        conn.close()
        content = f"""
        <h1>已達方案上限</h1>
        <div class="card">
            <p>你的方案：{esc(plan)}</p>
            <p>目前上限：{limit} 個掃描結果</p>
            <p>請升級方案，或刪除舊資料。</p>
            <a class="btn" href="/">查看方案</a>
            <a class="btn" href="/dashboard">回 Dashboard</a>
        </div>
        """
        return layout("已達方案上限", content)

    raw_url = request.form.get("url", "").strip()
    result = scan_site(raw_url)

    c.execute("""
    INSERT INTO reports
    (user_id, website_name, url, ip, status, response_time, server,
     ssl_expire, ssl_days, score, risk, alert, report, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        uid,
        result["website_name"],
        result["url"],
        result["ip"],
        str(result["status"]),
        str(result["response_time"]),
        result["server"],
        result["ssl_expire"],
        safe_int(result["ssl_days"]),
        safe_int(result["score"]),
        result["risk"],
        result["alert"],
        result["report"],
        now()
    ))

    conn.commit()
    conn.close()

    return redirect("/dashboard")


# =========================
# Dashboard
# =========================

@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect("/login")

    user = current_user()
    uid = user["id"]
    limit = plan_limit(user["plan"])

    conn = db()
    c = conn.cursor()
    c.execute("""
    SELECT * FROM reports
    WHERE user_id = ?
    ORDER BY id DESC
    """, (uid,))
    reports = c.fetchall()

    conn.close()

    result_html = ""

    if not reports:
        result_html = "<p>目前還沒有掃描結果。</p>"
    else:
        for r in reports:
            risk_class = "good"
            if r["risk"] == "中風險":
                risk_class = "warn"
            if r["risk"] == "高風險":
                risk_class = "danger"

            result_html += f"""
            <div class="box">
                <h2>{esc(r["website_name"])}</h2>
                <p>網址：{esc(r["url"])}</p>
                <p>IP：{esc(r["ip"])}</p>
                <p>HTTP 狀態碼：{esc(r["status"])}</p>
                <p>回應時間：{esc(r["response_time"])} 秒</p>
                <p>Server：{esc(r["server"])}</p>
                <p>SSL 到期：{esc(r["ssl_expire"])}</p>
                <p>SSL 剩餘天數：{esc(r["ssl_days"])}</p>

                <h3>安全分數</h3>
                <p>分數：{esc(r["score"])}/100</p>
                <p>風險等級：<span class="{risk_class}">{esc(r["risk"])}</span></p>

                <h3>AI 風險建議</h3>
                <pre>{esc(r["alert"])}</pre>

                <h3>完整報告文字</h3>
                <pre>{esc(r["report"])}</pre>
            </div>
            """

    content = f"""
    <h1>Dashboard</h1>

    <div class="card">
        <h2>新增掃描</h2>
        <form method="post" action="/scan">
            <input name="url" placeholder="輸入網址，例如 https://google.com">
            <button type="submit">開始掃描</button>
        </form>
    </div>

    <div class="card">
        <h2>帳號資訊</h2>
        <p>帳號：{esc(user["username"])}</p>
        <p>方案：{esc(user["plan"])}</p>
        <p>網站上限：{limit}</p>
        <p>到期日：{esc(user["expire_date"])}</p>
        <p>API Key：{esc(user["api_key"])}</p>
    </div>

    <div class="card">
        <h2>掃描結果</h2>
        {result_html}
    </div>
    """

    return layout("Dashboard", content)


# =========================
# CSV 匯出
# =========================

@app.route("/export")
def export_csv():
    if not require_login():
        return redirect("/login")

    user = current_user()
    uid = user["id"]

    conn = db()
    c = conn.cursor()
    c.execute("""
    SELECT website_name, url, ip, status, response_time, server,
           ssl_expire, ssl_days, score, risk, alert, created_at
    FROM reports
    WHERE user_id = ?
    ORDER BY id DESC
    """, (uid,))
    rows = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "網站名稱", "網址", "IP", "HTTP狀態碼", "回應時間",
        "Server", "SSL到期", "SSL剩餘天數", "分數",
        "風險", "建議", "建立時間"
    ])

    for r in rows:
        writer.writerow([
            r["website_name"],
            r["url"],
            r["ip"],
            r["status"],
            r["response_time"],
            r["server"],
            r["ssl_expire"],
            r["ssl_days"],
            r["score"],
            r["risk"],
            r["alert"],
            r["created_at"]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=security_reports.csv"
        }
    )


# =========================
# API
# =========================

@app.route("/api/scan", methods=["POST"])
def api_scan():
    api_key = request.headers.get("X-API-Key", "").strip()
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")

    if not api_key:
        return jsonify({"error": "缺少 X-API-Key"}), 401

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "API Key 錯誤"}), 401

    result = scan_site(raw_url)
    return jsonify(result)


# =========================
# 啟動
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)