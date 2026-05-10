from flask import Flask, request, redirect, session, jsonify
import sqlite3
import requests
import socket
import ssl
import time
import os
import secrets
from datetime import datetime
from html import escape as h
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import stripe
except Exception:
    stripe = None


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DB = "business_saas.db"

ADMIN_USER = "admin"
ADMIN_PASS = "123456"


# =========================
# 基本工具
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def add_column_if_missing(cursor, table, column, col_type):
    try:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")
    except Exception:
        pass


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

    add_column_if_missing(c, "users", "plan", "TEXT DEFAULT 'Free'")
    add_column_if_missing(c, "users", "api_key", "TEXT")
    add_column_if_missing(c, "users", "stripe_subscription_id", "TEXT")
    add_column_if_missing(c, "users", "expire_date", "TEXT")
    add_column_if_missing(c, "users", "created_at", "TEXT")

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


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None

    conn = db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return user


def login_required():
    if not current_user():
        return redirect("/login")
    return None


def plan_limit(plan):
    plan = (plan or "Free").lower()
    if plan == "business":
        return 50
    if plan == "pro":
        return 5
    return 1


# =========================
# 掃描功能
# =========================

def normalize_url(raw_url):
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return ""

    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    return raw_url


def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_text = cert.get("notAfter", "")
                expire_date = datetime.strptime(expire_text, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.utcnow()).days
                return expire_text, days_left
    except Exception:
        return "無法取得", 0


def scan_site(raw_url):
    url = normalize_url(raw_url)
    if not url:
        raise ValueError("請輸入網址")

    parsed = urlparse(url)
    hostname = parsed.netloc.replace("www.", "")

    if not hostname:
        raise ValueError("網址格式錯誤")

    result = {
        "website_name": hostname,
        "url": url,
        "ip": "無法取得",
        "status": "無法取得",
        "response_time": "無法取得",
        "server": "無法取得",
        "ssl_expire": "無法取得",
        "ssl_days": 0,
        "score": 100,
        "risk": "低風險",
        "alert": "目前未發現重大明顯風險。",
        "report": ""
    }

    try:
        result["ip"] = socket.gethostbyname(hostname)
    except Exception:
        result["ip"] = "無法解析"

    start = time.time()

    try:
        r = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "Security-SaaS-Scanner/1.0"}
        )

        cost = round(time.time() - start, 2)

        result["status"] = str(r.status_code)
        result["response_time"] = str(cost)
        result["server"] = r.headers.get("Server", "未公開")

        score = 100
        alerts = []

        if not url.startswith("https://"):
            score -= 30
            alerts.append("網站未使用 HTTPS。")

        if r.status_code >= 500:
            score -= 25
            alerts.append("網站出現 5xx 伺服器錯誤。")
        elif r.status_code >= 400:
            score -= 15
            alerts.append("網站出現 4xx 錯誤。")

        if cost > 3:
            score -= 10
            alerts.append("網站回應速度偏慢。")

        headers = r.headers

        if "Strict-Transport-Security" not in headers:
            score -= 10
            alerts.append("缺少 HSTS 安全標頭。")

        if "X-Frame-Options" not in headers:
            score -= 5
            alerts.append("缺少 X-Frame-Options，可能有點擊劫持風險。")

        if "X-Content-Type-Options" not in headers:
            score -= 5
            alerts.append("缺少 X-Content-Type-Options。")

        if "Content-Security-Policy" not in headers:
            score -= 10
            alerts.append("缺少 CSP 內容安全政策。")

        ssl_expire, ssl_days = get_ssl_info(hostname)
        result["ssl_expire"] = ssl_expire
        result["ssl_days"] = ssl_days

        if ssl_days <= 0:
            score -= 20
            alerts.append("SSL 憑證無法取得或已過期。")
        elif ssl_days < 30:
            score -= 15
            alerts.append("SSL 憑證即將到期。")

        if score < 0:
            score = 0

        if score >= 80:
            risk = "低風險"
        elif score >= 60:
            risk = "中風險"
        else:
            risk = "高風險"

        if alerts:
            alert_text = " / ".join(alerts)
        else:
            alert_text = "目前未發現重大明顯風險。"

        report_text = f"""網站安全檢測完成
網址：{url}
IP：{result["ip"]}
HTTP 狀態碼：{result["status"]}
回應時間：{result["response_time"]} 秒
Server：{result["server"]}
SSL 到期：{result["ssl_expire"]}
SSL 剩餘天數：{result["ssl_days"]}
安全分數：{score}/100
風險等級：{risk}
AI 建議：{alert_text}
"""

        result["score"] = score
        result["risk"] = risk
        result["alert"] = alert_text
        result["report"] = report_text

    except Exception as e:
        result["score"] = 30
        result["risk"] = "高風險"
        result["alert"] = f"網站無法正常連線或掃描失敗：{str(e)}"
        result["report"] = result["alert"]

    return result


# =========================
# HTML 模板
# =========================

def layout(title, body):
    user = current_user()

    nav = ""
    if user:
        nav = f"""
        <div class="nav">
            <a href="/">首頁</a>
            <a href="/dashboard">Dashboard</a>
            <a href="/logout">登出</a>
        </div>
        """
    else:
        nav = """
        <div class="nav">
            <a href="/">首頁</a>
            <a href="/register">免費註冊</a>
            <a href="/login">登入</a>
        </div>
        """

    return f"""
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{h(title)}</title>
<style>
body {{
    margin: 0;
    font-family: Arial, "Microsoft JhengHei", sans-serif;
    background: #020617;
    color: #f8fafc;
}}
.container {{
    max-width: 1200px;
    margin: auto;
    padding: 34px;
}}
.nav {{
    display: flex;
    gap: 12px;
    margin-bottom: 22px;
}}
.nav a {{
    color: #e2e8f0;
    text-decoration: none;
    background: #111827;
    border: 1px solid #334155;
    padding: 10px 14px;
    border-radius: 10px;
}}
.card {{
    background: #111827;
    border: 1px solid #243244;
    border-radius: 16px;
    padding: 26px;
    margin: 22px 0;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 18px;
}}
.box {{
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 22px;
    background: #0f172a;
}}
input {{
    width: 100%;
    padding: 15px;
    border-radius: 10px;
    border: 1px solid #64748b;
    font-size: 16px;
    box-sizing: border-box;
}}
button, .btn {{
    background: #22c55e;
    color: #001b0b;
    border: 0;
    padding: 14px 22px;
    border-radius: 10px;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
}}
.btn2 {{
    background: #38bdf8;
    color: #001018;
}}
pre {{
    white-space: pre-wrap;
    background: #020617;
    border: 1px solid #334155;
    padding: 16px;
    border-radius: 12px;
}}
.badge {{
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    background: #334155;
}}
.warn {{
    color: #facc15;
    font-weight: bold;
}}
.err {{
    color: #f87171;
    font-weight: bold;
}}
.ok {{
    color: #4ade80;
    font-weight: bold;
}}
</style>
</head>
<body>
<div class="container">
{nav}
{body}
</div>
</body>
</html>
"""


# =========================
# 首頁 / 會員
# =========================

@app.route("/")
def home():
    body = """
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
            </div>
            <div class="box">
                <h2>Pro</h2>
                <p>5 個網站</p>
                <h2>NT$299/月</h2>
                <a class="btn" href="/create-checkout/pro">立即訂閱</a>
            </div>
            <div class="box">
                <h2>Business</h2>
                <p>50 個網站</p>
                <h2>NT$999/月</h2>
                <a class="btn" href="/create-checkout/business">立即訂閱</a>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>商業功能</h2>
        <p>✅ 會員系統</p>
        <p>✅ 免費 / Pro / Business 方案</p>
        <p>✅ Stripe 付款</p>
        <p>✅ Dashboard</p>
        <p>✅ 網站安全掃描</p>
        <p>✅ 掃描結果保存</p>
        <p>✅ AI 風險建議</p>
    </div>
    """
    return layout("Security SaaS", body)


@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            msg = "<p class='err'>請輸入帳號與密碼</p>"
        else:
            try:
                conn = db()
                conn.execute("""
                INSERT INTO users
                (username, password_hash, plan, api_key, created_at)
                VALUES (?, ?, ?, ?, ?)
                """, (
                    username,
                    generate_password_hash(password),
                    "Free",
                    "key-" + secrets.token_hex(8),
                    now()
                ))
                conn.commit()
                conn.close()
                return redirect("/login")
            except Exception:
                msg = "<p class='err'>帳號已存在，請換一個</p>"

    body = f"""
    <h1>免費註冊</h1>
    <div class="card">
        {msg}
        <form method="post">
            <p>帳號</p>
            <input name="username">
            <p>密碼</p>
            <input name="password" type="password">
            <br><br>
            <button type="submit">註冊</button>
        </form>
    </div>
    """
    return layout("註冊", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect("/dashboard")
        else:
            msg = "<p class='err'>帳號或密碼錯誤</p>"

    body = f"""
    <h1>登入</h1>
    <div class="card">
        {msg}
        <form method="post">
            <p>帳號</p>
            <input name="username">
            <p>密碼</p>
            <input name="password" type="password">
            <br><br>
            <button type="submit">登入</button>
        </form>
        <p>測試管理員：admin / 123456</p>
    </div>
    """
    return layout("登入", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =========================
# Stripe 付款
# =========================

@app.route("/create-checkout/<plan>")
def create_checkout(plan):
    plan = (plan or "").lower()

    if plan not in ["pro", "business"]:
        return "方案不存在", 404

    user = current_user()
    if not user:
        return redirect("/login")

    success_url = request.host_url.rstrip("/") + f"/payment-success/{plan}"
    cancel_url = request.host_url.rstrip("/") + "/"

    direct_link = ""
    if plan == "pro":
        direct_link = os.environ.get("STRIPE_PRO_LINK", "")
        price_id = os.environ.get("STRIPE_PRO_PRICE_ID", "")
    else:
        direct_link = os.environ.get("STRIPE_BUSINESS_LINK", "")
        price_id = os.environ.get("STRIPE_BUSINESS_PRICE_ID", "")

    if direct_link:
        return redirect(direct_link)

    secret_key = os.environ.get("STRIPE_SECRET_KEY", "")

    if not stripe:
        return "Stripe 套件未安裝，請在 requirements.txt 加上 stripe", 500

    if not secret_key or not price_id:
        return f"""
        <h1>Stripe 尚未設定完成</h1>
        <p>目前方案：{h(plan)}</p>
        <p>Render 環境變數需要：</p>
        <p>STRIPE_SECRET_KEY</p>
        <p>STRIPE_PRO_PRICE_ID</p>
        <p>STRIPE_BUSINESS_PRICE_ID</p>
        <a href="/">回首頁</a>
        """, 500

    stripe.api_key = secret_key

    try:
        checkout_session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=[{
                "price": price_id,
                "quantity": 1
            }],
            success_url=success_url,
            cancel_url=cancel_url,
            customer_email=None,
            metadata={
                "user_id": str(user["id"]),
                "plan": plan
            }
        )
        return redirect(checkout_session.url)
    except Exception as e:
        return f"Stripe 建立結帳失敗：{h(str(e))}", 500


@app.route("/payment-success/<plan>")
def payment_success(plan):
    user = current_user()
    if not user:
        return redirect("/login")

    plan = (plan or "").lower()
    if plan == "pro":
        new_plan = "Pro"
    elif plan == "business":
        new_plan = "Business"
    else:
        new_plan = "Free"

    conn = db()
    conn.execute("UPDATE users SET plan = ? WHERE id = ?", (new_plan, user["id"]))
    conn.commit()
    conn.close()

    return redirect("/dashboard?payment=success")


@app.route("/webhook", methods=["POST"])
def webhook():
    return jsonify({"ok": True})


# =========================
# Dashboard / 掃描
# =========================

@app.route("/dashboard")
def dashboard():
    need_login = login_required()
    if need_login:
        return need_login

    user = current_user()
    limit = plan_limit(user["plan"])

    conn = db()
    reports = conn.execute("""
        SELECT * FROM reports
        WHERE user_id = ?
        ORDER BY id DESC
    """, (user["id"],)).fetchall()
    conn.close()

    payment_msg = ""
    if request.args.get("payment") == "success":
        payment_msg = "<div class='card'><p class='ok'>付款完成，方案已更新。</p></div>"

    report_html = ""

    if not reports:
        report_html = "<p>目前還沒有掃描結果。</p>"
    else:
        for r in reports:
            risk_class = "ok"
            if r["risk"] == "中風險":
                risk_class = "warn"
            if r["risk"] == "高風險":
                risk_class = "err"

            report_html += f"""
            <div class="box">
                <h2>{h(str(r["website_name"] or ""))}</h2>
                <p>網址：{h(str(r["url"] or ""))}</p>
                <p>IP：{h(str(r["ip"] or ""))}</p>
                <p>HTTP 狀態碼：{h(str(r["status"] or ""))}</p>
                <p>回應時間：{h(str(r["response_time"] or ""))} 秒</p>
                <p>Server：{h(str(r["server"] or ""))}</p>
                <p>SSL 到期：{h(str(r["ssl_expire"] or ""))}</p>
                <p>SSL 剩餘天數：{h(str(r["ssl_days"] or ""))}</p>
                <h3>安全分數</h3>
                <p>分數：{h(str(r["score"] or 0))}/100</p>
                <p>風險等級：<span class="{risk_class}">{h(str(r["risk"] or ""))}</span></p>
                <h3>AI 風險建議</h3>
                <pre>{h(str(r["alert"] or ""))}</pre>
                <h3>完整報告文字</h3>
                <pre>{h(str(r["report"] or ""))}</pre>
                <p>建立時間：{h(str(r["created_at"] or ""))}</p>
            </div>
            """

    body = f"""
    <h1>Dashboard</h1>
    {payment_msg}

    <div class="card">
        <h2>新增掃描</h2>
        <form method="post" action="/scan">
            <input name="url" placeholder="輸入網址，例如 https://google.com">
            <br><br>
            <button type="submit">開始掃描</button>
        </form>
    </div>

    <div class="card">
        <h2>帳號資訊</h2>
        <p>帳號：{h(str(user["username"]))}</p>
        <p>方案：{h(str(user["plan"]))}</p>
        <p>網站上限：{limit}</p>
        <p>到期日：{h(str(user["expire_date"] or ""))}</p>
        <p>API Key：{h(str(user["api_key"] or ""))}</p>
    </div>

    <div class="card">
        <h2>掃描結果</h2>
        {report_html}
    </div>
    """

    return layout("Dashboard", body)


@app.route("/scan", methods=["POST"])
def scan():
    need_login = login_required()
    if need_login:
        return need_login

    user = current_user()
    raw_url = request.form.get("url", "").strip()

    conn = db()
    used_count = conn.execute(
        "SELECT COUNT(*) AS total FROM reports WHERE user_id = ?",
        (user["id"],)
    ).fetchone()["total"]

    limit = plan_limit(user["plan"])

    if used_count >= limit:
        conn.close()
        return layout("掃描上限", f"""
        <h1>已達方案上限</h1>
        <div class="card">
            <p>你的方案：{h(str(user["plan"]))}</p>
            <p>可掃描網站數：{limit}</p>
            <p>請升級方案或清除舊資料。</p>
            <a class="btn" href="/">查看方案</a>
            <a class="btn btn2" href="/dashboard">回 Dashboard</a>
        </div>
        """)

    try:
        result = scan_site(raw_url)

        conn.execute("""
        INSERT INTO reports
        (user_id, website_name, url, ip, status, response_time, server,
         ssl_expire, ssl_days, score, risk, alert, report, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user["id"],
            result["website_name"],
            result["url"],
            result["ip"],
            result["status"],
            result["response_time"],
            result["server"],
            result["ssl_expire"],
            result["ssl_days"],
            result["score"],
            result["risk"],
            result["alert"],
            result["report"],
            now()
        ))

        conn.commit()
        conn.close()
        return redirect("/dashboard")

    except Exception as e:
        conn.close()
        return layout("掃描錯誤", f"""
        <h1>掃描失敗</h1>
        <div class="card">
            <p class="err">{h(str(e))}</p>
            <a class="btn" href="/dashboard">回 Dashboard</a>
        </div>
        """)


# =========================
# 啟動
# =========================

init_db()

if __name__ == "__main__":
    app.run(debug=True)