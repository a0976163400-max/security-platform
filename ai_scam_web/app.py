from flask import Flask, request, redirect, session, Response, jsonify
import sqlite3
import requests
import socket
import ssl
import time
import os
import csv
import io
import secrets
from datetime import datetime
from html import escape
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

DB = "business_saas.db"

ADMIN_USER = "admin"
ADMIN_PASS = "123456"


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

    user_columns = [
        ("username", "TEXT UNIQUE"),
        ("password_hash", "TEXT"),
        ("plan", "TEXT DEFAULT 'Free'"),
        ("api_key", "TEXT"),
        ("stripe_subscription_id", "TEXT"),
        ("expire_date", "TEXT"),
        ("created_at", "TEXT"),
    ]

    report_columns = [
        ("user_id", "INTEGER"),
        ("website_name", "TEXT"),
        ("url", "TEXT"),
        ("ip", "TEXT"),
        ("status", "TEXT"),
        ("response_time", "TEXT"),
        ("server", "TEXT"),
        ("ssl_expire", "TEXT"),
        ("ssl_days", "INTEGER"),
        ("score", "INTEGER"),
        ("risk", "TEXT"),
        ("alert", "TEXT"),
        ("report", "TEXT"),
        ("created_at", "TEXT"),
    ]

    for column, col_type in user_columns:
        add_column_if_missing(c, "users", column, col_type)

    for column, col_type in report_columns:
        add_column_if_missing(c, "reports", column, col_type)

    c.execute("SELECT * FROM users WHERE username = ?", (ADMIN_USER,))
    admin = c.fetchone()

    if not admin:
        c.execute("""
        INSERT INTO users
        (username, password_hash, plan, api_key, expire_date, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ADMIN_USER,
            generate_password_hash(ADMIN_PASS),
            "Business",
            "admin-key",
            "",
            now()
        ))
    else:
        c.execute("""
        UPDATE users
        SET password_hash = ?,
            plan = ?,
            api_key = COALESCE(api_key, ?),
            created_at = COALESCE(created_at, ?)
        WHERE username = ?
        """, (
            generate_password_hash(ADMIN_PASS),
            "Business",
            "admin-key",
            now(),
            ADMIN_USER
        ))

    conn.commit()
    conn.close()


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


def user_by_api_key(api_key):
    if not api_key:
        return None

    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))
    user = c.fetchone()
    conn.close()

    return user


def is_admin():
    user = current_user()

    if not user:
        return False

    return user["username"] == ADMIN_USER


def plan_limit(plan):
    plan = str(plan or "Free")

    if plan == "Business":
        return 50

    if plan == "Pro":
        return 5

    return 1


def layout(title, body):
    return f"""
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{escape(str(title))}</title>
<style>
body {{
    margin: 0;
    padding: 34px;
    background: #020617;
    color: #e5e7eb;
    font-family: Arial, "Microsoft JhengHei", sans-serif;
}}

h1 {{
    font-size: 38px;
    margin: 0 0 24px 0;
}}

h2 {{
    font-size: 26px;
    margin: 0 0 18px 0;
}}

p {{
    font-size: 18px;
    line-height: 1.6;
}}

.card {{
    background: #111827;
    border: 1px solid #243044;
    border-radius: 18px;
    padding: 24px;
    margin-bottom: 24px;
}}

input, select {{
    width: 100%;
    padding: 16px;
    font-size: 18px;
    border-radius: 12px;
    border: 1px solid #94a3b8;
    box-sizing: border-box;
    margin-bottom: 12px;
}}

button {{
    padding: 14px 24px;
    border: 0;
    border-radius: 12px;
    background: #22c55e;
    color: #020617;
    font-size: 18px;
    font-weight: bold;
    cursor: pointer;
}}

button.danger {{
    background: #ef4444;
    color: white;
}}

button.gray {{
    background: #64748b;
    color: white;
}}

a {{
    color: #93c5fd;
    text-decoration: none;
}}

.nav {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 24px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
}}

.box {{
    background: #020617;
    border: 1px solid #334155;
    border-radius: 14px;
    padding: 18px;
}}

.ok {{
    color: #22c55e;
    font-weight: bold;
}}

.bad {{
    color: #fb7185;
    font-weight: bold;
}}

.mid {{
    color: #facc15;
    font-weight: bold;
}}

pre {{
    white-space: pre-wrap;
    background: #020617;
    border: 1px solid #334155;
    padding: 16px;
    border-radius: 12px;
    font-size: 15px;
    line-height: 1.5;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: #020617;
    border-radius: 12px;
    overflow: hidden;
}}

td, th {{
    border-bottom: 1px solid #334155;
    padding: 12px;
    text-align: left;
}}

th {{
    color: #93c5fd;
}}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def nav():
    user = current_user()

    if not user:
        return """
<div class="nav">
    <a href="/"><button class="gray">首頁</button></a>
    <a href="/login"><button>登入</button></a>
    <a href="/register"><button>註冊</button></a>
</div>
"""

    admin_button = ""

    if user["username"] == ADMIN_USER:
        admin_button = '<a href="/admin"><button class="gray">Admin 後台</button></a>'

    return f"""
<div class="nav">
    <a href="/dashboard"><button>Dashboard</button></a>
    <a href="/export"><button class="gray">匯出 CSV</button></a>
    {admin_button}
    <a href="/logout"><button class="danger">登出</button></a>
</div>
"""


@app.route("/")
def home():
    body = nav() + """
<h1>安全 SaaS 網站防禦檢測平台</h1>

<div class="card">
    <h2>網站安全檢測</h2>
    <p>可檢查網站 HTTP 狀態、IP、Server、SSL 到期、安全 Header、Cookie 風險、回應速度與整體風險分數。</p>
    <p>適合接案、網站維護、WordPress、電商網站、企業形象網站。</p>
    <a href="/register"><button>免費註冊</button></a>
    <a href="/login"><button class="gray">登入</button></a>
</div>

<div class="card">
  <h2>方案價格</h2>

  <div class="grid">

    <div class="box">
      <h2>Free</h2>
      <p>1 個網站</p>
      <h2>NT$0</h2>
      <a href="/register">
        <button>免費註冊</button>
      </a>
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
"""
    return layout("首頁", body)


@app.route("/health")
def health():
    return "OK", 200


@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            msg = "帳號或密碼不可空白"
        else:
            try:
                conn = db()
                c = conn.cursor()

                api_key = secrets.token_hex(16)

                c.execute("""
                INSERT INTO users
                (username, password_hash, plan, api_key, expire_date, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    username,
                    generate_password_hash(password),
                    "Free",
                    api_key,
                    "",
                    now()
                ))

                conn.commit()
                conn.close()

                return redirect("/login")

            except Exception as e:
                msg = "註冊失敗，帳號可能已存在：" + str(e)

    body = nav() + f"""
<h1>註冊</h1>

<div class="card">
    <form method="POST">
        <p>帳號</p>
        <input name="username" placeholder="輸入帳號">

        <p>密碼</p>
        <input name="password" type="password" placeholder="輸入密碼">

        <button type="submit">註冊</button>
    </form>

    <p class="bad">{escape(msg)}</p>
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
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and user["password_hash"] and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect("/dashboard")
        else:
            msg = "帳號或密碼錯誤"

    body = nav() + f"""
<h1>登入</h1>

<div class="card">
    <form method="POST">
        <p>帳號</p>
        <input name="username" placeholder="輸入帳號">

        <p>密碼</p>
        <input name="password" type="password" placeholder="輸入密碼">

        <button type="submit">登入</button>
    </form>

    <p class="bad">{escape(msg)}</p>
    <p>預設管理員：admin / 123456</p>
</div>
"""
    return layout("登入", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


def ssl_check(hostname):
    try:
        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expire_text = cert.get("notAfter", "")

                if not expire_text:
                    return "無法取得", -1

                expire_dt = datetime.strptime(expire_text, "%b %d %H:%M:%S %Y %Z")
                days = (expire_dt - datetime.utcnow()).days

                return expire_text, days

    except Exception:
        return "無法取得", -1


def normalize_url(url):
    url = str(url or "").strip()

    if not url:
        raise Exception("網址不可空白")

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise Exception("網址格式錯誤")

    return url, parsed.hostname


def make_report(url):
    url, hostname = normalize_url(url)

    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "無法解析"

    start = time.time()

    headers = {
        "User-Agent": "SecuritySaaSScanner/1.0"
    }

    try:
        r = requests.get(url, headers=headers, timeout=12, allow_redirects=True)
        status_code = r.status_code
        server = r.headers.get("Server", "未顯示")
        response_time = round(time.time() - start, 2)
    except Exception as e:
        status_code = "連線失敗"
        server = "無法取得"
        response_time = round(time.time() - start, 2)

        return {
            "website_name": hostname,
            "url": url,
            "ip": ip,
            "status": str(status_code),
            "response_time": str(response_time),
            "server": server,
            "ssl_expire": "無法取得",
            "ssl_days": -1,
            "score": 0,
            "risk": "高風險",
            "alert": "網站無法連線：" + str(e),
            "report": "掃描失敗，請確認網址是否正確。"
        }

    ssl_expire, ssl_days = ssl_check(hostname)

    score = 100
    alerts = []
    missing_headers = []

    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy"
    ]

    for h in required_headers:
        if h not in r.headers:
            missing_headers.append(h)
            score -= 10

    if str(url).startswith("http://"):
        score -= 20
        alerts.append("網站使用 HTTP，建議改用 HTTPS。")

    if ssl_days < 0:
        score -= 15
        alerts.append("SSL 憑證無法取得。")
    elif ssl_days < 30:
        score -= 15
        alerts.append("SSL 憑證即將到期。")

    cookies = r.headers.get("Set-Cookie", "")

    if cookies:
        if "HttpOnly" not in cookies:
            score -= 10
            alerts.append("Cookie 可能缺少 HttpOnly。")

        if "Secure" not in cookies:
            score -= 10
            alerts.append("Cookie 可能缺少 Secure。")
    else:
        cookies = "沒有 Set-Cookie"

    if status_code >= 500:
        score -= 20
        alerts.append("網站伺服器回傳 5xx 錯誤。")
    elif status_code >= 400:
        score -= 10
        alerts.append("網站回傳 4xx 錯誤。")

    score = max(score, 0)

    if score >= 80:
        risk = "低風險"
    elif score >= 50:
        risk = "中風險"
    else:
        risk = "高風險"

    if not alerts:
        alerts.append("目前未發現重大明顯風險。")

    report = ""
    report += "網站安全檢測完成\n"
    report += "網址：" + str(url) + "\n"
    report += "IP：" + str(ip) + "\n"
    report += "HTTP 狀態碼：" + str(status_code) + "\n"
    report += "回應時間：" + str(response_time) + " 秒\n"
    report += "Server：" + str(server) + "\n"
    report += "SSL 到期：" + str(ssl_expire) + "\n"
    report += "SSL 剩餘天數：" + str(ssl_days) + "\n"
    report += "缺少安全 Header：" + (", ".join(missing_headers) if missing_headers else "無") + "\n"
    report += "Cookie 檢查：" + str(cookies)[:500] + "\n"

    return {
        "website_name": hostname,
        "url": url,
        "ip": ip,
        "status": str(status_code),
        "response_time": str(response_time),
        "server": str(server),
        "ssl_expire": str(ssl_expire),
        "ssl_days": int(ssl_days),
        "score": int(score),
        "risk": risk,
        "alert": "\n".join(alerts),
        "report": report
    }


def save_report(user_id, result):
    conn = db()
    c = conn.cursor()

    c.execute("""
    INSERT INTO reports
    (user_id, website_name, url, ip, status, response_time, server,
     ssl_expire, ssl_days, score, risk, alert, report, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
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


@app.route("/dashboard")
def dashboard():
    user = current_user()

    if not user:
        return redirect("/login")

    limit = plan_limit(user["plan"])

    conn = db()
    c = conn.cursor()

    c.execute("""
    SELECT * FROM reports
    WHERE user_id = ?
    ORDER BY id DESC
    """, (user["id"],))

    reports = c.fetchall()
    conn.close()

    report_html = ""

    if reports:
        for r in reports:
            score_value = r["score"] if r["score"] is not None else 0
            risk_value = r["risk"] if r["risk"] else "未知"

            risk_class = "ok"

            if risk_value == "中風險":
                risk_class = "mid"
            elif risk_value == "高風險":
                risk_class = "bad"

            report_html += f"""
<div class="card">
    <h2>{escape(str(r["website_name"] or ""))}</h2>
    <p>網址：{escape(str(r["url"] or ""))}</p>
    <p>IP：{escape(str(r["ip"] or ""))}</p>
    <p>HTTP 狀態碼：{escape(str(r["status"] or ""))}</p>
    <p>回應時間：{escape(str(r["response_time"] or ""))} 秒</p>
    <p>Server：{escape(str(r["server"] or ""))}</p>
    <p>SSL 到期：{escape(str(r["ssl_expire"] or ""))}</p>
    <p>SSL 剩餘天數：{escape(str(r["ssl_days"] or ""))}</p>
    <h2>安全分數</h2>
    <p>分數：{escape(str(score_value))}/100</p>
    <p>風險等級：<span class="{risk_class}">{escape(str(risk_value))}</span></p>
    <h2>AI 風險建議</h2>
    <pre>{escape(str(r["alert"] or ""))}</pre>
    <pre>{escape(str(r["report"] or ""))}</pre>
    <form method="POST" action="/delete_report/{r["id"]}">
        <button class="danger" type="submit">刪除此結果</button>
    </form>
</div>
"""
    else:
        report_html = "<p>目前還沒有掃描結果。</p>"

    body = nav() + f"""
<div class="card">
    <h2>新增掃描</h2>
    <form method="POST" action="/scan">
        <input name="url" placeholder="輸入網址，例如 https://google.com">
        <button type="submit">開始掃描</button>
    </form>
</div>

<h1>Dashboard</h1>

<div class="card">
    <h2>帳號資訊</h2>
    <p>帳號：{escape(str(user["username"] or ""))}</p>
    <p>方案：{escape(str(user["plan"] or ""))}</p>
    <p>網站上限：{escape(str(limit))}</p>
    <p>到期日：{escape(str(user["expire_date"] or ""))}</p>
    <p>API Key：{escape(str(user["api_key"] or ""))}</p>
</div>

<div class="card">
    <h2>掃描結果</h2>
    {report_html}
</div>
"""

    return layout("Dashboard", body)


@app.route("/scan", methods=["POST"])
def scan():
    user = current_user()

    if not user:
        return redirect("/login")

    url = request.form.get("url", "").strip()

    if not url:
        return redirect("/dashboard")

    limit = plan_limit(user["plan"])

    conn = db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS total FROM reports WHERE user_id = ?", (user["id"],))
    total = c.fetchone()["total"]
    conn.close()

    if total >= limit:
        body = nav() + """
<h1>已達方案掃描上限</h1>

<div class="card">
    <p>你的方案已達網站掃描上限。</p>
    <p>請刪除舊結果，或升級方案。</p>
    <p><a href="/dashboard">回 Dashboard</a></p>
</div>
"""
        return layout("掃描上限", body)

    try:
        result = make_report(url)
        save_report(user["id"], result)
        return redirect("/dashboard")

    except Exception as e:
        body = nav() + f"""
<h1>掃描失敗</h1>

<div class="card">
    <p class="bad">{escape(str(e))}</p>
    <p><a href="/dashboard">回 Dashboard</a></p>
</div>
"""
        return layout("掃描失敗", body)


@app.route("/delete_report/<int:report_id>", methods=["POST"])
def delete_report(report_id):
    user = current_user()

    if not user:
        return redirect("/login")

    conn = db()
    c = conn.cursor()

    if user["username"] == ADMIN_USER:
        c.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    else:
        c.execute("DELETE FROM reports WHERE id = ? AND user_id = ?", (report_id, user["id"]))

    conn.commit()
    conn.close()

    return redirect("/dashboard")


@app.route("/export")
def export_csv():
    user = current_user()

    if not user:
        return redirect("/login")

    conn = db()
    c = conn.cursor()

    if user["username"] == ADMIN_USER:
        c.execute("""
        SELECT reports.*, users.username
        FROM reports
        LEFT JOIN users ON users.id = reports.user_id
        ORDER BY reports.id DESC
        """)
    else:
        c.execute("""
        SELECT reports.*, users.username
        FROM reports
        LEFT JOIN users ON users.id = reports.user_id
        WHERE reports.user_id = ?
        ORDER BY reports.id DESC
        """, (user["id"],))

    rows = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "User",
        "Website",
        "URL",
        "IP",
        "Status",
        "Response Time",
        "Server",
        "SSL Expire",
        "SSL Days",
        "Score",
        "Risk",
        "Alert",
        "Created At"
    ])

    for r in rows:
        writer.writerow([
            r["id"],
            r["username"],
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


@app.route("/admin")
def admin():
    if not is_admin():
        return redirect("/dashboard")

    conn = db()
    c = conn.cursor()

    c.execute("SELECT * FROM users ORDER BY id DESC")
    users = c.fetchall()

    c.execute("""
    SELECT reports.*, users.username
    FROM reports
    LEFT JOIN users ON users.id = reports.user_id
    ORDER BY reports.id DESC
    LIMIT 50
    """)
    reports = c.fetchall()

    conn.close()

    users_html = ""

    for u in users:
        users_html += f"""
<tr>
    <td>{escape(str(u["id"]))}</td>
    <td>{escape(str(u["username"] or ""))}</td>
    <td>{escape(str(u["plan"] or ""))}</td>
    <td>{escape(str(u["api_key"] or ""))}</td>
    <td>{escape(str(u["created_at"] or ""))}</td>
</tr>
"""

    reports_html = ""

    for r in reports:
        reports_html += f"""
<tr>
    <td>{escape(str(r["id"]))}</td>
    <td>{escape(str(r["username"] or ""))}</td>
    <td>{escape(str(r["website_name"] or ""))}</td>
    <td>{escape(str(r["score"] or ""))}</td>
    <td>{escape(str(r["risk"] or ""))}</td>
    <td>{escape(str(r["created_at"] or ""))}</td>
</tr>
"""

    body = nav() + f"""
<h1>Admin 後台</h1>

<div class="card">
    <h2>使用者列表</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>帳號</th>
            <th>方案</th>
            <th>API Key</th>
            <th>建立時間</th>
        </tr>
        {users_html}
    </table>
</div>

<div class="card">
    <h2>最新掃描紀錄</h2>
    <table>
        <tr>
            <th>ID</th>
            <th>使用者</th>
            <th>網站</th>
            <th>分數</th>
            <th>風險</th>
            <th>時間</th>
        </tr>
        {reports_html}
    </table>
</div>
"""

    return layout("Admin 後台", body)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    api_key = request.headers.get("X-API-Key", "")
    user = user_by_api_key(api_key)

    if not user:
        return jsonify({
            "ok": False,
            "error": "API Key 錯誤"
        }), 401

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not url:
        return jsonify({
            "ok": False,
            "error": "缺少 url"
        }), 400

    limit = plan_limit(user["plan"])

    conn = db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) AS total FROM reports WHERE user_id = ?", (user["id"],))
    total = c.fetchone()["total"]
    conn.close()

    if total >= limit:
        return jsonify({
            "ok": False,
            "error": "已達方案掃描上限"
        }), 403

    try:
        result = make_report(url)
        save_report(user["id"], result)

        return jsonify({
            "ok": True,
            "result": result
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e)
        }), 500


init_db()

if __name__ == "__main__":
    app.run(debug=True)