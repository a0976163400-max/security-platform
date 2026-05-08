from flask import Flask, request, redirect, session
import requests
import socket
import sqlite3
import ssl
import time
from datetime import datetime
from html import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DB_NAME = "saas_security.db"

ADMIN_USER = "admin"
ADMIN_PASS = "123456"

def db():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = db()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        plan TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        note TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        url TEXT,
        ip TEXT,
        status_code TEXT,
        response_time TEXT,
        server TEXT,
        score INTEGER,
        risk TEXT,
        alert TEXT,
        created_at TEXT
    )
    """)

    conn.commit()

    admin_hash = generate_password_hash(ADMIN_PASS)
    c.execute("""
    INSERT OR IGNORE INTO users (username, password_hash, plan, created_at)
    VALUES (?, ?, ?, ?)
    """, (ADMIN_USER, admin_hash, "Business", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    conn.commit()
    conn.close()

def normalize_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    return url

def get_host(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def get_user():
    if "user_id" not in session:
        return None
    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, username, plan FROM users WHERE id=?", (session["user_id"],))
    row = c.fetchone()
    conn.close()
    return row

def plan_limit(plan):
    if plan == "Free":
        return 1
    if plan == "Pro":
        return 5
    return 50

def ssl_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                exp = cert.get("notAfter", "未知")
                exp_ts = ssl.cert_time_to_seconds(exp)
                days_left = int((exp_ts - time.time()) / 86400)
                return exp, days_left
    except:
        return "查詢失敗", -1

def scan_site(user_id, raw_url):
    url = normalize_url(raw_url)
    host = get_host(url)

    start = time.time()
    r = requests.get(url, timeout=8)
    response_time = round(time.time() - start, 3)

    headers = r.headers
    ip = socket.gethostbyname(host)
    server = headers.get("Server", "未顯示")

    score = 0
    alerts = []

    if r.status_code >= 500:
        alerts.append("伺服器錯誤")
    elif r.status_code >= 400:
        alerts.append("網站回應異常")
    else:
        alerts.append("網站在線")

    if response_time > 3:
        alerts.append("回應時間過慢")

    ssl_exp, ssl_days = ssl_info(host)
    if ssl_days != -1 and ssl_days < 30:
        alerts.append("SSL 即將到期")

    checks = {
        "Content-Security-Policy": "防 XSS",
        "X-Frame-Options": "防點擊劫持",
        "Strict-Transport-Security": "強制 HTTPS",
        "X-Content-Type-Options": "防 MIME 混淆",
        "Referrer-Policy": "保護來源資訊"
    }

    header_html = ""
    for h, desc in checks.items():
        if h in headers:
            score += 20
            header_html += f"<p class='ok'>✅ {h}：有（{desc}）</p>"
        else:
            header_html += f"<p class='bad'>❌ {h}：沒有（{desc}）</p>"
            alerts.append(f"缺少 {h}")

    if score >= 80:
        risk, risk_class = "低風險", "low"
    elif score >= 40:
        risk, risk_class = "中風險", "mid"
    else:
        risk, risk_class = "高風險", "high"

    port_html = ""
    for port in [80, 443, 8080]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        open_port = s.connect_ex((host, port)) == 0
        s.close()

        if open_port:
            port_html += f"<p class='ok'>🟢 Port {port} 開放</p>"
        else:
            port_html += f"<p class='bad'>🔴 Port {port} 關閉</p>"

    alert_text = "、".join(alerts)

    conn = db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO history (user_id, url, ip, status_code, response_time, server, score, risk, alert, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, url, ip, str(r.status_code), str(response_time),
        server, score, risk, alert_text,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()

    return f"""
    <div class='card'>
        <h2>掃描結果</h2>
        <p>網址：{escape(url)}</p>
        <p>IP：{ip}</p>
        <p>狀態碼：{r.status_code}</p>
        <p>回應時間：{response_time} 秒</p>
        <p>Server：{escape(server)}</p>
        <p>SSL 到期：{ssl_exp}</p>
        <p>SSL 剩餘天數：{ssl_days}</p>
    </div>

    <div class='card'>
        <h2>安全分數</h2>
        <div class='score'>{score}/100</div>
        <h1 class='{risk_class}'>風險等級：{risk}</h1>
    </div>

    <div class='card'>
        <h2>Security Header</h2>
        {header_html}
    </div>

    <div class='card'>
        <h2>Port 監控</h2>
        {port_html}
    </div>

    <div class='card'>
        <h2>AI 防禦建議</h2>
        <p>告警：{escape(alert_text)}</p>
        <p>建議：補強缺少的 Security Header，定期檢查 SSL 與網站可用性。</p>
    </div>
    """

def page(title, body):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                background:#020617;
                color:#e5e7eb;
                font-family:Arial, sans-serif;
                padding:24px;
                font-size:18px;
            }}
            h1 {{ font-size:34px; }}
            input, select {{
                width:90%;
                padding:15px;
                border-radius:12px;
                border:0;
                font-size:18px;
                margin-top:8px;
            }}
            button {{
                padding:15px 20px;
                border-radius:12px;
                border:0;
                background:#22c55e;
                font-weight:bold;
                font-size:18px;
                box-shadow:0 0 18px #22c55e66;
                margin-top:10px;
            }}
            a {{ color:#38bdf8; }}
            .danger {{
                background:#ef4444;
                color:white;
                box-shadow:0 0 18px #ef444466;
            }}
            .card {{
                background:#0f172a;
                border:1px solid #1e293b;
                border-radius:18px;
                padding:22px;
                margin-top:22px;
            }}
            .history {{
                background:#111827;
                border:1px solid #334155;
                border-radius:14px;
                padding:14px;
                margin-top:12px;
            }}
            .score {{
                font-size:42px;
                font-weight:bold;
            }}
            .ok {{ color:#22c55e; }}
            .bad {{ color:#fb7185; }}
            .mid {{ color:#facc15; }}
            .low {{ color:#22c55e; }}
            .high {{ color:#ef4444; }}
        </style>
    </head>
    <body>
        {body}
    </body>
    </html>
    """

init_db()

@app.route("/")
def index():
    user = get_user()
    if user:
        return redirect("/dashboard")

    body = """
    <h1>🛡️ Security SaaS 防禦監控平台</h1>
    <div class='card'>
        <h2>網站安全監控 SaaS</h2>
        <p>提供網站健檢、SSL 監控、Header 檢查、Port 監控、風險分數與歷史紀錄。</p>
        <p><b>Free：</b>1 個網站</p>
        <p><b>Pro：</b>5 個網站</p>
        <p><b>Business：</b>50 個網站</p>
        <a href='/login'><button>登入</button></a>
        <a href='/register'><button>註冊</button></a>
    </div>
    """
    return page("Security SaaS", body)

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        plan = request.form.get("plan")

        try:
            conn = db()
            c = conn.cursor()
            c.execute("""
            INSERT INTO users (username, password_hash, plan, created_at)
            VALUES (?, ?, ?, ?)
            """, (
                username,
                generate_password_hash(password),
                plan,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
            conn.commit()
            conn.close()
            return redirect("/login")
        except Exception as e:
            msg = f"<p class='bad'>註冊失敗：{e}</p>"

    body = f"""
    <h1>註冊帳號</h1>
    <div class='card'>
        {msg}
        <form method="POST">
            <input name="username" placeholder="帳號">
            <input name="password" type="password" placeholder="密碼">
            <select name="plan">
                <option value="Free">Free - 1 個網站</option>
                <option value="Pro">Pro - 5 個網站</option>
                <option value="Business">Business - 50 個網站</option>
            </select>
            <button type="submit">註冊</button>
        </form>
        <p><a href="/login">已有帳號？登入</a></p>
    </div>
    """
    return page("註冊", body)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[2], password):
            session["user_id"] = row[0]
            return redirect("/dashboard")
        else:
            msg = "<p class='bad'>帳號或密碼錯誤</p>"

    body = f"""
    <h1>登入</h1>
    <div class='card'>
        {msg}
        <form method="POST">
            <input name="username" placeholder="帳號">
            <input name="password" type="password" placeholder="密碼">
            <button type="submit">登入</button>
        </form>
        <p>預設管理員：admin / 123456</p>
    </div>
    """
    return page("登入", body)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    user = get_user()
    if not user:
        return redirect("/login")

    user_id, username, plan = user
    limit = plan_limit(plan)
    result = ""

    conn = db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM targets WHERE user_id=?", (user_id,))
    count = c.fetchone()[0]
    conn.close()

    if request.method == "POST" and request.form.get("target"):
        if count >= limit:
            result = "<div class='card bad'>已達目前方案可新增網站數量上限</div>"
        else:
            target = normalize_url(request.form.get("target"))
            note = request.form.get("note", "")

            conn = db()
            c = conn.cursor()
            c.execute("""
            INSERT INTO targets (user_id, url, note, created_at)
            VALUES (?, ?, ?, ?)
            """, (user_id, target, note, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
            return redirect("/dashboard")

    if request.method == "POST" and request.form.get("scan_url"):
        try:
            result = scan_site(user_id, request.form.get("scan_url"))
        except Exception as e:
            result = f"<div class='card bad'>掃描失敗：{e}</div>"

    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, url, note, created_at FROM targets WHERE user_id=? ORDER BY id DESC", (user_id,))
    targets = c.fetchall()

    c.execute("""
    SELECT url, ip, status_code, response_time, server, score, risk, alert, created_at
    FROM history WHERE user_id=? ORDER BY id DESC LIMIT 10
    """, (user_id,))
    history = c.fetchall()
    conn.close()

    targets_html = ""
    for tid, url, note, created in targets:
        targets_html += f"""
        <div class='history'>
            <p><b>{escape(url)}</b></p>
            <p>備註：{escape(note)}</p>
            <p>加入：{created}</p>
            <form method="POST">
                <input type="hidden" name="scan_url" value="{escape(url)}">
                <button type="submit">掃描此網站</button>
            </form>
        </div>
        """

    history_html = ""
    for row in history:
        url, ip, status, rt, server, score, risk, alert, created = row
        history_html += f"""
        <div class='history'>
            <p><b>{escape(url)}</b></p>
            <p>IP：{ip}</p>
            <p>狀態碼：{status}｜回應：{rt} 秒</p>
            <p>Server：{escape(server)}</p>
            <p>分數：{score}/100｜風險：{risk}</p>
            <p>告警：{escape(alert)}</p>
            <p>時間：{created}</p>
        </div>
        """

    body = f"""
    <h1>🛡️ 會員 Dashboard</h1>
    <p>帳號：{escape(username)}｜方案：{plan}｜網站上限：{limit}</p>
    <p><a href="/logout">登出</a></p>

    <div class='card'>
        <h2>新增監控網站</h2>
        <form method="POST">
            <input name="target" placeholder="網站，例如 example.com">
            <input name="note" placeholder="備註">
            <button type="submit">新增</button>
        </form>
    </div>

    <div class='card'>
        <h2>單次掃描</h2>
        <form method="POST">
            <input name="scan_url" placeholder="輸入網站，例如 google.com">
            <button type="submit">開始掃描</button>
        </form>
    </div>

    {result}

    <div class='card'>
        <h2>我的監控網站</h2>
        {targets_html if targets_html else "<p>尚未新增網站。</p>"}
    </div>

    <div class='card'>
        <h2>最近掃描紀錄</h2>
        {history_html if history_html else "<p>目前沒有紀錄。</p>"}
    </div>
    """

    return page("Dashboard", body)

app.run(host="0.0.0.0", port=5000)