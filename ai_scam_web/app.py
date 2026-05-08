from flask import Flask, request, redirect, session
import sqlite3, requests, socket, ssl, time, os
from datetime import datetime
from html import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = "security_saas_final.db"

ADMIN_USER = "admin"
ADMIN_PASS = "123456"

def db():
    return sqlite3.connect(DB)

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
    INSERT OR IGNORE INTO users (username, password_hash, plan, created_at)
    VALUES (?, ?, ?, ?)
    """, (
        ADMIN_USER,
        generate_password_hash(ADMIN_PASS),
        "Business",
        now()
    ))

    conn.commit()
    conn.close()

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def normalize_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    return url

def host_from_url(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def current_user():
    if "uid" not in session:
        return None
    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, username, plan FROM users WHERE id=?", (session["uid"],))
    row = c.fetchone()
    conn.close()
    return row

def plan_limit(plan):
    return {"Free": 1, "Pro": 5, "Business": 50}.get(plan, 1)

def ssl_check(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                exp = cert.get("notAfter", "未知")
                ts = ssl.cert_time_to_seconds(exp)
                days = int((ts - time.time()) / 86400)
                return exp, days
    except:
        return "查詢失敗", -1

def safe_scan(user_id, url):
    url = normalize_url(url)
    host = host_from_url(url)

    start = time.time()
    r = requests.get(url, timeout=10, allow_redirects=True)
    rt = round(time.time() - start, 3)

    headers = r.headers
    ip = socket.gethostbyname(host)
    server = headers.get("Server", "未顯示")

    ssl_exp, ssl_days = ssl_check(host)

    score = 0
    alerts = []

    if r.status_code >= 500:
        alerts.append("伺服器錯誤")
    elif r.status_code >= 400:
        alerts.append("網站回應異常")
    else:
        alerts.append("網站在線")

    if rt > 3:
        alerts.append("回應速度偏慢")

    if ssl_days != -1 and ssl_days < 30:
        alerts.append("SSL 即將到期")

    checks = {
        "Content-Security-Policy": "防 XSS",
        "X-Frame-Options": "防點擊劫持",
        "Strict-Transport-Security": "強制 HTTPS",
        "X-Content-Type-Options": "防 MIME 混淆",
        "Referrer-Policy": "保護來源資訊"
    }

    header_result = ""
    report_headers = ""

    for h, desc in checks.items():
        if h in headers:
            score += 20
            header_result += f"<p class='ok'>✅ {h}：有（{desc}）</p>"
            report_headers += f"✅ {h}：有（{desc}）\n"
        else:
            header_result += f"<p class='bad'>❌ {h}：沒有（{desc}）</p>"
            report_headers += f"❌ {h}：沒有（{desc}）\n"
            alerts.append(f"缺少 {h}")

    cookies = headers.get("Set-Cookie", "")
    cookie_html = ""
    cookie_report = ""

    if cookies:
        if "Secure" in cookies:
            cookie_html += "<p class='ok'>✅ Cookie 有 Secure</p>"
            cookie_report += "Cookie Secure：有\n"
        else:
            cookie_html += "<p class='bad'>❌ Cookie 缺少 Secure</p>"
            cookie_report += "Cookie Secure：沒有\n"

        if "HttpOnly" in cookies:
            cookie_html += "<p class='ok'>✅ Cookie 有 HttpOnly</p>"
            cookie_report += "Cookie HttpOnly：有\n"
        else:
            cookie_html += "<p class='bad'>❌ Cookie 缺少 HttpOnly</p>"
            cookie_report += "Cookie HttpOnly：沒有\n"
    else:
        cookie_html = "<p>未偵測到 Set-Cookie。</p>"
        cookie_report = "Cookie：未偵測到 Set-Cookie\n"

    if score >= 80:
        risk = "低風險"
        cls = "low"
    elif score >= 40:
        risk = "中風險"
        cls = "mid"
    else:
        risk = "高風險"
        cls = "high"

    alert_text = "、".join(alerts)

    report = f"""網站安全健檢報告
====================

網站：{url}
IP：{ip}
HTTP 狀態碼：{r.status_code}
回應時間：{rt} 秒
Server：{server}
SSL 到期：{ssl_exp}
SSL 剩餘天數：{ssl_days}

安全分數：{score}/100
風險等級：{risk}
告警：{alert_text}

Security Header：
{report_headers}

Cookie：
{cookie_report}

改善建議：
1. 補上缺少的 Security Header。
2. 確認 SSL 憑證有效且提前續約。
3. 檢查網站回應速度與主機穩定性。
4. 建議啟用 Cloudflare / WAF 基礎防護。
5. 定期產出安全健檢報告。
"""

    conn = db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO reports (
        user_id, url, ip, status, response_time, server,
        ssl_expire, ssl_days, score, risk, alert, report, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, url, ip, str(r.status_code), str(rt), server,
        ssl_exp, ssl_days, score, risk, alert_text, report, now()
    ))
    conn.commit()
    conn.close()

    return f"""
    <div class='card'>
        <h2>健檢摘要</h2>
        <p>網站：{escape(url)}</p>
        <p>IP：{ip}</p>
        <p>HTTP 狀態碼：{r.status_code}</p>
        <p>回應時間：{rt} 秒</p>
        <p>Server：{escape(server)}</p>
        <p>SSL 到期：{ssl_exp}</p>
        <p>SSL 剩餘天數：{ssl_days}</p>
    </div>

    <div class='card'>
        <h2>安全分數</h2>
        <div class='score'>{score}/100</div>
        <h1 class='{cls}'>風險等級：{risk}</h1>
    </div>

    <div class='card'>
        <h2>Security Header</h2>
        {header_result}
    </div>

    <div class='card'>
        <h2>Cookie 安全</h2>
        {cookie_html}
    </div>

    <div class='card'>
        <h2>AI 防禦建議</h2>
        <p>告警：{escape(alert_text)}</p>
        <p>建議：優先補強缺少的 Header、監控 SSL、確認網站穩定性。</p>
    </div>

    <div class='card'>
        <h2>客戶報告</h2>
        <textarea id="report">{escape(report)}</textarea>
        <button onclick="copyReport()">一鍵複製報告</button>
    </div>
    """

def layout(title, body):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script>
        function copyReport() {{
            var r = document.getElementById("report");
            r.select();
            document.execCommand("copy");
            alert("報告已複製");
        }}
        </script>
        <style>
            body {{
                background:#020617;
                color:#e5e7eb;
                font-family:Arial, sans-serif;
                padding:26px;
                font-size:18px;
            }}
            h1 {{ font-size:36px; }}
            h2 {{ font-size:26px; }}
            input, select {{
                width:92%;
                padding:15px;
                border-radius:12px;
                border:0;
                font-size:18px;
                margin-top:10px;
            }}
            button {{
                padding:15px 22px;
                border:0;
                border-radius:12px;
                background:#22c55e;
                font-weight:bold;
                font-size:18px;
                margin-top:12px;
                box-shadow:0 0 18px #22c55e66;
            }}
            a {{ color:#38bdf8; text-decoration:none; }}
            .danger {{
                background:#ef4444;
                color:white;
                box-shadow:0 0 18px #ef444466;
            }}
            .card {{
                background:#0f172a;
                border:1px solid #1e293b;
                border-radius:18px;
                padding:24px;
                margin-top:22px;
            }}
            .box {{
                background:#111827;
                border:1px solid #334155;
                border-radius:14px;
                padding:15px;
                margin-top:12px;
            }}
            .grid {{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
                gap:18px;
            }}
            .score {{
                font-size:46px;
                font-weight:bold;
            }}
            textarea {{
                width:100%;
                height:300px;
                border-radius:12px;
                padding:14px;
                font-size:16px;
            }}
            .ok {{ color:#22c55e; }}
            .bad {{ color:#fb7185; }}
            .mid {{ color:#facc15; }}
            .low {{ color:#22c55e; }}
            .high {{ color:#ef4444; }}
        </style>
    </head>
    <body>{body}</body>
    </html>
    """

init_db()

@app.route("/")
def home():
    if current_user():
        return redirect("/dashboard")

    body = """
    <h1>🛡️ Security SaaS 網站防禦健檢平台</h1>

    <div class='card'>
        <h2>幫客戶檢查網站安全、SSL、Header、Cookie、回應速度與風險分數</h2>
        <p>適合接案、網站維護、企業形象站、WordPress、電商網站、個人品牌網站。</p>
        <a href='/register'><button>免費註冊</button></a>
        <a href='/login'><button>登入</button></a>
    </div>

    <div class='card'>
        <h2>方案價格</h2>
        <div class='grid'>
            <div class='box'>
                <h2>Free</h2>
                <p>1 個網站</p>
                <p>基本健檢</p>
                <h2>NT$0</h2>
            </div>
            <div class='box'>
                <h2>Pro</h2>
                <p>5 個網站</p>
                <p>歷史紀錄 / 報告</p>
                <h2>NT$299/月</h2>
            </div>
            <div class='box'>
                <h2>Business</h2>
                <p>50 個網站</p>
                <p>客戶監控 / 接案展示</p>
                <h2>NT$999/月</h2>
            </div>
        </div>
    </div>

    <div class='card'>
        <h2>功能</h2>
        <p>✅ SSL 檢查</p>
        <p>✅ Security Header 檢查</p>
        <p>✅ Cookie 安全檢查</p>
        <p>✅ 回應速度檢查</p>
        <p>✅ 風險分數</p>
        <p>✅ 客戶報告複製</p>
        <p>✅ 會員 Dashboard</p>
    </div>
    """
    return layout("Security SaaS", body)

@app.route("/register", methods=["GET", "POST"])
def register():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        plan = request.form.get("plan", "Free")

        try:
            conn = db()
            c = conn.cursor()
            c.execute("""
            INSERT INTO users (username, password_hash, plan, created_at)
            VALUES (?, ?, ?, ?)
            """, (username, generate_password_hash(password), plan, now()))
            conn.commit()
            conn.close()
            return redirect("/login")
        except Exception as e:
            msg = f"<p class='bad'>註冊失敗：{escape(str(e))}</p>"

    body = f"""
    <h1>註冊</h1>
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
            <button>建立帳號</button>
        </form>
        <p><a href='/login'>已有帳號？登入</a></p>
    </div>
    """
    return layout("註冊", body)

@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = db()
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row[1], password):
            session["uid"] = row[0]
            return redirect("/dashboard")
        msg = "<p class='bad'>帳號或密碼錯誤</p>"

    body = f"""
    <h1>登入</h1>
    <div class='card'>
        {msg}
        <form method="POST">
            <input name="username" placeholder="帳號">
            <input name="password" type="password" placeholder="密碼">
            <button>登入</button>
        </form>
        <p>預設管理員：admin / 123456</p>
    </div>
    """
    return layout("登入", body)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    u = current_user()
    if not u:
        return redirect("/login")

    uid, username, plan = u
    limit = plan_limit(plan)
    result = ""

    if request.method == "POST" and request.form.get("scan_url"):
        try:
            result = safe_scan(uid, request.form.get("scan_url"))
        except Exception as e:
            result = f"<div class='card bad'>掃描失敗：{escape(str(e))}</div>"

    if request.method == "POST" and request.form.get("target_url"):
        conn = db()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM targets WHERE user_id=?", (uid,))
        count = c.fetchone()[0]

        if count >= limit:
            result = "<div class='card bad'>已達目前方案網站數量上限</div>"
        else:
            c.execute("""
            INSERT INTO targets (user_id, name, url, note, created_at)
            VALUES (?, ?, ?, ?, ?)
            """, (
                uid,
                request.form.get("target_name", "未命名"),
                normalize_url(request.form.get("target_url")),
                request.form.get("note", ""),
                now()
            ))
            conn.commit()
            result = "<div class='card ok'>已新增監控網站</div>"
        conn.close()

    conn = db()
    c = conn.cursor()

    c.execute("SELECT id, name, url, note, created_at FROM targets WHERE user_id=? ORDER BY id DESC", (uid,))
    targets = c.fetchall()

    c.execute("""
    SELECT url, ip, status, response_time, server, score, risk, alert, created_at
    FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 10
    """, (uid,))
    reports = c.fetchall()

    conn.close()

    targets_html = ""
    for tid, name, url, note, created in targets:
        targets_html += f"""
        <div class='box'>
            <p><b>{escape(name)}</b></p>
            <p>{escape(url)}</p>
            <p>{escape(note)}</p>
            <form method="POST">
                <input type="hidden" name="scan_url" value="{escape(url)}">
                <button>掃描此網站</button>
            </form>
        </div>
        """

    reports_html = ""
    for r in reports:
        url, ip, status, rt, server, score, risk, alert, created = r
        reports_html += f"""
        <div class='box'>
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
        <h2>單次網站健檢</h2>
        <form method="POST">
            <input name="scan_url" placeholder="輸入網站，例如 example.com">
            <button>開始健檢</button>
        </form>
    </div>

    <div class='card'>
        <h2>新增客戶網站</h2>
        <form method="POST">
            <input name="target_name" placeholder="客戶名稱 / 網站名稱">
            <input name="target_url" placeholder="網站，例如 example.com">
            <input name="note" placeholder="備註">
            <button>新增</button>
        </form>
    </div>

    {result}

    <div class='card'>
        <h2>我的監控網站</h2>
        {targets_html if targets_html else "<p>尚未新增網站。</p>"}
    </div>

    <div class='card'>
        <h2>最近健檢紀錄</h2>
        {reports_html if reports_html else "<p>目前沒有紀錄。</p>"}
    </div>
    """

    return layout("Dashboard", body)

@app.route("/admin")
def admin():
    u = current_user()
    if not u:
        return redirect("/login")

    uid, username, plan = u
    if username != ADMIN_USER:
        return redirect("/dashboard")

    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, username, plan, created_at FROM users ORDER BY id DESC")
    users = c.fetchall()
    conn.close()

    html = ""
    for user in users:
        i, name, p, t = user
        html += f"""
        <div class='box'>
            <p>ID：{i}</p>
            <p>帳號：{escape(name)}</p>
            <p>方案：{p}</p>
            <p>建立：{t}</p>
        </div>
        """

    body = f"""
    <h1>Admin 管理台</h1>
    <p><a href="/dashboard">回 Dashboard</a></p>
    <div class='card'>
        <h2>會員列表</h2>
        {html}
    </div>
    """

    return layout("Admin", body)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)