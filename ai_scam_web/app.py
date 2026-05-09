from flask import Flask, request, redirect, session, send_file, jsonify
import sqlite3, requests, socket, ssl, time, os, secrets, io
from datetime import datetime
from html import escape
from werkzeug.security import generate_password_hash, check_password_hash
from reportlab.pdfgen import canvas

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = "business_saas.db"

ADMIN_USER = "admin"
ADMIN_PASS = "123456"

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        api_key TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        email TEXT,
        note TEXT,
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
    INSERT OR IGNORE INTO users (username, password_hash, plan, api_key, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (
        ADMIN_USER,
        generate_password_hash(ADMIN_PASS),
        "Business",
        secrets.token_hex(24),
        now()
    ))

    conn.commit()
    conn.close()

def normalize_url(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    return url

def get_host(url):
    return url.replace("https://", "").replace("http://", "").split("/")[0]

def current_user():
    if "uid" not in session:
        return None
    conn = db()
    c = conn.cursor()
    c.execute("SELECT id, username, plan, api_key FROM users WHERE id=?", (session["uid"],))
    row = c.fetchone()
    conn.close()
    return row

def plan_limit(plan):
    if plan == "Free":
        return 1
    if plan == "Pro":
        return 5
    return 50

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

def scan(user_id, url, website_name="單次健檢"):
    url = normalize_url(url)
    host = get_host(url)

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

    header_html = ""
    header_report = ""

    for h, desc in checks.items():
        if h in headers:
            score += 20
            header_html += f"<p class='ok'>✅ {h}：有（{desc}）</p>"
            header_report += f"✅ {h}：有（{desc}）\n"
        else:
            header_html += f"<p class='bad'>❌ {h}：沒有（{desc}）</p>"
            header_report += f"❌ {h}：沒有（{desc}）\n"
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
            cookie_report += "Cookie Secure：無\n"

        if "HttpOnly" in cookies:
            cookie_html += "<p class='ok'>✅ Cookie 有 HttpOnly</p>"
            cookie_report += "Cookie HttpOnly：有\n"
        else:
            cookie_html += "<p class='bad'>❌ Cookie 缺少 HttpOnly</p>"
            cookie_report += "Cookie HttpOnly：無\n"
    else:
        cookie_html = "<p>未偵測到 Set-Cookie</p>"
        cookie_report = "未偵測到 Set-Cookie\n"

    if score >= 80:
        risk, cls = "低風險", "low"
    elif score >= 40:
        risk, cls = "中風險", "mid"
    else:
        risk, cls = "高風險", "high"

    alert_text = "、".join(alerts)

    ai = "建議持續監控 SSL、Header 與網站回應速度。"
    if score < 80:
        ai = "建議優先補強缺少的 Security Header，並建立定期監控流程。"
    if score < 40:
        ai = "建議立即補上 CSP、HSTS、X-Frame-Options，並檢查主機與網站安全設定。"

    report = f"""網站安全健檢報告

客戶網站：{website_name}
網址：{url}
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
{header_report}

Cookie：
{cookie_report}

AI 風險建議：
{ai}
"""

    conn = db()
    c = conn.cursor()
    c.execute("""
    INSERT INTO reports (
        user_id, website_name, url, ip, status, response_time, server,
        ssl_expire, ssl_days, score, risk, alert, report, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id, website_name, url, ip, str(r.status_code), str(rt), server,
        ssl_exp, ssl_days, score, risk, alert_text, report, now()
    ))
    rid = c.lastrowid
    conn.commit()
    conn.close()

    html = f"""
    <div class='card'>
        <h2>健檢摘要</h2>
        <p>網站名稱：{escape(website_name)}</p>
        <p>網址：{escape(url)}</p>
        <p>IP：{ip}</p>
        <p>狀態碼：{r.status_code}</p>
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

    <div class='card'><h2>Security Header</h2>{header_html}</div>
    <div class='card'><h2>Cookie 安全</h2>{cookie_html}</div>

    <div class='card'>
        <h2>AI 風險分析</h2>
        <p>告警：{escape(alert_text)}</p>
        <p>{escape(ai)}</p>
    </div>

    <div class='card'>
        <h2>客戶報告</h2>
        <textarea id="report">{escape(report)}</textarea>
        <button onclick="copyReport()">一鍵複製報告</button>
        <a href="/report/{rid}/pdf"><button>下載 PDF</button></a>
    </div>
    """

    return html

def layout(title, body):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <script>
        function copyReport(){{
            var r=document.getElementById("report");
            r.select();
            document.execCommand("copy");
            alert("報告已複製");
        }}
        </script>
        <style>
            body {{
                background:#020617;
                color:#e5e7eb;
                font-family:Arial,sans-serif;
                padding:26px;
                font-size:18px;
            }}
            h1 {{ font-size:36px; }}
            h2 {{ font-size:26px; }}
            input,select {{
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
            .danger {{ background:#ef4444;color:white; }}
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
                padding:16px;
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
    return layout("Security SaaS", """
    <h1>🛡️ Security SaaS 網站防禦健檢平台</h1>
    <div class='card'>
        <h2>幫客戶檢查網站 SSL、Header、Cookie、回應速度與風險分數</h2>
        <p>適合網站維護、接案、WordPress、電商網站、企業形象站。</p>
        <a href='/register'><button>免費註冊</button></a>
        <a href='/login'><button>登入</button></a>
    </div>

    <div class='card'>
        <h2>方案價格</h2>
        <div class='grid'>
            <div class='box'><h2>Free</h2><p>1 個網站</p><h2>NT$0</h2></div>
            <div class='box'>
<h2>Pro</h2>
<p>5 個網站</p>
<h2>NT$299/月</h2>
<a href="/create-checkout/pro">
<button>立即訂閱</button>
</a>
</div>

<div class='box'>
<h2>Business</h2>
<p>50 個網站</p>
<h2>NT$999/月</h2>
<a href="/create-checkout/business">
<button>立即訂閱</button>
</a>
</div>
        </div>
    </div>

    <div class='card'>
        <h2>商業功能</h2>
        <p>✅ 會員系統</p>
        <p>✅ 客戶 CRM</p>
        <p>✅ 網站健檢</p>
        <p>✅ AI 風險分析</p>
        <p>✅ PDF 報告</p>
        <p>✅ API Key</p>
        <p>✅ Admin 管理台</p>
    </div>
    """)

@app.route("/register", methods=["GET","POST"])
def register():
    msg=""
    if request.method=="POST":
        username=request.form.get("username","").strip()
        password=request.form.get("password","")
        plan=request.form.get("plan","Free")
        try:
            conn=db()
            c=conn.cursor()
            c.execute("""
            INSERT INTO users (username,password_hash,plan,api_key,created_at)
            VALUES (?,?,?,?,?)
            """,(username,generate_password_hash(password),plan,secrets.token_hex(24),now()))
            conn.commit()
            conn.close()
            return redirect("/login")
        except Exception as e:
            msg=f"<p class='bad'>註冊失敗：{escape(str(e))}</p>"
    return layout("註冊",f"""
    <h1>註冊</h1>
    <div class='card'>
        {msg}
        <form method='POST'>
            <input name='username' placeholder='帳號'>
            <input name='password' type='password' placeholder='密碼'>
            <select name='plan'>
                <option value='Free'>Free - 1 個網站</option>
                <option value='Pro'>Pro - 5 個網站</option>
                <option value='Business'>Business - 50 個網站</option>
            </select>
            <button>建立帳號</button>
        </form>
    </div>
    """)

@app.route("/login", methods=["GET","POST"])
def login():
    msg=""
    if request.method=="POST":
        username=request.form.get("username","")
        password=request.form.get("password","")
        conn=db()
        c=conn.cursor()
        c.execute("SELECT id,password_hash FROM users WHERE username=?",(username,))
        row=c.fetchone()
        conn.close()
        if row and check_password_hash(row[1],password):
            session["uid"]=row[0]
            return redirect("/dashboard")
        msg="<p class='bad'>帳號或密碼錯誤</p>"
    return layout("登入",f"""
    <h1>登入</h1>
    <div class='card'>
        {msg}
        <form method='POST'>
            <input name='username' placeholder='帳號'>
            <input name='password' type='password' placeholder='密碼'>
            <button>登入</button>
        </form>
        <p>預設管理員：admin / 123456</p>
    </div>
    """)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    u=current_user()
    if not u:
        return redirect("/login")

    uid, username, plan, api_key = u
    limit=plan_limit(plan)
    result=""

    if request.method=="POST" and request.form.get("client_name"):
        conn=db()
        c=conn.cursor()
        c.execute("""
        INSERT INTO clients (user_id,name,email,note,created_at)
        VALUES (?,?,?,?,?)
        """,(uid,request.form.get("client_name"),request.form.get("client_email"),request.form.get("client_note"),now()))
        conn.commit()
        conn.close()
        result="<div class='card ok'>客戶已新增</div>"

    if request.method=="POST" and request.form.get("website_url"):
        conn=db()
        c=conn.cursor()
        c.execute("SELECT COUNT(*) FROM websites WHERE user_id=?",(uid,))
        count=c.fetchone()[0]
        if count>=limit:
            result="<div class='card bad'>已達方案網站數量上限</div>"
        else:
            c.execute("""
            INSERT INTO websites (user_id,client_id,name,url,note,created_at)
            VALUES (?,?,?,?,?,?)
            """,(uid,0,request.form.get("website_name"),normalize_url(request.form.get("website_url")),request.form.get("website_note"),now()))
            conn.commit()
            result="<div class='card ok'>網站已新增</div>"
        conn.close()

    if request.method=="POST" and request.form.get("scan_url"):
        try:
            result=scan(uid,request.form.get("scan_url"),request.form.get("scan_name","單次健檢"))
        except Exception as e:
            result=f"<div class='card bad'>掃描失敗：{escape(str(e))}</div>"

    conn=db()
    c=conn.cursor()
    c.execute("SELECT name,email,note,created_at FROM clients WHERE user_id=? ORDER BY id DESC",(uid,))
    clients=c.fetchall()
    c.execute("SELECT name,url,note,created_at FROM websites WHERE user_id=? ORDER BY id DESC",(uid,))
    websites=c.fetchall()
    c.execute("SELECT website_name,url,score,risk,alert,created_at FROM reports WHERE user_id=? ORDER BY id DESC LIMIT 10",(uid,))
    reports=c.fetchall()
    conn.close()

    clients_html="".join([f"<div class='box'><b>{escape(x[0])}</b><p>{escape(x[1] or '')}</p><p>{escape(x[2] or '')}</p><p>{x[3]}</p></div>" for x in clients])
    websites_html=""
    for name,url,note,created in websites:
        websites_html+=f"""
        <div class='box'>
            <p><b>{escape(name or '')}</b></p>
            <p>{escape(url)}</p>
            <p>{escape(note or '')}</p>
            <form method='POST'>
                <input type='hidden' name='scan_url' value='{escape(url)}'>
                <input type='hidden' name='scan_name' value='{escape(name or "網站")}' >
                <button>掃描此網站</button>
            </form>
        </div>
        """

    reports_html="".join([f"<div class='box'><b>{escape(x[0] or '')}</b><p>{escape(x[1])}</p><p>{x[2]}/100｜{x[3]}</p><p>{escape(x[4])}</p><p>{x[5]}</p></div>" for x in reports])

    return layout("Dashboard",f"""
    <h1>🛡️ Dashboard</h1>
    <p>帳號：{escape(username)}｜方案：{plan}｜網站上限：{limit}</p>
    <p>API Key：<code>{api_key}</code></p>
    <p><a href='/admin'>Admin</a>｜<a href='/logout'>登出</a></p>

    <div class='card'>
        <h2>單次網站健檢</h2>
        <form method='POST'>
            <input name='scan_name' placeholder='網站名稱'>
            <input name='scan_url' placeholder='網站，例如 example.com'>
            <button>開始健檢</button>
        </form>
    </div>

    <div class='card'>
        <h2>新增客戶 CRM</h2>
        <form method='POST'>
            <input name='client_name' placeholder='客戶名稱'>
            <input name='client_email' placeholder='Email'>
            <input name='client_note' placeholder='備註'>
            <button>新增客戶</button>
        </form>
    </div>

    <div class='card'>
        <h2>新增監控網站</h2>
        <form method='POST'>
            <input name='website_name' placeholder='網站名稱'>
            <input name='website_url' placeholder='網址'>
            <input name='website_note' placeholder='備註'>
            <button>新增網站</button>
        </form>
    </div>

    {result}

    <div class='card'><h2>客戶 CRM</h2>{clients_html if clients_html else '<p>尚無客戶</p>'}</div>
    <div class='card'><h2>監控網站</h2>{websites_html if websites_html else '<p>尚無網站</p>'}</div>
    <div class='card'><h2>最近報告</h2>{reports_html if reports_html else '<p>尚無報告</p>'}</div>
    """)

@app.route("/report/<int:rid>/pdf")
def report_pdf(rid):
    u=current_user()
    if not u:
        return redirect("/login")
    uid=u[0]

    conn=db()
    c=conn.cursor()
    c.execute("SELECT report FROM reports WHERE id=? AND user_id=?",(rid,uid))
    row=c.fetchone()
    conn.close()

    if not row:
        return "Report not found"

    buffer=io.BytesIO()
    p=canvas.Canvas(buffer)
    y=800
    for line in row[0].split("\n"):
        p.drawString(40,y,line[:90])
        y-=18
        if y<50:
            p.showPage()
            y=800
    p.save()
    buffer.seek(0)
    return send_file(buffer,as_attachment=True,download_name="security_report.pdf",mimetype="application/pdf")

@app.route("/api/scan")
def api_scan():
    key=request.args.get("key")
    url=request.args.get("url")

    conn=db()
    c=conn.cursor()
    c.execute("SELECT id FROM users WHERE api_key=?",(key,))
    user=c.fetchone()
    conn.close()

    if not user:
        return jsonify({"error":"invalid api key"}),403

    if not url:
        return jsonify({"error":"missing url"}),400

    try:
        scan(user[0],url,"API Scan")
        return jsonify({"ok":True,"message":"scan completed"})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)}),500

@app.route("/admin")
def admin():
    u=current_user()
    if not u:
        return redirect("/login")
    if u[1]!=ADMIN_USER:
        return redirect("/dashboard")

    conn=db()
    c=conn.cursor()
    c.execute("SELECT id,username,plan,created_at FROM users ORDER BY id DESC")
    users=c.fetchall()
    conn.close()

    html="".join([f"<div class='box'><p>ID：{x[0]}</p><p>帳號：{escape(x[1])}</p><p>方案：{x[2]}</p><p>{x[3]}</p></div>" for x in users])
    return layout("Admin",f"<h1>Admin 管理台</h1><p><a href='/dashboard'>回 Dashboard</a></p><div class='card'>{html}</div>")
import stripe

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

@app.route("/create-checkout/<plan>")
def create_checkout(plan):
    if plan == "pro":
        price_id = os.getenv("STRIPE_PRO_PRICE_ID")
    else:
        price_id = os.getenv("STRIPE_BUSINESS_PRICE_ID")

    checkout_session = stripe.checkout.Session.create(       
        payment_method_types=["card"],
        mode="subscription",
        line_items=[
            {
                "price": price_id,
                "quantity": 1,
            }
        ],
        client_reference_id=session.get("user_id"),
        metadata={"plan": plan},
        success_url="https://security-platform-e33q.onrender.com/dashboard",
        cancel_url="https://security-platform-e33q.onrender.com/",
    )

    return redirect(checkout_session.url)
@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    endpoint_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            endpoint_secret
        )
    except Exception as e:
        return str(e), 400

    if event["type"] == "checkout.session.completed":
        checkout_session = event["data"]["object"]

        user_id = checkout_session.get("client_reference_id")
        plan = checkout_session.get("metadata", {}).get("plan", "Free")

        if user_id:
            conn = db()
            c = conn.cursor()

            c.execute(
                "UPDATE users SET plan=? WHERE id=?",
                (plan.capitalize(), user_id)
            )

            conn.commit()
            conn.close()

    return "ok", 200
if __name__ == "__main__":
    port=int(os.environ.get("PORT",5000))
    app.run(host="0.0.0.0",port=port)