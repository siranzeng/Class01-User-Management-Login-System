# 用户信息管理平台 v2.0
# 修复: 曾思填
# 说明: 密码改哈希存储 + CSRF + 防暴力破解

from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
import sqlite3
import os
import re
import struct

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ---- 初始化上传目录 ----
os.makedirs("static/uploads", exist_ok=True)

# ---- 数据库初始化 ----
def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()

init_db()

# 用户数据，密码存的是哈希值，不是明文了
# 原密码: admin=admin123, alice=alice2025
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# ---- 防暴力破解相关变量 ----
ACCOUNT_LOCKOUT = {}
IP_RATE_LIMIT = {}
LOGIN_FAILURES = {}

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900
IP_RATE_WINDOW = 60
IP_MAX_REQUESTS = 10
INITIAL_DELAY = 1
DELAY_MULTIPLIER = 2
MAX_DELAY = 30
FAILURE_WINDOW = 300


# ---- CSRF ----
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf_token():
    token = request.form.get("csrf_token", "")
    stored = session.get("csrf_token")
    if not stored or not secrets.compare_digest(stored, token):
        return False
    session["csrf_token"] = secrets.token_hex(32)
    return True


# ---- IP限流 ----
def check_ip_rate_limit():
    client_ip = request.remote_addr or "unknown"
    now = time.time()
    ip_data = IP_RATE_LIMIT.get(client_ip)
    if ip_data:
        if now - ip_data["window_start"] < IP_RATE_WINDOW:
            ip_data["count"] += 1
            if ip_data["count"] > IP_MAX_REQUESTS:
                return False
        else:
            IP_RATE_LIMIT[client_ip] = {"count": 1, "window_start": now}
    else:
        IP_RATE_LIMIT[client_ip] = {"count": 1, "window_start": now}
    return True


# ---- 账户锁定检查 ----
def check_account_locked(username):
    lock_data = ACCOUNT_LOCKOUT.get(username)
    if lock_data:
        if time.time() < lock_data["locked_until"]:
            return int(lock_data["locked_until"] - time.time())
        else:
            del ACCOUNT_LOCKOUT[username]
    return 0


# ---- 记录失败 + 指数退避 ----
def record_login_failure(username):
    now = time.time()
    fail_data = LOGIN_FAILURES.get(username)
    if fail_data:
        if now - fail_data["last_fail"] < FAILURE_WINDOW:
            fail_data["fail_count"] += 1
        else:
            fail_data["fail_count"] = 1
        fail_data["last_fail"] = now
    else:
        LOGIN_FAILURES[username] = {"fail_count": 1, "last_fail": now}

    if fail_data and fail_data["fail_count"] >= MAX_LOGIN_ATTEMPTS:
        ACCOUNT_LOCKOUT[username] = {
            "count": fail_data["fail_count"],
            "locked_until": now + LOCKOUT_DURATION,
            "last_fail": now
        }
        return None

    delay = min(
        INITIAL_DELAY * (DELAY_MULTIPLIER ** (fail_data["fail_count"] - 1)),
        MAX_DELAY
    )
    return delay


def apply_login_delay(delay):
    if delay and delay > 0:
        time.sleep(delay)


def clear_login_records(username):
    if username in LOGIN_FAILURES:
        del LOGIN_FAILURES[username]
    if username in ACCOUNT_LOCKOUT:
        del ACCOUNT_LOCKOUT[username]


# ---- 路由: 首页（含搜索）----
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    keyword = request.args.get("keyword", "")
    search_results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f"%{keyword}%"
        print("[SQL]", sql, "| keyword:", keyword)
        c.execute(sql, (param, param))
        search_results = c.fetchall()
        conn.close()

    csrf_token = generate_csrf_token()
    return render_template("index.html", user_info=user_info, csrf_token=csrf_token,
                           search_results=search_results, keyword=keyword)


# ---- 路由: 登录 ----
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    success = None
    csrf_token = generate_csrf_token()

    # 注册成功跳转提示
    if request.method == "GET" and request.args.get("msg") == "reg_ok":
        success = "注册成功，请登录"

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not check_ip_rate_limit():
            error = "请求过于频繁，请稍后再试"
            return render_template("login.html", error=error, success=success, csrf_token=csrf_token)

        if not check_csrf_token():
            error = "Token验证失败，请刷新页面重试"
            return render_template("login.html", error=error, success=success, csrf_token=csrf_token)

        remaining = check_account_locked(username)
        if remaining > 0:
            minutes = remaining // 60
            seconds = remaining % 60
            error = f"账户已被暂时锁定，请{minutes}分{seconds}秒后再试"
            return render_template("login.html", error=error, success=success, csrf_token=csrf_token)

        user = USERS.get(username)
        if not user:
            delay = record_login_failure(username)
            apply_login_delay(delay)
            error = "用户名或密码错误"
            return render_template("login.html", error=error, success=success, csrf_token=csrf_token)

        if not check_password_hash(user["password"], password):
            delay = record_login_failure(username)
            if delay is None:
                minutes = LOCKOUT_DURATION // 60
                error = f"登录失败次数过多，账户已被锁定{minutes}分钟"
            else:
                apply_login_delay(delay)
                error = "用户名或密码错误"
            return render_template("login.html", error=error, success=success, csrf_token=csrf_token)

        clear_login_records(username)
        session["username"] = username
        session["csrf_token"] = secrets.token_hex(32)

        user_info = USERS[username]
        return render_template("index.html", user_info=user_info, csrf_token=session["csrf_token"])

    return render_template("login.html", error=error, success=success, csrf_token=csrf_token)


# ---- 路由: 注册 ----
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    csrf_token = generate_csrf_token()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if username in USERS:
            error = "用户名已存在"
        else:
            conn = sqlite3.connect("data/users.db")
            c = conn.cursor()
            sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
            print("[SQL]", sql, "| username:", username)
            try:
                c.execute(sql, (username, password, email, phone))
                conn.commit()
                USERS[username] = {
                    "username": username,
                    "password": generate_password_hash(password),
                    "role": "user",
                    "email": email,
                    "phone": phone,
                    "balance": 0
                }
                conn.close()
                return redirect("/login?msg=reg_ok")
            except Exception as e:
                conn.close()
                error = f"注册失败: {e}"

    return render_template("register.html", error=error, csrf_token=csrf_token)


# ---- 路由: 搜索（单独接口）----
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    search_results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f"%{keyword}%"
        print("[SQL]", sql, "| keyword:", keyword)
        c.execute(sql, (param, param))
        search_results = c.fetchall()
        conn.close()
    return {"results": [{"id": r[0], "username": r[1], "email": r[2], "phone": r[3]} for r in search_results]}


# ---- 校验文件魔数 ----
def check_image_magic(data):
    """读取文件头魔数判断是否为真实图片"""
    if len(data) < 4:
        return False
    # JPEG: ff d8 ff
    if data[0:2] == b"\xff\xd8":
        return True
    # PNG: 89 50 4e 47
    if data[0:4] == b"\x89PNG":
        return True
    # GIF: 47 49 46 38 37 61 或 47 49 46 38 39 61
    if data[0:6] in (b"GIF87a", b"GIF89a"):
        return True
    # BMP: 42 4d
    if data[0:2] == b"BM":
        return True
    # WebP: 52 49 46 46 x x x x 57 45 42 50
    if len(data) >= 12 and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        return True
    return False


# ---- 路由: 上传头像（含5项安全校验）----
# 安全校验:
#   1. 文件名路径穿越防护
#   2. 文件后缀白名单校验
#   3. MIME 类型校验
#   4. 文件内容头校验（魔数）
#   5. 文件重命名防覆盖
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    error = None
    file_url = None
    filename = None

    ALLOWED_EXT = {"jpg", "jpeg", "png", "gif", "bmp", "webp"}
    ALLOWED_MIME = {"image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"}

    if request.method == "POST":
        file = request.files.get("file")
        if not file or not file.filename:
            error = "请选择一个文件"
            return render_template("upload.html", error=error, file_url=file_url, filename=filename)

        # 校验1: 路径穿越防护 - 过滤 ../ ./ 等路径字符
        raw_name = file.filename.replace("\\", "/")
        if ".." in raw_name or raw_name.startswith("/"):
            error = "文件名不合法"
            return render_template("upload.html", error=error, file_url=file_url, filename=filename)

        # 校验2: 文件后缀白名单
        ext = raw_name.rsplit(".", 1)[-1].lower() if "." in raw_name else ""
        if ext not in ALLOWED_EXT:
            error = "仅支持图片格式: jpg/jpeg/png/gif/bmp/webp"
            return render_template("upload.html", error=error, file_url=file_url, filename=filename)

        # 校验3: MIME 类型校验
        mime = file.content_type
        if mime not in ALLOWED_MIME:
            error = "文件类型不合法"
            return render_template("upload.html", error=error, file_url=file_url, filename=filename)

        # 校验4: 文件内容头校验（读取魔数判断真实类型）
        file.seek(0)
        head = file.read(16)
        file.seek(0)
        if not check_image_magic(head):
            error = "文件内容不是有效图片"
            return render_template("upload.html", error=error, file_url=file_url, filename=filename)

        # 校验5: 重命名防覆盖 - UUID + 时间戳 + 原始后缀
        saved_name = f"{secrets.token_hex(8)}_{int(time.time())}.{ext}"
        file.save(os.path.join("static/uploads", saved_name))
        file_url = url_for("static", filename=f"uploads/{saved_name}")
        filename = saved_name

    return render_template("upload.html", error=error, file_url=file_url, filename=filename)


# ---- 路由: 登出 ----
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    print("用户信息管理平台 v2.0 已启动")
    print("安全措施: 密码哈希 / CSRF / IP限流 / 账户锁定 / 延迟退避")
    app.run(debug=True, host="0.0.0.0", port=5000)
