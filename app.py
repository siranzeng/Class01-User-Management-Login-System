"""
================================================================
  用户信息管理平台 - 登录功能
  ──────────────────────────────────────────────────────────────
  安全修复版本 v2.0
  ──────────────────────────────────────────────────────────────
  漏洞修复说明：
    1. [高危] 明文密码存储 → 使用 werkzeug.security 哈希存储
    2. [高危] 无 CSRF 防护   → 新增 Token 校验机制
    3. [高危] 无暴力破解防护 → 新增登录频率限制、账户锁定、
       IP 级别限流、递增延迟等多种防护
    4. [中危] 密码在前端明文展示 → 隐藏为 ******
    5. [中危] 调试信息泄露默认账号 → 移除但保留注释说明

  修复日期 : 2026-07-19
================================================================
"""

from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time
import functools

# ================================================================
# Flask 基础配置
# ================================================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # 使用强随机密钥

# ================================================================
# 用户数据库（密码已替换为哈希值）
# ────────────────────────────────────────────────────────────────
# 原始明文密码（仅供开发和测试参考）：
#   admin : admin123
#   alice : alice2025
# 注意：实际数据库中仅存储哈希值，明文无法逆向还原
# ================================================================
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

# ================================================================
# 暴力破解防护 - 数据存储
# ================================================================

# 账户锁定状态: { "username": {"count": N, "locked_until": timestamp, "last_fail": timestamp} }
ACCOUNT_LOCKOUT = {}

# IP 级别请求计数: { "192.168.1.1": {"count": N, "window_start": timestamp} }
IP_RATE_LIMIT = {}

# 登录失败记录（用于递增延迟）: { "username": {"fail_count": N, "last_fail": timestamp} }
LOGIN_FAILURES = {}

# 配置参数
MAX_LOGIN_ATTEMPTS = 5          # 最大失败尝试次数
LOCKOUT_DURATION = 900          # 锁定时间（秒）= 15 分钟
IP_RATE_WINDOW = 60             # IP 统计窗口（秒）= 1 分钟
IP_MAX_REQUESTS = 10            # 每个 IP 每分钟最大请求数
INITIAL_DELAY = 1               # 初始延迟（秒）
DELAY_MULTIPLIER = 2            # 延迟倍增系数
MAX_DELAY = 30                  # 最大延迟（秒）
FAILURE_WINDOW = 300            # 失败记录窗口（秒）= 5 分钟


# ================================================================
# 暴力破解防护 - 辅助函数
# ================================================================

def generate_csrf_token():
    """生成并存储 CSRF Token"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf_token():
    """校验 CSRF Token，防止跨站请求伪造"""
    token = request.form.get("csrf_token", "")
    stored = session.get("csrf_token")
    if not stored or not secrets.compare_digest(stored, token):
        return False
    # Token 一次性使用，用后立即刷新
    session["csrf_token"] = secrets.token_hex(32)
    return True


def check_ip_rate_limit():
    """
    IP 级别访问频率限制
    每个 IP 在 IP_RATE_WINDOW 秒内最多 IP_MAX_REQUESTS 次请求
    """
    client_ip = request.remote_addr or "unknown"
    now = time.time()

    ip_data = IP_RATE_LIMIT.get(client_ip)
    if ip_data:
        if now - ip_data["window_start"] < IP_RATE_WINDOW:
            ip_data["count"] += 1
            if ip_data["count"] > IP_MAX_REQUESTS:
                return False
        else:
            # 重置窗口
            IP_RATE_LIMIT[client_ip] = {"count": 1, "window_start": now}
    else:
        IP_RATE_LIMIT[client_ip] = {"count": 1, "window_start": now}

    return True


def check_account_locked(username):
    """检查账户是否被锁定"""
    lock_data = ACCOUNT_LOCKOUT.get(username)
    if lock_data:
        if time.time() < lock_data["locked_until"]:
            remaining = int(lock_data["locked_until"] - time.time())
            return remaining
        else:
            # 锁定时间已过，清除记录
            del ACCOUNT_LOCKOUT[username]
    return 0


def record_login_failure(username):
    """记录登录失败并计算延迟时间"""
    now = time.time()
    fail_data = LOGIN_FAILURES.get(username)

    if fail_data:
        # 如果上次失败时间在统计窗口内，递增计数
        if now - fail_data["last_fail"] < FAILURE_WINDOW:
            fail_data["fail_count"] += 1
        else:
            fail_data["fail_count"] = 1
        fail_data["last_fail"] = now
    else:
        LOGIN_FAILURES[username] = {"fail_count": 1, "last_fail": now}

    # 检查是否达到锁定阈值
    if fail_data and fail_data["fail_count"] >= MAX_LOGIN_ATTEMPTS:
        ACCOUNT_LOCKOUT[username] = {
            "count": fail_data["fail_count"],
            "locked_until": now + LOCKOUT_DURATION,
            "last_fail": now
        }
        return None  # 账户已被锁定

    # 计算递增延迟（指数退避）
    delay = min(
        INITIAL_DELAY * (DELAY_MULTIPLIER ** (fail_data["fail_count"] - 1)),
        MAX_DELAY
    )
    return delay


def apply_login_delay(delay):
    """应用登录延迟，增加暴力破解时间成本"""
    if delay and delay > 0:
        time.sleep(delay)


def clear_login_records(username):
    """登录成功后清除失败记录"""
    if username in LOGIN_FAILURES:
        del LOGIN_FAILURES[username]
    if username in ACCOUNT_LOCKOUT:
        del ACCOUNT_LOCKOUT[username]


# ================================================================
# 路由 - 首页
# ================================================================
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    csrf_token = generate_csrf_token()
    return render_template("index.html", user_info=user_info, csrf_token=csrf_token)


# ================================================================
# 路由 - 登录（含多重暴力破解防护）
# ================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    csrf_token = generate_csrf_token()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # ── 防护层 1：IP 级别频率限制 ──
        if not check_ip_rate_limit():
            error = "请求过于频繁，请稍后再试"
            return render_template("login.html", error=error, csrf_token=csrf_token)

        # ── 防护层 2：CSRF Token 校验 ──
        if not check_csrf_token():
            error = "Token 验证失败，请刷新页面重试"
            return render_template("login.html", error=error, csrf_token=csrf_token)

        # ── 防护层 3：检查账户是否被锁定 ──
        remaining = check_account_locked(username)
        if remaining > 0:
            minutes = remaining // 60
            seconds = remaining % 60
            error = f"账户已被暂时锁定，请 {minutes} 分 {seconds} 秒后再试"
            return render_template("login.html", error=error, csrf_token=csrf_token)

        # ── 防护层 4：校验用户名是否存在（通用错误信息 + 用户枚举防护） ──
        user = USERS.get(username)
        if not user:
            # 即使用户不存在也记录失败，防止用户枚举
            delay = record_login_failure(username)
            apply_login_delay(delay)
            error = "用户名或密码错误"
            return render_template("login.html", error=error, csrf_token=csrf_token)

        # ── 防护层 5：密码哈希比对 ──
        if not check_password_hash(user["password"], password):
            delay = record_login_failure(username)
            if delay is None:
                minutes = LOCKOUT_DURATION // 60
                error = f"登录失败次数过多，账户已被锁定 {minutes} 分钟"
            else:
                apply_login_delay(delay)
                error = "用户名或密码错误"
            return render_template("login.html", error=error, csrf_token=csrf_token)

        # ── 登录成功：清除防护记录 ──
        clear_login_records(username)
        session["username"] = username
        # 刷新 CSRF Token
        session["csrf_token"] = secrets.token_hex(32)

        user_info = USERS[username]
        return render_template("index.html", user_info=user_info, csrf_token=session["csrf_token"])

    return render_template("login.html", error=error, csrf_token=csrf_token)


# ================================================================
# 路由 - 登出
# ================================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ================================================================
# 启动入口
# ================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  用户信息管理平台 v2.0（安全修复版）")
    print("  ─────────────────────────────────────")
    print("  安全措施已启用：")
    print("  1. 密码哈希存储（werkzeug.security）")
    print("  2. CSRF Token 校验")
    print("  3. IP 级别频率限制（10次/分钟）")
    print("  4. 账户锁定（5次失败锁定15分钟）")
    print("  5. 指数退避延迟策略")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
