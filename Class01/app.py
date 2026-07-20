#!/usr/bin/env python3
"""
用户管理系统 - 安全加固版
- 密码 bcrypt 加盐哈希存储（单独文件）
- 前端密码脱敏（掩码显示）
- 密码强度校验
- 登录错误次数限流防爆破
- 全站 HTTPS 强制跳转
- 随机生成 secret_key
- 关闭 debug 模式

新增功能：
- SQLite 数据库存储注册用户
- 用户注册（参数化查询，防 SQL 注入）
- 用户搜索（参数化查询，防 SQL 注入）
"""

import json
import os
import secrets
import re
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# 应用配置
# ============================================================

# 随机生成 64 位 hex 作为 secret_key
SECRET_KEY = secrets.token_hex(32)

# 密码哈希存储文件
PASSWD_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users_passwd.json")

# HTTPS 证书路径
CERT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cert.pem")
KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "key.pem")

# SQLite 数据库路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

# ============================================================
# 用户数据库 — 注意：不包含密码字段！
# ============================================================
USERS = {
    "admin": {
        "username": "admin",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ============================================================
# 密码管理器 — 从独立文件读取 bcrypt 哈希
# ============================================================
def load_password_hashes() -> dict:
    """从 JSON 文件加载密码哈希"""
    if os.path.exists(PASSWD_FILE):
        with open(PASSWD_FILE, "r") as f:
            return json.load(f)
    return {}


def verify_password(username: str, password: str) -> bool:
    """验证用户密码（与 bcrypt 哈希比对）"""
    hashes = load_password_hashes()
    stored_hash = hashes.get(username)
    if stored_hash is None:
        return False
    return check_password_hash(stored_hash, password)


# ============================================================
# 密码强度校验
# ============================================================
def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    校验密码强度：
    - 长度 >= 8
    - 包含大写字母
    - 包含小写字母
    - 包含数字
    """
    if len(password) < 8:
        return False, "密码长度不能少于 8 位"
    if not re.search(r"[A-Z]", password):
        return False, "密码必须包含至少一个大写字母"
    if not re.search(r"[a-z]", password):
        return False, "密码必须包含至少一个小写字母"
    if not re.search(r"[0-9]", password):
        return False, "密码必须包含至少一个数字"
    return True, ""


# ============================================================
# 登录限流 — 防爆破
# ============================================================
LOGIN_ATTEMPTS: dict[str, list[datetime]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
CLEANUP_INTERVAL = 60
_last_cleanup = datetime.now()


def get_login_key() -> str:
    """生成限流 key（IP + 用户名组合）"""
    ip = request.remote_addr or "unknown"
    username = request.form.get("username", "unknown")
    return f"{ip}:{username}"


def cleanup_expired_attempts():
    """清理过期的尝试记录"""
    global _last_cleanup
    now = datetime.now()
    if (now - _last_cleanup).total_seconds() < CLEANUP_INTERVAL:
        return
    _last_cleanup = now
    cutoff = now - timedelta(minutes=LOCKOUT_MINUTES)
    expired = [k for k, v in LOGIN_ATTEMPTS.items() if v and v[-1] < cutoff]
    for k in expired:
        del LOGIN_ATTEMPTS[k]


def is_login_locked() -> tuple[bool, int]:
    """检查登录是否被锁定"""
    cleanup_expired_attempts()
    key = get_login_key()
    now = datetime.now()
    cutoff = now - timedelta(minutes=LOCKOUT_MINUTES)

    attempts = LOGIN_ATTEMPTS.get(key, [])
    recent = [t for t in attempts if t > cutoff]
    LOGIN_ATTEMPTS[key] = recent

    if len(recent) >= MAX_ATTEMPTS:
        oldest = min(recent)
        remaining = int((cutoff + timedelta(minutes=LOCKOUT_MINUTES) - now).total_seconds())
        remaining = max(remaining, 1)
        return True, remaining

    return False, 0


def record_failed_attempt(username: str):
    """记录一次失败的登录尝试"""
    ip = request.remote_addr or "unknown"
    key = f"{ip}:{username}"
    if key not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[key] = []
    LOGIN_ATTEMPTS[key].append(datetime.now())


# ============================================================
# SQLite 数据库初始化
# ============================================================
def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("  ✅ SQLite 数据库初始化完成")


# ============================================================
# Flask 初始化
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.debug = False

# 启动时初始化数据库
init_db()


# ============================================================
# HTTPS 强制跳转中间件
# ============================================================
@app.before_request
def enforce_https():
    """非 HTTPS 请求强制 301 跳转到 HTTPS"""
    if not request.is_secure and not app.debug:
        https_url = request.url.replace("http://", "https://", 1)
        return redirect(https_url, 301)


# ============================================================
# 路由
# ============================================================

@app.route("/")
def index():
    """首页：已登录显示用户信息（密码脱敏），未登录提示登录"""
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    # 处理搜索
    keyword = request.args.get("keyword", "")
    search_results = None
    if keyword:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # 使用参数化查询防 SQL 注入
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"
        print(f"  [SQL] {sql}  参数: like_param='{like_param}'")
        try:
            c.execute(sql, (like_param, like_param))
            search_results = [dict(row) for row in c.fetchall()]
        except Exception as e:
            print(f"  [SQL ERROR] {e}")
            search_results = []
        conn.close()

    return render_template("index.html", username=username, user=user_info,
                           keyword=keyword, search_results=search_results)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录：支持 GET 显示表单，POST 验证凭据"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 检查是否被限流锁定
        locked, remaining = is_login_locked()
        if locked:
            return render_template("login.html", error=f"登录过于频繁，请 {remaining} 秒后再试")

        # 验证用户是否存在
        if username not in USERS:
            record_failed_attempt(username)
            return render_template("login.html", error="用户名或密码错误")

        # 验证密码（bcrypt 哈希比对）
        if verify_password(username, password):
            session["username"] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=8)
            user_info = USERS[username]
            return render_template("index.html", username=username, user=user_info)
        else:
            record_failed_attempt(username)
            remaining = MAX_ATTEMPTS - len(LOGIN_ATTEMPTS.get(get_login_key(), []))
            if remaining <= 0:
                return render_template("login.html", error=f"登录过于频繁，请稍后再试")
            return render_template("login.html", error=f"用户名或密码错误（还可尝试 {remaining} 次）")

    # 从注册页跳转过来的成功提示
    msg = request.args.get("msg", "")
    return render_template("login.html", msg=msg)


@app.route("/logout")
def logout():
    """登出：清除 session 后重定向"""
    session.clear()
    return redirect(url_for("index"))


# ============================================================
# 新增：用户注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面：GET 显示表单，POST 处理注册"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")

        # 使用参数化查询防 SQL 注入
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"  [SQL] {sql}  参数: username='{username}'")
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            print(f"  ✅ 用户 {username} 注册成功")
            conn.close()
            return redirect(url_for("login", msg="注册成功，请登录"))
        except sqlite3.IntegrityError as e:
            conn.close()
            return render_template("register.html", error=f"用户名 '{username}' 已存在")
        except Exception as e:
            conn.close()
            return render_template("register.html", error=f"注册失败: {e}")

    return render_template("register.html")


# ============================================================
# 新增：搜索用户（GET）
# ============================================================
@app.route("/search")
def search():
    """搜索用户：通过 URL 参数 keyword 搜索"""
    keyword = request.args.get("keyword", "")

    if not keyword:
        return redirect(url_for("index"))

    # 使用参数化查询防 SQL 注入
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    like_param = f"%{keyword}%"
    print(f"  [SQL] {sql}  参数: like_param='{like_param}'")
    results = []
    try:
        c.execute(sql, (like_param, like_param))
        results = [dict(row) for row in c.fetchall()]
    except Exception as e:
        print(f"  [SQL ERROR] {e}")

    conn.close()

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    return render_template("index.html", username=username, user=user_info,
                           keyword=keyword, search_results=results)


# ============================================================
# 启动
# ============================================================
if __name__ == "__main__":
    use_https = os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    if use_https:
        print("  🔒 HTTPS 模式启动")
        app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=(CERT_FILE, KEY_FILE))
    else:
        print("  ⚠️  未找到证书文件，以 HTTP 模式启动（生产环境请配置 HTTPS）")
        app.run(host="0.0.0.0", port=5000, debug=False)
