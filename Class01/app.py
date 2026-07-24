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
- 用户头像上传（不校验文件类型，保留原始文件名）
"""

import json
import math
import os
import secrets
import re
import sqlite3
import uuid
import imghdr
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, session, url_for, abort, send_from_directory
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

# 上传文件配置
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp"}
MAX_AVATAR_SIZE = 2 * 1024 * 1024  # 2MB

# ============================================================
# 用户数据库 — 注意：不包含密码字段！
# 余额以"分"为单位存储（整数），避免浮点数精度损失
# ============================================================
USERS = {
    "admin": {
        "username": "admin",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 9999900,  # 99999.00 元 = 9999900 分
    },
    "alice": {
        "username": "alice",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 10000,  # 100.00 元 = 10000 分
    },
}


# ============================================================
# 登录校验装饰器 — 所有需要登录的接口必须使用此装饰器
# ============================================================
def login_required(f):
    """登录校验装饰器：未登录用户重定向到登录页"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# CSRF 防护 — 基于 Session 的 Token 校验
# ============================================================
def generate_csrf_token() -> str:
    """生成或获取当前会话的 CSRF Token"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf() -> bool:
    """校验请求中的 CSRF Token 是否与会话中的一致"""
    token = request.form.get("csrf_token", "")
    expected = session.get("csrf_token")
    if not expected or not token:
        return False
    return token == expected


def csrf_required(f):
    """CSRF 校验装饰器：Token 不匹配时返回 400"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == "POST":
            if not validate_csrf():
                return "CSRF Token 无效或缺失", 400
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# 余额格式化函数 — 将"分"转换为"元.角分"显示
# ============================================================
def format_balance(cents: int) -> str:
    """将整数分格式化为元（保留两位小数），如 10000 → '100.00'"""
    return f"{cents / 100:.2f}"


def parse_yuan_to_cents(yuan_str: str) -> int | None:
    """将用户输入的元转换为分，格式非法返回 None，超上限或负数也返回 None"""
    try:
        amount = float(yuan_str)
    except (ValueError, TypeError):
        return None
    # P0-5: 禁止负数充值
    if amount <= 0:
        return None
    # P0-6: 禁止 inf / nan 等特殊浮点值
    if not math.isfinite(amount):
        return None
    # P0-6: 单笔充值上限 10000 元 = 1000000 分
    MAX_RECHARGE_CENTS = 1000000
    cents = int(round(amount * 100))
    if cents > MAX_RECHARGE_CENTS:
        return None
    return cents


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
# 上传文件安全校验函数
# ============================================================
def allowed_file(filename: str) -> bool:
    """校验文件扩展名是否在允许的白名单内"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_valid_image(filepath: str) -> bool:
    """通过读取文件头校验是否为真实图片"""
    try:
        return imghdr.what(filepath) is not None
    except:
        return False


def get_secure_filename(filename: str) -> str:
    """生成安全的文件名：UUID + 合法扩展名（防止路径穿越、文件名覆盖和恶意文件名）

    修复 V-02: UUID 命名防路径穿越
    修复 V-06: 文件存在检测防文件名覆盖
    """
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'png'
    if ext not in ALLOWED_EXTENSIONS:
        ext = 'png'
    # 循环检查文件是否存在，避免覆盖已有文件
    while True:
        name = f"{uuid.uuid4().hex}.{ext}"
        filepath = os.path.join(UPLOAD_DIR, name)
        if not os.path.exists(filepath):
            return name


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
    # 插入/更新默认用户：旧版数据库可能存有明文密码，此处用哈希覆盖
    # P0-7: 密码使用 werkzeug.security 哈希后存储，杜绝明文
    default_admin_pwd = generate_password_hash("admin123")
    default_alice_pwd = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", default_admin_pwd, "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", default_alice_pwd, "alice@example.com", "13900139001"))
    # 迁移已有记录的密码为哈希（防止旧版 INSERT OR IGNORE 遗留的明文密码）
    c.execute("UPDATE users SET password = ? WHERE username = ? AND password NOT LIKE 'scrypt:%' AND password NOT LIKE 'pbkdf2:%'",
              (default_admin_pwd, "admin"))
    c.execute("UPDATE users SET password = ? WHERE username = ? AND password NOT LIKE 'scrypt:%' AND password NOT LIKE 'pbkdf2:%'",
              (default_alice_pwd, "alice"))
    conn.commit()
    conn.close()
    print("  ✅ SQLite 数据库初始化完成")


# ============================================================
# Flask 初始化
# ============================================================
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.debug = False
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 启动时初始化数据库
init_db()


# ============================================================
# 上下文处理器 — 所有模板自动获得 csrf_token 变量
# ============================================================
@app.context_processor
def inject_csrf_token():
    """向所有模板注入 csrf_token 变量"""
    return dict(csrf_token=generate_csrf_token())


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
        # P1-8: 将余额从"分"转为"元"显示
        user_info = dict(USERS[username])
        user_info["balance_display"] = format_balance(user_info["balance"])

    # 处理搜索（P1-9: 仅已登录用户可搜索）
    keyword = request.args.get("keyword", "")
    search_results = None
    if keyword and session.get("user_id"):
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
    elif keyword and not session.get("user_id"):
        # 未登录用户尝试搜索，重定向到登录页
        return redirect(url_for("login"))

    return render_template("index.html", username=username, user=user_info,
                           keyword=keyword, search_results=search_results)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录：支持 GET 显示表单，POST 验证凭据"""
    if request.method == "POST":
        # CSRF-03: 登录表单 CSRF 校验
        if not validate_csrf():
            return "CSRF Token 无效或缺失", 400
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 检查是否被限流锁定
        locked, remaining = is_login_locked()
        if locked:
            return render_template("login.html", error=f"登录过于频繁，请 {remaining} 秒后再试")

        # ---- 鉴权流程 ----
        # 1) 优先查 SQLite（注册用户的密码已哈希存储在 users 表）
        # 2) 如果 SQLite 中无此用户或密码不符，回退到 users_passwd.json（admin/alice 的旧密码文件）
        # ---- P0-7: 统一密码校验，无论存储方式如何 ----
        authenticated = False
        user_id = None

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        try:
            c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            if row:
                user_id = row[0]
                stored_hash = row[1]
                # 如果存储的是 werkzeug 哈希（以常见哈希前缀开头），用 check_password_hash
                if stored_hash.startswith(('pbkdf2:', 'scrypt:', '$2', '$5', '$6')):
                    authenticated = check_password_hash(stored_hash, password)
                else:
                    # 兼容旧版明文数据（init_db 在修复前写入的明文密码）
                    authenticated = (stored_hash == password)
        except Exception as e:
            print(f"  [SQL ERROR] {e}")
        conn.close()

        # 如果 SQLite 验证未通过，尝试旧密码文件（admin/alice 在 users_passwd.json 中的哈希）
        if not authenticated and username in USERS:
            authenticated = verify_password(username, password)
            # 从 SQLite 获取 user_id
            if authenticated:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                try:
                    c.execute("SELECT id FROM users WHERE username = ?", (username,))
                    row = c.fetchone()
                    if row:
                        user_id = row[0]
                except:
                    pass
                conn.close()

        if authenticated and user_id:
            session["username"] = username
            session["user_id"] = user_id
            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=8)

            # P0-7: 登录成功后，如果数据库仍存有明文密码，升级为哈希
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                c.execute("SELECT password, email, phone FROM users WHERE id = ?", (user_id,))
                row = c.fetchone()
                if row:
                    # 密码升级
                    if not row[0].startswith(('pbkdf2:', 'scrypt:', '$2', '$5', '$6')):
                        hashed = generate_password_hash(password)
                        c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
                        conn.commit()
                        print(f"  🔐 用户 {username} 密码已从明文升级为哈希")
                    # 用户同步：确保 USERS 字典中存在该用户记录（充值/余额功能依赖它）
                    if username not in USERS:
                        USERS[username] = {
                            "username": username,
                            "role": "user",
                            "email": row[1] or "",
                            "phone": row[2] or "",
                            "balance": 0,
                        }
                        print(f"  ✅ 用户 {username} 已同步到 USERS 字典")
                conn.close()
            except Exception as e:
                print(f"  [登录后处理失败] {e}")
            user_info = USERS.get(username)

            # P1-8: 将余额从"分"转为"元"显示
            user_info_display = None
            if user_info:
                user_info_display = dict(user_info)
                user_info_display["balance_display"] = format_balance(user_info["balance"])

            return render_template("index.html", username=username, user=user_info_display)
        else:
            # P2-10: 登录失败统一返回"用户名或密码错误"，不区分具体原因
            record_failed_attempt(username)
            return render_template("login.html", error="用户名或密码错误")

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
        # CSRF-04: 注册表单 CSRF 校验
        if not validate_csrf():
            return "CSRF Token 无效或缺失", 400
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")

        # P0-7: 密码使用 werkzeug.security 哈希后存储，杜绝明文
        hashed_password = generate_password_hash(password)

        # 使用参数化查询防 SQL 注入
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"  [SQL] {sql}  参数: username='{username}'")
        try:
            c.execute(sql, (username, hashed_password, email, phone))
            conn.commit()
            # 将新用户加入 USERS 字典（初始余额 0 分），使其余额可被充值和展示
            USERS[username] = {
                "username": username,
                "role": "user",
                "email": email or "",
                "phone": phone or "",
                "balance": 0,  # 初始余额 0 分 = 0.00 元
            }
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
@login_required
def search():
    """搜索用户：通过 URL 参数 keyword 搜索（需登录）"""
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
        user_info = dict(USERS[username])
        user_info["balance_display"] = format_balance(user_info["balance"])

    return render_template("index.html", username=username, user=user_info,
                           keyword=keyword, search_results=results)


# ============================================================
# 上传功能 — 安全加固版（5层防御）
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    """头像上传：GET 显示表单，POST 处理文件上传（已做安全加固）"""
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        # CSRF-05: 上传表单 CSRF 校验
        if not validate_csrf():
            return "CSRF Token 无效或缺失", 400
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        file = request.files.get("file")
        if file is None or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        # === 第1层防御：扩展名白名单校验 ===
        if not allowed_file(file.filename):
            return render_template("upload.html", error="不支持的文件类型，仅允许图片文件（jpg/png/gif/bmp/webp）")

        # === 第2层防御：应用层文件大小校验 ===
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size > MAX_AVATAR_SIZE:
            return render_template("upload.html", error=f"文件大小超过限制（最大 {MAX_AVATAR_SIZE // 1024 // 1024}MB）")

        # === 第3层防御：UUID重命名（防路径穿越、防恶意文件名） ===
        safe_filename = get_secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_DIR, safe_filename)

        # === 第3层防御延伸：路径穿越终极校验（符号链接/编码绕过） ===
        real_dir = os.path.realpath(UPLOAD_DIR)
        real_path = os.path.realpath(filepath)
        if os.path.commonpath([real_dir]) != os.path.commonpath([real_dir, real_path]):
            # 如果解析后的路径不在上传目录内，拒绝保存
            return render_template("upload.html", error="非法的文件路径")

        file.save(filepath)

        # === 第4层防御：真实图片文件头检测 ===
        if not is_valid_image(filepath):
            os.remove(filepath)
            return render_template("upload.html", error="文件不是有效的图片文件，请上传真实图片")

        # === 第5层防御：移除文件可执行权限 ===
        os.chmod(filepath, 0o644)

        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_filename)

    return render_template("upload.html")


# ============================================================
# 新增：个人中心
# ============================================================
@app.route("/profile")
@login_required
def profile():
    """个人中心：从 session 获取当前登录用户身份，查询资料"""
    # P0-1/P0-2: 只从 session["user_id"] 获取身份，拒绝 URL 参数
    user_id = session["user_id"]

    # 查询 SQLite 数据库获取用户信息
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    user_row = None
    try:
        c.execute("SELECT id, username, email, phone FROM users WHERE id = ?", (user_id,))
        user_row = c.fetchone()
    except Exception as e:
        print(f"  [SQL ERROR] {e}")
    conn.close()

    if user_row is None:
        return render_template("profile.html", error="未找到该用户", user=None)

    user_data = dict(user_row)

    # 从 USERS 字典补充余额和角色信息
    username = user_data["username"]
    if username in USERS:
        user_data["balance"] = USERS[username].get("balance", 0)
        user_data["role"] = USERS[username].get("role", "user")
    else:
        user_data["balance"] = 0
        user_data["role"] = "user"

    # P1-8: 余额从"分"格式化为"元"显示
    user_data["balance_display"] = format_balance(user_data["balance"])

    return render_template("profile.html", user=user_data, error=None)


@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    """充值：从 session 获取当前用户身份，不信任表单传入的 user_id"""
    # CSRF-02: 充值表单 CSRF 校验
    if not validate_csrf():
        return "CSRF Token 无效或缺失", 400
    # P0-3/P0-4: 只从 session["user_id"] 获取身份，拒绝表单传入的 user_id
    user_id = session["user_id"]
    amount_str = request.form.get("amount", "0")

    # P0-5/P0-6/P1-8: 金额校验（正数、上限、格式），转换为"分"存储
    cents = parse_yuan_to_cents(amount_str)
    if cents is None:
        # 金额格式非法/负数/超上限，重定向到个人中心并携带错误信息
        # 使用 flash 或 URL 参数传递错误
        return redirect(f"/profile?error=invalid_amount")

    # 查询对应的用户名
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    username = None
    try:
        c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if row:
            username = row[0]
    except Exception as e:
        print(f"  [SQL ERROR] {e}")
    conn.close()

    if username and username in USERS:
        # P1-8: 余额以"分"为单位存储（整数）
        USERS[username]["balance"] = USERS[username].get("balance", 0) + cents
        yuan = format_balance(USERS[username]["balance"])
        print(f"  ✅ 用户 {username} 充值 {cents} 分，当前余额 {yuan} 元")

    return redirect(f"/profile")


# ============================================================
# 新增：动态页面加载（page route）— 已修复路径遍历漏洞
# ============================================================
@app.route("/page")
@login_required
def page():
    """动态页面加载：从 URL 参数获取页面名称，安全读取 pages/ 目录下的文件"""
    name = request.args.get("name", "")

    if not name:
        return render_template("index.html", page_content="页面不存在",
                               username=session.get("username"))

    # 修复LFI：限制文件读取只能在 pages/ 目录内
    # Step 1: 获取 pages/ 目录的绝对路径
    base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
    )

    # Step 2: 拼接用户输入后用 os.path.realpath 解析真实路径（去除 ../）
    user_path = os.path.join(base_dir, name)
    real_path = os.path.realpath(user_path)

    # Step 3: 校验解析后的路径必须在 pages/ 目录范围内
    if not real_path.startswith(base_dir):
        content = "页面不存在"
    else:
        content = None
        # 先尝试精确路径
        if os.path.exists(real_path):
            try:
                with open(real_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except:
                content = "页面不存在"
        else:
            # 尝试加上 .html 后缀
            real_path_html = real_path + ".html"
            if os.path.exists(real_path_html):
                try:
                    with open(real_path_html, "r", encoding="utf-8") as f:
                        content = f.read()
                except:
                    content = "页面不存在"
            else:
                content = "页面不存在"

    # XSS-02: 防御性过滤 — 移除 <script> 标签及事件处理器（即使 pages/ 受控）
    if content and content != "页面不存在":
        # 移除 <script>...</script> 块
        content = re.sub(r'<script[^>]*>.*?</script>', '', content, flags=re.DOTALL | re.IGNORECASE)
        # 移除 on* 事件处理器属性（onclick, onload, onerror 等）
        content = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', content, flags=re.IGNORECASE)
        # 移除 javascript: 伪协议链接
        content = re.sub(r'javascript\s*:\s*', '', content, flags=re.IGNORECASE)

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = dict(USERS[username])
        user_info["balance_display"] = format_balance(user_info["balance"])

    return render_template("index.html", page_content=content,
                           username=username, user=user_info)


# ============================================================
# 新增：修改密码
# ============================================================
@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """修改密码：从表单接收 username 和 new_password，直接更新（不验证原密码）"""
    # CSRF-01: 修改密码表单 CSRF 校验
    if not validate_csrf():
        return "CSRF Token 无效或缺失", 400
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")

    if not username or not new_password:
        return redirect("/profile?error=password_empty")

    # 使用 werkzeug.security 哈希后存储
    hashed_password = generate_password_hash(new_password)

    # 更新 SQLite 数据库中的密码
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("UPDATE users SET password = ? WHERE username = ?",
                  (hashed_password, username))
        conn.commit()
        affected = c.rowcount
        print(f"  🔐 用户 {username} 密码已修改（影响 {affected} 行）")
    except Exception as e:
        print(f"  [SQL ERROR] {e}")
    conn.close()

    # 如果该用户在 USERS 字典中存在且密码哈希文件有记录，一同更新
    if username in USERS:
        try:
            hashes = load_password_hashes()
            if username in hashes:
                hashes[username] = hashed_password
                with open(PASSWD_FILE, "w") as f:
                    json.dump(hashes, f, indent=2)
                print(f"  🔐 用户 {username} 密码哈希文件已同步更新")
        except Exception as e:
            print(f"  [同步密码文件失败] {e}")

    return redirect("/profile")


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
