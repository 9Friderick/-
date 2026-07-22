# 用户信息管理平台

基于 Python Flask 构建的轻量级用户管理系统，包含登录、注册、搜索、头像上传、个人中心、充值等功能，已做完整安全加固。

## 项目结构

```
/opt/Classes/Class01/
├── app.py                          # Flask 主应用（安全加固版 V2）
├── users_passwd.json               # 独立密码文件（遗留的 scrypt 哈希，兼容登录）
├── cert.pem                        # HTTPS 自签证书
├── key.pem                         # HTTPS 私钥
├── README.md                       # 本文件
├── hunter_search.py                # 鹰图 Hunter 资产搜索工具（独立工具）
├── hunter_results/                 # 鹰图搜索结果保存目录
│   └── example.json
├── day5-越权访问漏洞和业务逻辑漏洞修复报告.docx  # 第5轮安全修复报告
├── data/
│   └── users.db                    # SQLite 数据库（用户信息、密码哈希）
├── static/
│   ├── css/
│   │   └── style.css               # 全局样式
│   └── uploads/                    # 用户头像上传目录
├── templates/
│   ├── base.html                   # 基础模板（导航栏 + 渐变背景）
│   ├── index.html                  # 首页（用户信息展示、搜索）
│   ├── login.html                  # 登录页
│   ├── register.html               # 注册页
│   ├── profile.html                # 个人中心（含充值表单）
│   └── upload.html                 # 头像上传页
```

## 环境要求

| 依赖 | 说明 |
|------|------|
| Python | 3.8+ |
| Flask | Web 框架 |
| Werkzeug | 密码哈希（Flask 内置依赖） |

```bash
pip install flask
```

## 快速启动

```bash
cd /opt/Classes/Class01
python3 app.py
```

启动成功后输出：

```
🔒 HTTPS 模式启动
 * Running on https://0.0.0.0:5000
 * Running on https://192.168.228.128:5000
```

**⚠️ 注意事项：**
- 项目使用自签证书，浏览器首次访问会提示"不安全"，点击 **高级 → 继续前往** 即可
- 服务监听 `0.0.0.0:5000`，同局域网内其他设备可通过 `https://<本机IP>:5000` 访问

## 测试账号

| 用户名 | 密码 | 角色 | 邮箱 | 初始余额 |
|--------|------|------|------|----------|
| `admin` | `admin123` | admin 管理员 | admin@example.com | ¥99999.00 |
| `alice` | `alice2025` | user 普通用户 | alice@example.com | ¥100.00 |

> 🔐 密码通过 `werkzeug.security.generate_password_hash` 使用 **scrypt 加盐哈希** 存储在 SQLite 数据库中。

## 页面功能

### 登录页 (`/login`)
- 卡片式登录表单，支持用户名/密码输入
- **安全加固**：登录失败统一提示"用户名或密码错误"，不区分具体原因（防用户名枚举）
- 连续 5 次失败锁定 15 分钟（IP + 用户名组合粒度）
- 登录成功后进入首页

### 注册页 (`/register`)
- 新用户注册表单（用户名、密码、邮箱、手机）
- 密码强度校验：长度 ≥8、含大写字母、小写字母、数字
- 密码使用 `generate_password_hash` 哈希后存储，杜绝明文

### 首页 (`/`)
- **已登录**：显示欢迎语及用户的完整信息（用户名、密码掩码、邮箱、手机、角色、余额）
- **未登录**：显示"请先登录"及跳转按钮
- 搜索功能：按用户名或邮箱搜索（仅登录用户可用）

### 个人中心 (`/profile`)
- **需登录**，仅查看当前登录用户资料
- 显示用户 ID、用户名、邮箱、手机、角色、余额
- 充值表单：输入金额充值到当前登录账号（单笔上限 ¥10,000）

### 头像上传 (`/upload`)
- 支持上传头像图片（jpg/png/gif/bmp/webp/svg）
- 5 层安全防御：扩展名白名单、文件大小限制、UUID 重命名、真实文件头检测、移除可执行权限

## API 路由

| 路由 | 方法 | 登录校验 | 说明 |
|------|------|----------|------|
| `/` | GET | 否 | 首页，根据 session 显示用户信息或登录提示 |
| `/login` | GET | 否 | 显示登录表单 |
| `/login` | POST | 否 | 提交登录凭据（表单：`username`, `password`） |
| `/logout` | GET | 否 | 清除 session 并重定向到首页 |
| `/register` | GET | 否 | 显示注册表单 |
| `/register` | POST | 否 | 提交注册信息（表单：`username`, `password`, `email`, `phone`） |
| `/search` | GET | ✅ 是 | 按用户名/邮箱搜索用户（参数：`keyword`） |
| `/profile` | GET | ✅ 是 | 个人中心，显示当前登录用户资料（身份从 session 获取） |
| `/recharge` | POST | ✅ 是 | 充值（表单：`amount`），身份从 session 获取 |
| `/upload` | GET | ✅ 是 | 显示上传表单 |
| `/upload` | POST | ✅ 是 | 处理头像文件上传 |

## 安全特性

### 🔐 密码存储 — bcrypt/scrypt 加盐哈希

- SQLite 数据库 `users` 表中密码字段使用 `werkzeug.security.generate_password_hash` 存储
- 旧版 `users_passwd.json` 中的 scrypt 哈希仍可兼容登录
- **绝不存储或传输明文密码**
- 登录时自动检测并升级遗留明文密码为哈希

### 🎭 前端密码脱敏

- 模板中密码字段显示为 `******` 掩码
- 所有 HTML 响应中均不输出原始密码

### 🚫 登录防爆破限流

| 策略 | 说明 |
|------|------|
| 最大失败次数 | 连续 **5 次** 密码错误 |
| 锁定时长 | **15 分钟** 内不可登录 |
| 锁定粒度 | **IP + 用户名** 组合锁定 |
| 提示信息 | 统一提示"用户名或密码错误"（防枚举） |

### 🔒 HTTPS 强制跳转

- 非 HTTPS 请求自动 **301 重定向** 到 HTTPS
- 使用自签证书加密传输

### 🔑 随机 Secret Key

- 每次启动使用 `secrets.token_hex(32)` 生成 64 位随机密钥
- 不硬编码固定密钥

### 🛡️ 越权访问防护（V2 新增）

| 防护措施 | 说明 |
|----------|------|
| `@login_required` 装饰器 | 拦截所有未登录请求，重定向到登录页 |
| session 身份来源 | 所有接口从 `session["user_id"]` 获取身份，拒绝 URL 参数和表单隐藏字段 |
| 用户隔离 | 普通用户无法通过修改 URL/表单参数访问或充值其他用户账号 |

### 💰 充值安全校验（V2 新增）

| 校验项 | 说明 |
|--------|------|
| 正数校验 | 充值金额必须 > 0，拒绝负数/零 |
| 上限校验 | 单笔充值上限 ¥10,000 |
| 格式校验 | 拒绝 `inf`、`nan` 等特殊浮点值 |
| 精度保护 | 余额以整数"分"存储，展示时格式化为"元"（保留两位小数） |

### 🛡️ 其他安全加固

- `debug=False` — 关闭 Flask 调试模式
- 密码强度校验（长度 ≥8、大写字母、小写字母、数字）
- 全站参数化 SQL 查询（防 SQL 注入）
- 头像上传 5 层防御（扩展名白名单、大小限制、UUID 重命名、真实文件头检测、移除可执行权限）

## API 路由（详细参数）

### 登录
```bash
curl -k -X POST https://localhost:5000/login \
  -d "username=admin&password=admin123"
```

### 注册
```bash
curl -k -X POST https://localhost:5000/register \
  -d "username=newuser&password=MyPass123&email=new@test.com&phone=13800000000"
```

### 搜索（需登录）
```bash
curl -k -b "cookies.txt" "https://localhost:5000/search?keyword=admin"
```

### 查看个人中心（需登录）
```bash
curl -k -b "cookies.txt" https://localhost:5000/profile
```

### 充值（需登录）
```bash
curl -k -b "cookies.txt" -X POST https://localhost:5000/recharge \
  -d "amount=100.50"
```

### 上传头像（需登录）
```bash
curl -k -b "cookies.txt" -X POST https://localhost:5000/upload \
  -F "file=@avatar.jpg"
```

## 安全加固历程

### 第1轮：基础安全加固
| 项目 | 改造前 | 改造后 |
|------|--------|--------|
| 密码存储 | 明文在 `USERS` 字典 | 独立文件 `users_passwd.json`，scrypt 加盐哈希 |
| 前端密码 | `{{ user.password }}` 明文显示 | `******` 掩码 |
| 调试信息 | HTML 注释泄露 `admin:admin123` | 已删除 |
| 密码强度 | 无校验 | ≥8位 + 大小写 + 数字 |
| 登录限流 | 无限制 | 5次错误锁定15分钟 |
| 传输加密 | HTTP | HTTPS 强制跳转 |
| debug 模式 | `True` | `False` |
| secret_key | 硬编码 `"dev-key-2025"` | `secrets.token_hex(32)` 随机生成 |

### 第2轮：越权访问与业务逻辑漏洞修复（Day5）

| 漏洞类别 | 漏洞数 | 修复策略 |
|----------|--------|----------|
| 越权访问（P0） | 4 条 | `@login_required` 装饰器 + session 身份来源治理 |
| 业务逻辑/数据安全（P0） | 3 条 | 金额正数/上限校验 + 密码哈希存储 |
| 信息泄露/精度（P1） | 2 条 | 搜索加登录校验 + 整数分存储余额 |
| 低危（P2） | 2 条 | 统一登录错误消息 + 导航栏去参 |

详见 `day5-越权访问漏洞和业务逻辑漏洞修复报告.docx`

## 附：鹰图 Hunter 资产搜索工具

项目中还包含 `hunter_search.py`，用于通过奇安信鹰图 (hunter.qianxin.com) API 搜索互联网资产。

```bash
# 需先配置 API Key
python3 hunter_search.py --search 'port=8080'

# 查看帮助
python3 hunter_search.py --help
```

详见脚本内置帮助文档。
