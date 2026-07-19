# 用户信息管理平台

基于 Python Flask 构建的轻量级用户管理系统，包含用户登录、信息展示等功能，已做完整安全加固。

## 项目结构

```
/opt/Class01/
├── app.py                  # Flask 主应用（安全加固版）
├── users_passwd.json       # 独立密码文件（scrypt 加盐哈希，不存储明文）
├── cert.pem                # HTTPS 自签证书
├── key.pem                 # HTTPS 私钥
├── README.md               # 本文件
├── hunter_search.py        # 鹰图 Hunter 资产搜索工具（独立工具）
├── hunter_results/         # 鹰图搜索结果保存目录
│   └── example.json
├── templates/
│   ├── base.html           # 基础模板（导航栏 + 渐变背景）
│   ├── index.html          # 首页（用户信息展示，密码脱敏）
│   └── login.html          # 登录页
└── static/css/
    └── style.css           # 全局样式
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
cd /opt/Class01
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

| 用户名 | 密码 | 角色 | 邮箱 | 余额 |
|--------|------|------|------|------|
| `admin` | `r4rb0Ld6lx80mORj` | admin 管理员 | admin@example.com | 99999 |
| `alice` | `slAK61I4SHUHlB6a` | user 普通用户 | alice@example.com | 100 |

## 页面功能

### 登录页 (`/login`)
- 卡片式登录表单，支持用户名/密码输入
- 登录失败时显示错误提示
- 登录成功跳转至首页展示用户信息

### 首页 (`/`)
- **已登录**：显示欢迎语及用户的完整信息（用户名、密码掩码、邮箱、手机、角色、余额）
- **未登录**：显示"请先登录"及跳转按钮

## 安全特性

### 🔐 密码存储 — bcrypt/scrypt 加盐哈希

密码以 **scrypt 加盐哈希** 形式存储在独立的 `users_passwd.json` 文件中：

```json
{
  "admin": "scrypt:32768:8:1$...",
  "alice": "scrypt:32768:8:1$..."
}
```

- `USERS` 字典中 **不包含密码字段**
- 使用 Werkzeug `generate_password_hash` / `check_password_hash` 管理
- 绝不存储或传输明文密码

### 🎭 前端密码脱敏

- 模板中密码字段显示为 `******` 掩码
- 所有 HTML 响应中均不输出原始密码

### 🚫 登录防爆破限流

| 策略 | 说明 |
|------|------|
| 最大失败次数 | 连续 **5 次** 密码错误 |
| 锁定时长 | **15 分钟** 内不可登录 |
| 锁定粒度 | **IP + 用户名** 组合锁定 |
| 提示信息 | 每次错误提示剩余尝试次数 |

### 🔒 HTTPS 强制跳转

- 非 HTTPS 请求自动 **301 重定向** 到 HTTPS
- 使用自签证书加密传输

### 🔑 随机 Secret Key

- 每次启动使用 `secrets.token_hex(32)` 生成 64 位随机密钥
- 不硬编码固定密钥

### 🛡️ 其他安全加固

- `debug=False` — 关闭 Flask 调试模式
- 密码强度校验（长度 ≥8、大写字母、小写字母、数字）
- 登录页面 HTML 源码无调试注释泄露

## API 路由

| 路由 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页，根据 session 显示用户信息或登录提示 |
| `/login` | GET | 显示登录表单 |
| `/login` | POST | 提交登录凭据（表单：`username`, `password`） |
| `/logout` | GET | 清除 session 并重定向到首页 |

## 安全演示 — 改造前后对比

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

## 附：鹰图 Hunter 资产搜索工具

项目中还包含 `hunter_search.py`，用于通过奇安信鹰图 (hunter.qianxin.com) API 搜索互联网资产。

```bash
# 需先配置 API Key
python3 hunter_search.py --search 'port=8080'

# 查看帮助
python3 hunter_search.py --help
```

详见脚本内置帮助文档。
