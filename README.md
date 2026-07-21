# 用户信息管理平台

一个基于 Python Flask 的简易用户管理 Web 系统，支持登录、注册、用户搜索功能。

## 项目结构

```
Class01-User-Management-Login-System/
├── app.py                  # Flask 主程序
├── templates/
│   ├── base.html           # 基础模板
│   ├── index.html          # 首页（用户信息 + 搜索）
│   ├── login.html          # 登录页
│   ├── register.html       # 注册页
│   └── upload.html         # 头像上传页
├── static/
│   ├── css/
│   │   └── style.css           # 样式文件
│   └── uploads/                # 上传文件目录
├── data/
│   └── users.db            # SQLite 数据库（自动生成）
└── README.md               # 本文件
```

## 快速启动

```bash
pip install flask werkzeug
python app.py
```

访问 http://localhost:5000

**默认账号：**
- admin / admin123（管理员）
- alice / alice2025（普通用户）

---

## 版本历史

### v2.3 — 文件上传安全加固

**修复漏洞：**

| 漏洞 | 描述 | 修复方式 |
|------|------|----------|
| 路径穿越攻击 | 文件名含 ../ 可写入上级目录 | 过滤 ../ 和 / 开头路径 |
| 可执行文件上传 | 可上传 .php/.py/.exe 等脚本 | 后缀白名单仅允许图片格式 |
| MIME 类型伪造 | Content-Type 可随意伪造 | 校验 Content-Type 字段 |
| 图片马/隐藏代码 | 非图片内容伪装为图片后缀 | 读取文件头魔数验证真实类型 |
| 文件名冲突覆盖 | 同名文件互相覆盖 | UUID+时间戳重命名 |

**修改文件：** app.py, .gitignore, templates/upload.html, README.md

---

### v2.2 — 新增头像上传功能

**新增功能：**
- 用户头像上传（/upload），支持任意类型文件上传
- 上传最大限制 16MB，保存原始文件名
- 首页和导航栏添加上传入口

**修改文件：** app.py, templates/upload.html（新增）, templates/base.html, templates/index.html, README.md

---

### v2.1 — SQL 注入修复 + 注册搜索功能

**新增功能：**
- 用户注册（/register），注册后跳转登录页
- 用户搜索（首页搜索框 + /search API），按用户名或邮箱模糊查询

**修复漏洞：**

| 漏洞 | 描述 | 修复方式 |
|------|------|----------|
| SQL 注入 | 注册和搜索中 f-string 拼接 SQL，用户输入未过滤 | 改用参数化查询 `?` 占位符 |
| SQL 注入 | 搜索功能有回显，UNION 注入可获取任意数据 | 同上 |

**POC 测试结果：**

| 注入方式 | 修复前 | 修复后 |
|----------|--------|--------|
| `' UNION SELECT 1,'inj',...` | 返回自定义数据 | 无搜索结果 |
| `' OR '1'='1` | 返回所有用户 | 无搜索结果 |
| 注册注入 `hacker',+'pass'...` | SQL 被篡改 | 字符串原样存储 |

**修改文件：** app.py, templates/register.html（新增）, templates/index.html, templates/base.html, templates/login.html, static/css/style.css

---

### v2.0 — 安全加固（防暴力破解）

**修复漏洞：**

| 漏洞 | 等级 | 修复方式 |
|------|------|----------|
| 明文密码存储 | 高危 | PBKDF2+SHA256 哈希存储 |
| 无 CSRF 防护 | 高危 | 一次性 Token + compare_digest |
| 暴力破解无防护 | 高危 | 四层防护：IP限流 / 账户锁定 / 指数退避 / 用户枚举防护 |
| 密码前端明文展示 | 中危 | 改为显示 `******` |
| HTML注释泄露账号 | 中危 | 注释中移除明文密码 |
| SECRET_KEY 硬编码 | 中危 | secrets.token_hex(32) 随机生成 |

**防护参数：**

| 防护层 | 参数 |
|--------|------|
| IP 限流 | 每分钟每个 IP 最多 10 次请求 |
| 账户锁定 | 连续 5 次失败锁定 15 分钟 |
| 指数退避 | 1s → 2s → 4s → ... → 30s（上限） |
| 用户枚举防护 | 统一错误"用户名或密码错误" |

**修改文件：** app.py（重写）, templates/login.html, templates/index.html, VULN_REPORT.md（新增）

---

### v1.0 — 初始版本

基础登录功能，密码明文存储，无任何安全防护。

---

## 漏洞修复记录

| 版本 | 修复人 | 修复内容 |
|------|--------|----------|
| v2.3 | 曾思填 | 文件上传安全加固5项 |
| v2.2 | 曾思填 | 新增头像上传功能 |
| v2.1 | 曾思填 | SQL注入修复，新增注册/搜索 |
| v2.0 | 曾思填 | 密码哈希/CSRF/暴力破解防护/密码隐藏/SECRET_KEY加固 |
| v1.0 | - | 初始版本 |

