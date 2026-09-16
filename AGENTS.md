# AGENTS.md — auth-server（认证中心 / SSO）

> 维护本仓库前先读本文件。README.md 是面向用户的介绍；冲突时以本文件为准。

## 这个项目是什么

自建统一认证中心（HomeAuth）。整个自托管全家桶的登录入口：

- **TOTP 动态码登录**（无账号、无静态密码；30 秒一变，±1 步容忍）
- **Redis 滑动过期会话**（默认 7 天不登录自动失效）
- **中心化 token 验证**（`/api/verify`）—— 子站通过 nginx `auth_request` 探针接入，后端零鉴权代码
- 登录设备会话管理（列表 / 改名 / 踢下线）+ 来源 GeoIP
- TOTP **两阶段重置**（pending secret 验证通过才转正，永远不会把已登录的人锁在外面）
- 按 IP 阶梯限速防爆破

监听 `127.0.0.1:3200`（systemd `auth-server.service`），对外域名 `auth.example.com`。

## 技术栈

- Node 24 + Express 4，**CommonJS 单文件**
- Redis（`127.0.0.1:6379`）—— 会话唯一存储
- `lib/totp-auth/`：零依赖自研模块（`index.js` 工厂 + `lib/totp.js` / `lib/rate-limit.js` / `lib/jwt.js`）
- 无数据库、无构建步骤

> `lib/totp-auth` 同时以软链方式暴露给 `../admin-server`（`file:../totp-auth`）。**改这个目录会同时影响认证中心和 admin-server**，改前全局搜引用。

## 目录结构

```
src/index.js          # 登录页 + 全部路由（单文件）
lib/totp-auth/        # TOTP 模块：生成/验证/限速/JWT
├── index.js          # createTotpAuth() 工厂（含 auth.router 内置路由）
└── lib/{totp,rate-limit,jwt}.js
public/index.html     # 登录页静态资源
totp-secret.json      # TOTP 正式 secret（本地，不入库）
totp-pending.json     # 重置中的 pending secret（本地，不入库）
jwt-secret            # JWT 密钥（本地，不入库）
```

## 命令

```bash
npm install
node src/index.js           # 监听 3200
systemctl restart auth-server
journalctl -u auth-server -n 100 --no-pager
```

无测试、无 lint、无构建。

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/auth` | 无 | 登录页（`?redirect=` 登录后回跳） |
| POST | `/api/login` | 无 | `{code}` → 验 TOTP → 签发 token 存 Redis |
| GET | `/api/verify` | 无 | `?token=` 或 Bearer → 验证 + 刷新 TTL，通过返回 `X-Auth-User` |
| POST | `/api/logout` | 无 | `{token}` → 删会话 |
| POST | `/api/totp/setup` | 无（仅首启） | 生成 secret，返回 `{secret, otpauthUri}` |
| POST | `/api/totp/reset` | Bearer | 两阶段①：生成 pending secret（5 分钟），不覆盖正式 |
| POST | `/api/totp/confirm` | Bearer | 两阶段②：用 pending 验证，通过才转正 |
| GET | `/api/sessions` | Bearer | 登录设备会话列表 |
| PUT | `/api/sessions/:id/name` | Bearer | 重命名会话 |
| DELETE | `/api/sessions/:id` | Bearer | 踢下线 |

## 路由注册顺序（有坑，别乱动）

```
POST /api/login   ← 自定义实现必须注册在 app.use('/api', auth.router) 之前
app.use('/api/totp', auth.router)
app.use('/api', auth.router)   ← 模块内置 JWT login，会覆盖同路径
/api/verify /api/logout /api/sessions…
```

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `3200` / `127.0.0.1` | systemd 显式设置 |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | 会话存储 |
| `SESSION_DAYS` | `7` | 会话滑动过期天数 |
| `JWT_SECRET` | 读 `jwt-secret` 文件 | 签发密钥 |
| `AUTH_GEOIP_URL` | `https://ipwho.is/{ip}?fields=success,country,region,city` | 登录来源解析 |

## 安全红线

- TOTP secret、pending secret、JWT 密钥**一律不入库**，已被 `.gitignore` 拦截。
- 两阶段重置语义不能简化成「直接覆盖」——否则用户一旦绑错设备就永久锁死。
- 限速必须**按真实客户端 IP**（阶梯 60s → 300s → 900s）；nginx 侧要把 `X-Real-IP` 传进来。
- 不要把 `auth.example.com`、服务器 IP 等私有地址写进任何源代码（前端跳转地址由调用方带 `redirect` 参数传入）。

## 已知坑

- **`/auth-check` 探针的 query token 会丢**：nginx `auth_request` 子请求默认不带原始 query，主域配置里已手动把父请求 args 拼回（见 `homepage.conf` 的 `/auth-check` 块）。别的域名接探针时要照抄这段，否则 `?token=` 场景全部 401。
- `proxy_method GET` + 清空 `Content-Length`/`Content-Type` 是必须的：否则带 body 的 PUT/POST 会被探针挂起直到 504。
- Redis 挂了等于全站登不上；排查顺序：`systemctl status redis-server` → `redis-cli ping`。
- 单文件无热重载，改完必须重启。

## 项目记忆（PROJECT_MEMORY.md）

**分工**：`AGENTS.md` 记**规则**（稳定、必须遵守）；`PROJECT_MEMORY.md` 记**记忆**（可演进、随事实更新）。
两者冲突时以 `AGENTS.md` 为准；只有经用户明确确认、且长期稳定的规则，才由用户决定升级进 `AGENTS.md`。
`PROJECT_MEMORY.md` 已被 `.gitignore` 拦截：**只存本机，不提交、不推送**。

### 什么时候写

- 读完代码 / 查完日志后，**确认了可复用、长期有效**的结论：API 契约与参数语义、数据模型与单位、踩坑的根因、
  产品与 UI 习惯、历史 bug 的判据（"见到 X 现象就查 Y"）。
- **任务收尾时必须回写**：本次确认了什么、推翻了什么、遗留了什么（写清复核条件）。
- **不要写**：临时猜测、单次偶发现象、未经验证的产品判断、敏感信息（密钥 / token / 口令 / 私有地址）、
  与项目无关的个人偏好、以及从代码一眼可见的常识。

### 每条记忆的字段（缺一不可）

```md
### YYYY-MM-DD · 主题（一句话）
- **结论**：一句话说清（可执行、可判断真假）。
- **适用范围**：哪个模块 / 接口 / 页面；**不适用**的情况也要写。
- **证据**：`路径:行号` / commit / 实测输出摘要（附可复现命令）。
- **复核条件**：什么情况下这条会失效（如"升级 Flutter 大版本后重测"）。
- **最后复核**：YYYY-MM-DD
```

### 迭代规则

1. **先查后写**：任务开始时按关键词（模块名 / 接口名 / 报错文本 / 表名）检索本文件；命中就按结论行事，
   并**把该条的「最后复核」更新为今天**（同一次任务只更新一次，不要刷日期）。
2. **更新优先于新增**：主题已有条目 → 就地改写（结论变了要写"曾认为 X，实测为 Y"），**不要追加重复条目**。
3. **失效即删**：结论被推翻、或复核条件已命中（代码已改 / 版本已升）→ 直接删掉或改写，不留"已废弃"堆积。
4. **合并同类**：同一模块超过 3 条相关记忆 → 合并成一节，只保留最新结论 + 关键证据。

### 容量与清理（硬约束）

- 文件上限 **200 行 / 12 KB**（以 `wc -c` 为准）。超限时按以下优先级淘汰：
  ① 已被代码或配置取代的（先删）→ ② 「最后复核」最久远的 → ③ 证据最弱的（只有结论、没有出处）。
- 单条记忆 **≤ 15 行**；细节过长就把细节留在代码注释 / `references/` 里，本文件只留结论与指针。
- **每次写入后顺手清理一次**（行数、体积、重复项、失效项），保证文件始终处于上限内。
- 清理若删掉仍有价值的内容，必须在提交说明或对话里说明，**不要静默丢弃**。

### 写法

- 读者是**下一个接手这个仓库的人**：用最短的句子、最强的证据，先写结论再写理由。
- 结论要能被证伪：写"接口 X 的 `:id` 是数据库数字 id（`WHERE id = ?`）"，不要写"注意 id 类型"。
- 需要跨文件的长篇背景（架构选型、迁移过程）放 `references/` 或项目文档，这里只留一行指针。
