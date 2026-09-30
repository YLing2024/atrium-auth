# AGENTS.md — auth-server（认证中心 / SSO）

> 维护本仓库前先读本文件。README.md 是面向用户的介绍；冲突时以本文件为准。

## 这个项目是什么

自建统一认证中心（SSO / OIDC Provider）。整个自托管全家桶的登录入口：

- **TOTP 动态码登录**（无账号、无静态密码；30 秒一变，±1 步容忍）
- **Redis 滑动过期会话**（默认 7 天不登录自动失效）
- **业务站由 Auth Gateway 统一接管登录态**（Go 单二进制，`127.0.0.1:18920`）：网关走 OIDC（`/authorize` `/token` `/userinfo`）判断登录、维护站点 cookie、向后端注入 `X-Auth-User`；业务项目零鉴权代码。
  `GET /api/verify` 仍保留，但**已不是主路径**，仅供旧探针 / 兼容场景使用。
- 登录设备会话管理（列表 / 改名 / 踢下线）+ 来源 GeoIP
- TOTP **两阶段重置**（pending secret 验证通过才转正，永远不会把已登录的人锁在外面）
- 按 IP 阶梯限速防爆破

监听 `127.0.0.1:3200`（systemd `auth-server.service`）；对外域名由部署决定，不写进仓库。

## 技术栈

- Node 24 + Express 4，**CommonJS 单文件**
- Redis（`127.0.0.1:6379`）—— 会话唯一存储
- `lib/totp-auth/`：零依赖自研模块，**保持 JS 不迁移**（被 admin-server 以 `file:` 依赖共用）：`index.js` 工厂 + `lib/totp.js` / `lib/rate-limit.js` / `lib/jwt.js`，另配手写 `index.d.ts` / `lib/totp.d.ts` / `lib/rate-limit.d.ts` 供 TS 侧引用
- 无数据库、无构建步骤

> `lib/totp-auth` 同时以软链方式暴露给 `../admin-server`（`file:../totp-auth`）。**改这个目录会同时影响认证中心和 admin-server**，改前全局搜引用。

## 目录结构

```
src/index.ts          # 登录页 + 全部路由（单文件）
src/oidc/             # OIDC Provider：discovery/authorize/token/userinfo/jwks/introspect/end_session/revoke
├── index.ts          # createOidcProvider() 工厂（挂到 app 根路径）
├── keys.ts           # ES256 密钥库（oidc-keys.json / JWKS / kid=thumbprint）
├── clients.ts        # 客户端注册表（clients.json / redirect_uri 精确匹配）
└── util.ts           # base64url / PKCE S256 / cookie / 哈希
lib/totp-auth/        # TOTP 模块：生成/验证/限速/JWT
├── index.js          # createTotpAuth() 工厂（含 auth.router 内置路由）
└── lib/{totp,rate-limit,jwt}.js
public/index.html     # 登录页静态资源
clients.json          # OIDC 客户端注册表（本地，不入库）
clients.example.json  # 注册表占位示例（入库）
oidc-keys.json        # OIDC ES256 私钥（本地，不入库）
totp-secret.json      # TOTP 正式 secret（本地，不入库）
totp-pending.json     # 重置中的 pending secret（本地，不入库）
jwt-secret            # JWT 密钥（本地，不入库）
```

## 命令

```bash
npm install
node src/index.ts           # 监听 3200
systemctl restart auth-server
journalctl -u auth-server -n 100 --no-pager
```

无测试、无 lint、无构建。

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/auth` | 无 | 登录页（`?redirect=` 登录后回跳） |
| POST | `/api/login` | 无 | `{code}` → 验 TOTP → 签发 token 存 Redis |
| GET | `/api/verify` | 无 | **兼容保留**（网关走 `/_auth/*` 与 OIDC 端点，不再走探针）：`?token=` / `X-Auth-Token` / Bearer → 会话令牌**或首方 SSO 令牌**验证 + 刷新 TTL，通过返回 `X-Auth-User`（= `SSO_SUBJECT`） |
| POST | `/api/logout` | 无 | `{token}` → 删会话 |
| POST | `/api/totp/setup` | 无（仅首启） | 生成 secret，返回 `{secret, otpauthUri}` |
| POST | `/api/totp/reset` | Bearer | 两阶段①：生成 pending secret（5 分钟），不覆盖正式 |
| POST | `/api/totp/confirm` | Bearer | 两阶段②：用 pending 验证，通过才转正 |
| GET | `/api/sessions` | Bearer | 登录设备会话列表 |
| PUT | `/api/sessions/:id/name` | Bearer | 重命名会话 |
| DELETE | `/api/sessions/:id` | Bearer | 踢下线 |
| GET | `/api/internal/sessions?sub=` | `X-Internal-Token` | **内部**：按 `sub` 定位用户的设备会话列表（结构同 `/api/sessions`），供本机服务调用 |
| PUT | `/api/internal/sessions/:id/name` | `X-Internal-Token` | **内部**：重命名会话 |
| DELETE | `/api/internal/sessions/:id` | `X-Internal-Token` | **内部**：踢下线 |
| POST | `/api/internal/totp/reset?sub=` | `X-Internal-Token` | **内部**：两阶段重置①，与 `/api/totp/reset` **共用同一实现**，结构一致 |
| POST | `/api/internal/totp/confirm?sub=` | `X-Internal-Token` | **内部**：两阶段重置② body `{code}`，与 `/api/totp/confirm` **共用同一实现** |

> `/api/internal/*` 只认共享内部令牌（`X-Internal-Token`），**不走 `requireSession`**：任何客户端凭证（cookie / Bearer JWT / 会话 token）都无效。
> 令牌首次启动自动生成到 `INTERNAL_TOKEN_FILE`（默认 `<DATA_DIR>/internal-token`，0600），值绝不打印、不返回。
> **两阶段重置红线**：`reset` 只写 pending、绝不覆盖正式 secret；`confirm` 必须 pending 验证码通过才转正。
> 对外与内部端点共用 `performTotpReset` / `performTotpConfirm`，**禁止复刻实现**（防止语义分叉）。
> 内部端点 `sub` 必须等于本实例 `SSO_SUBJECT`：缺 `sub`→400、非本实例用户→404。

OIDC（根路径，issuer 取 `ISSUER` 环境变量）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/authorize` | 授权端点（PKCE S256；redirect_uri 精确匹配） |
| POST | `/token` | code / refresh（refresh 轮换+重放整链作废）；access_token 为 **ES256 JWT** |
| GET | `/userinfo` | Bearer access_token（支持 JWT 与旧式不透明串） |
| GET | `/jwks.json` | ES256 公钥集 |
| POST | `/introspect` | RFC 7662（也接受 Bearer） |
| GET/POST | `/end_session` | RP-Initiated Logout（回跳白名单） |
| POST | `/revoke` | RFC 7009 |
| GET | `/auth` | 登录页（`?redirect=` 旧流程 + 白名单 + Deprecated） |

## 路由注册顺序（有坑，别乱动）

```
POST /api/totp/reset|confirm   ← 自定义实现必须在 app.use('/api/totp', auth.router) 之前
POST /api/login   ← 自定义实现必须注册在 app.use('/api', auth.router) 之前
app.use('/api/totp', auth.router)
app.use('/api', auth.router)   ← 模块内置 JWT login，会覆盖同路径
/api/verify /api/logout /api/sessions…
app.use(oidc.router)           ← OIDC 路由挂根路径（/authorize /token ...），最后挂
```

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `3200` / `127.0.0.1` | systemd 显式设置 |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | 会话存储 |
| `REDIS_DB` | `0` | Redis 库号（测试实例用 15 隔离） |
| `DATA_DIR` | 项目根 | 密钥 / 注册表所在目录（totp-secret、jwt-secret、oidc-keys.json、clients.json） |
| `ISSUER` | `http://127.0.0.1:3200` | OIDC issuer，所有端点 URL 由它拼接；**不得硬编码真实域名** |
| `SSO_SUBJECT` | `linden` | 用户稳定唯一标识：`sub` / `preferred_username` / `X-Auth-User`。与 `ISSUER` 无关 |
| `SSO_DISPLAY_NAME` | = `SSO_SUBJECT` | 展示名：OIDC `name`（id_token / userinfo） |
| `SESSION_DAYS` | `7` | 会话滑动过期天数 |
| `JWT_SECRET` | 读 `jwt-secret` 文件 | 签发密钥 |
| `INTERNAL_TOKEN_FILE` | `<DATA_DIR>/internal-token` | 内部接口共享令牌文件（0600 自动生成；`INTERNAL_TOKEN` 可直接覆盖值） |
| `AUTH_GEOIP_URL` | `https://ipwho.is/{ip}?fields=success,country,region,city` | 登录来源解析 |

## 安全红线

- TOTP secret、pending secret、JWT 密钥、`oidc-keys.json`、`clients.json`**一律不入库**，已被 `.gitignore` 拦截。
- 两阶段重置语义不能简化成「直接覆盖」——否则用户一旦绑错设备就永久锁死。
- 限速必须**按真实客户端 IP**（阶梯 60s → 300s → 900s）；nginx 侧要把 `X-Real-IP` 传进来。
- **redirect_uri 必须与注册值字符串精确相等**（不许前缀/通配）——授权端点第一安全边界。
- **id_token 与 access_token 只准 ES256**（P-256，带 `kid`，共用 `oidc-keys.json`）；禁止 HS256。access_token 虽为 JWT，**撤销仍以 Redis 哈希记录为准**（不许"签名有效就永远有效"）；refresh / sso token 只存哈希。
- 身份只有一个来源：`SSO_SUBJECT`（展示名 `SSO_DISPLAY_NAME`）。OIDC 路径与 `/api/verify` 必须给出**完全一致**的身份；历史标签 `HomeAuth` 仅是 cookie 名 / 旧 Redis 值，读取时归一化为 `SSO_SUBJECT`。
- 不要把真实域名、服务器 IP 等私有地址写进任何源代码；OIDC issuer 走 `ISSUER` 环境变量。

## 已知坑

- **nginx `auth_request` 探针 / `/auth-check` 已废弃**：全站登录态由 Auth Gateway 接管（站点 nginx 只做 TLS + 路由，`/_auth/*` 转网关）。不要再新增 `/auth-check` location，也不要再依赖 `?token=` / `X-Auth-Token` 传令牌；`/api/verify` 仅作兼容保留。
- **OIDC 端点挂在根路径**（`/authorize` `/token` `/jwks.json` …），由 Auth Gateway 在服务端（loopback）调用；不需要给业务站 nginx 暴露这些路径。
- **首方客户端（`first_party:true`）不强制 PKCE**：auth-server 自己完成 code→token，code 不落浏览器；普通公开客户端仍强制 S256。
- **首方 SSO 令牌与会话的关联**：`ensureSsoSession` 建的记录含 `session_hash`（来源会话 token 哈希），并写反向索引 `oidc:sso-session:<会话哈希>` → SSO 令牌哈希集合。`/api/logout`、`DELETE /api/sessions/:id`、同设备去重共用 `revokeSession`，会连带删除 `oidc:sso:<哈希>`（登出后共享 cookie 立即失效，不用满 7 天）。改 `revokeSession` 或 `ensureSsoSession` 时必须保持这对关联。
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
