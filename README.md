# 认证中心（SSO / OIDC Provider）

统一认证系统：**TOTP 动态验证码登录 + Redis 滑动过期会话 + 标准 OIDC Provider**。
业务站的登录态由 **Auth Gateway**（独立项目）统一接管：网关走 OIDC 完成登录、维护站点 cookie、
向后端注入 `X-Auth-User`；业务项目零鉴权代码。认证中心本身只管认证与令牌签发/吊销。

> **令牌有效期**（现行）：**access_token：ES256 JWT，TTL 15 分钟**（`ACCESS_TTL_SEC` 可覆盖，下限 60 秒；Bearer 为本地验签，故把吊销后的暴露窗口压到 15 分钟）；refresh_token 30 天且每次续期轮转。

## 架构

```
┌──────────┐  ①请求   ┌───────────────────────────┐
│  浏览器   │ ───────→ │ 站点 nginx（TLS + 路由）    │
└──────────┘          └────────────┬──────────────┘
                                   │ ②全部转 127.0.0.1:18920
                                   ▼
                        ┌──────────────────────────┐
                        │ Auth Gateway（Go 单二进制）│
                        │ 登录态 / cookie / 注入身份  │
                        └──────┬────────────┬───────┘
                   ③OIDC 授权    │            │ ④注入 X-Auth-User
                                ▼            ▼
                    ┌────────────────┐  ┌────────────────┐
                    │ 认证中心 :3200  │  │ 业务项目        │
                    │ TOTP / Redis   │  │ （零鉴权代码）   │
                    └────────────────┘  └────────────────┘
```

## 核心能力

| 功能 | 说明 |
|---|---|
| **TOTP 动态验证码** | 登录凭据 = 6 位动态码（30 秒变化，±1 步容忍），无账号无静态密码 |
| **Redis 滑动过期会话** | token 存 Redis，每次验证刷新 TTL，N 天不登录自动过期（默认 7 天） |
| **标准 OIDC Provider** | `/authorize` `/token` `/userinfo` `/jwks.json` 等标准端点，供 Auth Gateway 接入 |
| **按 IP 阶梯限速** | 5 次失败锁 60s → 300s → 900s（防暴力破解） |
| **统一登录** | 一个登录页管所有站点；登录态由 Auth Gateway 维持，业务站不再各自存 token |

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/auth` | 无 | 登录页（TOTP 验证码输入，`?redirect=` 登录后回跳） |
| POST | `/api/login` | 无 | body `{code}` → 验证 TOTP → 签发 token（存 Redis） |
| GET | `/api/verify` | 无 | **兼容保留**（网关不再走它）：`?token=` / `X-Auth-Token` / Bearer → 验证 + 刷新 TTL，通过返回 `X-Auth-User` header |
| POST | `/api/logout` | 无 | body `{token}` → 删除 Redis 会话 |
| POST | `/api/totp/setup` | 无（仅首启） | 生成 TOTP secret，返回 `{secret, otpauthUri}` |
| POST | `/api/totp/reset` | Bearer（已登录） | **两阶段重置①**：生成新 secret 存 pending（5 分钟），**不覆盖正式**，返回 `{secret, otpauthUri, expiresIn}` |
| POST | `/api/totp/confirm` | Bearer（已登录） | **两阶段重置②**：body `{code}` 用 pending secret 验证 → 通过才转正（旧 secret 作废）；失败/无 pending 丢弃 pending，旧 secret 保持 |
| GET | `/api/internal/sessions?sub=` | `X-Internal-Token` | **内部**（仅本机服务）：按 `sub` 返回设备会话列表，结构同 `/api/sessions` |
| PUT | `/api/internal/sessions/:id/name` | `X-Internal-Token` | **内部**：重命名会话 |
| DELETE | `/api/internal/sessions/:id` | `X-Internal-Token` | **内部**：踢下线 |
| POST | `/api/internal/totp/reset?sub=` | `X-Internal-Token` | **内部**：两阶段重置①，与 `/api/totp/reset` 共用实现、结构一致 |
| POST | `/api/internal/totp/confirm?sub=` | `X-Internal-Token` | **内部**：两阶段重置② body `{code}`，与 `/api/totp/confirm` 共用实现 |

> `/api/internal/*` 是给本机服务（如 admin-server）调用的内部接口：只认共享令牌 `X-Internal-Token`，
> **不接受**任何客户端凭证（cookie / Bearer JWT / 会话 token），也不走 `requireSession`。
> 令牌首次启动自动生成到 `<DATA_DIR>/internal-token`（0600），可用 `INTERNAL_TOKEN_FILE` 指定路径。
> **两阶段重置红线**：`reset` 只写 pending、绝不覆盖正式 secret；`confirm` 必须 pending 验证码通过才转正。
> 对外与内部端点共用 `performTotpReset` / `performTotpConfirm`；内部 `sub` 必须等于本实例 `SSO_SUBJECT`（缺→400，非本实例用户→404）。

## OIDC Provider（标准接入，OAuth 2.1 + OIDC Core 1.0）

TOTP 仍是唯一的用户验证手段；标准只规范流程。issuer 取环境变量 `ISSUER`（默认 `http://127.0.0.1:3200`）。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/authorize` | 授权端点（PKCE S256） |
| POST | `/token` | `authorization_code` / `refresh_token`（refresh 轮换 + 重放整链作废） |
| GET | `/userinfo` | `Authorization: Bearer <access_token>` |
| GET | `/jwks.json` | ES256 公钥集（带 `kid`） |
| POST | `/introspect` | RFC 7662；也接受 `Authorization: Bearer` |
| GET/POST | `/end_session` | RP-Initiated Logout（`post_logout_redirect_uri` 白名单） |
| POST | `/revoke` | RFC 7009 |
| GET | `/auth` | 登录页（`?redirect=` 旧流程保留，白名单 + `Deprecated` 标记） |

- **redirect_uri 精确匹配**：只接受注册表里完全相等的字符串，堵开放重定向 / token 外泄。
- **access_token 也是 ES256 JWT**（claims 含 `iss`/`sub`/`aud`/`exp`/`iat`/`jti`/`sid`/`scope`/`client_id`），任何消费方可本地验签；**撤销仍以本服务的 Redis 记录为准**（`/introspect`、`/revoke` 生效），旧式不透明 token 过期前继续可用。
- **id_token 只用 ES256**（P-256，`kid`=JWK thumbprint）；密钥首次启动生成 `<DATA_DIR>/oidc-keys.json`（0600）。
- **身份取值**：`sub`/`preferred_username` 取 `SSO_SUBJECT`（默认 `linden`），展示名 `name` 取 `SSO_DISPLAY_NAME`（默认同值）；`/api/verify` 的 `X-Auth-User` 与之一致。
- **首方模式**（`"first_party": true`）：auth-server 自己完成 code→token，`Set-Cookie`（HttpOnly/SameSite=Lax/`Domain` 取 `cookie_domain`）后 302 回跳，子站前端零 SSO 代码。
- 客户端注册表：`clients.json`（0600，gitignore），格式见 `clients.example.json`；非法条目（空 redirect_uris / 含 `*` / 非 http(s)）加载时跳过。

> 业务站登录态由 Auth Gateway 接管（站点 nginx 只做 TLS + 路由，`/_auth/*` 转网关）；OIDC 端点在服务端（loopback）被网关调用，不需要给业务站 nginx 暴露。

## TOTP 重置流程（标准两阶段）

```
1. 已登录状态下调 /reset → 生成新 secret（pending，暂不生效）
2. App 扫码绑定新 secret
3. 输入新验证码调 /confirm → 验证通过 → 新 secret 正式生效（旧作废）
   · 验证通过前旧码一直有效（不会锁在外面）
   · 失败/取消 → pending 丢弃，旧 secret 不受影响
```

## 业务站接入（Auth Gateway）

业务项目**零鉴权代码**：登录、TOTP、token、会话全部在网关与认证中心完成。

1. **后端**：从请求头 `X-Auth-User` 读身份（网关注入，会先剥掉客户端伪造的同名头）；头缺失返回 **401**。
2. **前端**：任何 API 返回 401 → 整页跳 `/_auth/login?next=<当前地址>`；不要 `localStorage` 存 token。
3. **站点 nginx**：需要登录的 location `proxy_pass http://127.0.0.1:18920`（网关），不再有
   `auth_request` / `/auth-check` / `?token=`。
4. 站点会话 cookie 为 `__Host-<app>_session`（每个站一份，不跨子域共享）。

> `/api/verify` 与 nginx `auth_request` 探针属**兼容保留**，新接入不要再使用。

## 部署

```bash
npm install
node src/index.js          # 端口 3200
# systemd: auth-server.service（WorkingDirectory=/root/proj/auth-server）
```

依赖：Node.js 20+、Redis（127.0.0.1:6379）。

## 目录结构

```
├── src/index.js            # 认证服务（登录页/签发/验证/登出/TOTP 管理）
├── src/oidc/               # OIDC Provider（新增）
│   ├── index.js            # createOidcProvider()：discovery/authorize/token/... 路由
│   ├── keys.js             # ES256 密钥库（oidc-keys.json / JWKS / 轮换）
│   ├── clients.js          # 客户端注册表（clients.json / 精确 redirect_uri 校验）
│   └── util.js             # base64url / PKCE S256 / cookie / 哈希
├── lib/totp-auth/          # TOTP 子功能模块（生成/验证/限速/JWT，零依赖）
│   ├── index.js            # createTotpAuth() 工厂
│   └── lib/totp.js         # TOTP 算法（HMAC-SHA1/Base32/±1 步）
│       lib/rate-limit.js   # 按 IP 阶梯限速
│       lib/jwt.js          # JWT（HS256，可选）
├── clients.example.json    # 客户端注册表示例
├── totp-secret.json        # TOTP secret（本地保存，不入库）
└── oidc-keys.json          # OIDC ES256 私钥（本地保存，不入库）
```
