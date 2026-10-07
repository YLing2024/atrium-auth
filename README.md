[简体中文](README.md) ｜ [English](README.en.md)

# atrium-auth

自建统一认证中心（OIDC Provider）：一个 TOTP 动态码，管住全家桶所有站点的登录。

## 它能做什么

- **TOTP 动态码登录**：6 位、30 秒变化、±1 步容忍；无账号、无静态密码。
- **Redis 滑动过期会话**：登录 token 存 Redis，每次校验刷新 TTL，默认 7 天不活跃即失效。
- **标准 OIDC Provider**：discovery / authorize / token / userinfo / jwks / introspect / end_session / revoke，支持 PKCE S256。
- **ES256 令牌**：id_token 与 access_token 均为 ES256 JWT（P-256、带 `kid`），公钥由 `/jwks.json` 发布；access_token 默认 15 分钟，refresh_token 30 天且每次续期轮换，重放旧值整条链作废。
- **首方静默 SSO**：标记 `first_party` 的客户端由 auth-server 内部完成 code→token 交换，只下发 HttpOnly 会话 cookie，子站前端零 SSO 代码。
- **登录设备管理**：列出 / 重命名 / 踢下线登录设备，附来源 GeoIP。
- **两阶段 TOTP 重置**：新 secret 先进 pending，验证通过才转正；失败或超时不影响旧 secret，已登录的人不会被锁在外面。
- **按 IP 阶梯限速**：连续失败 5 次锁 60s，再 5 次 300s，再 5 次 900s。

## 快速开始

```bash
npm install
npm start            # = node src/index.ts，默认监听 0.0.0.0:3200
npm run check        # = typecheck（tsc --noEmit）+ lint + test
```

需要本机 Redis（默认 `127.0.0.1:6379`）。首次启动会在 `DATA_DIR` 自动生成 `oidc-keys.json`、`jwt-secret`、`internal-token`。

## 配置

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `3200` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址（生产由 systemd 显式设为 `127.0.0.1`） |
| `REDIS_HOST` / `REDIS_PORT` | `127.0.0.1` / `6379` | 会话与令牌存储 |
| `REDIS_DB` | `0` | Redis 库号（测试实例可用 `15` 隔离） |
| `DATA_DIR` | 项目根 | 密钥与注册表所在目录 |
| `ISSUER` | `http://127.0.0.1:3200` | OIDC issuer，所有端点 URL 由它拼接；生产填真实对外地址 |
| `SSO_SUBJECT` | `linden` | 用户稳定标识（`sub` / `preferred_username`） |
| `SSO_DISPLAY_NAME` | 同 `SSO_SUBJECT` | 展示名（`name`） |
| `SESSION_DAYS` | `7` | 会话滑动过期天数 |
| `ACCESS_TTL_SEC` | `900` | access_token 秒数，下限 60 |
| `JWT_SECRET` | 读 `jwt-secret` 文件 | 会话 JWT 签名密钥 |
| `INTERNAL_TOKEN_FILE` | `<DATA_DIR>/internal-token` | 内部接口共享令牌文件（0600，自动生成） |
| `INTERNAL_TOKEN` | 无 | 直接指定内部令牌值，覆盖文件 |
| `AUTH_GEOIP_URL` | `https://ip-api.com/json/{ip}?fields=status,country,regionName,city` | 登录来源解析接口 |
| `ALLOWED_REDIRECT_ROOTS` | 空（仅同源） | 登录页 `?redirect=` 允许跨域回跳的域名根，逗号分隔（示例 `example.com,example.org`）；只有这些根域及其子域可回跳，未配置时仅同源、拒绝跨域并提示 |

## 接口

登录与兼容接口：

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/auth` | 无 | 登录页（`?redirect=` 回跳，带白名单） |
| GET | `/config.js` | 无 | 登录页运行期配置：仅注入回跳白名单域名根（`ALLOWED_REDIRECT_ROOTS`），不含凭据 |
| POST | `/api/login` | 无 | `{code}` → 验 TOTP → 签发 Redis 会话 token |
| GET | `/api/verify` | 无 | **兼容保留**：会话 token / 首方 SSO 令牌 / API token，通过返回 `X-Auth-User` 并刷新 TTL |
| POST | `/api/logout` | 无 | `{token}` 或 Bearer → 删会话（并连带撤销关联 SSO 令牌） |
| POST | `/api/totp/setup` | 无（仅首启） | 生成 TOTP secret |
| POST | `/api/totp/reset` | Bearer | 两阶段①：生成 pending secret（5 分钟），不覆盖正式 |
| POST | `/api/totp/confirm` | Bearer | 两阶段②：pending 验证码通过才转正 |
| GET | `/api/sessions` | Bearer | 已登录设备会话列表 |
| PUT | `/api/sessions/:id/name` | Bearer | 重命名会话 |
| DELETE | `/api/sessions/:id` | Bearer | 踢下线 |

OIDC（挂在根路径，issuer 取 `ISSUER`）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/authorize` | 授权端点（PKCE S256） |
| POST | `/token` | code / refresh（refresh 轮换，重放整链作废） |
| GET/POST | `/userinfo` | Bearer access_token |
| GET | `/jwks.json` | ES256 公钥集 |
| POST/GET | `/introspect` | RFC 7662 |
| GET/POST | `/end_session` | RP-Initiated Logout（回跳白名单） |
| POST | `/revoke` | RFC 7009 |
| GET | `/auth` | 登录页（`?redirect=` 旧流程 + 白名单） |

内部接口（仅本机服务，共享令牌 `X-Internal-Token`，不走会话鉴权）：`GET /api/internal/sessions?sub=`、`PUT /api/internal/sessions/:id/name`、`DELETE /api/internal/sessions/:id`、`POST /api/internal/totp/reset?sub=`、`POST /api/internal/totp/confirm?sub=`。`sub` 必须等于本实例 `SSO_SUBJECT`（缺→400，非本用户→404）。

## 部署

由 systemd 单元 `auth-server.service` 托管，监听 `127.0.0.1:3200`，工作目录为项目根。
nginx 只做 TLS 与路由：登录态由独立项目 **Auth Gateway** 接管，站点 nginx 把 `/_auth/*` 转给网关（`127.0.0.1:18920`），由网关向后端注入 `X-Auth-User`；OIDC 各端点由网关在服务端经 loopback 调用。不再使用 nginx `auth_request` 探针或 `/auth-check`。真实域名与对外地址一律由 `ISSUER` / 反向代理配置提供，不写进代码。

登录页 `?redirect=` 的跨域回跳白名单由环境变量 `ALLOWED_REDIRECT_ROOTS`（逗号分隔域名根，示例 `example.com,example.org`）提供，服务端经 `GET /config.js` 注入登录页（`window.__AUTH_CONFIG__.allowedRedirectRoots`）；只有这些根域及其子域可跨域回跳。未配置时只允许同源回跳，跨域目标被拒并给出可读提示——不会回退成允许任意域。

## 认证与安全

- **唯一用户凭据是 TOTP 动态码**：没有静态密码，登录页不接受账号；验证窗口 ±1 步。
- **redirect_uri 精确匹配**：只接受注册表 `clients.json` 中完全相等的字符串，禁止通配与前缀匹配。
- **id_token 与 access_token 只用 ES256**；撤销以 Redis 记录为准（`/introspect`、`/revoke` 生效），不因签名有效而永久有效。
- **两阶段 TOTP 重置**：`reset` 只写 pending、绝不覆盖正式 secret；`confirm` 必须 pending 验证码通过才转正。
- **内部接口令牌**首次启动生成到 `INTERNAL_TOKEN_FILE`（0600），值不打印、不返回给客户端。
- **限速按真实客户端 IP**（`X-Forwarded-For` → `X-Real-IP` → socket），失败阶梯 60s → 300s → 900s。
- 密钥与注册表（`totp-secret.json`、`oidc-keys.json`、`clients.json`、`jwt-secret`、`internal-token`）均被 `.gitignore` 拦截，不入库。

## 许可证

MIT，见 `LICENSE`。
