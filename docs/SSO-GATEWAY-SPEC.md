# SSO + Auth Gateway 总施工规格（正式版）

> 2026-09-28 定稿。方向：**SSO 保持纯认证；所有鉴权收进一个 Auth Gateway；业务项目零认证代码。**
> 本文是施工图 + 验收标准的唯一依据。改动前先读 §0 不变量。

---

## 实施现状（2026-09-28）

- **Auth Gateway 已上线**：Go 单二进制，监听 `127.0.0.1:18920`（仅本机，nginx 反代进来）。
- **已接管三站**：`android` / `desktop` / `linux` —— 三站验收 **54/54** 全过（含 WebSocket、第二层口令、身份头防伪）。
- 站点会话 cookie 名为 **`__Host-<app>_session`**（HttpOnly + Secure + SameSite=Lax + Path=/，**不设 Domain**，每站独立）。
- **access_token 现为 ES256 JWT**（本仓库 2026-09-28 改造）：claims 含 `iss/sub/aud/exp/iat/jti/sid/scope/client_id`，用 `/jwks.json` 公钥本地验签；**撤销仍以 auth-server 的 Redis 记录为准**（`/introspect`、`/revoke` 生效）。网关可据此本地验签 + 用 `jti`/`sid` 做撤销。
- 本仓库（认证中心）只负责认证与令牌签发/吊销；`X-Auth-User` 由网关注入（先剥客户端伪造同名头）。

---

## 0. 三个不变量（违反即作废）

| # | 不变量 | 取证方式 |
|---|---|---|
| **I1** | **TOTP 密钥绝不改动** | `auth-server/totp-secret.json` sha256 前 16 位 = `836b9494072719b4`（49 B，mtime 2026-08-11）；`admin-server/totp-secret.json` = `30a25da9296d7483`（50 B）。施工前后必须一致 |
| **I2** | **SSO 只做认证** | 不许在 auth-server 里加反代、静态文件、业务路由、nginx 概念 |
| **I3** | **业务项目零认证代码** | 业务仓库里不出现 OAuth / token / state / PKCE / SSO / localStorage-token / 私有认证域名 |

---

## 1. 组件与职责

```
SSO（auth-server，既有，几乎不改）      你是谁 / 登录了吗 / 签发与校验授权结果
Auth Gateway（新项目，Go 单二进制）     要不要登录 / 完成 OAuth / 维护会话 / 反向代理 / 注入身份
nginx（既有，逐站改造）                 证书、路由到 Gateway、其余一律不管鉴权
业务项目（6 个 + 后续新增）             干业务。不写一行认证代码
```

## 2. 端口与命名

| 项 | 值 |
|---|---|
| Gateway 监听 | `127.0.0.1:18920`（仅本地；由 nginx 反代进来） |
| Gateway 健康检查 | `GET 127.0.0.1:18920/-/health`（不经 nginx） |
| Gateway 专用路径 | `/_auth/login`、`/_auth/callback`、`/_auth/logout`、`/_auth/me`（**所有站统一**；业务项目不得占用该前缀） |
| 会话 cookie | `__Host-<app>_session`（app = quotahub / v2 / admin / android / desktop / linux）<br>属性固定：`HttpOnly; Secure; SameSite=Lax; Path=/`，**不设 Domain** |
| Redis | 现有实例，**专用 DB 2**（现用 DB 0，勿混） |

## 3. Auth Gateway 功能规格

### 3.1 请求判定（每请求）
1. 先匹配 `/_auth/*` → 直接交给 `_auth` 处理器（**必须在会话检查之前**，否则死循环）
2. 否则按 host → 找到站点配置 → 取该站 cookie
   - cookie 有效 → 反向代理到 upstream（§3.4），并把上游需要的身份/令牌带上
   - cookie 无效 → `GET`/导航 → `302 /_auth/login?next=<原地址>`；`POST`/`PUT`/`DELETE`/`fetch`（`Accept: application/json` 或 `X-Requested-With` 或 `Sec-Fetch-Mode: cors`）→ **401 + 清 cookie**

### 3.2 登录（`/_auth/login`）
1. `state = random(16B hex)`、`verifier = random(32B base64url)`、`challenge = base64url(sha256(verifier))`
2. Redis `gw:state:<state> = { app, verifier, original_url, createdAt }`，**TTL 10 分钟**
3. `302 <issuer>/authorize?client_id=<app>&redirect_uri=https://<host>/_auth/callback&response_type=code&scope=openid%20profile&state=<state>&code_challenge=<challenge>&code_challenge_method=S256`

### 3.3 回调（`/_auth/callback`）
1. 取 `state` → 查 Redis → **查不到/不匹配 → 400**（不建会话）
2. **立刻删掉这条 state**（一次性）
3. `POST <issuer>/token`：`grant_type=authorization_code & code & redirect_uri(同一个) & client_id & client_secret & code_verifier`
4. 校验 `id_token` 签名（JWKS 缓存 + 定期刷新）
5. 建会话：`sid = random(32B hex)`；Redis `gw:sess:<sid> = { app, sub, name, access_token?, refresh_token?, exp, original_url }`，**TTL 7 天滑动**
   - `mode: protect` 的站**不保存 token**（只留身份，泄漏面最小）
   - `mode: proxy` 的站保存 token（**加密存放**，密钥来自 0600 文件）
6. `Set-Cookie: __Host-<app>_session=<sid>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
7. `302 <original_url>`（**这就是"跳回原页面"的来源**）

### 3.4 反向代理
- **先删掉客户端传来的** `X-Auth-User`、`X-Auth-Email`、`X-Forwarded-User` 等身份头（**防伪造，必须**）
- 注入 `X-Auth-User: <sub>`（+ `X-Auth-App`、`X-Auth-Sid`）
- **转发前剥掉本站的 `__Host-<app>_session` cookie**（上游永远看不到网关 cookie）
- `mode: proxy` 时额外注入 `Authorization: Bearer <access_token>` 到 `api_upstream`
- **必须支持 WebSocket**（透传 `Upgrade` / `Connection` / `Sec-WebSocket-*`；云安卓、云桌面全靠它）
- 大文件/流式：**不缓冲整包**，直接流式转发（admin 文件区）
- 目标地址**只能来自配置白名单**（绝不接受请求里的 URL 决定转发目标 → 防 SSRF）

### 3.5 令牌有效性
- **默认本地验签**（JWKS + `exp`），**不许每请求 introspection**（否则 SSO 成每请求瓶颈 + 二次单点）
- 撤销即时性：Redis 黑名单 `gw:revoked:<jti>`（仅装被撤回的，TTL ≤ token 剩余寿命）

### 3.6 登出（`/_auth/logout`）
1. 删 `gw:sess:<sid>` + 清 `__Host-<app>_session`
2. 有 token 则调 `<issuer>/revoke`
3. 302 回 `/_auth/login`（或站点首页）
4. **默认不动 SSO 的 `auth_session`**（各站独立退）；单点登出留作可选项，后加

### 3.7 审计
- 记：`时间 / app / sub / 动作(login|logout|denied) / 结果`，不记 token 与 cookie 值
- 落 `/data/authgw/audit.log`（30 天 rotation 归现有 logrotate）

## 4. Redis 键规格（DB 2）

| 键 | 值 | TTL |
|---|---|---|
| `gw:state:<state>` | `{app, verifier, original_url}` | 10 min |
| `gw:sess:<sid>` | `{app, sub, name, exp, access_token?（加密）, refresh_token?（加密）, original_url}` | 7 d 滑动 |
| `gw:revoked:<jti>` | `1` | ≤ token 剩余寿命 |
| `gw:jwks` | JWKS 缓存 | 24 h |

## 5. SSO（auth-server）侧的改动 —— 只做最少

1. **不动**：TOTP 密钥、`/api/login`、`/api/verify`、`/api/logout`、`/api/sessions*`、`/api/totp/*` 的现有语义（I1、I2）
2. 为 6 个 app 注册 confidential client（`client_secret` 0600 文件，不进仓库；已有 quotahub / v2link）
3. 确认 `/token` 支持 `client_secret_post` + PKCE 校验（重算 `challenge` 比对，通过后 code 立即失效）
4. 新增（可选、后做）：`/api/admin/user-sessions`（按用户列出各站会话）+ `/api/admin/revoke-session`（供将来单点登出）

## 6. nginx 改造（逐站）

```
① 删掉该站所有 auth_request / auth_request_set / @auth_redirect
② location /_auth/  → proxy_pass http://127.0.0.1:18920   （精确、优先）
③ location /        → proxy_pass http://127.0.0.1:18920   （整站进网关；上游地址由网关配置决定）
④ 保留：证书、镜像域 301、老登录页白名单、精确 location 不互踩
⑤ 主域下 /api/admin/*、/api/blog/admin/* → 同样改成进网关的 admin 站点配置
```

> nginx 侧**不再有任何鉴权逻辑**，只做 TLS + 路由。

## 7. 各站改造清单

| 站点 | mode | 业务侧要改什么 |
|---|---|---|
| `quotahub`（:5300） | `proxy`（有 API） | **删掉 P2 加的 4 个 SSO 端点和前端残留**（回归零认证代码）；其余业务不动 |
| `v2`（真域名 `v2.example.com`；:7897 + xray :7895） | `proxy` | 删 `frontend/src/lib/sso.ts` 及 token 逻辑 |
| `admin`（admin-server :3100 + admin-web） | `proxy` | 删 `admin-web/src/api.js` 的 token 存取与 401 跳转；后端探针通道保留为第二层 |
| `android`（ws-scrcpy :8000） | `protect` | **零改动**（连代码都不碰） |
| `desktop`（KasmVNC :3999） | `protect` | **零改动**（KasmVNC 自己的口令保留为第二层） |
| `linux`（ttyd :7901） | `protect` | **零改动**（ttyd 自己的口令保留） |
| `homepage`（静态） | — | 主页不鉴权；只把主域下 admin API 路径纳入网关 |
| `home-admin`（Flutter） | — | **标准 PKCE**（§8），不走 cookie 网关 |

## 8. Flutter（home-admin）

- 用**系统浏览器或 App 内 WebView** 走 PKCE：`authorize` → 自定义 scheme 回调（如 `homeadmin://callback`）→ `code + verifier` 换 token
- token 存 **`flutter_secure_storage`**（Keychain / Keystore）；**不存 shared_preferences**（现有 `shared_preferences` 里的旧 token 要清掉）
- **不走网关 cookie**（APP 的 CookieJar 与系统浏览器不是同一个 store，走 cookie 会导致每次打开都要重登）
- 调后端时带 `Authorization: Bearer`；网关**同时接受 Bearer**（本地验签 JWKS）→ 业务项目仍然零改动
- `--dart-define` 保持现有三个注入（`API_BASE` / `AUTH_BASE` / `HERMES_URL`），不得硬编码私有域名

## 9. 分阶段与验收

| 阶段 | 内容 | 验收（Hermes 独立执行，不采信自述） |
|---|---|---|
| **P1** | Gateway 立项：配置加载、`/_auth/*`、protect 模式、反代、WS、注入头、剥 cookie | 本地起 18920 + mock SSO：未登录 302 ✓ 登录后 cookie ✓ 带 cookie 200 ✓ 伪头被删 ✓ WS 能连 ✓ 目标白名单生效 ✓ |
| **P2** | 打样一站（`android` 最干净：protect + 零业务改动） | 浏览器实测：未登录被弹 ✓ TOTP 登录 ✓ 回原页 ✓ cookie 名/属性 ✓ 云安卓画面正常 ✓ **WS 正常** ✓ |
| **P3** | `desktop` / `linux` 接入 | 同上 + 各自第二层口令仍生效 ✓ |
| **P4** | `quotahub` / `v2` / `admin` 切 `proxy`；删业务侧认证代码 | §10 全表 ✓ + 三站 API 正常（含大文件下载 ✓） |
| **P5** | `home-admin` 改 PKCE + `flutter_secure_storage` | `flutter analyze` + `flutter test` ✓ + 真机/模拟器实测登录 ✓ + 换 token/刷新 ✓ |
| **P6** | 撤残留（旧登录页白名单保留）、巡检脚本更新、文档 | 全站 grep 认证代码 = 0 ✓ 巡检无告警 ✓ |

## 10. 验收清单（每站必过）

| # | 检查 | 期望 |
|---|---|---|
| 1 | 未登录访问 | 302 → `/_auth/login` → SSO `/authorize` ✓ URL 无 token ✓ |
| 2 | SSO 无会话 | 显示 TOTP 登录页 ✓ |
| 3 | SSO 已有会话（第二个站） | **不显示登录页**，直接发 code 回跳 ✓ |
| 4 | 回调后 | 302 回**最初要访问的地址**（不是首页）✓ |
| 5 | cookie | `__Host-<app>_session`，HttpOnly/Secure/SameSite=Lax/无 Domain ✓ |
| 6 | 带 cookie 再访问 | 200 ✓（desktop/linux 可能出现它们自己第二层的 401 ✓ 属正常） |
| 7 | **跨站隔离** | A 站 cookie 拿去访问 B 站 → 不认 ✓ |
| 8 | **伪造身份头** | 手工发 `X-Auth-User: root` → 被剥掉 ✓ 上游收到的是网关注入值 ✓ |
| 9 | **WebSocket** | 云安卓/云桌面连接成功、画面刷新 ✓ |
| 10 | API 401 行为 | fetch 收到 401 ✓（不是 302 重定向 HTML ✓）✓ cookie 被清 ✓ |
| 11 | 登出 | 本站 cookie 立即失效 ✓ 其他站不受影响 ✓ |
| 12 | 大文件 | admin 文件下载/上传正常 ✓ 不 OOM ✓ |
| 13 | **I1 取证** | 两个 TOTP 文件 sha256 前 16 位与 §0 一致 ✓ |
| 14 | **I3 取证** | 各业务仓库 `git grep -E "oauth|pkce|state|sso|auth_token|localStorage"` 命中仅剩无关项 ✓ |

## 11. 施工纪律

- 编码流程为 **opencode**；Hermes 负责 nginx/systemd/部署/独立验收
- **小步 commit（每个可验收小步一次）✓ 禁止 push** ✓
- 禁止 `systemctl` / `pkill` / 碰生产端口；测试用独立端口 + **Redis DB 2**
- **构建产物目录绝不可与生产静态目录共用**（quotahub 半态事故的教训：`npm run build` 会直接改线上前端）→ 构建前先备份 `public/`，或在副本里构建
- 需求文档必须写明"不许动生产 / 不许动其他项目 / 不许 pkill / 不许改 TOTP 密钥"
- 每阶段结束：Hermes 独立复核 + 生产服务 active + 站点实测 ✓ 通过才进下一阶段
