# OIDC 改造完成报告（auth-server → OIDC Provider）

> ⚠️ 已被 docs/SSO-GATEWAY-SPEC.md 取代（2026-09-28 起全站走 Auth Gateway）。本文仅存历史设计记录。

> 施工图：`docs/OIDC-UPGRADE.md`。本报告诚实记录**做了什么 / 没做到什么 / 遗留风险**。
> 日期：2026-09-28。改造期间生产实例（`127.0.0.1:3200` / systemd `auth-server`）全程未重启、未占用、未影响。

## 1. 做了什么

新增 `src/oidc/` 模块（零依赖，只用 `node:crypto` + 现有 `express`/`ioredis`），实现 SPEC §1–§8：

| 模块 | 文件 | 内容 |
|---|---|---|
| 工具 | `src/oidc/util.js` | base64url、SHA-256、PKCE S256、常量时间比较、随机 token、cookie 解析、HTML 转义 |
| 密钥库 | `src/oidc/keys.js` | ES256（P-256）生成/签名/验签；`kid`=公钥 JWK thumbprint（RFC 7638）；`oidc-keys.json`（0600）；多密钥并存、可轮换 |
| 注册表 | `src/oidc/clients.js` | `clients.json`（0600）；`redirect_uri` 精确匹配；拒绝空/含 `*`/非 http(s)（http 仅 localhost）；加载时跳过非法条目 |
| 路由 | `src/oidc/index.js` | discovery / authorize / token / userinfo / jwks.json / introspect / end_session / revoke；旧 `/auth?redirect=` 白名单 |

端点语义（均按 SPEC）：

- `/.well-known/openid-configuration`：字段完整（§2 全列），issuer 取 `ISSUER` 环境变量。
- `/authorize`：校验 client → **redirect_uri 字符串精确相等** → `response_type=code` → scope 含 `openid` → 公开客户端强制 PKCE S256（**首方客户端除外**，见 §6）；无会话则复用现有 TOTP 登录页；授权成功只回 `code`+`state`；`prompt=login`/`max_age` 可强制重新验证。
- `/token`：`authorization_code`（code 60s、一次性、`getdel` 原子消费、绑定 client/redirect_uri/PKCE/nonce/sub/auth_time）、`refresh_token`（**轮换 + 重放整链作废**）；支持 `client_secret_basic`/`client_secret_post`/`none`。
- id_token：**ES256 only**，含 `iss/sub/aud/exp/iat/auth_time/nonce/preferred_username/sid`。
- access_token：不透明随机串，Redis `oidc:at:<sha256>` TTL 1h；refresh `oidc:rt:<sha256>` TTL 30d；SSO 会话 `oidc:sso:<sha256>` 滑动 7d。
- `/userinfo`：Bearer access_token，`{sub, preferred_username, name?, sid?}`，无效 401 + `WWW-Authenticate`。
- `/introspect`：RFC 7662，识别 access/refresh/sso/旧会话 token，也接受 `Authorization: Bearer`。
- `/end_session`：清 cookie；`post_logout_redirect_uri` 仅放行注册白名单，否则 400 不跳转。
- `/revoke`：RFC 7009，撤销 access/refresh（整链）/sso。
- 首方模式：`first_party:true` 的客户端授权成功后由 auth-server 内部换 token，`Set-Cookie`（HttpOnly / SameSite=Lax / issuer 为 https 时带 Secure / `Domain` 取 `cookie_domain`）后 302。

同时：`/api/*` 与 `/auth?redirect=` 全部保持原语义；`/auth` 新增服务端白名单与 `Deprecated` 标记。

## 2. 新增依赖

**0 个**。`package.json` 依赖仍为 `express`、`ioredis` 两项（另修掉了一处本就存在、会导致 `package.json` 非法 JSON 的尾部逗号）。

## 3. 可测试性环境变量（默认值=现状）

| 变量 | 默认 | 用途 |
|---|---|---|
| `DATA_DIR` | 项目根 | 密钥/注册表所在目录（`totp-secret.json`/`jwt-secret`/`totp-pending.json`/`oidc-keys.json`/`clients.json`） |
| `REDIS_DB` | `0` | Redis 库号（测试用 15） |
| `ISSUER` | `http://127.0.0.1:3200` | OIDC issuer |

测试实例：`PORT=13200 HOST=127.0.0.1 DATA_DIR=/tmp/auth-oidc-dev REDIS_DB=15 ISSUER=http://127.0.0.1:13200`。

## 4. 自测（SPEC §9）

测试客户端为独立脚本（仅 Node 内置 `fetch`/`node:crypto`，自带独立 TOTP 与 JWKS 验签实现，不引用 auth-server 源码）：
`/tmp/auth-oidc-dev/run-tests.js`（A/B/C）、`run-extra.js`（首方/机密客户端/登出/撤销）。

### A 段 · 标准客户端全流程（原始输出）

```
========== A. 标准客户端全流程 ==========
[PASS] A1 discovery 200 且字段完整 :: missing=[]
[PASS] A1b issuer/alg/PKCE 正确 :: issuer=http://127.0.0.1:13200
[PASS] A2a authorize 重定向回注册 redirect_uri 且带 code :: location=http://localhost:9999/callback?code=<code>&state=st-9d43ec36599ac712
[PASS] A2b token 返回 access/id/refresh :: status=200 keys=access_token,token_type,expires_in,id_token,scope,refresh_token
[PASS] A3 JWKS 独立验签 id_token（ES256 + iss/aud/exp/nonce） :: alg=ES256 kid=JK3Py-4W2yDjEgS_DpVRx9sdvO1XC_EACNoPnsmqbMU claims={"iss":"http://127.0.0.1:13200","sub":"HomeAuth","aud":"test-public","exp":1790592103,"iat":1790588503,"auth_time":1790588503,"preferred_username":"HomeAuth","nonce":"n-67dfa3e91d5f0068","sid":"076e033eb1e00e56"}
[PASS] A4 userinfo 用 access_token 返回身份 :: status=200 body={"sub":"HomeAuth","preferred_username":"HomeAuth","name":"HomeAuth","sid":"076e033eb1e00e56"}
[PASS] A5a refresh 成功且换发新 refresh :: status=200
[PASS] A5b 旧 refresh 重放被拒（整链作废） :: status=400 body={"error":"invalid_grant","error_description":"refresh_token 已使用，整条链作废"}
[PASS] A5c 重放后新 refresh 也失效 :: status=400
[PASS] A6a introspect access_token → active:true :: body={"active":true,"sub":"HomeAuth","scope":"openid profile offline_access","client_id":"test-public","exp":1790592103,"token_type":"access_token"}
[PASS] A6b introspect 乱串 → active:false :: body={"active":false}
```

### B 段 · 安全负例（原始输出）

```
========== B. 安全负例 ==========
[PASS] B7a 未注册 redirect_uri → 400 不回跳 :: status=400 loc=null
[PASS] B7b 前缀匹配 redirect_uri → 400 不回跳 :: status=400 loc=null
[PASS] B7c 通配 redirect_uri → 400 不回跳 :: status=400 loc=null
[PASS] B8 code 一次性：第二次 400 :: first=200 second=400
[PASS] B9 PKCE code_verifier 不匹配 → 400 :: status=400 body={"error":"invalid_grant","error_description":"PKCE 校验失败"}
[PASS] B10 state 原样回传 :: sent=st-9d43ec36599ac712 got=st-9d43ec36599ac712
[PASS] B11 伪造 access_token → 401 :: status=401 www=Bearer error="invalid_token"
[PASS] B12 HS256 伪造 id_token 验签失败 :: alg-not-es256:HS256
```

### C 段 · 兼容回归 §8 六条（原始输出）

```
========== C. 兼容回归（§8） ==========
[PASS] C1a /api/login 有效码 → 200 {token} :: status=200 keys=token,expiresIn
[PASS] C1b /api/login 无效码 → 401 invalid_code :: status=401 body={"code":"invalid_code","message":"Invalid TOTP code"}
[PASS] C2a /api/verify 有效 → 200 + X-Auth-User(ASCII) :: status=200 X-Auth-User=HomeAuth body={"ok":true,"user":"HomeAuth","exp":1791193303}
[PASS] C2b /api/verify 无效 → 401 :: status=401
[PASS] C3a GET /api/sessions 列出设备 :: status=200 count=4
[PASS] C3b PUT /api/sessions/:id/name → 200 :: status=200
[PASS] C3c DELETE /api/sessions/:id → 200 :: status=200
[PASS] C3d POST /api/logout 后该 token 失效 :: logout=200 verify=401
[PASS] C5a /auth?redirect= 同源路径 → 200 且带 Deprecated :: status=200 Deprecated=true
[PASS] C5b /auth?redirect= 未白名单 → 页面仍给但标记拒绝 :: status=200 X-Auth-Deprecated=redirect-not-allowed
[PASS] C5c /auth 无 redirect → 200 页面 :: status=200
[PASS] C4a POST /api/totp/reset → pending，不覆盖正式 :: status=200 body={"secret":"<pending-secret>","otpauthUri":"otpauth://totp/...","expiresIn":300}
[PASS] C4b pending 期间旧 secret 仍可登录（不锁死） :: status=200
[PASS] C4c confirm 错误码 → 400 且 pending 丢弃 :: status=400
[PASS] C4d confirm 失败后旧 secret 仍有效 :: status=200
[PASS] C4e POST /api/totp/setup 已配置 → 409 :: status=409
[PASS] C4f 两阶段成功：pending 通过才转正，旧 secret 失效、新 secret 生效 :: confirm=200 old=401 new=200
[PASS] C6 Redis 挂掉 /api/verify refuse（非 200） :: status=503 body={"code":"redis_unavailable","message":"Session store unavailable"}
[PASS] C1c /api/login 连续失败触发 429 限速 :: status=429 body={"code":"rate_limited","message":"Too many failed attempts","retryAfter":60}

========== 汇总 ==========
PASS=38 FAIL=0
```

- C6 用独立实例（`REDIS_PORT` 指向空端口）验证，`/api/verify` 返回 **503 refuse**，未 fail-open。
- C1c 限速测试置于最后（会锁当前 IP 60s）。

### 补充：首方模式 / 机密客户端 / end_session / revoke（原始输出）

```
[PASS] E1 首方 /authorize 无会话 → 302 登录页 :: status=302 loc=/auth?redirect=...
[PASS] E2 首方授权成功 → 302 回跳 + HttpOnly/SameSite cookie，且 Location 不含 code :: status=302 loc=http://localhost:9999/fp?state=fp-state set-cookie=HomeAuth=...; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800
[PASS] E3 首方静默 SSO：仅 cookie 即可再次授权（不再要求登录） :: status=302 loc=http://localhost:9999/fp?state=fp-state
[PASS] E4 introspect SSO 会话 cookie → active:true (sso_session) :: body={"active":true,"sub":"HomeAuth","scope":"openid","client_id":"test-first-party","token_type":"sso_session"}
[PASS] E5a 机密客户端 client_secret_basic 换取令牌成功 :: status=200
[PASS] E5b 机密客户端错误 secret → 401 invalid_client :: status=401 body={"error":"invalid_client","error_description":"客户端密钥错误"}
[PASS] E6 /revoke 后 access_token introspect → inactive :: revoke=200 before=true after=false
[PASS] E7a end_session 未白名单 post_logout_redirect_uri → 400 不跳转 :: status=400 loc=null
[PASS] E7b end_session 白名单 post_logout_redirect_uri → 302 且清 cookie :: status=302 loc=http://localhost:9999/ set-cookie=HomeAuth=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0

PASS=9 FAIL=0
```

合计 **47/47 通过**。

### D 段 · 收尾（原始输出）

```
=== after: 13200/13202 应无监听 ===
none
=== 3200 仍在（同一 pid）===
797
=== systemctl is-active auth-server ===
active
=== redis db15 清空 ===
OK
=== redis db0（生产）keys 数 ===
17
```

生产实例 PID 797 全程未变（`127.0.0.1:3200`），临时实例与 13200/13202 端口、DB15 测试数据、redis-down 子实例均已清理，无残留进程。

## 5. 提交（小步多次，未 push）

```
0c385b7 security(oidc): 加载 clients.json 时收紧权限为 0600（含 client_secret）
98cf2f2 fix(oidc): 首方客户端不强制 PKCE（code 由服务端内部消费）；DATA_DIR 下 JWT secret 写入前建目录
5b246fa feat(oidc): 新增 OIDC Provider 路由（...）并接入服务（DATA_DIR/REDIS_DB/ISSUER 可选变量，默认不变）
dfc9bb5 feat(oidc): 客户端注册表（redirect_uri 精确匹配校验）+ clients.example.json + gitignore
cb08710 feat(oidc): ES256 密钥库（P-256/JWK thumbprint kid/JWKS）+ 基础工具（PKCE S256/cookie/哈希）
f66cc24 chore: 修复 package.json 尾部多余逗号（非法 JSON）
```

## 6. 没做到 / 与规格的偏差（诚实）

1. **nginx 未改**（SPEC §7 明示本次不动配置）：OIDC 端点挂在根路径，而现有 nginx 只反代 `/api/`。**投产前必须**为 `/.well-known/`、`/authorize`、`/token`、`/userinfo`、`/jwks.json`、`/introspect`、`/end_session`、`/revoke` 增加 `location` 反代到 `127.0.0.1:3200`，否则公网访问不到。已在 `README.md`/`AGENTS.md` 标注。
2. **`/auth` 的服务端白名单在现网不生效**：nginx 直接静态服务 `/var/www/auth/index.html`，请求不经过 auth-server。服务端白名单仅在直连实例（如本次测试/未来改为反代）时生效；现网仍依赖页面内置 JS 的校验。要真正强制白名单，需把 `/auth` 改为反代到 auth-server。
3. **首方模式不返还 id_token/access_token 给客户端**：按 SPEC §3，auth-server 自己完成交换后只 `Set-Cookie` + 302，因此首方客户端拿到的是 SSO 会话 cookie（可用 `/introspect` 校验），拿不到标准 id_token。若某子站需要 id_token 做本地验签，需要单独走标准第三方流程。
4. **`Secure` cookie 在 http issuer 下不置位**：SPEC 要求 `Secure`，实现仅在 issuer 为 `https://` 时添加（默认 http://127.0.0.1 便于本地调试）。生产设 `ISSUER=https://…` 即满足。
5. **`/authorize` 复用旧登录页时通过 URL `?token=` 传递旧会话**：沿用既有登录页机制（登录页登录后带 token 回跳），并非新引入；但对严格 OIDC 客户端而言，会话凭据出现在 URL 中。可接受范围内的兼容取舍。
6. **userinfo 身份字段有限**：无邮箱等资料，`name` 回退为 `sub`（`HomeAuth`），未实现 `email` claim（SPEC claims_supported 列了 email 但无数据源）。
7. **多密钥并存已实现但无在线轮换接口**：`KeyStore.rotate()` 存在，未暴露管理端点（SPEC 只要求"支持并存"）。
8. **`/introspect` 对 refresh_token 未返回 `exp`**（记录未存 exp 字段）；access/refresh 的 `active` 与身份信息正确。RFC 7662 中 `exp` 为可选。

## 7. 遗留风险

- **Redis 单点**：会话/OIDC 令牌/授权码全在 Redis；Redis 宕机时 `/api/verify` 与新 OIDC 端点均 fail-closed（返回 503/401，已测 C6），但服务不可用。
- **`authorize` 到 `token` 之间依赖 Redis 原子性**：授权码用 `GETDEL` 保证一次性；refresh 链作废用集合删除，非事务，极端并发下可能有瞬时窗口（单进程实例下风险低）。
- **`oidc-keys.json` 丢失/损坏会导致 id_token 验签全失败**：加载损坏文件会抛错阻止启动（有意的 fail-fast），需备份该文件。
- **未做 `at_hash`/`c_hash`**：未实现，标准客户端若强制校验这两个声明可能不兼容（Core 中多数客户端可接受缺失）。
- **测试数据目录残留**：`/tmp/auth-oidc-dev` 保留测试脚本与报告输出，未提交；生产 `DATA_DIR` 下首次启动会生成 `oidc-keys.json`/需人工创建 `clients.json`。

## 8. 复核方法

```bash
# 生产未受影响
systemctl is-active auth-server          # active
ss -ltnp | grep :3200                    # 生产实例

# 直连临时实例复跑（可选）
redis-cli -n 15 flushdb
cd /tmp/auth-oidc-dev
node run-tests.js && node run-extra.js
```

生产启用步骤（本次未执行，交由验收方）：在 `DATA_DIR` 放置 `clients.json`（参考 `clients.example.json`，0600），设 `ISSUER=https://<auth 域>`，nginx 增加 OIDC 端点反代，重启 `auth-server.service`。

## 9. 第三轮修复（2026-09-28）：SSO 令牌 verify 兼容 + 登出彻底撤销

**根因**：首方模式 `/authorize` 下发的共享 cookie（`HomeAuth=<43 字符 SSO 令牌>`）在 `/introspect` 认、但 `/api/verify` 不认（探针 401 → 登录成功仍弹回登录页）；且 `revokeSession` 只删会话，不删关联 SSO 令牌（登出后 cookie 可用满 7 天）。

**改动**（2 个提交，未 push）：

- `1c6b024 feat(oidc): ...`：`ensureSsoSession` 在 SSO 记录里存 `session_hash`（来源会话 token 的 sha256），并写反向索引 `oidc:sso-session:<会话哈希>` → SSO 令牌哈希集合；新增 `verifySsoToken` / `revokeSsoForToken`；`/revoke`、`/end_session` 复用 `revokeSsoForToken`。
- `f82b4c0 fix(api): ...`：`/api/verify` 在原始会话未命中后追加识别 SSO 令牌（同样 200 + `X-Auth-User`，滑动续期；原始会话路径一行未改）；`revokeSession` 末尾调用 `oidc.revokeSsoForToken(token)`，使 `/api/logout`、`DELETE /api/sessions/:id`、同设备去重都连带撤销 SSO。

**前 / 后（原始 curl，测试实例 `127.0.0.1:13200` / `REDIS_DB=15` / 临时 `DATA_DIR`）**：

修复前：
```
GET /api/verify (X-Auth-Token: <43字符SSO>) → 401 {"code":"invalid_token",...}
下线后 POST /introspect <SSO> → {"active":true,...,"token_type":"sso_session"}   ← 仍可用，安全洞
```
修复后：
```
GET /api/verify (X-Auth-Token: <43字符SSO>) → 200  X-Auth-User: HomeAuth  {"ok":true,"user":"HomeAuth","exp":...}
GET /api/verify (X-Auth-Token: <会话令牌>) → 200  X-Auth-User: HomeAuth      ← 回归不变
POST /introspect <SSO> (登出前) → {"active":true,...,"token_type":"sso_session"}
POST /api/logout (Bearer 会话) → {"ok":true,"message":"Session revoked"}
GET /api/verify (会话, 登出后) → 401
GET /api/verify (SSO,  登出后) → 401
POST /introspect <SSO> (登出后) → {"active":false}
```

**测试结果**（修复后重跑，全部通过）：

| 套件 | 结果 |
|---|---|
| 自测 `repro.js`（verify 兼容 + 登出撤销） | PASS=8 FAIL=0 |
| 自测 `revoke-paths.js`（删设备 / 同设备去重连带撤销） | PASS=3 FAIL=0 |
| 既有 `run-extra.js`（首方/机密/end_session/revoke） | PASS=9 FAIL=0 |
| 既有 `run-tests.js`（A/B/C 段，含 Redis 挂掉 refuse） | PASS=38 FAIL=0 |

新增依赖 0；生产实例（`127.0.0.1:3200`，PID 1951039）全程未重启、未占用；临时实例与 13200/13202 端口、DB15 数据均已清理。

