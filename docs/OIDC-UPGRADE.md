# auth-server → OIDC Provider 改造规格（权威施工图）

> ⚠️ 已被 docs/SSO-GATEWAY-SPEC.md 取代（2026-09-28 起全站走 Auth Gateway）。本文仅存历史设计记录。

> 目标：把现有自研 SSO 升级为**标准 OAuth 2.1 + OpenID Connect Core 1.0** 的 IdP。
> **TOTP 保留为唯一的用户验证手段**（标准允许自定义认证方式，标准管的是流程）。
> 与 `AGENTS.md` 冲突时以本文件为准（本文件是本次改造的施工图）。

---

## 0. 硬性边界（违反即失败）

- **绝不** `systemctl restart/stop/start auth-server` ✗；**绝不**碰生产端口 **3200** ✗
- 本地测试一律用**临时端口**（如 `13200`）+ 临时数据目录（`/tmp/auth-oidc-dev`）✓
- 不许改 `/etc/nginx/**`、容器、cron、`/root/.hermes/**`、其他项目 ✓
- 不许 `pkill` / `killall` ✗（自己起的测试进程按 PID 清理 ✓）
- **新增依赖 0 个** ✗：只用 Node 内置 `node:crypto`（ES256 签名/验签、S256 PKCE、随机数）+ 已有 `express` / `ioredis` ✓
- **允许小步 `git commit`**（每完成一个模块提交一次）✓；**禁止 `git push`** ✗
- 为可测试性，新增两个**可选**环境变量（**默认值 = 现状** ✓ 保证兼容 ✓）：`DATA_DIR`（密钥/注册表所在目录，默认项目根 ✓）、`REDIS_DB`（默认 `0` ✓）。测试实例用临时目录 + `REDIS_DB=15` ✓ 避免污染生产 Redis ✓
- 源码/配置文件里**不得出现**真实域名、IP、密钥明文 ✓（issuer 走环境变量 ✓）
- **向后兼容是硬要求** ✗：`/api/verify`、`/api/logout`、`/api/sessions*`、`/api/totp/*`、`/api/login` 与登录页行为**一个都不能坏**（现有 8 个站点靠它们活着 ✓）

---

## 1. 新增端点（全部挂在现有服务上，不改端口）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Discovery ✓ 字段见 §2 |
| GET | `/authorize` | 授权端点 ✓ 见 §3 |
| POST | `/token` | 令牌端点 ✓ 见 §4 |
| GET | `/userinfo` | 身份端点 ✓ Bearer access_token ✓ |
| GET | `/jwks.json` | 公钥集 ✓ ES256 ✓ 带 `kid` ✓ |
| POST | `/introspect` | RFC 7662 ✓ 供 nginx 探针用 ✓（`/api/verify` 作为兼容别名保留 ✓）|
| GET/POST | `/end_session` | RP-Initiated Logout ✓（`id_token_hint` + `post_logout_redirect_uri` 需白名单 ✓）|
| POST | `/revoke` | RFC 7009 ✓ 撤销 access/refresh ✓（可选，但建议 ✓）|

## 2. Discovery 文档要求的字段

```
issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
end_session_endpoint, introspection_endpoint, revocation_endpoint,
response_types_supported: ["code"],
grant_types_supported: ["authorization_code","refresh_token"],
code_challenge_methods_supported: ["S256"],
scopes_supported: ["openid","profile","email","offline_access"],
id_token_signing_alg_values_supported: ["ES256"],
token_endpoint_auth_methods_supported: ["client_secret_basic","client_secret_post","none"],
subject_types_supported: ["public"],
claims_supported: ["sub","iss","aud","exp","iat","auth_time","nonce","preferred_username","name"]
```

- `issuer` 一律取环境变量 `ISSUER`（默认 `http://127.0.0.1:3200`）✓ **不得硬编码** ✗
- 所有端点 URL 由 `ISSUER` 拼接 ✓

## 3. `/authorize` 参数与校验（**这是修洞的地方** ✗）

必填：`client_id`、`redirect_uri`、`response_type=code`、`scope`（须含 `openid`）
选填：`state`、`nonce`、`code_challenge`、`code_challenge_method=S256`、`prompt`、`max_age`

**校验（任一不过 → 直接渲染错误页，绝不 302 回带 code）**：
1. `client_id` 必须存在于客户端注册表 ✓（否则 400 错误页 ✗ 不许回跳 ✓）
2. **`redirect_uri` 必须与注册值「字符串精确相等」** ✗ **不允许通配、不允许前缀匹配、不允许未注册** ✓✓ ← **这就是堵掉开放重定向 + token 外泄的那一刀** ✓
3. `response_type` 必须 `code` ✓
4. `scope` 必须含 `openid` ✓
5. 公开客户端（`token_endpoint_auth_method: none`）**必须带 `code_challenge`（S256）** ✓
6. `state` 缺失不阻断但**原样回传** ✓；`prompt=login` 时强制重新验证 TOTP ✓

**流程**：无有效会话 → 渲染现有 TOTP 登录页（复用现有 UI ✓ 只多带上下文）→ TOTP 通过 → 生成 **authorization code** → 302 `redirect_uri?code=…&state=…`（**只给 code，绝不给 token** ✓）

**code 语义**：Redis 存 ✓ TTL **60 秒** ✓ **一次性**（用后即删 ✓）；绑定 `client_id` + `redirect_uri` + `code_challenge` + `nonce` + `sub` + `auth_time` ✓

**首方模式（本机全家桶用 ✓ 重要）**：注册表里标 `"first_party": true` 的客户端：
- 授权成功后**由 auth-server 自己完成 code→token 交换** ✓ 并 `Set-Cookie`（HttpOnly ✓ Secure ✓ SameSite=Lax ✓ `Domain` 取注册项 `cookie_domain` ✓）✓ 然后 302 到 `redirect_uri` ✓
- 这样各子站**不需要任何前端 SSO 代码** ✓ nginx 只负责探针 ✓（见 §7）

## 4. `/token`（`application/x-www-form-urlencoded`）

**grant_type=authorization_code**：参数 `code`、`redirect_uri`、`client_id`（+ 机密客户端再带 `client_secret` ✓）、`code_verifier`
- 校验：code 存在且未用 ✓、`client_id`/`redirect_uri` 与授权时**完全一致** ✓、PKCE `S256(code_verifier) == code_challenge`（`timingSafeEqual` ✓）、机密客户端密钥校验 ✓
- 返回 JSON：`access_token`、`token_type:"Bearer"`、`expires_in`、`id_token`、`refresh_token`（当 scope 含 `offline_access` 或客户端允许 ✓）

**grant_type=refresh_token**：`refresh_token` + `client_id`（+ secret ✓）
- **轮换**：每次刷新签发新 refresh_token 并作废旧的 ✓；旧的被再次使用 → **整条链作废**（重放检测 ✓）

**id_token 要求（JWT, ES256, 必须带 `kid`）**
```
iss, sub, aud=client_id, exp, iat, auth_time, nonce(授权时带了就必须回填 ✓),
preferred_username, sid(可选)
```
- 签名用 ES256（P-256 ✓ `node:crypto` 直接支持 ✓）；**不得**再用 HS256 签 id_token ✗（HS256 是共享密钥，第三方无法安全验签 ✗）
- 密钥对首次启动生成 → `oidc-keys.json`（0600 ✓ **gitignore** ✓）；`kid` = 公钥 JWK thumbprint ✓；支持多密钥并存（轮换用 ✓）

**access_token**：（历史：曾为不透明随机串 → Redis `oidc:at:<hash>`，TTL 1 小时）**现为 ES256 JWT，TTL 15 分钟**（`ACCESS_TTL_SEC` 可覆盖），撤销仍以 Redis 为准 ✓
**refresh_token**：同法 ✓ Redis `oidc:rt:<hash>` ✓ TTL **30 天** ✓

## 5. 客户端注册表

- 文件：`clients.json`（0600 ✓ **gitignore** ✓）；提交 `clients.example.json` ✓（占位 `client_id: "example-app"`、`redirect_uri: "https://app.example.com/sso/callback"` ✓）
- 结构（每客户端一条）：
```json
{
  "client_id": "…",
  "client_secret": "…",            // 公开客户端留空 → token_endpoint_auth_method=none
  "redirect_uris": ["https://…"],  // 精确匹配 ✓ 必填非空 ✓
  "post_logout_redirect_uris": ["https://…"],
  "grant_types": ["authorization_code","refresh_token"],
  "scopes": ["openid","profile"],
  "first_party": true,
  "cookie_domain": ".example.com"
}
```
- 校验函数必须**拒绝**：空 `redirect_uris` ✗、含 `*` 通配 ✗、非 `http(s)` 协议 ✗（`http://localhost` 除外，便于本地调试 ✓）

## 6. `/userinfo` 与 `/introspect`

- `/userinfo`：`Authorization: Bearer <access_token>` ✓ → `{sub, preferred_username, name?, sid?}` ✓；无效/过期 → 401 + `WWW-Authenticate: Bearer` ✓
- `/introspect`：`token=` → 返回 `{active:true, sub, scope, exp, client_id}` ✓ 或 `{active:false}` ✓；**同时保留**通过 `Authorization: Bearer` 校验 refresh/access/会话 token 的兼容行为 ✓
- **`/api/verify` 保持不变** ✓（200 + `X-Auth-User` ✓ 401 否则 ✓）—— 8 个站点靠它 ✓ 一行都不许改语义 ✓

## 7. nginx 侧配合（本次只写文档，不动配置 ✓）

标准首方接法（每个子站一个 client ✓）：
```nginx
location @sso_entry {
    return 302 https://<auth 域>/authorize?client_id=<站点名>&redirect_uri=https%3A%2F%2F<站点域>%2F&response_type=code&scope=openid+profile&state=$request_id;
}
location / {
    auth_request /auth-check;                 # → /introspect 或 /api/verify
    error_page 401 = @sso_entry;
    auth_request_set $u $upstream_http_x_auth_user;
    proxy_set_header X-Auth-User $u;
    proxy_pass http://127.0.0.1:<站点端口>;
}
```
`state` 用 nginx 内置 `$request_id`（每请求唯一 ✓ 免自己造 ✓）。

## 8. 绝不回退的行为（回归清单）

1. `POST /api/login {code}` → 200 `{token}` ✓ / 403 `totp_setup_required` ✓ / 429 限速 ✓
2. `GET /api/verify?token=` → 200 + `X-Auth-User`（ASCII ✓）/ 401 ✓
3. `POST /api/logout` ✓；`GET /api/sessions` ✓；`PUT/DELETE /api/sessions/:id` ✓
4. `POST /api/totp/{setup,reset,confirm}` ✓（两阶段语义不许简化 ✗）
5. 登录页 `?redirect=` 旧流程**继续可用** ✓ 但：**加白名单**（只允许「同 issuer 下的路径」或注册客户端的 `redirect_uris` ✓）✓ 并在响应头/日志打 `Deprecated` 标记 ✓
6. Redis 挂掉时 `/api/verify` 必须 **refuse**（不放过 ✓）—— 现有行为不许改成 fail-open ✗

## 9. 自测清单（交付前必须逐项跑 + 贴原始输出 ✓）

**A. 标准客户端全流程（必须用「非自研客户端」证明互通 ✓）**
1. `GET /.well-known/openid-configuration` → 200 ✓ 字段完整 ✓
2. 走完 `authorize → code → token`（PKCE S256 ✓）→ 拿到 `id_token` + `access_token` + `refresh_token` ✓
3. 用 JWKS 公钥**独立验签** `id_token` ✓ 且核对 `iss/aud/exp/nonce` ✓
4. `/userinfo` 用 access_token → 200 ✓ 身份正确 ✓
5. `refresh_token` 刷新 → 成功 ✓ 且旧 refresh 立即失效 ✓（重放 → 整链作废 ✓）
6. `/introspect` 对 access_token → `active:true` ✓；对乱串 → `active:false` ✓

**B. 安全负例（每条都必须被拒 ✓）**
7. `redirect_uri` 未注册 / 前缀匹配 / 带 `*` → 全部 400 ✓ **不回跳** ✓
8. `code` 重放 → 第二次 400 ✓
9. PKCE `code_verifier` 不匹配 → 400 ✓
10. `state` 原样回传 ✓
11. 过期/伪造 access_token 调 `/userinfo` → 401 ✓
12. `id_token` 用 HS256 伪造 → 验签失败 ✓

**C. 兼容回归（§8 六条）→ 全部手测一遍 ✓**

**D. 收尾**：临时实例已停 ✓ 3200 未受任何影响 ✓（`systemctl is-active auth-server` 仍 active ✓）无残留进程/端口 ✓

## 10. 交付物

- 代码（小步 commit ✓ 不许 push ✗）
- `docs/COMPLETION_REPORT.md`：做了什么、新增依赖（应为 0 ✓）、没做到什么、遗留风险 ✓
- `clients.example.json` ✓ + `.gitignore` 更新 ✓ + README/AGENTS.md 相应章节更新 ✓
