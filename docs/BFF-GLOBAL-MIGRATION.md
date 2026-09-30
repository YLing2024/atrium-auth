# 全局 BFF 化改造 · 总施工规格

> ⚠️ 已被 docs/SSO-GATEWAY-SPEC.md 取代（2026-09-28 起全站走 Auth Gateway）。本文仅存历史设计记录。

> 2026-09-28 定稿。方向：**推翻 nginx 探针 + 共享 cookie，全部改成 BFF（每站自己的后端换 token、发自己的会话 cookie）**。
> 范围铁律：**只动「已接入 SSO 的项目」+ SSO 系统本身**；其他系统一律不碰。

---

## 0. 一句话原则

> **每个域名只认自己的 cookie；前端不碰 token、不碰 code；换 token 一律在服务端。**

## 1. 改造对象（事实清单，2026-09-28 实测）

| 组 | 站点 | 有无自家后端 | 改造方式 |
|---|---|---|---|
| **A** | `quotahub`（:5300）、`v2link`（:7897）、`admin`（:3100） | ✓ 有 | 各自后端加 4 个端点（§3） |
| **B** | `android`（ws-scrcpy :8000）、`desktop`（KasmVNC :3999）、`linux`（ttyd :7901） | ✗ 无 | 统一网关 `ssogate`（§4） |
| **C** | `home-admin`（Flutter App） | — | 标准 PKCE + Keychain（§5） |
| **D** | `auth-server`（:3200，认证中心自己） | ✓ | confidential client 注册 + 撤销链（§2） |

**不在范围内**：思源（未叠 SSO）、主页（主页本身无鉴权，只有主域下的 `/api/admin/*` 属于 admin 体系）、davbox（未部署）、以及所有其他项目。

---

## 2. 认证中心（auth-server）侧

1. `clients.json` 为 A 组三站注册 **confidential client**（`client_secret`，0600 权限，不进仓库）：
   ```json
   {
     "client_id": "quotahub",
     "client_secret": "<随机 32 字节 hex>",
     "type": "confidential",
     "redirect_uris": ["https://quotahub.<your-domain>/sso/callback"]
   }
   ```
   （`v2link` / `admin` 同理；`redirect_uris` **精确匹配**，不加通配符）
2. B 组三站注册 confidential client（给 ssogate 用），`redirect_uri` 指向网关的 `/sso/callback`。
3. 确认既有能力：`/authorize`、`/token`（支持 `client_secret_basic` / `client_secret_post`）、`/userinfo`、`/revoke`、`/jwks.json`、`/.well-known/openid-configuration`。
4. **撤销必须彻底**：`/sso/logout` 调用方 → 站点后端撤自家会话 → 调 `/revoke` 撤 refresh/access token；认证中心的 `auth_session` 由用户自行决定是否同撤（默认**不撤**，因为那是"单点登录"本体，撤了会牵连其他站）。
5. 老接口（`/api/login`、`/api/verify`、`/api/logout`、`/api/sessions*`、`/api/totp/*`）**语义一行不改**，保留过渡。
6. `auth_session` cookie 保留 ✓（它就是"你登录过"这件事本身 → 别的站免密靠它 ✓）

## 3. A 组站点后端：4 个端点（每站 60~100 行）

```
GET  /sso/login     生成 state + code_verifier → 存本后端（Redis，TTL 10 分钟）
                    → 302 到 <auth>/authorize?client_id=<站>&redirect_uri=<站>/sso/callback
                       &response_type=code&scope=openid profile
                       &state=<S>&code_challenge=<C>&code_challenge_method=S256
GET  /sso/callback  ① 取 state，和 Redis 里那份比对，不符 → 400 并清掉
                    ② POST <auth>/token  { grant_type=authorization_code, code,
                                           redirect_uri, client_id, client_secret, code_verifier }
                    ③ 得到 access_token / id_token / refresh_token → **只存服务端**
                    ④ 建站内会话 sid（随机 32 字节）→ Redis: <站>:sess:<sha256(sid)>
                       = { sub, name, access_token, refresh_token, exp }
                    ⑤ Set-Cookie: __Host-<站>_session=<sid>; HttpOnly; Secure; SameSite=Lax; Path=/
                    ⑥ 302 回 /
GET  /api/me        读会话 cookie → { name, role }（前端"显示你是谁"只用这个）→ 未登录 401
POST /sso/logout    撤站内会话 + 调 <auth>/revoke → 清 cookie
```

规则：
- cookie 名：`__Host-<站>_session`（`quotahub` → `__Host-quotahub_session`；v2link / admin 同理）
- **`SameSite=Lax`**（跨站导航回来时需要带上；不要用 `Strict`）
- 会话 TTL 7 天滑动；**access_token 过期时用 refresh_token 在服务端静默续**
- 前端**不做** 401→跳转（由后端 302 处理）；`/sso/login`、`/sso/callback`、`/api/me` 免业务鉴权

## 4. ssogate：B 组统一网关（Go 单二进制，约 300~400 行）

一个进程，配置文件驱动，可同时服务多个站；每站**独立 cookie 名 + 独立密钥**。

```yaml
# /etc/ssogate/config.yaml
listen: 127.0.0.1:18910          # 由 nginx 反代进来
issuer: https://auth.<your-domain>
sites:
  - id: android                  # client_id
    secret_file: /etc/ssogate/android.secret
    cookies: sg_android          # 站点自己的会话 cookie
    upstream: http://127.0.0.1:8000
    user_header: X-Auth-User
    redirect_uri: https://android.<your-domain>/sso/callback
  - id: desktop
    secret_file: /etc/ssogate/desktop.secret
    cookies: sg_desktop
    upstream: http://127.0.0.1:3999
    redirect_uri: https://desktop.<your-domain>/sso/callback
  - id: linux
    secret_file: /etc/ssogate/linux.secret
    cookies: sg_linux
    upstream: http://127.0.0.1:7901
    redirect_uri: https://linux.<your-domain>/sso/callback
```

行为：
1. 请求进来 → 认站 → 查自己的会话 cookie → 有效则**反向代理**到 `upstream`，并注入 `X-Auth-User`（**先删掉客户端传进来的同名头**，防伪造）
2. 无效 → 302 到 `/authorize`（标准流程，`state`+PKCE 在后端）
3. `/sso/callback` → 换 token → 建自己的会话 → `Set-Cookie: sg_<站>=…; HttpOnly; Secure; SameSite=Lax; Path=/` → 回原地址
4. `/sso/logout` → 撤会话 + 调 `/revoke`
5. **不共享 cookie**：每站一个 cookie 名 ✓ 一个站漏了不牵连其他站 ✓

依赖：只用标准库（`net/http` + `net/http/httputil`）+ 一个配置解析（`gopkg.in/yaml.v3`）—— 足够了 ✓

## 5. home-admin（Flutter App）

- 标准 PKCE（`RFC 8252`）：系统浏览器或 `WebView` → 回跳 `homeadmin://callback` → 用 `code + code_verifier` 换 token
- token 存 **Keychain / Keystore**（`flutter_secure_storage`）
- 请求带 `Authorization: Bearer`；认证中心无需为它开 CORS
- **不参与 cookie 体系** ✓（App 本来就没有 cookie 一说 ✓）

## 6. 前端改动（A 组三站 + home-admin）

**删**：`sso.ts` / `lib/sso.ts` / `api.js` 里的 `getToken/setToken/clearToken`、`tokenFromUrl()`、`localStorage.auth_token`、401→清 token 跳转、`?token=` 下载地址拼接 ✓
**留**：只调 `/api/*`，且带 `credentials: 'same-origin'` ✓
**加**：启动时调一次 `/api/me` 判断是否已登录（未登录由后端 302 接管 ✓）

## 7. nginx 改动

1. **撤掉全部 `auth_request /auth-check`**（A 组三站 ✓ B 组三站 ✓ 主域下的 `/api/admin/*`、`/api/blog/admin/*` ✓）
2. A 组：`location /sso/` 与 `/api/` 直接反代到站点后端（后端自己管鉴权）
3. B 组：`location /` 反代到 `ssogate`（`127.0.0.1:18910`），由网关管鉴权
4. **不再需要共享 cookie** → 认证中心的 `auth_session` 只作用于 `auth.<your-domain>` 自己
5. 保留：老登录页白名单 ✓ 证书 ✓ 精确 location 不互踩 ✓

## 8. 验收标准（逐站，脚本化 ✓）

| # | 检查 | 期望 |
|---|---|---|
| 1 | 未登录访问站点 | 302 → 认证中心 `/authorize?client_id=<站>` ✓ |
| 2 | 认证中心无会话 | 显示登录页 ✓ |
| 3 | TOTP 登录后回跳 | 回到站点 ✓ **URL 里没有任何 token** ✓ |
| 4 | 站点 cookie | **本站自己的**（`__Host-quotahub_session` / `sg_android`）✓ `HttpOnly` `Secure` `SameSite=Lax` ✓ |
| 5 | 带本站 cookie 访问 | **不再 302** ✓（desktop/linux 仍可能 401 = 它们自己的第二层口令 ✓ 属正常 ✓） |
| 6 | 无 cookie 访问 | 302 ✓（闸门在 ✓）|
| 7 | **跨站隔离** | A 站的 cookie 拿去访问 B 站 → **不认** ✓（关键 ✓ 这是本次改造的核心收益）|
| 8 | 登出 | 本站 cookie 立刻失效 ✓且再去是被 302 ✓ |
| 9 | 前端源码 | `grep -r "auth_token\|localStorage" 前端源码` = 0 ✓ |
| 10 | 老接口回归 | `/api/verify`、`/api/login`、`/api/sessions*` 语义不变 ✓ |

## 9. 施工纪律

- 分工：需求 → 实现 → 验收 → 部署 → 提交
- **小步 commit ✓ 禁止 push** ✓（每个可验收小步一次提交 ✓）
- 禁止 `systemctl` / `pkill` 动生产服务；测试一律用**独立端口 + 独立 Redis DB**（`REDIS_DB=15`）
- 需求文档必须写明"不许动生产端口 / 不许动其他项目 / 不许 pkill"
- 每阶段结束：独立复核（生产服务 active + 站点实测）

## 10. 分阶段

| 阶段 | 内容 | 可验收 |
|---|---|---|
| P1 | 认证中心：注册 confidential client（A 组 + B 组）+ 确认 revoke 链 | discovery/JWKS/token 全过 ✓ |
| P2 | **挑一个站打样**（建议 quotahub）：后端 4 端点 + 前端删 token + nginx 撤该站探针 | §8 全部 ✓ |
| P3 | 推广到 v2link、admin | §8 全部 ✓ |
| P4 | 写 ssogate + 接 android/desktop/linux | §8 全部 ✓ |
| P5 | 撤掉全部探针 + 前端清理（含 home-admin 改 PKCE） | grep 检查 = 0 ✓ |
| P6 | 巡检脚本更新（新端口/cookie 健康检查）+ 文档 | 巡检无告警 ✓ |
