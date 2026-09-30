# 前端鉴权接入方案调研 · token 拿到之后怎么"设置到前端"

> ⚠️ 已被 docs/SSO-GATEWAY-SPEC.md 取代（2026-09-28 起全站走 Auth Gateway）。本文仅存历史设计记录。

> 面向本服务器上所有接入 SSO 的项目。作者 Linden Zhang，2026-09-28。
> 依据（全部为现行标准/官方文档，非二手转述）：
> - **RFC 10017 / BCP 212《OAuth 2.0 for Browser-Based Applications》**（2026-08 发布，A. Parecki / P. De Ryck / D. Waite）—— 浏览器端 OAuth 的现行最佳实践，§6 把架构分成三类，§8 专门讨论 token 存放位置
> - **OWASP HTML5 Security Cheat Sheet** —— localStorage 的明确结论
> - **Auth0 Token Storage** 官方文档 —— "把 token 留给谁"的决策树
> - **Curity：Token Handler Pattern** —— SPA 无后端时的业界解法

---

## 0. 先把问题说准

"服务器拿 code 换到 token 之后"——接下来要解决的是**另一个问题**：

> 浏览器**下一次**发请求时，凭什么证明自己已登录？

因为 HTTP 每次请求都是独立的。服务器把 token 锁在自己那边（这步是正确的、也是最安全的），
但浏览器侧的"凭证载体"必须存在一个，否则第二个请求就又是匿名的。

RFC 10017 §8 把这件事故意单列一章（Cookies / Service Worker / Web Worker / In-Memory / Persistent），
就是因为**方案之间的差别几乎全部来自"凭证放在哪"**。

---

## 1. RFC 10017 认定的三类架构

### 方案 A：Backend for Frontend（BFF）— §6.1

```
浏览器 ──(cookie)──> BFF（本站后端）──(Bearer access token)──> 资源服务器
```

- **谁换 token**：BFF，以 **confidential client** 身份（有 client_secret）
- **前端拿到什么**：**什么都没有**（RFC 原文："because of the nature of the BFF architecture pattern… there are simply no tokens to be stolen"）
- **浏览器怎么保持登录态**：**cookie**。§6.1.2.3 原文："The BFF relies on browser cookies to keep track of the user's session, which is used to access the user's tokens."
- **RFC 对 cookie 的硬要求（§6.1.3.2）**：
  - `Secure` **MUST** ✓
  - `HttpOnly` **MUST** ✓
  - `SameSite=Strict` **SHOULD** ✓
  - `Path=/` **SHOULD** ✓
  - **不要设 `Domain` 属性**（SHOULD NOT）→ 避免共享给子域 ✓
  - 名字加 `__Host-` 前缀（SHOULD）✓
- **CSRF（§6.1.3.3）**：BFF **MUST** 做 CSRF 防护；SameSite=Strict 是同站场景下够用的手段；跨站场景要配合 CORS + **要求前端带一个自定义请求头**（强制 preflight）
- **RFC 结论（§6.1.4.3）**："This architecture is **strongly recommended** for business applications, sensitive applications, and applications that handle personal data."
- **代价**：所有 API 请求要经后端转发；后端成为关键路径

### 方案 B：Token-Mediating Backend — §6.2

```
浏览器 ──(cookie 换 token)──> 中介后端 ──(换)── 认证中心
浏览器 ──(Bearer access token 直连)──> 资源服务器
```

- **谁换 token**：中介后端（confidential client + PKCE）
- **前端拿到什么**：**access token**（"the application receives the corresponding access token"）→ 直接拿它调 API
- **浏览器怎么保持登录态**：**也是 cookie**（§6.2.1 步骤 G："sets a cookie in the response to keep track of this session"）——但 cookie 只用于"取 token"，不用于调 API
- **安全性**：比 BFF 弱（access token 暴露给前端，可被 XSS 偷；且前端可向后端要新 token），但比纯 SPA 强（refresh token 不外泄；HttpOnly cookie 让攻击者无法升级为会话劫持）
- **适合**：前端要直连多个不同域的资源服务器、又不想要 BFF 那层全量代理

### 方案 C：Browser-Based OAuth 2.0 Client — §6.3

```
浏览器（就是 OAuth 客户端本身）──(PKCE)──> 认证中心
浏览器 ──(Bearer)──> 资源服务器
```

- **谁换 token**：浏览器自己（public client，**没有 client_secret**；§6.3.3.1 明确：AS 不许要求共享密钥，因为它在用户手里）
- **前端拿到什么**：access token（+ 可能 refresh token）→ 存哪见 §8
- **必要条件**：PKCE ✓；`redirect_uri` 必须精确匹配（§6.3.3.2.1 双端 MUST）✓；跨域要 AS 配好 CORS ✓
- **refresh token 管控（§6.3.2）**：应限总时长、且 AS **SHOULD** 把 refresh token 生命周期绑定到用户在 AS 的会话 → 用户登出即全部失效（单点登出）
- **代价**：token 必须落在浏览器可读的地方 → §8 的所有问题都在这里

---

## 2. 凭证放哪：五种位置的结论（§8 + OWASP + Auth0）

| 位置 | 标准/官方结论 | 关键理由 |
|---|---|---|
| **HttpOnly cookie** | BFF/中介后端的标准做法 ✓ | JS 读不到 → XSS 偷不走；浏览器自动携带 → 前端零代码。代价：需要 CSRF 防护 |
| Web Worker / Service Worker | RFC 列为可选；Auth0 推荐（默认存储方式）✓ | 独立作用域，同源 JS 不易直读；SW 复杂、有缓存/劫持风险 |
| **内存** | Auth0："the most secure option" ✓（无后端 SPA 的首选） | 刷新页面即丢、XSS 仍可发起调用 ✗ |
| IndexedDB / OPFS | OWASP：不要存 token，除非用不可导出的密钥加密 ✗ | 磁盘可读；一次 XSS 全读 |
| **localStorage / sessionStorage** | OWASP 明确不建议 ✗ | 原文："**Do not store session identifiers in local storage** as the data is always accessible by JavaScript. Cookies can mitigate this risk using the `httpOnly` flag." |

Auth0 还有一句直接对应本服务器场景的结论：

> "When the SPA calls only an API that is served from a domain that can share cookies with the domain of the SPA,
> **no tokens are needed**. OAuth adds additional attack vectors without providing any additional value and should
> be avoided in favor of a traditional cookie-based approach."

本服务器所有站点都在同一站点（`<your-domain>`）下 → 正好落在这句话里 ✓

---

## 3. 落到本项目：三种接法，具体改哪里

> 判据只有一条：**这个站点有没有我们自己的、能写代码的后端？**
> 有 → 可以做正统版（A/B）；没有 → 只能靠 nginx 挡（A 的变体）。

### 3.1 【有自己后端】方案 A：BFF 正统版

以 QuotaHub / v2link / admin-server / blog-server / davbox 为例。

**后端加三个端点**（约 60~100 行，用现成库或手写都可以）：

```
GET /sso/login        → 生成 state(+PKCE)，302 到
                        <auth>/authorize?client_id=<本站>&redirect_uri=<本站>/sso/callback
                                         &response_type=code&scope=openid&state=…&code_challenge=…&code_challenge_method=S256
GET /sso/callback     → 校验 state → 用 code+verifier+client_secret 调 <auth>/token
                        → 拿 id_token/access_token（**只存在服务器**）
                        → Set-Cookie: __Host-<站>_session=<自有会话id>; HttpOnly; Secure; SameSite=Strict; Path=/
                        → 302 回 /
GET /api/me           → 读自己的会话 cookie → 返回 {user, ...}（前端"显示你是谁"靠它，不靠 token）
POST /sso/logout      → 撤自己的会话 + 调 <auth>/revoke
```

**前端要怎么写**（关键：**不碰 token**）：

```js
// 只需要这两个：
const me = await fetch('/api/me', { credentials: 'same-origin' }).then(r => r.ok ? r.json() : null);
if (!me) location.href = '/sso/login';        // 未登录 → 交给后端跳认证中心
// 业务请求照旧，什么头都不用加：
await fetch('/api/platforms', { credentials: 'same-origin' });
```

**要删掉的东西**：`src/auth/sso.ts`、`lib/sso.ts`、`api.js` 里的 token 存取、`tokenFromUrl()`、
`localStorage.auth_token`、401 时"清 token 跳认证中心"的逻辑、（后端侧）`sso/verify` 换会话接口。

**nginx 配合**：`/api/*` 不再需要 `auth_request` 探针（后端的会话 cookie 自己管）；
`auth_request` 那条链整体可以退场。`/sso/login`、`/sso/callback` 必须放行（免鉴权）。

### 3.2 【有自己后端，但前端要直连 API】方案 B：中介后端

与 A 的差别：`/sso/callback` 之后不建自己的业务会话，而是提供

```
GET /api/session → 返回 { access_token, expires_at }（凭 HttpOnly cookie 换取）
```

前端拿到后**只放内存**（`let token = null;` 模块级变量），业务请求带 `Authorization: Bearer`，
刷新页面丢 token 时再调一次 `/api/session` 恢复。

适合"前端要直连多个不同域 API"的场景；本站各站点 API 都在自己域下 → **没必要选 B**。

### 3.3 【没有自己后端】nginx 探针 + 共享 IdP cookie

适用：`android`（ws-scrcpy）、`desktop`（KasmVNC）、`linux`（ttyd）、`sftpgo`、`memos`、`sy`、
`changedetection`、`opencode-webui` —— **这些是别人的程序，代码里没有任何地方能插 OAuth 逻辑** ✗

```
浏览器 → 站点 nginx ──auth_request──> 认证中心 /api/verify ──> 200 + X-Auth-User
       ↑ 请求自动带 IdP 的 HttpOnly cookie（Domain=.<your-domain>）
未登录 → 302 → /authorize?client_id=<本站>&redirect_uri=…  → 登录 → 回站点（URL 里没有 token）
```

- 前端代码：**0 行**（这就是现在 android/desktop/linux 已生效的状态）
- 与方案 A 的差别：cookie 是**认证中心发的共享 cookie**（跨全部子域通用），不是每站自己的
- RFC 对应：这是 BFF 的"托管版"——把 BFF 的职责交给认证中心 + nginx。
  §6.1.2.3 的 cookie 要求同样适用：`HttpOnly` ✓ `Secure` ✓ `SameSite=Lax`（我们为了跨子域导航用了 Lax，比 Strict 宽一档，属"需要动机的偏离"，动机=多子域导航体验）

### 3.4 【App / CLI】标准 PKCE

Flutter（home-admin）、脚本、webhook：**没有浏览器**，就没有 cookie 这一说 ✗
→ 用 RFC 8252（AppAuth）那一套：系统浏览器/WebView 跑 PKCE → token 存 Keychain / Keystore →
每次请求 `Authorization: Bearer` ✓ 这就是"纯 OAuth2、无 cookie"的正统形态 ✓

---

## 4. 结论与建议

| 站点类型 | 采用 | 前端代码量 | 会话 cookie |
|---|---|---|---|
| 我们自己的后端（quotahub / v2link / admin-server / blog-server / davbox） | **A（BFF 正统版）** | 删代码，降到 ~0 | 每站自己的 `__Host-` cookie ✓ 隔离最好 ✓ |
| 第三方应用（android / desktop / linux / sftpgo / memos / sy / changedetection） | **A'（nginx 探针 + 共享 cookie）** | 0 | 认证中心的共享 cookie |
| App / CLI（home-admin / 脚本） | **PKCE（RFC 8252）** | 私有实现，可开源 ✓ | 无 cookie ✓ |

三句话总结：

1. **cookie 不是"额外的坏东西"** ✗ —— 浏览器场景里它是"登录态记在哪"的答案；
   换成"服务器换 token"只是把 token 从浏览器赶走 ✓ 那个"记在哪"的问题依然要用 cookie 或 JS 存储来答 ✓
2. **RFC 的答案是 cookie** ✓：BFF 与中介后端**两种**架构都用 cookie 记会话；唯一不用 cookie 的是纯 SPA 方案 C ✗ 而那正是"token 落浏览器/被 XSS 偷"的那一档 ✗
3. **本站所有站点同在一个站点（`<your-domain>`）下** → Auth0 的结论直接适用：**根本不需要 token 到前端** ✓
   前端只需要一个 `/api/me` 知道"我是谁" ✓ 其余全由后端/nginx 处理 ✓
