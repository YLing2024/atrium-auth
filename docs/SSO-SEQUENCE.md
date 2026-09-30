# SSO 时序图 · 两种形态对照

> ⚠️ 已被 docs/SSO-GATEWAY-SPEC.md 取代（2026-09-28 起全站走 Auth Gateway）。本文仅存历史设计记录。

> 2026-09-28 Hermes。都以本服务器真实的组件和域名画：浏览器 / 站点 nginx / 站点后端 / 认证中心（auth.<your-domain>，:3200）。

---

## 形态一：现在生产跑的（nginx 探针 + 共享 cookie）

适用于：`android` / `desktop` / `linux` / `memos` / `sy` / `sftpgo` / `changedetection` —— **别人的程序，没有我们能改的后端**。

```mermaid
sequenceDiagram
    autonumber
    participant B as 浏览器
    participant N as 站点 nginx
    participant A as 认证中心

    B->>N: ① GET https://android.<your-domain>/
    Note over N: ② 探针 auth_request → 认证中心 /api/verify（此时没有 cookie）
    N-->>B: ③ 401 → 页面 location @auth_redirect

    B->>A: ④ GET /authorize?client_id=android&redirect_uri=https://android.<your-domain>/&response_type=code&scope=openid
    Note over A: 无会话
    A-->>B: ⑤ 302 → 登录页
    B->>A: ⑥ 输入 TOTP，POST 登录
    A-->>B: ⑦ 302 回 android... + Set-Cookie: HomeAuth=…（HttpOnly，7 天）<br/>【URL 里没有 token】

    B->>N: ⑧ GET / （浏览器自动带 HomeAuth）
    N->>A: ⑨ auth_request（带 cookie）
    A-->>N: 200 + X-Auth-User: linden
    N-->>B: ⑩ 200 页面

    Note over B,N: ⑪ 之后每个请求都由浏览器自动带 cookie。<br/>前端 0 行代码。code 从来没到过浏览器。
```

**要点**：`code` 由认证中心自己消化 ✓ 浏览器只拿到一张 HttpOnly cookie ✓ **没有 state、没有 PKCE、没有续期逻辑** ✓

---

## 形态二：你要的那版（前端拿到 token）+ 它的完整性要求

适用于：`quotahub` / `v2link` / `admin-server` / `blog-server` / `davbox` —— **有我们自己能改的后端**。

```mermaid
sequenceDiagram
    autonumber
    participant B as 浏览器（前端 JS）
    participant S as 站点后端
    participant A as 认证中心

    B->>S: ① GET / （前端发现未登录）
    B->>S: ② 跳 /sso/login
    Note over S: ★1 生成 state + code_verifier<br/>存在服务端会话里
    S-->>B: ③ 302 /authorize?client_id=quotahub&redirect_uri=…/sso/callback&state=…&code_challenge=…&code_challenge_method=S256

    B->>A: ④ GET /authorize?…
    A-->>B: ⑤ 302 → 登录页
    B->>A: ⑥ 输入 TOTP
    A-->>B: ⑦ 302 回 /sso/callback?code=XXX&state=…

    B->>S: ⑧ GET /sso/callback?code=XXX&state=…
    Note over S: ★2 比对 state —— 不符就拒<br/>（攻击者带回来的 code 在这一步被挡掉）
    S->>A: ⑨ POST /token （code + code_verifier + client_secret）
    A-->>S: ⑩ access_token / id_token / refresh_token

    S-->>B: ⑪ Set-Cookie: __Host-qh_session=…（HttpOnly）★3<br/>+ body: { "access_token": "eyJ…" }
    Note over B: ⑫ 前端把 access_token 放内存，业务请求带 Authorization: Bearer

    B->>S: ⑬ F5 刷新 → 内存空了 → GET /api/session（浏览器自动带 ★3 那个 cookie）
    S-->>B: ⑭ 再发一张新的 access_token
```

**★ 标记的三处，就是形态二比形态一多出来的全部东西**：

| 标记 | 是什么 | 少了它会怎样 |
|---|---|---|
| ★1 ★2 | `state`（+ `code_verifier`） | 别人拿他自己的 code 构造一个 URL 让受害者打开 → 受害者活在他的账号里（会话固定 / 登录 CSRF） |
| ★3 | 一张 HttpOnly 的 **续期票** | 用户按 F5 就掉登录态（内存里的 token 没了，没东西能证明"还是我"） |

---

## 一句话对照

| | 形态一 ✓ 现在跑的 | 形态二 ✓ 你要的 |
|---|---|---|
| `code` 到得了浏览器吗 | **到不了** | 到得了（回调 URL 里） |
| 浏览器里存着什么凭证 | HttpOnly cookie（JS 看不到） | HttpOnly cookie（续期票）+ 内存 token（业务票） |
| 前端代码 | **0 行** | 拿 token / 存内存 / 刷新续期 |
| 必须实现的额外机制 | **无** | state ✓ PKCE ✓ 续期接口 ✓ |
| 攻击面 | 只有共享 cookie 跨子域这一点 | 加上"token 暴露给 JS"（XSS 可偷） |

**两张图里"每次请求必须带个东西"这件事是一样的** ✓ —— 区别只在：形态一那个东西 JS 碰不到 ✓ 形态二有两个，其中一个 JS 拿在手里 ✓
