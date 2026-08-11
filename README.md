# HomeAuth — 认证中心（单点登录 SSO）

统一认证系统：**TOTP 动态验证码登录 + Redis 滑动过期会话 + Nginx 探针统一鉴权**。
任何子站（Admin / 博客后台 / 其他服务）通过 Nginx `auth_request` 接入，后端零鉴权代码。

## 架构

```
┌──────────────┐   ①请求    ┌──────────────────────────────┐
│   浏览器      │ ─────────→ │  Nginx（auth_request 探针）    │
└──────────────┘ ←───────── │  验 token：有效才转发           │
   ②响应        └───────┬──────────────────────────────┘
                        │ ③内部子请求（/auth-check）
                        ▼
              ┌────────────────────────┐
              │  HomeAuth 认证中心 :3200 │
              │  TOTP 验证 / Redis 会话  │
              └─────────┬──────────────┘
                        │ ④有效 → 2xx（注入 X-Auth-User）
                        ▼
              ┌────────────────────────┐
              │  子站应用（零鉴权代码）   │
              └────────────────────────┘
```

## 核心能力

| 功能 | 说明 |
|---|---|
| **TOTP 动态验证码** | 登录凭据 = 6 位动态码（30 秒变化，±1 步容忍），无账号无静态密码 |
| **Redis 滑动过期会话** | token 存 Redis，每次验证刷新 TTL，N 天不登录自动过期（默认 7 天） |
| **中心化验证** | 子站调 `/api/verify` 验证 token（Nginx 探针或应用层） |
| **按 IP 阶梯限速** | 5 次失败锁 60s → 300s → 900s（防暴力破解） |
| **单点登录** | 一个登录页管所有子站，登录后回跳带 token |

## 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/auth` | 无 | 登录页（TOTP 验证码输入，`?redirect=` 登录后回跳） |
| POST | `/api/login` | 无 | body `{code}` → 验证 TOTP → 签发 token（存 Redis） |
| GET | `/api/verify` | 无 | `?token=` 或 `Authorization: Bearer` → 验证 + 刷新 TTL，通过返回 `X-Auth-User` header |
| POST | `/api/logout` | 无 | body `{token}` → 删除 Redis 会话 |
| POST | `/api/totp/setup` | 无（仅首启） | 生成 TOTP secret，返回 `{secret, otpauthUri}` |
| POST | `/api/totp/reset` | Bearer | 重置 TOTP secret |

## 子站接入（Nginx 探针，后端零代码）

```nginx
# 子站受保护 API：探针验证 + 注入 X-Auth-User
location /api/admin/ {
    auth_request /auth-check;
    auth_request_set $auth_user $upstream_http_x_auth_user;
    proxy_pass http://127.0.0.1:<子站端口>;
    proxy_set_header X-Auth-User $auth_user;
}

# 探针（内部）
location = /auth-check {
    internal;
    proxy_pass http://127.0.0.1:3200/api/verify;
    proxy_pass_request_body off;
    proxy_set_header Authorization $http_authorization;
}
```

**前端 SSO 客户端**（登录跳转 + token 存取，约 30 行）：
1. 无 token → 跳 `https://auth.example.com/auth?redirect=<本站地址>`
2. 回跳解析 token（`?token=`）→ 存 localStorage
3. 请求带 `Authorization: Bearer <token>`；401 → 清 token → 再跳认证中心

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
├── lib/totp-auth/          # TOTP 子功能模块（生成/验证/限速/JWT，零依赖）
│   ├── index.js            # createTotpAuth() 工厂
│   └── lib/totp.js         # TOTP 算法（HMAC-SHA1/Base32/±1 步）
│       lib/rate-limit.js   # 按 IP 阶梯限速
│       lib/jwt.js          # JWT（HS256，可选）
└── totp-secret.json        # TOTP secret（本地保存，不入库）
```
