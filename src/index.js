'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const express = require('express');
const Redis = require('ioredis');
const { createTotpAuth } = require('../lib/totp-auth');
const { base32Encode } = require('../lib/totp-auth/lib/totp');
const { RateLimiter } = require('totp-auth/lib/rate-limit');

const PORT = Number(process.env.PORT || 3200);
const HOST = process.env.HOST || '0.0.0.0';
const ISSUER = 'HomeAuth';
const SECRET_FILE = path.join(__dirname, '..', 'totp-secret.json');
const JWT_SECRET_FILE = path.join(__dirname, '..', 'jwt-secret');
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);
const SESSION_TTL = SESSION_DAYS * 86400;
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);

function loadOrCreateJwtSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  if (fs.existsSync(JWT_SECRET_FILE)) return fs.readFileSync(JWT_SECRET_FILE, 'utf8').trim();
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(JWT_SECRET_FILE, secret, { mode: 0o600 });
  return secret;
}

const jwtSecret = loadOrCreateJwtSecret();

const auth = createTotpAuth({
  secretFile: SECRET_FILE,
  issuer: ISSUER,
  jwtSecret,
  rateLimit: { maxFailures: 5, lockout: [60, 300, 900] },
});

const redis = new Redis({
  host: REDIS_HOST,
  port: REDIS_PORT,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 2,
  retryStrategy: (times) => Math.min(times * 200, 3000),
});

let redisReady = false;
redis.on('ready', () => {
  redisReady = true;
  console.log(`[auth-server] redis connected ${REDIS_HOST}:${REDIS_PORT} session_ttl=${SESSION_TTL}s`);
});
redis.on('error', (err) => {
  redisReady = false;
  console.error(`[auth-server] redis error: ${err.message}`);
});
redis.on('end', () => {
  redisReady = false;
});

function redisAvailable() {
  return redisReady && redis.status === 'ready';
}

const app = express();
app.disable('x-powered-by');
app.use(express.json());

function clientIp(req) {
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* ============ TOTP 两阶段重置（reset 生成 pending → confirm 验证转正） ============ */

// pending 存储文件：{secret, expiresAt: now + 5min}。不覆盖正式 secret，
// 正式 secret 在 confirm 成功前保持有效（旧验证码仍可登录）
const PENDING_FILE = path.join(__dirname, '..', 'totp-pending.json');
const PENDING_TTL_MS = 300 * 1000; // 5 分钟

function loadPending() {
  if (!fs.existsSync(PENDING_FILE)) return null;
  try {
    const data = JSON.parse(fs.readFileSync(PENDING_FILE, 'utf8'));
    if (!data || typeof data.secret !== 'string' || typeof data.expiresAt !== 'number') return null;
    if (Date.now() > data.expiresAt) {
      try {
        fs.unlinkSync(PENDING_FILE);
      } catch (e) {
        /* 忽略清理失败 */
      }
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

function savePending(secret) {
  fs.mkdirSync(path.dirname(PENDING_FILE), { recursive: true });
  const tmp = `${PENDING_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ secret, expiresAt: Date.now() + PENDING_TTL_MS }, null, 2));
  fs.renameSync(tmp, PENDING_FILE);
}

function deletePending() {
  try {
    fs.unlinkSync(PENDING_FILE);
  } catch (e) {
    /* 无 pending 文件属正常 */
  }
}

// 原子写正式 secret（与模块 saveSecret 同款实现）
function saveFormalSecret(base32Secret) {
  fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true });
  const tmp = `${SECRET_FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ secret: base32Secret }, null, 2));
  fs.renameSync(tmp, SECRET_FILE);
}

// 复用 /api/verify 的 Redis 会话校验：header/query token → Redis GET 存在即通过，滑动续期
async function requireSession(req) {
  const token = tokenFrom(req);
  if (!token) return null;
  if (!redisAvailable()) return null;
  try {
    const user = await redis.get(token);
    if (!user) return null;
    await redis.expire(token, SESSION_TTL);
    return user;
  } catch (err) {
    console.error(`[auth-server] session check error: ${err.message}`);
    return null;
  }
}

function otpauthUriFor(secret) {
  const label = encodeURIComponent(ISSUER);
  return `otpauth://totp/${label}:${label}?secret=${secret}&issuer=${label}&period=30&digits=6&algorithm=SHA1`;
}

// POST /api/totp/reset —— 需登录；生成新 secret 存 pending，不覆盖正式 secret（旧码仍可登录）
app.post('/api/totp/reset', async (req, res) => {
  const user = await requireSession(req);
  if (!user) {
    return res.status(401).json({ code: 'unauthorized', message: '未登录或会话已过期' });
  }
  const secret = base32Encode(crypto.randomBytes(20));
  savePending(secret);
  return res.json({ secret, otpauthUri: otpauthUriFor(secret), expiresIn: 300 });
});

// POST /api/totp/confirm —— 需登录；pending 验证码通过（±1 步）→ 转正写正式 secret 并删 pending
app.post('/api/totp/confirm', async (req, res) => {
  const user = await requireSession(req);
  if (!user) {
    return res.status(401).json({ code: 'unauthorized', message: '未登录或会话已过期' });
  }
  const pending = loadPending();
  if (!pending) {
    return res.status(400).json({ code: 'no_pending', message: '没有待确认的 TOTP 重置' });
  }
  const code = String((req.body && req.body.code) || '').trim();
  if (!auth.verifyCode(pending.secret, code)) {
    deletePending(); // 失败即作废 pending，保持旧正式 secret
    return res.status(400).json({ code: 'invalid_code', message: '验证码错误' });
  }
  saveFormalSecret(pending.secret);
  deletePending();
  return res.json({ ok: true });
});

// POST /api/totp/setup —— 复用 auth.router（首次设置引导），限速/TOTP 逻辑不变
app.use('/api/totp', auth.router);

const loginLimiter = new RateLimiter({ maxFailures: 5, lockout: [60, 300, 900] });

// POST /api/login —— TOTP 校验 + IP 限速 + Redis 会话签发（有状态、滑动过期）
// 注意：必须先于下方 app.use('/api', auth.router)，否则被模块内置的 JWT login 覆盖
app.post('/api/login', async (req, res) => {
  const ip = clientIp(req);
  const status = loginLimiter.status(ip);
  if (status.locked) {
    return res.status(429).json({
      code: 'rate_limited',
      message: 'Too many failed attempts',
      retryAfter: status.retryAfter,
    });
  }

  const secret = auth.getSecret();
  if (!secret) {
    return res.status(403).json({ code: 'totp_setup_required', message: 'TOTP is not configured yet' });
  }

  const code = String((req.body && req.body.code) || '').trim();
  if (!auth.verifyCode(secret, code)) {
    loginLimiter.recordFailure(ip);
    return res.status(401).json({ code: 'invalid_code', message: 'Invalid TOTP code' });
  }

  loginLimiter.recordSuccess(ip);

  if (!redisAvailable()) {
    console.error('[auth-server] login: redis unavailable, refusing to issue session');
    return res.status(500).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  try {
    await redis.set(token, ISSUER, 'EX', SESSION_TTL);
  } catch (err) {
    console.error(`[auth-server] login: redis SET failed: ${err.message}`);
    return res.status(500).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
  return res.json({ token, expiresIn: SESSION_TTL });
});

// /api/setup、/api/reset —— 兼容旧路径（auth.router 内的 /api/login 已被上方自定义路由覆盖）
app.use('/api', auth.router);

function tokenFrom(req) {
  const queryToken = req.query && req.query.token;
  if (queryToken) return String(queryToken).trim();
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  return m ? m[1].trim() : '';
}

app.get('/api/verify', async (req, res) => {
  const token = tokenFrom(req);
  if (!token) {
    return res.status(401).json({ code: 'unauthorized', message: 'Missing token' });
  }
  if (!redisAvailable()) {
    console.error('[auth-server] verify: redis unavailable, refusing');
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
  try {
    const user = await redis.get(token);
    if (!user) {
      return res.status(401).json({ code: 'invalid_token', message: 'Invalid or expired session' });
    }
    await redis.expire(token, SESSION_TTL); // 滑动过期：每次验证刷新 TTL
    const ttl = await redis.ttl(token);
    const exp = Math.floor(Date.now() / 1000) + Math.max(0, ttl);
    res.setHeader("X-Auth-User", user);
    return res.json({ ok: true, user, exp });
  } catch (err) {
    console.error(`[auth-server] verify: redis error: ${err.message}`);
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
});

app.post('/api/logout', async (req, res) => {
  const token = tokenFrom(req);
  if (!redisAvailable()) {
    console.error('[auth-server] logout: redis unavailable, refusing');
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
  try {
    if (token) await redis.del(token);
    return res.json({ ok: true, message: 'Session revoked' });
  } catch (err) {
    console.error(`[auth-server] logout: redis error: ${err.message}`);
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
});

function sanitizeRedirect(value) {
  const raw = typeof value === 'string' && value ? value : '/';
  if (!raw.startsWith('/') && !/^https?:\/\//i.test(raw)) return '/';

  let url;
  try {
    url = /^https?:\/\//i.test(raw)
      ? new URL(raw)
      : new URL(raw, 'http://placeholder.invalid');
  } catch {
    return '/';
  }

  const pathname = url.pathname;
  if (!pathname.endsWith('/') && !/\.[^/]+$/.test(pathname)) {
    url.pathname = pathname + '/';
  }

  return raw.startsWith('/')
    ? url.pathname + url.search + url.hash
    : url.href;
}

const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HomeAuth</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: Helvetica, Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
    background: #f2f2f0;
    color: #111;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .card {
    width: 100%;
    max-width: 420px;
    background: #fff;
    border: 2px solid #111;
    padding: 40px 36px;
  }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 28px; }
  .brand .dot { width: 14px; height: 14px; background: #e30613; flex: none; }
  .brand h1 { font-size: 26px; font-weight: 800; letter-spacing: 1px; text-transform: uppercase; }
  .sub { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 26px; }
  label { display: block; font-size: 12px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px; }
  input#code {
    width: 100%;
    font-size: 28px;
    letter-spacing: 0.55em;
    text-indent: 0.55em;
    text-align: center;
    padding: 12px 0;
    border: none;
    border-bottom: 2px solid #111;
    border-radius: 0;
    outline: none;
    font-variant-numeric: tabular-nums;
  }
  input#code:focus { border-bottom-color: #e30613; }
  button {
    width: 100%;
    margin-top: 22px;
    padding: 14px 0;
    background: #111;
    color: #fff;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 3px;
    text-transform: uppercase;
    border: 2px solid #111;
    cursor: pointer;
  }
  button:hover { background: #fff; color: #111; }
  button:disabled { opacity: .5; cursor: wait; }
  .error { display: none; margin-top: 14px; font-size: 12px; color: #e30613; font-weight: 700; }
  .error.show { display: block; }
  .setup {
    display: none;
    margin-top: 20px;
    border-top: 2px solid #111;
    padding-top: 18px;
  }
  .setup.show { display: block; }
  .setup h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }
  .setup ol { margin: 0 0 12px 18px; font-size: 13px; line-height: 1.8; color: #333; }
  .setup code {
    display: block;
    word-break: break-all;
    font-family: "SF Mono", Menlo, Consolas, monospace;
    font-size: 12px;
    background: #f2f2f0;
    border: 1px solid #ccc;
    padding: 10px;
    margin-bottom: 8px;
  }
  .setup a { color: #111; font-size: 12px; }
  .foot { margin-top: 26px; font-size: 10px; color: #999; letter-spacing: 1px; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <div class="brand"><span class="dot"></span><h1>HomeAuth</h1></div>
  <div class="sub">Single Sign-On</div>

  <label for="code">Authenticator Code</label>
  <input id="code" type="text" inputmode="numeric" pattern="[0-9]*" autocomplete="one-time-code"
         maxlength="6" placeholder="·····" autofocus>
  <div class="error" id="error"></div>
  <button id="btn" type="button">Login</button>

  <div class="setup" id="setup">
    <h2>首次使用 · 绑定身份验证器</h2>
    <ol>
      <li>复制下方密钥，或点击 otpauth 链接添加</li>
      <li>在 Google Authenticator / Authy / 1Password 中新建条目</li>
      <li>回到本页输入 6 位动态码完成登录</li>
    </ol>
    <code id="secret">…</code>
    <a id="uri" href="#" target="_blank" rel="noopener">添加 otpauth:// 条目</a>
  </div>

  <div class="foot">HOME AUTH</div>
</div>
<script>
var REDIRECT = __REDIRECT__;
var form = document.querySelector('.card');
var code = document.getElementById('code');
var btn = document.getElementById('btn');
var error = document.getElementById('error');
var setup = document.getElementById('setup');

function showError(msg) { error.textContent = msg; error.classList.add('show'); }
function hideError() { error.classList.remove('show'); }

// 回跳用 URL query（?token=，OAuth2 风格）：fragment 经 nginx 301 重定向会被丢弃，query 不会
function redirectWithToken(token) {
  var sep = REDIRECT.indexOf('?') === -1 ? '?' : '&';
  window.location.href = REDIRECT + sep + 'token=' + encodeURIComponent(token);
}

btn.addEventListener('click', login);
code.addEventListener('keydown', function (e) { if (e.key === 'Enter') login(); });

function login() {
  var value = code.value.replace(/\\s/g, '');
  if (!/^\\d{6}$/.test(value)) { showError('请输入 6 位数字验证码'); return; }
  hideError();
  btn.disabled = true;
  fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: value })
  }).then(function (res) {
    return res.json().catch(function () { return {}; }).then(function (data) {
      return { status: res.status, data: data };
    });
  }).then(function (r) {
    if (r.data && r.data.token) { redirectWithToken(r.data.token); return; }
    if (r.status === 403 && r.data && r.data.code === 'totp_setup_required') {
      showError('首次使用：请先完成下方绑定，再输入动态码');
      return setupInit();
    }
    if (r.status === 429) {
      showError('尝试次数过多，请 ' + (r.data.retryAfter || 60) + ' 秒后重试');
      return;
    }
    showError('验证码错误，请重试');
  }).catch(function () {
    showError('网络错误，请重试');
  }).finally(function () {
    btn.disabled = false;
    code.value = '';
    code.focus();
  });
}

function setupInit() {
  return fetch('/api/totp/setup', { method: 'POST' }).then(function (res) {
    return res.json();
  }).then(function (data) {
    if (!data.secret) { showError('初始化失败：' + (data.message || '未知错误')); return; }
    document.getElementById('secret').textContent = data.secret;
    document.getElementById('uri').href = data.otpauthUri;
    document.getElementById('uri').textContent = data.otpauthUri;
    setup.classList.add('show');
  }).catch(function () {
    showError('初始化失败，请刷新重试');
  });
}

code.focus();
</script>
</body>
</html>
`;

app.get('/auth', (req, res) => {
  const redirect = sanitizeRedirect(req.query.redirect);
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.set('Cache-Control', 'no-store');
  res.send(LOGIN_PAGE.replace('__REDIRECT__', JSON.stringify(redirect)));
});

app.listen(PORT, HOST, () => {
  console.log(`[auth-server] listening on http://${HOST}:${PORT} issuer=${ISSUER}`);
});
