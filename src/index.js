'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const express = require('express');
const Redis = require('ioredis');
const { createTotpAuth } = require('../lib/totp-auth');
const { base32Encode } = require('../lib/totp-auth/lib/totp');
const { RateLimiter } = require('totp-auth/lib/rate-limit');
const { createOidcProvider } = require('./oidc');

const PORT = Number(process.env.PORT || 3200);
const HOST = process.env.HOST || '0.0.0.0';
const ISSUER = 'HomeAuth'; // 会话用户标签（历史命名，非 OIDC issuer）
// 可测试性：密钥 / 注册表所在目录（默认项目根，保证现状不变）
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..');
const SECRET_FILE = path.join(DATA_DIR, 'totp-secret.json');
const JWT_SECRET_FILE = path.join(DATA_DIR, 'jwt-secret');
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 7);
const SESSION_TTL = SESSION_DAYS * 86400;
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = Number(process.env.REDIS_PORT || 6379);
const REDIS_DB = Number(process.env.REDIS_DB || 0);
// OIDC issuer：一律取环境变量 ISSUER，默认本机 3200（不得硬编码真实域名）
const OIDC_ISSUER = process.env.ISSUER || 'http://127.0.0.1:3200';

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
  db: REDIS_DB,
  enableOfflineQueue: false,
  maxRetriesPerRequest: 2,
  retryStrategy: (times) => Math.min(times * 200, 3000),
});

let redisReady = false;
redis.on('ready', () => {
  redisReady = true;
  console.log(`[auth-server] redis connected ${REDIS_HOST}:${REDIS_PORT} db=${REDIS_DB} session_ttl=${SESSION_TTL}s`);
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

// 取客户端 IP：nginx 反代时 req.ip 恒为 127.0.0.1（trust proxy 未开），
// 故优先取 x-forwarded-for 第一段（最贴近真实客户端）→ x-real-ip → req.ip
function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) {
    const first = String(fwd).split(',')[0].trim();
    if (first) return first;
  }
  const real = req.headers['x-real-ip'];
  if (real) return String(real).trim();
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* ============ 设备会话元数据（已登录设备管理的数据源） ============ */

// 索引集合存全部已登记会话 token；hash `auth:session:<token>` 存元数据，EXPIRE 与 token 同 TTL
const SESSION_INDEX_KEY = 'auth:sessions';
function sessionHashKey(token) {
  return 'auth:session:' + token;
}

// 私网判定：私网 IP 直接标记 isLocal='1'，不解析地理位置
function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === '::1' || ip.startsWith('fe80:')) return true;
  if (ip === 'unknown') return true;
  if (ip.indexOf(':') !== -1) return false; // 其他 IPv6 视作公网（尽力解析）
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 127 || a === 10) return true; // 127/8, 10/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16/12
  if (a === 192 && b === 168) return true; // 192.168/16
  if (a === 169 && b === 254) return true; // 169.254/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10
  if (a === 0) return true;
  if (a >= 224) return true;
  return false;
}

// 从 User-Agent 推导设备名（浏览器 · 系统），与登录页 JS（public/index.html）同一套规则
function deviceNameFromUA(ua) {
  if (!ua) return '';
  const name = [];
  let m;
  if ((m = /Edg\/([\d.]+)/.exec(ua))) name.push('Edge ' + m[1]);
  else if (/OPR\//.test(ua) || /Opera/.test(ua)) name.push('Opera');
  else if ((m = /Firefox\/([\d.]+)/.exec(ua))) name.push('Firefox ' + m[1]);
  else if (/SamsungBrowser\//.test(ua)) name.push('Samsung Browser');
  else if (/MicroMessenger\//.test(ua)) name.push('WeChat');
  else if ((m = /CriOS\/([\d.]+)/.exec(ua))) name.push('Chrome ' + m[1]);
  else if ((m = /Chrome\/([\d.]+)/.exec(ua))) name.push('Chrome ' + m[1]);
  else if (/Safari\//.test(ua)) name.push('Safari');
  if (/Windows NT/.test(ua)) name.push('Windows');
  else if (/iPhone|iPad|iPod/.test(ua)) name.push('iOS');
  else if (/Mac OS X/.test(ua)) name.push('macOS');
  else if (/Android/.test(ua)) name.push('Android');
  else if (/CrOS/.test(ua)) name.push('ChromeOS');
  else if (/Linux/.test(ua)) name.push('Linux');
  return name.join(' · ').slice(0, 64);
}

// 地理位置后台异步解析：私网直接跳过（isLocal 登录时已置 1）；公网 fetch ip-api.com，
// 2.5s 超时、失败静默留空；结果 24h 内存缓存，环境变量 AUTH_GEOIP_URL 可覆盖接口地址
const GEOIP_URL =
  process.env.AUTH_GEOIP_URL ||
  'https://ip-api.com/json/{ip}?fields=status,country,regionName,city';
const GEO_CACHE_TTL_MS = 24 * 3600 * 1000;
const geoCache = new Map(); // ip -> { location, ts }

function geoCacheGet(ip) {
  const rec = geoCache.get(ip);
  if (!rec) return undefined;
  if (Date.now() - rec.ts > GEO_CACHE_TTL_MS) {
    geoCache.delete(ip);
    return undefined;
  }
  return rec.location;
}

function geoCacheSet(ip, location) {
  if (geoCache.size > 5000) {
    // 防内存膨胀：超限时清掉一半最旧条目
    let n = 0;
    for (const k of geoCache.keys()) {
      geoCache.delete(k);
      if (++n >= 2500) break;
    }
  }
  geoCache.set(ip, { location, ts: Date.now() });
}

async function resolveLocation(hashKey, ip) {
  try {
    if (!ip || isPrivateIp(ip)) return;
    const cached = geoCacheGet(ip);
    if (cached !== undefined) {
      if (cached) await redis.hset(hashKey, { location: cached });
      return;
    }
    let data = null;
    try {
      const res = await fetch(GEOIP_URL.replace('{ip}', encodeURIComponent(ip)), {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(2500),
      });
      if (res.ok) data = await res.json().catch(() => null);
    } catch (e) {
      // 网络失败静默（留空）
    }
    let location = '';
    if (data && (data.status === 'success' || data.success === true)) {
      location = [data.country, data.regionName || data.region, data.city]
        .filter(Boolean)
        .join(', ')
        .trim();
    }
    geoCacheSet(ip, location);
    if (location) await redis.hset(hashKey, { location });
  } catch (e) {
    // 地理位置解析失败不影响任何流程
  }
}

// 登录后登记设备会话元数据：SADD 索引 + HSET 元数据 + EXPIRE（与 token 同 TTL）。
// 地理位置解析异步执行，不阻塞登录响应
async function registerSessionMeta(token, req) {
  const ip = clientIp(req);
  const rawName =
    req.body && typeof req.body.deviceName === 'string' ? req.body.deviceName.trim() : '';
  const deviceName = (rawName || deviceNameFromUA(req.headers['user-agent'] || '')).slice(0, 64);
  const now = Date.now();
  const hashKey = sessionHashKey(token);
  await redis.sadd(SESSION_INDEX_KEY, token);
  await redis.hset(hashKey, {
    user: ISSUER,
    deviceName,
    ip,
    location: '',
    isLocal: isPrivateIp(ip) ? '1' : '0',
    userAgent: String(req.headers['user-agent'] || '').slice(0, 300),
    createdAt: String(now),
    lastSeenAt: String(now),
  });
  await redis.expire(hashKey, SESSION_TTL);
  resolveLocation(hashKey, ip); // 异步，不 await
}

// 撤销单个会话：删 token + 移出索引 + 删元数据（logout / 设备删除 / 同设备去重共用）
async function revokeSession(token) {
  await redis.del(token);
  await redis.srem(SESSION_INDEX_KEY, token);
  await redis.del(sessionHashKey(token));
}

// 设备指纹去重：登录成功后仅保留最新一次会话。
// 匹配条件 = clientIp 完全相同 + User-Agent 完全相同的字符串比对（ip / userAgent 字段）；
// 元数据缺失的旧会话跳过；全程 try/catch，去重失败不影响登录成功返回
async function dedupSameDeviceSessions(newToken, req) {
  const ip = clientIp(req);
  const ua = String(req.headers['user-agent'] || '').slice(0, 300);
  const members = await redis.smembers(SESSION_INDEX_KEY);
  for (const t of members) {
    if (t === newToken) continue;
    if (!TOKEN_ID_RE.test(t)) continue;
    const meta = await redis.hgetall(sessionHashKey(t));
    if (!meta || !Object.keys(meta).length) continue; // 元数据缺失的旧会话跳过
    if (meta.ip === ip && String(meta.userAgent || '') === ua) {
      await revokeSession(t); // 同设备旧会话全部撤销，只保留本次新会话
    }
  }
}

// verify 成功后节流更新最近活跃：60s 内同一 token 只写一次；历史会话（无元数据）自动补建最小元数据
const lastSeenWrites = new Map(); // token -> ts
async function touchSession(token, req) {
  const now = Date.now();
  const last = lastSeenWrites.get(token);
  if (last && now - last < 60000) return;
  if (lastSeenWrites.size > 20000) lastSeenWrites.clear();
  lastSeenWrites.set(token, now);
  try {
    const hashKey = sessionHashKey(token);
    const exists = await redis.exists(hashKey);
    if (exists === 1) {
      await redis.hset(hashKey, { lastSeenAt: String(now) });
      await redis.expire(hashKey, SESSION_TTL);
    } else {
      // 历史会话补建最小元数据（设备名空、ip 取当前请求）
      const ip = clientIp(req);
      await redis.sadd(SESSION_INDEX_KEY, token);
      await redis.hset(hashKey, {
        user: ISSUER,
        deviceName: '',
        ip,
        location: '',
        isLocal: isPrivateIp(ip) ? '1' : '0',
        userAgent: String(req.headers['user-agent'] || '').slice(0, 300),
        createdAt: String(now),
        lastSeenAt: String(now),
      });
      await redis.expire(hashKey, SESSION_TTL);
      resolveLocation(hashKey, ip);
    }
  } catch (e) {
    console.error(`[auth-server] touchSession error: ${e.message}`);
  }
}

/* ============ TOTP 两阶段重置（reset 生成 pending → confirm 验证转正） ============ */

// pending 存储文件：{secret, expiresAt: now + 5min}。不覆盖正式 secret，
// 正式 secret 在 confirm 成功前保持有效（旧验证码仍可登录）
const PENDING_FILE = path.join(DATA_DIR, 'totp-pending.json');
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
    await registerSessionMeta(token, req); // 登记设备会话元数据（地理位置异步，不阻塞）
    try {
      await dedupSameDeviceSessions(token, req); // 撤销同设备指纹旧会话（失败不影响登录）
    } catch (err) {
      console.error(`[auth-server] login: dedup failed: ${err.message}`);
    }
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
  // nginx 探针转发:父请求 query token 经 X-Auth-Token 头传递(<img> 等无 header 场景)
  const xAuthToken = req.headers['x-auth-token'];
  if (xAuthToken) return String(xAuthToken).trim();
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
  return m ? m[1].trim() : '';
}

// 接口令牌（API Token）：只存哈希，不存明文；固定过期、不滑动续期、不 touchSession。
// 绝不 sadd 进 SESSION_INDEX_KEY、绝不动 admin:session: 前缀、不写设备元数据 hash，
// 与「登录设备管理」完全隔离（本服务内只在 verify 和本函数里触达 api:token: 前缀）
function sha256(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

const API_TOKEN_PREFIX = 'api:token:';
const API_TOKEN_USED_THROTTLE_MS = 3600 * 1000; // lastUsedAt 节流更新窗口（>1 小时才写回）

// 校验接口令牌：Redis GET api:token:<sha256(token)> 存在即有效（过期由 TTL 自动删除）。
// 命中 → 解析 JSON → 返回 { ok, user: meta.name, exp }；解析失败/已过期按未命中返回 null
async function verifyApiToken(token) {
  const key = API_TOKEN_PREFIX + sha256(token);
  let raw;
  try {
    raw = await redis.get(key);
  } catch (err) {
    console.error(`[auth-server] verify: api token check error: ${err.message}`);
    return null;
  }
  if (!raw) return null;
  let meta;
  try {
    meta = JSON.parse(raw);
  } catch (e) {
    return null;
  }
  if (!meta || typeof meta.name !== 'string' || !meta.name) return null;
  if (!(Number(meta.expiresAt) > Date.now())) return null; // 防御性判断（正常由 TTL 兜底）
  try {
    const lastUsed = Number(meta.lastUsedAt) || 0;
    if (Date.now() - lastUsed > API_TOKEN_USED_THROTTLE_MS) {
      meta.lastUsedAt = Date.now();
      const ttl = Math.max(1, Math.floor((Number(meta.expiresAt) - Date.now()) / 1000));
      await redis.set(key, JSON.stringify(meta), 'EX', ttl);
    }
  } catch (err) {
    console.error(`[auth-server] verify: api token lastUsed update error: ${err.message}`);
  }
  return { ok: true, user: meta.name, exp: Number(meta.expiresAt) };
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
      // 会话未命中：追加查接口令牌（固定过期、不滑动续期、不 touchSession）
      const api = await verifyApiToken(token);
      if (!api) {
        return res.status(401).json({ code: 'invalid_token', message: 'Invalid or expired session' });
      }
      // X-Auth-User 必须为 ASCII（HTTP 头限制，中文名会被 Node 拒绝 → ERR_INVALID_CHAR）。
      // 名称 ASCII 化保留可读性（如 api:my-tool），纯中文名则用固定值兜底；JSON body 里仍返回中文原名。
      const hdrUser = String(api.user || '').replace(/[^\x20-\x7e]/g, '').trim().slice(0, 40);
      res.setHeader("X-Auth-User", hdrUser || 'api-token');
      return res.json(api);
    }
    await redis.expire(token, SESSION_TTL); // 滑动过期：每次验证刷新 TTL
    touchSession(token, req); // 节流更新最近活跃 + 历史会话补建元数据（不阻塞响应）
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
    if (token) {
      await revokeSession(token); // 删 token + 移出索引 + 删元数据
    }
    return res.json({ ok: true, message: 'Session revoked' });
  } catch (err) {
    console.error(`[auth-server] logout: redis error: ${err.message}`);
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
});

/* ============ 已登录设备管理（列表 / 重命名 / 删除） ============ */

const TOKEN_ID_RE = /^[a-f0-9]{64}$/i;

// GET /api/sessions —— 按最近活跃倒序返回全部已登录设备；
// 已过期/无元数据的成员惰性移出索引并清理
app.get('/api/sessions', async (req, res) => {
  const user = await requireSession(req);
  if (!user) {
    return res.status(401).json({ code: 'unauthorized', message: '未登录或会话已过期' });
  }
  if (!redisAvailable()) {
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
  const currentToken = tokenFrom(req);
  const nowSec = Math.floor(Date.now() / 1000);
  try {
    const members = await redis.smembers(SESSION_INDEX_KEY);
    const sessions = [];
    const stale = [];
    for (const t of members) {
      if (!TOKEN_ID_RE.test(t)) {
        stale.push(t); // 非法成员：移出索引
        continue;
      }
      let valid = false;
      try {
        valid = (await redis.exists(t)) === 1;
      } catch (e) {
        continue;
      }
      if (!valid) {
        // 已过期：移出索引并清理元数据
        stale.push(t);
        await redis.del(sessionHashKey(t));
        continue;
      }
      let meta;
      try {
        meta = await redis.hgetall(sessionHashKey(t));
      } catch (e) {
        continue;
      }
      if (!meta || !Object.keys(meta).length) {
        // 有效会话但无元数据：惰性移出索引（下次 verify 会补建）
        stale.push(t);
        continue;
      }
      let ttl = 0;
      try {
        ttl = Math.max(0, await redis.ttl(t));
      } catch (e) {
        /* 忽略 TTL 读取失败 */
      }
      sessions.push({
        id: t,
        deviceName: meta.deviceName || '',
        ip: meta.ip || '',
        location: meta.location || '',
        isLocal: meta.isLocal === '1',
        userAgent: meta.userAgent || '',
        createdAt: Number(meta.createdAt || 0),
        lastSeenAt: Number(meta.lastSeenAt || 0),
        expiresAt: nowSec + ttl,
        isCurrent: t === currentToken,
      });
    }
    if (stale.length) {
      await redis.srem(SESSION_INDEX_KEY, ...stale);
    }
    sessions.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
    return res.json({ sessions });
  } catch (e) {
    console.error(`[auth-server] sessions list error: ${e.message}`);
    return res.status(500).json({ code: 'server_error', message: '会话列表查询失败' });
  }
});

// PUT /api/sessions/:id/name —— 重命名设备
app.put('/api/sessions/:id/name', async (req, res) => {
  const user = await requireSession(req);
  if (!user) {
    return res.status(401).json({ code: 'unauthorized', message: '未登录或会话已过期' });
  }
  const id = req.params.id;
  if (!TOKEN_ID_RE.test(id)) {
    return res.status(400).json({ code: 'invalid_id', message: '无效的会话标识' });
  }
  const raw = req.body && typeof req.body.deviceName === 'string' ? req.body.deviceName.trim() : '';
  if (!raw) {
    return res.status(400).json({ code: 'invalid_name', message: '设备名称不能为空' });
  }
  const deviceName = raw.slice(0, 64);
  if (!redisAvailable()) {
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
  try {
    const exists = (await redis.exists(id)) === 1;
    if (!exists) {
      return res.status(404).json({ code: 'not_found', message: '会话不存在或已过期' });
    }
    const hashKey = sessionHashKey(id);
    const meta = await redis.hgetall(hashKey);
    if (!meta || !Object.keys(meta).length) {
      // 有效会话但无元数据：先补建最小元数据再改名
      const now = Date.now();
      const ip = clientIp(req);
      await redis.sadd(SESSION_INDEX_KEY, id);
      await redis.hset(hashKey, {
        user: ISSUER,
        deviceName: '',
        ip,
        location: '',
        isLocal: isPrivateIp(ip) ? '1' : '0',
        userAgent: String(req.headers['user-agent'] || '').slice(0, 300),
        createdAt: String(now),
        lastSeenAt: String(now),
      });
    }
    await redis.hset(hashKey, { deviceName });
    await redis.expire(hashKey, SESSION_TTL);
    return res.json({ ok: true, deviceName });
  } catch (e) {
    console.error(`[auth-server] sessions rename error: ${e.message}`);
    return res.status(500).json({ code: 'server_error', message: '重命名失败' });
  }
});

// DELETE /api/sessions/:id —— 删除设备 token，该设备必须重新认证（幂等）
app.delete('/api/sessions/:id', async (req, res) => {
  const user = await requireSession(req);
  if (!user) {
    return res.status(401).json({ code: 'unauthorized', message: '未登录或会话已过期' });
  }
  const id = req.params.id;
  if (!TOKEN_ID_RE.test(id)) {
    return res.status(400).json({ code: 'invalid_id', message: '无效的会话标识' });
  }
  if (!redisAvailable()) {
    return res.status(503).json({ code: 'redis_unavailable', message: 'Session store unavailable' });
  }
  try {
    await revokeSession(id);
    return res.json({ ok: true });
  } catch (e) {
    console.error(`[auth-server] sessions delete error: ${e.message}`);
    return res.status(500).json({ code: 'server_error', message: '删除会话失败' });
  }
});

/* ============ OIDC Provider（OAuth 2.1 + OIDC Core 1.0） ============ */

const oidc = createOidcProvider({
  redis,
  redisAvailable,
  dataDir: DATA_DIR,
  issuer: OIDC_ISSUER,
  loginPagePath: path.join(__dirname, '..', 'public', 'index.html'),
  sessionTtl: SESSION_TTL,
});
app.use(oidc.router);

app.listen(PORT, HOST, () => {
  console.log(`[auth-server] listening on http://${HOST}:${PORT} issuer=${OIDC_ISSUER} data_dir=${DATA_DIR}`);
});
