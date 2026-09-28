'use strict';

/**
 * OIDC Provider（OAuth 2.1 + OpenID Connect Core 1.0）路由工厂。
 *
 * 端点：discovery / authorize / token / userinfo / jwks.json / introspect / end_session / revoke
 * 用户验证沿用 TOTP（auth.verifyCode）；会话沿用 Redis。
 *
 * 与既有 /api/* 完全解耦：本模块只新增路由，不改任何旧接口语义。
 */

const express = require('express');

const { KeyStore } = require('./keys');
const { ClientRegistry } = require('./clients');
const {
  sha256hex,
  pkceChallenge,
  timingEqual,
  randomToken,
  parseCookies,
  htmlEscape,
  str,
} = require('./util');

const CODE_TTL = 60; // 授权码 60 秒
const ACCESS_TTL = 3600; // access_token 1 小时
const REFRESH_TTL = 30 * 86400; // refresh_token 30 天

const CODE_PREFIX = 'oidc:code:';
const AT_PREFIX = 'oidc:at:';
const RT_PREFIX = 'oidc:rt:';
const RTCHAIN_PREFIX = 'oidc:rtchain:';
const SSO_PREFIX = 'oidc:sso:';
// 来源会话哈希 → 关联 SSO 令牌哈希集合（登出/删设备时反向彻底撤销共享 cookie）
const SSO_SESSION_INDEX_PREFIX = 'oidc:sso-session:';

/**
 * @param {object} opts
 * @param {import('ioredis').Redis} opts.redis
 * @param {() => boolean} opts.redisAvailable
 * @param {string} opts.dataDir
 * @param {string} opts.issuer
 * @param {string} [opts.subject] 稳定用户标识（sub / preferred_username），默认 linden
 * @param {string} [opts.displayName] 展示名（name），默认 = subject
 * @param {string[]} [opts.legacySubjects] 历史遗留标签，读取时归一化为 subject
 * @param {{getSecret:Function, verifyCode:Function}} opts.auth
 * @param {{status:Function, recordFailure:Function, recordSuccess:Function}} opts.loginLimiter
 * @param {string} opts.loginPagePath
 * @param {number} [opts.sessionTtl] SSO cookie 生命周期（秒）
 * @param {string} [opts.cookieName]
 */
function createOidcProvider(opts) {
  const redis = opts.redis;
  const redisAvailable = opts.redisAvailable || (() => false);
  const issuer = String(opts.issuer || 'http://127.0.0.1:3200').replace(/\/+$/, '');
  // 稳定身份：sub / preferred_username = subject；name = displayName。displayName 缺省回退 subject。
  const subject = String(opts.subject || 'linden');
  const displayName = String(opts.displayName || subject);
  // 历史遗留标签（如 cookie 名 'HomeAuth'）读取时归一化，保证新旧令牌/会话身份一致
  const legacySubjects = new Set(Array.isArray(opts.legacySubjects) ? opts.legacySubjects : []);
  const normalizeSub = (s) => {
    if (!s) return subject;
    return legacySubjects.has(String(s)) ? subject : String(s);
  };
  const dataDir = opts.dataDir;
  const loginPagePath = opts.loginPagePath;
  const sessionTtl = Number(opts.sessionTtl || 7 * 86400);
  const cookieName = opts.cookieName || 'HomeAuth';
  const secureCookies = issuer.startsWith('https://');
  const issuerOrigin = (() => {
    try {
      return new URL(issuer).origin;
    } catch {
      return issuer;
    }
  })();

  const keyStore = new KeyStore(require('node:path').join(dataDir, 'oidc-keys.json'));
  const registry = new ClientRegistry(require('node:path').join(dataDir, 'clients.json'));
  for (const w of registry.warnings) console.warn(`[oidc] ${w}`);

  const router = express.Router();
  router.use(express.urlencoded({ extended: false }));

  // 公开端点允许跨域（SPA / 原生客户端）
  router.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      return res.sendStatus(204);
    }
    return next();
  });

  const wrap = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((err) => {
      console.error(`[oidc] ${req.method} ${req.path} error: ${err.message}`);
      if (!res.headersSent) res.status(500).json({ error: 'server_error' });
    });
  };

  const now = () => Math.floor(Date.now() / 1000);

  /* ---------------- 通用响应 ---------------- */

  function discovery() {
    return {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/jwks.json`,
      end_session_endpoint: `${issuer}/end_session`,
      introspection_endpoint: `${issuer}/introspect`,
      revocation_endpoint: `${issuer}/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      id_token_signing_alg_values_supported: ['ES256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      subject_types_supported: ['public'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'preferred_username',
        'name',
      ],
    };
  }

  function errorPage(res, status, code, description) {
    const body = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>授权失败</title>
<style>
  body { font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
         background:#f7f6f3; color:#171512; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .card { max-width:420px; border:1px solid rgba(23,21,18,.14); padding:48px 40px; }
  h1 { font-size:16px; margin:0 0 12px; letter-spacing:.02em; }
  p { font-size:13px; line-height:1.7; color:#3d3832; margin:0; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; font-size:12px; background:#efede7; padding:2px 6px; }
</style></head>
<body><div class="card"><h1>授权失败</h1>
<p><code>${htmlEscape(code)}</code></p><p>${htmlEscape(description)}</p></div></body></html>`;
    res.status(status).type('html').set('Cache-Control', 'no-store').send(body);
  }

  function tokenError(res, error, description, status = 400) {
    if (error === 'invalid_client') {
      res.setHeader('WWW-Authenticate', 'Basic realm="oidc"');
    }
    return res
      .status(status)
      .set('Cache-Control', 'no-store')
      .set('Pragma', 'no-cache')
      .json({ error, error_description: description });
  }

  /* ---------------- 会话 ---------------- */

  async function validateToken(tok) {
    if (!tok || !redisAvailable()) return null;
    try {
      // 1) 旧登录会话（原始 Redis key）；历史值可能是旧标签，统一归一化身份
      const user = await redis.get(tok);
      if (user) {
        await redis.expire(tok, sessionTtl);
        return { sub: normalizeSub(user), auth_time: now(), sid: sha256hex(tok).slice(0, 16), source: 'legacy' };
      }
      // 2) 首方 SSO 会话（哈希存储）
      const ssoRaw = await redis.get(SSO_PREFIX + sha256hex(tok));
      if (ssoRaw) {
        const s = JSON.parse(ssoRaw);
        await redis.expire(SSO_PREFIX + sha256hex(tok), sessionTtl);
        return { sub: normalizeSub(s.sub), auth_time: s.auth_time, sid: s.sid, source: 'sso' };
      }
      // 3) OIDC access_token
      const atRaw = await redis.get(AT_PREFIX + sha256hex(tok));
      if (atRaw) {
        const a = JSON.parse(atRaw);
        return { sub: normalizeSub(a.sub), auth_time: a.auth_time, sid: a.sid, source: 'access' };
      }
    } catch (err) {
      console.error(`[oidc] session lookup error: ${err.message}`);
    }
    return null;
  }

  async function resolveSession(req) {
    const candidates = [];
    const cookie = parseCookies(req.headers.cookie)[cookieName];
    if (cookie) candidates.push(cookie);
    const q = str(req.query.token);
    if (q) candidates.push(q);
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    if (m) candidates.push(m[1].trim());
    for (const tok of candidates) {
      const s = await validateToken(tok);
      if (s) return { ...s, raw: tok };
    }
    return null;
  }

  async function ensureSsoSession(session, client) {
    if (session.source === 'sso' && session.raw) {
      const h = sha256hex(session.raw);
      await redis.expire(SSO_PREFIX + h, sessionTtl);
      try {
        const raw = await redis.get(SSO_PREFIX + h);
        const rec = raw ? JSON.parse(raw) : null;
        if (rec && rec.session_hash) {
          await redis.expire(SSO_SESSION_INDEX_PREFIX + rec.session_hash, sessionTtl);
        }
      } catch (e) {
        /* 索引续期失败不影响 SSO 本身 */
      }
      return session.raw;
    }
    const token = randomToken(32);
    const h = sha256hex(token);
    const rec = {
      sub: session.sub,
      auth_time: session.auth_time || now(),
      sid: session.sid || h.slice(0, 16),
      client_id: client.client_id,
    };
    // 记录来源会话（旧登录会话 token 的哈希），以便 /api/logout、删除设备、同设备去重
    // 能连同这个共享 cookie 的 SSO 令牌一起撤销（否则登出后 cookie 还能用满 TTL）。
    const sessionHash = session.source === 'legacy' && session.raw ? sha256hex(session.raw) : '';
    if (sessionHash) rec.session_hash = sessionHash;
    await redis.set(SSO_PREFIX + h, JSON.stringify(rec), 'EX', sessionTtl);
    if (sessionHash) {
      const idxKey = SSO_SESSION_INDEX_PREFIX + sessionHash;
      await redis.sadd(idxKey, h);
      await redis.expire(idxKey, sessionTtl);
    }
    return token;
  }

  // 供 /api/verify 兼容识别首方共享 cookie 的 SSO 令牌：命中刷新滑动 TTL，返回身份。
  async function verifySsoToken(token) {
    if (!token || !redisAvailable()) return null;
    try {
      const h = sha256hex(token);
      const key = SSO_PREFIX + h;
      const raw = await redis.get(key);
      if (!raw) return null;
      let rec;
      try {
        rec = JSON.parse(raw);
      } catch {
        return null;
      }
      if (!rec || !rec.sub) return null;
      await redis.expire(key, sessionTtl);
      if (rec.session_hash) {
        await redis.expire(SSO_SESSION_INDEX_PREFIX + rec.session_hash, sessionTtl);
      }
      const ttl = await redis.ttl(key);
      return { sub: normalizeSub(rec.sub), exp: now() + Math.max(0, ttl) };
    } catch (err) {
      console.error(`[oidc] sso verify error: ${err.message}`);
      return null;
    }
  }

  // 彻底撤销：token 可能本身就是 SSO 令牌，也可能是与 SSO 关联的来源会话 token。
  async function revokeSsoForToken(token) {
    if (!token || !redisAvailable()) return;
    try {
      const h = sha256hex(token);
      await redis.del(SSO_PREFIX + h);
      const idxKey = SSO_SESSION_INDEX_PREFIX + h;
      const members = await redis.smembers(idxKey);
      if (members.length) await redis.del(...members.map((m) => SSO_PREFIX + m));
      await redis.del(idxKey);
    } catch (err) {
      console.error(`[oidc] sso revoke error: ${err.message}`);
    }
  }

  function cookieHeader(value, maxAge, domain) {
    const parts = [`${cookieName}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAge}`];
    if (secureCookies) parts.push('Secure');
    if (domain) parts.push(`Domain=${domain}`);
    return parts.join('; ');
  }

  function setSsoCookie(res, token, client) {
    res.append('Set-Cookie', cookieHeader(token, sessionTtl, client && client.cookie_domain));
  }

  function clearSsoCookie(res, domain) {
    res.append('Set-Cookie', cookieHeader('', 0, domain));
  }

  /* ---------------- 令牌签发 ---------------- */

  async function issueTokens(params) {
    const t = now();
    const { sub, client, scope, nonce, auth_time, sid } = params;

    const accessToken = randomToken(32);
    await redis.set(
      AT_PREFIX + sha256hex(accessToken),
      JSON.stringify({ sub, client_id: client.client_id, scope, sid, auth_time, exp: t + ACCESS_TTL }),
      'EX',
      ACCESS_TTL
    );

    const idClaims = {
      iss: issuer,
      sub,
      aud: client.client_id,
      exp: t + ACCESS_TTL,
      iat: t,
      auth_time: auth_time || t,
      preferred_username: subject,
      name: displayName,
    };
    if (nonce) idClaims.nonce = nonce;
    if (sid) idClaims.sid = sid;
    const idToken = keyStore.signJwt(idClaims);

    const out = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL,
      id_token: idToken,
      scope: scope || 'openid',
    };

    if (client.grant_types.includes('refresh_token')) {
      const refreshToken = randomToken(32);
      const chain = params.chain || randomToken(16);
      const rh = sha256hex(refreshToken);
      await redis.set(
        RT_PREFIX + rh,
        JSON.stringify({ sub, client_id: client.client_id, scope, sid, auth_time, chain, used: false }),
        'EX',
        REFRESH_TTL
      );
      await redis.sadd(RTCHAIN_PREFIX + chain, rh);
      await redis.expire(RTCHAIN_PREFIX + chain, REFRESH_TTL);
      out.refresh_token = refreshToken;
    }
    return out;
  }

  async function revokeChain(chain) {
    if (!chain) return;
    const members = await redis.smembers(RTCHAIN_PREFIX + chain);
    const keys = members.map((h) => RT_PREFIX + h);
    if (keys.length) await redis.del(...keys);
    await redis.del(RTCHAIN_PREFIX + chain);
  }

  function clientAuth(req) {
    let clientId = str(req.body && req.body.client_id);
    let secret = str(req.body && req.body.client_secret);
    const header = req.headers.authorization || '';
    if (/^Basic\s+/i.test(header)) {
      let decoded;
      try {
        decoded = Buffer.from(header.replace(/^Basic\s+/i, ''), 'base64').toString('utf8');
      } catch {
        decoded = '';
      }
      const idx = decoded.indexOf(':');
      if (idx !== -1) {
        let id = decoded.slice(0, idx);
        let sec = decoded.slice(idx + 1);
        // RFC 6749 §2.3.1: id/secret 先 form-urlencode 再 base64
        try {
          id = decodeURIComponent(id);
          sec = decodeURIComponent(sec);
        } catch {
          /* 客户端未编码时按原样使用 */
        }
        clientId = id;
        secret = sec;
      }
    }
    return { clientId, secret };
  }

  /* ---------------- 端点 ---------------- */

  router.get(
    '/.well-known/openid-configuration',
    wrap(async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      res.json(discovery());
    })
  );

  router.get(
    '/jwks.json',
    wrap(async (req, res) => {
      res.setHeader('Cache-Control', 'public, max-age=300');
      res.json(keyStore.jwks());
    })
  );

  // GET /authorize
  router.get(
    '/authorize',
    wrap(async (req, res) => {
      const clientId = str(req.query.client_id);
      const redirectUri = str(req.query.redirect_uri);
      const responseType = str(req.query.response_type);
      const scope = str(req.query.scope);
      const state = str(req.query.state);
      const nonce = str(req.query.nonce);
      const codeChallenge = str(req.query.code_challenge);
      const codeChallengeMethod = str(req.query.code_challenge_method);
      const prompt = str(req.query.prompt);
      const maxAge = str(req.query.max_age);

      const client = registry.get(clientId);
      if (!client) return errorPage(res, 400, 'invalid_request', '未知的 client_id');
      // ★ 精确匹配，堵开放重定向 / token 外泄
      if (!registry.matchRedirect(client, redirectUri)) {
        return errorPage(res, 400, 'invalid_request', 'redirect_uri 未注册或与注册值不完全一致');
      }
      if (responseType !== 'code') {
        return errorPage(res, 400, 'unsupported_response_type', '仅支持 response_type=code');
      }
      if (!scope.split(/\s+/).filter(Boolean).includes('openid')) {
        return errorPage(res, 400, 'invalid_scope', 'scope 必须包含 openid');
      }
      const isPublic = !registry.isConfidential(client);
      if (codeChallenge) {
        if (codeChallengeMethod !== 'S256') {
          return errorPage(res, 400, 'invalid_request', 'code_challenge_method 仅支持 S256');
        }
      } else if (isPublic && !client.first_party) {
        // 首方客户端由 auth-server 自己完成 code→token，code 不落浏览器，无需 PKCE
        return errorPage(res, 400, 'invalid_request', '公开客户端必须携带 code_challenge (S256)');
      }

      let session = await resolveSession(req);
      let forceLogin = false;
      if (prompt === 'login' && !str(req.query.token)) forceLogin = true;
      if (maxAge && session) {
        const n = Number(maxAge);
        if (Number.isFinite(n) && n >= 0 && now() - (session.auth_time || 0) > n) forceLogin = true;
      }
      if (forceLogin) session = null;

      if (!session) {
        // 复用现有 TOTP 登录页：登录成功后带 token 回跳本 authorize
        return res.redirect(302, '/auth?redirect=' + encodeURIComponent(req.originalUrl));
      }

      const authTime = session.auth_time || now();
      const code = randomToken(32);
      const rec = {
        client_id: client.client_id,
        redirect_uri: redirectUri,
        code_challenge: codeChallenge || '',
        code_challenge_method: codeChallenge ? 'S256' : '',
        nonce,
        sub: session.sub,
        auth_time: authTime,
        scope,
        sid: session.sid || '',
      };
      await redis.set(CODE_PREFIX + sha256hex(code), JSON.stringify(rec), 'EX', CODE_TTL);

      if (client.first_party) {
        // 首方：auth-server 自己完成 code→token，落共享 cookie，再回跳
        let tokens;
        try {
          tokens = await exchangeCode({
            code,
            clientId: client.client_id,
            redirectUri,
            codeVerifier: '',
            client,
          });
        } catch (err) {
          console.error(`[oidc] first_party exchange failed: ${err.message}`);
          return errorPage(res, 500, 'server_error', '首方令牌交换失败');
        }
        const ssoToken = await ensureSsoSession(session, client);
        setSsoCookie(res, ssoToken, client);
        const url = new URL(redirectUri);
        // 首方已换完 token，不把 code 暴露给前端；只回 state（若有）
        if (state) url.searchParams.set('state', state);
        void tokens;
        return res.redirect(302, url.toString());
      }

      const ssoToken = await ensureSsoSession(session, client);
      setSsoCookie(res, ssoToken, client);
      const url = new URL(redirectUri);
      url.searchParams.set('code', code);
      if (state) url.searchParams.set('state', state);
      return res.redirect(302, url.toString());
    })
  );

  /**
   * 消耗授权码并签发令牌（/token 与首方模式共用）。
   * 失败抛 Error（带 .oauthError / .oauthDescription）。
   */
  async function exchangeCode({ code, clientId, redirectUri, codeVerifier, client }) {
    const raw = await redis.getdel(CODE_PREFIX + sha256hex(code));
    if (!raw) throw oauthErr('invalid_grant', '授权码无效、已使用或已过期');
    let rec;
    try {
      rec = JSON.parse(raw);
    } catch {
      throw oauthErr('invalid_grant', '授权码记录损坏');
    }
    if (rec.client_id !== client.client_id) throw oauthErr('invalid_grant', '授权码与客户端不匹配');
    if (rec.redirect_uri !== redirectUri) throw oauthErr('invalid_grant', 'redirect_uri 与授权时不一致');
    if (rec.code_challenge) {
      if (!codeVerifier) throw oauthErr('invalid_grant', '缺少 code_verifier');
      if (!timingEqual(pkceChallenge(codeVerifier), rec.code_challenge)) {
        throw oauthErr('invalid_grant', 'PKCE 校验失败');
      }
    } else if (!registry.isConfidential(client) && !client.first_party) {
      throw oauthErr('invalid_grant', '公开客户端必须使用 PKCE');
    }
    return issueTokens({
      sub: rec.sub,
      client,
      scope: rec.scope,
      nonce: rec.nonce,
      auth_time: rec.auth_time,
      sid: rec.sid,
    });
  }

  function oauthErr(error, description) {
    const e = new Error(description);
    e.oauthError = error;
    e.oauthDescription = description;
    return e;
  }

  // POST /token
  router.post(
    '/token',
    wrap(async (req, res) => {
      if (!redisAvailable()) {
        return tokenError(res, 'temporarily_unavailable', '会话存储不可用', 503);
      }
      const grantType = str(req.body && req.body.grant_type);
      const { clientId, secret } = clientAuth(req);
      const client = registry.get(clientId);
      if (!client) return tokenError(res, 'invalid_client', '未知客户端', 401);
      if (!registry.checkSecret(client, secret)) return tokenError(res, 'invalid_client', '客户端密钥错误', 401);
      if (!registry.allowsGrant(client, grantType)) {
        return tokenError(res, 'unauthorized_client', '该客户端不允许此 grant_type');
      }

      try {
        if (grantType === 'authorization_code') {
          const code = str(req.body && req.body.code);
          const redirectUri = str(req.body && req.body.redirect_uri);
          const codeVerifier = str(req.body && req.body.code_verifier);
          if (!code) return tokenError(res, 'invalid_request', '缺少 code');
          const tokens = await exchangeCode({
            code,
            clientId: client.client_id,
            redirectUri,
            codeVerifier,
            client,
          });
          return sendTokens(res, tokens);
        }
        if (grantType === 'refresh_token') {
          const refreshToken = str(req.body && req.body.refresh_token);
          if (!refreshToken) return tokenError(res, 'invalid_request', '缺少 refresh_token');
          const h = sha256hex(refreshToken);
          const key = RT_PREFIX + h;
          const raw = await redis.get(key);
          if (!raw) return tokenError(res, 'invalid_grant', 'refresh_token 无效或已过期');
          let rec;
          try {
            rec = JSON.parse(raw);
          } catch {
            return tokenError(res, 'invalid_grant', 'refresh_token 记录损坏');
          }
          if (rec.client_id !== client.client_id) {
            return tokenError(res, 'invalid_grant', 'refresh_token 与客户端不匹配');
          }
          if (rec.used) {
            // ★ 重放：整条链作废
            await revokeChain(rec.chain);
            return tokenError(res, 'invalid_grant', 'refresh_token 已使用，整条链作废');
          }
          const ttl = await redis.ttl(key);
          rec.used = true;
          await redis.set(key, JSON.stringify(rec), 'EX', ttl > 0 ? ttl : REFRESH_TTL);
          const tokens = await issueTokens({
            sub: rec.sub,
            client,
            scope: rec.scope,
            auth_time: rec.auth_time,
            sid: rec.sid,
            chain: rec.chain,
          });
          return sendTokens(res, tokens);
        }
        return tokenError(res, 'unsupported_grant_type', '不支持的 grant_type');
      } catch (err) {
        if (err.oauthError) return tokenError(res, err.oauthError, err.oauthDescription);
        throw err;
      }
    })
  );

  function sendTokens(res, tokens) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    return res.json(tokens);
  }

  // GET/POST /userinfo
  async function userinfoHandler(req, res) {
    const header = req.headers.authorization || '';
    const m = /^Bearer\s+(.+)$/i.exec(header);
    const token = m ? m[1].trim() : str(req.body && req.body.access_token);
    if (!token) {
      res.setHeader('WWW-Authenticate', 'Bearer realm="oidc"');
      return res.status(401).json({ error: 'invalid_token', error_description: '缺少 access_token' });
    }
    if (!redisAvailable()) {
      return res.status(503).json({ error: 'temporarily_unavailable' });
    }
    let rec = null;
    try {
      const raw = await redis.get(AT_PREFIX + sha256hex(token));
      if (raw) rec = JSON.parse(raw);
    } catch (err) {
      console.error(`[oidc] userinfo error: ${err.message}`);
      return res.status(503).json({ error: 'temporarily_unavailable' });
    }
    if (!rec) {
      res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
      return res.status(401).json({ error: 'invalid_token', error_description: 'access_token 无效或已过期' });
    }
    const subj = normalizeSub(rec.sub);
    const body = { sub: subj, preferred_username: subj, name: displayName };
    if (rec.sid) body.sid = rec.sid;
    res.setHeader('Cache-Control', 'no-store');
    return res.json(body);
  }
  router.get('/userinfo', wrap(userinfoHandler));
  router.post('/userinfo', wrap(userinfoHandler));

  // POST /introspect（RFC 7662）
  async function introspectHandler(req, res) {
    const header = req.headers.authorization || '';
    const m = /^Bearer\s+(.+)$/i.exec(header);
    const token = str(req.body && req.body.token) || str(req.query.token) || (m ? m[1].trim() : '');
    const inactive = () => res.status(200).json({ active: false });
    if (!token) return inactive();
    if (!redisAvailable()) return res.status(503).json({ error: 'temporarily_unavailable' });
    try {
      const h = sha256hex(token);
      const atRaw = await redis.get(AT_PREFIX + h);
      if (atRaw) {
        const a = JSON.parse(atRaw);
        return res.json({
          active: true,
          sub: normalizeSub(a.sub),
          scope: a.scope,
          client_id: a.client_id,
          exp: a.exp,
          token_type: 'access_token',
        });
      }
      const rtRaw = await redis.get(RT_PREFIX + h);
      if (rtRaw) {
        const r = JSON.parse(rtRaw);
        if (r.used) return inactive();
        return res.json({
          active: true,
          sub: normalizeSub(r.sub),
          scope: r.scope,
          client_id: r.client_id,
          token_type: 'refresh_token',
        });
      }
      const ssoRaw = await redis.get(SSO_PREFIX + h);
      if (ssoRaw) {
        const s = JSON.parse(ssoRaw);
        return res.json({
          active: true,
          sub: normalizeSub(s.sub),
          scope: 'openid',
          client_id: s.client_id || undefined,
          token_type: 'sso_session',
        });
      }
      // 兼容：旧登录会话原始 token
      const user = await redis.get(token);
      if (user) {
        return res.json({ active: true, sub: normalizeSub(user), scope: 'openid', token_type: 'session' });
      }
    } catch (err) {
      console.error(`[oidc] introspect error: ${err.message}`);
      return res.status(503).json({ error: 'temporarily_unavailable' });
    }
    return inactive();
  }
  router.post('/introspect', wrap(introspectHandler));
  router.get('/introspect', wrap(introspectHandler));

  // POST /revoke（RFC 7009）
  router.post(
    '/revoke',
    wrap(async (req, res) => {
      const { clientId, secret } = clientAuth(req);
      const client = registry.get(clientId);
      if (!client) return tokenError(res, 'invalid_client', '未知客户端', 401);
      if (!registry.checkSecret(client, secret)) return tokenError(res, 'invalid_client', '客户端密钥错误', 401);
      const token = str(req.body && req.body.token);
      if (!token) return res.json({});
      if (!redisAvailable()) return res.status(503).json({ error: 'temporarily_unavailable' });
      try {
        const h = sha256hex(token);
        await redis.del(AT_PREFIX + h);
        const rtRaw = await redis.get(RT_PREFIX + h);
        if (rtRaw) {
          let chain = '';
          try {
            chain = JSON.parse(rtRaw).chain;
          } catch {
            /* ignore */
          }
          await revokeChain(chain);
        }
        await revokeSsoForToken(token);
        await redis.del(token); // 旧会话
      } catch (err) {
        console.error(`[oidc] revoke error: ${err.message}`);
      }
      return res.json({});
    })
  );

  // GET/POST /end_session（RP-Initiated Logout）
  async function endSessionHandler(req, res) {
    const src = req.method === 'POST' ? req.body : req.query;
    const cookieToken = parseCookies(req.headers.cookie)[cookieName];
    const idTokenHint = str(src.id_token_hint);
    const postLogout = str(src.post_logout_redirect_uri);

    let hintClient = null;
    let hintDomain = '';
    if (idTokenHint) {
      try {
        const payload = keyStore.verifyJwt(idTokenHint, { issuer });
        hintClient = registry.get(payload.aud);
        if (hintClient) hintDomain = hintClient.cookie_domain;
      } catch (err) {
        if (!postLogout) return errorPage(res, 400, 'invalid_request', `id_token_hint 无效: ${err.message}`);
      }
    }

    // 撤销当前 SSO 会话（同时清掉来源会话的反向索引）
    if (cookieToken) {
      await revokeSsoForToken(cookieToken);
    }
    clearSsoCookie(res, hintDomain);

    if (postLogout) {
      const clientId = str(src.client_id);
      const client = hintClient || registry.get(clientId);
      if (!client || !registry.matchPostLogout(client, postLogout)) {
        return errorPage(res, 400, 'invalid_request', 'post_logout_redirect_uri 未列入白名单');
      }
      return res.redirect(302, postLogout);
    }

    return res
      .status(200)
      .type('html')
      .set('Cache-Control', 'no-store')
      .send(
        '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>已退出</title></head>' +
          '<body style="font-family:sans-serif;text-align:center;padding:80px;color:#171512">已退出登录</body></html>'
      );
  }
  router.get('/end_session', wrap(endSessionHandler));
  router.post('/end_session', wrap(endSessionHandler));

  /* ---------------- 旧登录页（?redirect= 白名单） ---------------- */

  function isAllowedRedirect(raw) {
    if (typeof raw !== 'string' || !raw) return false;
    if (raw.startsWith('/')) return !raw.startsWith('//') && !raw.includes('\\');
    let u;
    try {
      u = new URL(raw);
    } catch {
      return false;
    }
    if (u.origin === issuerOrigin) return true;
    for (const client of registry.clients.values()) {
      if (client.redirect_uris.includes(raw)) return true;
    }
    return false;
  }

  router.get(
    '/auth',
    wrap(async (req, res) => {
      const redirect = str(req.query.redirect);
      if (redirect) {
        if (!isAllowedRedirect(redirect)) {
          console.warn(`[oidc] /auth 拒绝未列入白名单的 redirect: ${redirect}`);
          res.setHeader('X-Auth-Deprecated', 'redirect-not-allowed');
          return res.sendFile(loginPagePath);
        }
        // 旧 ?redirect= 流程：标记 Deprecated，后续由调用方迁移到 /authorize
        res.setHeader('Deprecated', 'true');
        res.setHeader('X-Auth-Deprecated', 'redirect');
      }
      return res.sendFile(loginPagePath);
    })
  );

  return {
    router,
    keyStore,
    registry,
    discovery,
    // 供 /api/verify 与 revokeSession 复用（SSO 令牌双向兼容 / 彻底撤销）
    verifySsoToken,
    revokeSsoForToken,
    // 供测试/诊断
    _internal: { exchangeCode, resolveSession, validateToken, issueTokens },
  };
}

module.exports = { createOidcProvider };
