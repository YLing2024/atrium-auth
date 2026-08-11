'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { base32Encode, verifyTotp } = require('./lib/totp');
const { RateLimiter } = require('./lib/rate-limit');
const jwt = require('./lib/jwt');

let express;
try {
  express = require('express'); // host app supplies it (peerDependency)
} catch {
  express = null;
}

/**
 * Build a reusable TOTP auth bundle: Express router + middleware + pure helpers.
 *
 * @param {object} options
 * @param {string} options.secretFile   Path (JSON) where the TOTP secret is persisted.
 * @param {string} [options.issuer='totp-auth'] Issuer label used in otpauth URIs.
 * @param {string} [options.jwtSecret]  HMAC secret for JWT signing (required for /reset & middleware).
 * @param {string|number} [options.jwtExpiresIn='12h'] JWT lifetime, e.g. "12h".
 * @param {{maxFailures?: number, lockout?: number[]}} [options.rateLimit]
 * @returns {{router: object, middleware: Function, verifyCode: Function, getSecret: Function}}
 */
function createTotpAuth(options = {}) {
  const {
    secretFile,
    issuer = 'totp-auth',
    jwtSecret,
    jwtExpiresIn = '12h',
    rateLimit,
  } = options;

  if (!secretFile) throw new Error('totp-auth: options.secretFile is required');
  if (!jwtSecret) throw new Error('totp-auth: options.jwtSecret is required');

  const limiter = new RateLimiter(rateLimit);
  const TOTP_WINDOW = 1; // +/- one 30s step on login

  function loadSecret() {
    if (!fs.existsSync(secretFile)) return null;
    try {
      const data = JSON.parse(fs.readFileSync(secretFile, 'utf8'));
      return typeof data.secret === 'string' ? data.secret : null;
    } catch {
      return null;
    }
  }

  function saveSecret(base32Secret) {
    fs.mkdirSync(path.dirname(secretFile), { recursive: true });
    const tmp = `${secretFile}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ secret: base32Secret }, null, 2));
    fs.renameSync(tmp, secretFile);
  }

  function generateSecret() {
    const raw = crypto.randomBytes(20);
    return base32Encode(raw);
  }

  function otpauthUri(secret) {
    const label = encodeURIComponent(issuer);
    return `otpauth://totp/${label}:${label}?secret=${secret}&issuer=${label}&period=30&digits=6&algorithm=SHA1`;
  }

  function clientIp(req) {
    return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
  }

  // ---- middleware: require a valid Bearer JWT ----
  function middleware(req, res, next) {
    const header = req.headers.authorization || '';
    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ code: 'unauthorized', message: 'Missing Bearer token' });
    }
    try {
      req.auth = jwt.verify(token, jwtSecret);
      return next();
    } catch {
      return res.status(401).json({ code: 'invalid_token', message: 'Invalid or expired token' });
    }
  }

  // ---- routes ----
  const router = express ? express.Router() : null;
  if (router) {
    // POST /setup — only usable while no secret is configured.
    router.post('/setup', (req, res) => {
      if (loadSecret()) {
        return res.status(409).json({ code: 'totp_already_setup', message: 'TOTP already configured' });
      }
      const secret = generateSecret();
      saveSecret(secret);
      return res.json({ secret, otpauthUri: otpauthUri(secret) });
    });

    // POST /reset — requires JWT, regenerates the secret.
    router.post('/reset', middleware, (req, res) => {
      const secret = generateSecret();
      saveSecret(secret);
      return res.json({ secret, otpauthUri: otpauthUri(secret) });
    });

    // POST /login — verify TOTP code, issue JWT, rate-limit by IP.
    router.post('/login', (req, res) => {
      const ip = clientIp(req);
      const status = limiter.status(ip);
      if (status.locked) {
        return res.status(429).json({
          code: 'rate_limited',
          message: 'Too many failed attempts',
          retryAfter: status.retryAfter,
        });
      }

      const secret = loadSecret();
      if (!secret) {
        return res.status(403).json({ code: 'totp_setup_required', message: 'TOTP is not configured yet' });
      }

      const code = String((req.body && req.body.code) || '').trim();
      if (!verifyTotp(secret, code, { window: TOTP_WINDOW })) {
        limiter.recordFailure(ip);
        return res.status(401).json({ code: 'invalid_code', message: 'Invalid TOTP code' });
      }

      limiter.recordSuccess(ip);
      const token = jwt.sign({ sub: issuer, ip }, jwtSecret, jwtExpiresIn);
      return res.json({ token, expiresIn: jwtExpiresIn });
    });
  }

  // ---- pure helper (re-export) ----
  function verifyCode(secret, code) {
    return verifyTotp(secret, code, { window: TOTP_WINDOW });
  }

  return {
    router,
    middleware,
    verifyCode,
    getSecret: loadSecret,
  };
}

module.exports = { createTotpAuth };
