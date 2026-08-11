'use strict';

const crypto = require('node:crypto');

const b64urlEncode = (input) =>
  Buffer.from(input).toString('base64').replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_');

const b64urlDecode = (input) =>
  Buffer.from(input.replace(/-/g, '+').replace(/_/g, '/'), 'base64');

/**
 * Parse a human duration like "12h", "30m", "60s", "7d" into milliseconds.
 * Bare numbers are treated as milliseconds.
 * @param {string|number} input
 * @returns {number} milliseconds
 */
function parseDuration(input) {
  if (typeof input === 'number') return input;
  const m = /^(\d+)(ms|s|m|h|d)?$/.exec(String(input).trim());
  if (!m) throw new Error(`jwt: invalid expiresIn "${input}"`);
  const n = Number(m[1]);
  const unit = m[2] || 'ms';
  const map = { ms: 1, s: 1000, m: 60 * 1000, h: 60 * 60 * 1000, d: 24 * 60 * 60 * 1000 };
  return n * map[unit];
}

/**
 * Sign a JWT (HS256). Throws on failure.
 * @param {object} payload Claims to embed.
 * @param {string} secret HMAC secret.
 * @param {string|number} [expiresIn] e.g. "12h" (default 12h).
 * @returns {string} JWT token
 */
function sign(payload, secret, expiresIn = '12h') {
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + Math.floor(parseDuration(expiresIn) / 1000) };

  const header = b64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const claims = b64urlEncode(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', String(secret)).update(`${header}.${claims}`).digest('base64');
  return `${header}.${claims}.${sig.replace(/=+$/g, '').replace(/\+/g, '-').replace(/\//g, '_')}`;
}

/**
 * Verify a JWT (HS256). Throws on invalid/expired token.
 * @param {string} token JWT token.
 * @param {string} secret HMAC secret.
 * @returns {object} decoded payload
 */
function verify(token, secret) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('jwt: malformed token');

  const expected = crypto
    .createHmac('sha256', String(secret))
    .update(`${parts[0]}.${parts[1]}`)
    .digest('base64')
    .replace(/=+$/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const actual = parts[2];
  if (expected.length !== actual.length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(actual))) {
    throw new Error('jwt: invalid signature');
  }

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  } catch {
    throw new Error('jwt: invalid payload');
  }
  if (typeof payload.exp !== 'number') throw new Error('jwt: missing exp');
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('jwt: token expired');
  return payload;
}

module.exports = { sign, verify, parseDuration };
