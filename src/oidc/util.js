'use strict';

/**
 * OIDC provider 内部工具：base64url / 哈希 / 随机串 / PKCE S256 / cookie 解析。
 * 零依赖，只用 node:crypto。
 */

const crypto = require('node:crypto');

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function b64urlDecode(input) {
  return Buffer.from(String(input), 'base64url');
}

function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}

function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

// PKCE S256：code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(String(verifier)).digest('base64url');
}

// 定长常量时间字符串比较（长度不同直接 false，不做 padding）
function timingEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// 不透明 token：32 字节随机 → base64url（43 字符）
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

// 解析 Cookie 头为对象（忽略无 = 的片段）
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 单值查询参数：只接受字符串（重复参数会成数组 → 视为非法）
function str(param) {
  return typeof param === 'string' ? param : '';
}

module.exports = {
  b64url,
  b64urlDecode,
  b64urlJson,
  sha256hex,
  pkceChallenge,
  timingEqual,
  randomToken,
  parseCookies,
  htmlEscape,
  str,
};
