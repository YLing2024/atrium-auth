'use strict';

/**
 * OIDC provider 内部工具：base64url / 哈希 / 随机串 / PKCE S256 / cookie 解析。
 * 零依赖，只用 node:crypto。
 */

const crypto: typeof import('node:crypto') = require('node:crypto');

function b64url(input: string | Uint8Array): string {
  return Buffer.from(input).toString('base64url');
}

function b64urlDecode(input: unknown): Buffer {
  return Buffer.from(String(input), 'base64url');
}

function b64urlJson(obj: unknown): string {
  return b64url(JSON.stringify(obj));
}

function sha256hex(str: unknown): string {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

// PKCE S256：code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
function pkceChallenge(verifier: unknown): string {
  return crypto.createHash('sha256').update(String(verifier)).digest('base64url');
}

// 定长常量时间字符串比较（长度不同直接 false，不做 padding）
function timingEqual(a: unknown, b: unknown): boolean {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// 不透明 token：32 字节随机 → base64url（43 字符）
function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

// 解析 Cookie 头为对象（忽略无 = 的片段）
function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
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

function htmlEscape(str: unknown): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 单值查询参数：只接受字符串（重复参数会成数组 → 视为非法）
function str(param: unknown): string {
  return typeof param === 'string' ? param : '';
}

// 类型-only 导出：让 TS 认为本文件是模块并拿到 require 的真实形状；
// Node 类型剥离会整段删除，运行时仍是纯 CommonJS。
export type UtilExports = {
  b64url: typeof b64url;
  b64urlDecode: typeof b64urlDecode;
  b64urlJson: typeof b64urlJson;
  sha256hex: typeof sha256hex;
  pkceChallenge: typeof pkceChallenge;
  timingEqual: typeof timingEqual;
  randomToken: typeof randomToken;
  parseCookies: typeof parseCookies;
  htmlEscape: typeof htmlEscape;
  str: typeof str;
};

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
