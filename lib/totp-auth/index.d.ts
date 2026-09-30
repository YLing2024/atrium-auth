/**
 * 手写类型声明 —— 对应同目录 index.js 的实现（本阶段不改动 .js 一个字节）。
 *
 * 依据（index.js 原文行号）：
 * - 工厂签名与参数：index.js:29-39（options 解构 + 必填校验 secretFile/jwtSecret）
 * - 返回对象：index.js:144-149（router / middleware / verifyCode / getSecret）
 * - middleware 形状：index.js:76-88
 * - verifyCode：index.js:140-142（verifyTotp ±1 步）
 * - getSecret：index.js:44-52 loadSecret（无文件/解析失败返回 null）
 *
 * 说明：index.js 用 require('express') 且 try/catch 兜底，host 未提供 express 时
 * router 为 null（index.js:11-16、91）。故 router 类型为 Router | null。
 */
import type { RateLimitOptions } from './lib/rate-limit.js';

export type TotpAuthOptions = {
  /** Path (JSON) where the TOTP secret is persisted. required */
  secretFile: string;
  /** Issuer label used in otpauth URIs. default 'totp-auth' */
  issuer?: string;
  /** HMAC secret for JWT signing (required for /reset & middleware). required */
  jwtSecret: string;
  /** JWT lifetime, e.g. "12h" (default '12h'). */
  jwtExpiresIn?: string | number;
  /** In-memory per-IP tiered lockout options. */
  rateLimit?: RateLimitOptions;
};

export type TotpAuth = {
  /** Express router; null when the host app did not supply express. */
  router: import('express').Router | null;
  /** Requires a valid `Authorization: Bearer <JWT>`; sets req.auth = payload on success. */
  middleware: import('express').RequestHandler;
  /** Verify a TOTP code with ±1 step tolerance. */
  verifyCode: (secret: string | Buffer, code: string) => boolean;
  /** Read the persisted secret; null when missing or unparsable. */
  getSecret: () => string | null;
};

export function createTotpAuth(options: TotpAuthOptions): TotpAuth;
