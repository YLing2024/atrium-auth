/**
 * 手写类型声明 —— 对应同目录 totp.js 的实现（本阶段不改动 .js 一个字节）。
 *
 * 依据（totp.js 原文行号）：
 * - 导出集合：totp.js:101-108（STEP/DIGITS/base32Encode/base32Decode/generateTotp/verifyTotp）
 * - STEP=30、DIGITS=6：totp.js:5-6
 * - base32Encode(input: Buffer): string：totp.js:14-28
 * - base32Decode(input): Buffer：totp.js:35-56
 * - generateTotp(secret, time?): string：totp.js:64-80（secret 为 Base32 字符串或原始 Buffer）
 * - verifyTotp(secret, code, opts?): boolean：totp.js:89-99（opts.window / opts.time）
 */

export const STEP: number;
export const DIGITS: number;

export function base32Encode(input: Uint8Array): string;

export function base32Decode(input: string): Buffer;

export function generateTotp(secret: string | Buffer, time?: number): string;

export function verifyTotp(
  secret: string | Buffer,
  code: string,
  opts?: { window?: number; time?: number }
): boolean;
