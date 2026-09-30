/**
 * 手写类型声明 —— 对应同目录 rate-limit.js 的实现（本阶段不改动 .js 一个字节）。
 *
 * 依据（rate-limit.js 原文行号）：
 * - constructor(options?): maxFailures 默认 5、lockout 默认 [60,300,900]、map = Map：rate-limit.js:15-19
 * - recordFailure(ip) → status()：rate-limit.js:37-48
 * - recordSuccess(ip) → map.delete：rate-limit.js:53-55
 * - status(ip) → { locked, retryAfter, failures, tier }：rate-limit.js:61-70
 * - reset() → map.clear：rate-limit.js:72-74
 *
 * 内部方法 `_entry(ip)`（rate-limit.js:21-32）是实例私有实现细节，未列入公开声明。
 */

export type RateLimitOptions = {
  /** 连续失败多少次触发下一档锁定；默认 5 */
  maxFailures?: number;
  /** 每档锁定时长（秒），按顺序递增；默认 [60, 300, 900] */
  lockout?: number[];
};

export type RateLimitStatus = {
  locked: boolean;
  /** 剩余锁定秒数（未锁定为 0） */
  retryAfter: number;
  failures: number;
  tier: number;
};

export type RateLimitEntry = { failures: number; tier: number; lockUntil: number };

export class RateLimiter {
  maxFailures: number;
  lockout: number[];
  map: Map<string, RateLimitEntry>;

  constructor(options?: RateLimitOptions);

  recordFailure(ip: string): RateLimitStatus;
  recordSuccess(ip: string): void;
  status(ip: string): RateLimitStatus;
  reset(): void;
}
