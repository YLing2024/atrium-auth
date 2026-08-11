'use strict';

/**
 * In-memory, per-IP tiered lockout limiter.
 *
 * Tiers: each round of maxFailures consecutive failures triggers the next
 * (longer) lockout period. A successful login clears the record.
 *
 * Default: 5 failures -> 60s lock -> 5 more -> 300s lock -> 5 more -> 900s lock.
 */
class RateLimiter {
  /**
   * @param {{maxFailures?: number, lockout?: number[]}} [options]
   */
  constructor(options = {}) {
    this.maxFailures = options.maxFailures == null ? 5 : options.maxFailures;
    this.lockout = options.lockout == null ? [60, 300, 900] : options.lockout;
    this.map = new Map();
  }

  _entry(ip) {
    let e = this.map.get(ip);
    if (!e) {
      e = { failures: 0, tier: 0, lockUntil: 0 };
      this.map.set(ip, e);
    }
    if (e.lockUntil && e.lockUntil <= Date.now()) {
      e.lockUntil = 0;
      e.failures = 0;
    }
    return e;
  }

  /**
   * Record a failed attempt. Returns the current lockout state.
   */
  recordFailure(ip) {
    const e = this._entry(ip);
    e.failures += 1;
    if (e.failures >= this.maxFailures) {
      const tier = Math.min(e.tier, this.lockout.length - 1);
      const seconds = this.lockout[tier];
      e.lockUntil = Date.now() + seconds * 1000;
      e.failures = 0;
      e.tier = Math.min(e.tier + 1, this.lockout.length);
    }
    return this.status(ip);
  }

  /**
   * Clear the record for an IP after a successful attempt.
   */
  recordSuccess(ip) {
    this.map.delete(ip);
  }

  /**
   * @returns {{locked: boolean, retryAfter: number, failures: number, tier: number}}
   *          retryAfter is seconds remaining until the lock lifts (0 if unlocked).
   */
  status(ip) {
    const e = this._entry(ip);
    const locked = e.lockUntil > Date.now();
    return {
      locked,
      retryAfter: locked ? Math.max(0, Math.ceil((e.lockUntil - Date.now()) / 1000)) : 0,
      failures: e.failures,
      tier: e.tier,
    };
  }

  reset() {
    this.map.clear();
  }
}

module.exports = { RateLimiter };
