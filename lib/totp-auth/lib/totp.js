'use strict';

const crypto = require('node:crypto');

const STEP = 30;
const DIGITS = 6;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode a Buffer into a Base32 (RFC 4648) string (no padding).
 * @param {Buffer} input
 * @returns {string}
 */
function base32Encode(input) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

/**
 * Decode a Base32 (RFC 4648) string into a Buffer.
 * @param {string} input
 * @returns {Buffer}
 */
function base32Decode(input) {
  const cleaned = String(input).toUpperCase().replace(/\s+/g, '').replace(/=+$/, '');
  if (!cleaned.length) {
    throw new Error('base32: empty secret');
  }
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error(`base32: invalid character "${ch}"`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

/**
 * Generate a TOTP code for the given secret at a point in time.
 * @param {string|Buffer} secret Base32 encoded secret (or raw Buffer).
 * @param {number} [time] Unix time in seconds; defaults to now.
 * @returns {string} DIGITS-length numeric code.
 */
function generateTotp(secret, time) {
  const key = Buffer.isBuffer(secret) ? secret : base32Decode(secret);
  const seconds = typeof time === 'number' ? time : Math.floor(Date.now() / 1000);
  const counter = Math.floor(seconds / STEP);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);

  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Verify a TOTP code with a tolerance window.
 * @param {string|Buffer} secret Base32 encoded secret (or raw Buffer).
 * @param {string} code The code to verify.
 * @param {{window?: number, time?: number}} [opts] window = +/- steps allowed.
 * @returns {boolean}
 */
function verifyTotp(secret, code, opts = {}) {
  const window = opts.window == null ? 0 : opts.window;
  const time = typeof opts.time === 'number' ? opts.time : Math.floor(Date.now() / 1000);
  const expected = String(code).replace(/\s+/g, '');
  for (let step = -window; step <= window; step += 1) {
    if (generateTotp(secret, time + step * STEP) === expected) {
      return true;
    }
  }
  return false;
}

module.exports = {
  STEP,
  DIGITS,
  base32Encode,
  base32Decode,
  generateTotp,
  verifyTotp,
};
