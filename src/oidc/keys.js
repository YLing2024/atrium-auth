'use strict';

/**
 * ES256（ECDSA P-256）签名密钥库。
 *
 * - 首次启动生成一对 P-256 密钥，写入 `<DATA_DIR>/oidc-keys.json`（0600，已 gitignore）
 * - `kid` = 公钥 JWK thumbprint（RFC 7638）
 * - 文件里可并存多把密钥（数组），签名用第一把；JWKS 暴露全部公钥（便于轮换）
 * - id_token **只允许 ES256**，绝不使用 HS256
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { b64url, b64urlDecode, b64urlJson } = require('./util');

function thumbprint(jwk) {
  // RFC 7638：成员按字典序、无空白，仅必需成员
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

function generateKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = publicKey.export({ format: 'jwk' }); // { kty, crv, x, y }
  const privateJwk = privateKey.export({ format: 'jwk' }); // 含 d
  const kid = thumbprint(publicJwk);
  return { kid, createdAt: Date.now(), privateJwk, publicJwk };
}

class KeyStore {
  /**
   * @param {string} file oidc-keys.json 路径
   */
  constructor(file) {
    this.file = file;
    this.keys = []; // 最新在前
    this.load();
  }

  load() {
    let data = null;
    if (fs.existsSync(this.file)) {
      try {
        data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      } catch (err) {
        throw new Error(`oidc-keys: 无法解析 ${this.file}: ${err.message}`);
      }
    }
    if (data && Array.isArray(data.keys) && data.keys.length) {
      this.keys = data.keys.filter((k) => k && k.privateJwk && k.publicJwk && k.kid);
      if (!this.keys.length) throw new Error('oidc-keys: 文件里没有可用密钥');
      // 兜底补 kid（旧文件可能缺）
      for (const k of this.keys) if (!k.kid) k.kid = thumbprint(k.publicJwk);
      return;
    }
    // 首次启动：生成并落盘
    this.keys = [generateKey()];
    this.save();
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ keys: this.keys }, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
    try {
      fs.chmodSync(this.file, 0o600);
    } catch (e) {
      /* 忽略（部分文件系统不支持） */
    }
  }

  /** 轮换：新增一把密钥并放到最前（后续签名的 kid） */
  rotate() {
    this.keys.unshift(generateKey());
    this.save();
    return this.keys[0].kid;
  }

  activeKid() {
    return this.keys.length ? this.keys[0].kid : null;
  }

  /** JWKS：只暴露公钥，附带 kid/use/alg */
  jwks() {
    return {
      keys: this.keys.map((k) => ({
        kty: k.publicJwk.kty,
        crv: k.publicJwk.crv,
        x: k.publicJwk.x,
        y: k.publicJwk.y,
        kid: k.kid,
        use: 'sig',
        alg: 'ES256',
      })),
    };
  }

  get(kid) {
    return this.keys.find((k) => k.kid === kid) || null;
  }

  /**
   * 用 active key 签一个 ES256 JWT。
   * @param {object} payload claims（需已含 exp/iat 等）
   * @param {object} [opts] { kid }
   */
  signJwt(payload, opts = {}) {
    const key = opts.kid ? this.get(opts.kid) : this.keys[0];
    if (!key) throw new Error('oidc-keys: no signing key');
    const header = { alg: 'ES256', typ: 'JWT', kid: key.kid };
    const signingInput = `${b64urlJson(header)}.${b64urlJson(payload)}`;
    const privateKey = crypto.createPrivateKey({ key: key.privateJwk, format: 'jwk' });
    const sig = crypto.sign('sha256', Buffer.from(signingInput), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    return `${signingInput}.${b64url(sig)}`;
  }

  /**
   * 校验 ES256 JWT（本服务自签的 id_token，用于 end_session 的 id_token_hint 等）。
   * @param {string} token
   * @param {{issuer?:string, audience?:string}} [opts]
   * @returns {object} payload
   */
  verifyJwt(token, opts = {}) {
    const parts = String(token).split('.');
    if (parts.length !== 3) throw new Error('jwt: malformed');
    let header;
    try {
      header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
    } catch {
      throw new Error('jwt: bad header');
    }
    if (header.alg !== 'ES256') throw new Error('jwt: alg not allowed');
    const key = this.get(header.kid);
    if (!key) throw new Error('jwt: unknown kid');
    const publicKey = crypto.createPublicKey({ key: key.publicJwk, format: 'jwk' });
    const ok = crypto.verify(
      'sha256',
      Buffer.from(`${parts[0]}.${parts[1]}`),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      b64urlDecode(parts[2])
    );
    if (!ok) throw new Error('jwt: bad signature');
    let payload;
    try {
      payload = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
    } catch {
      throw new Error('jwt: bad payload');
    }
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp < now) throw new Error('jwt: expired');
    if (opts.issuer && payload.iss !== opts.issuer) throw new Error('jwt: bad issuer');
    if (opts.audience && payload.aud !== opts.audience) throw new Error('jwt: bad audience');
    return payload;
  }
}

module.exports = { KeyStore, thumbprint, generateKey };
