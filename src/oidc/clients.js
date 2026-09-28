'use strict';

/**
 * OIDC 客户端注册表（<DATA_DIR>/clients.json）。
 *
 * 结构（{ "clients": [ … ] } 或裸数组）：
 * {
 *   "client_id": "…",
 *   "client_secret": "…",            // 省略/空 → 公开客户端（token_endpoint_auth_method=none）
 *   "redirect_uris": ["https://…"],  // 精确匹配，必填非空
 *   "post_logout_redirect_uris": ["https://…"],
 *   "grant_types": ["authorization_code","refresh_token"],
 *   "scopes": ["openid","profile"],
 *   "first_party": true,
 *   "cookie_domain": ".example.com"
 * }
 *
 * 校验函数**拒绝**：空 redirect_uris / 含 `*` 通配 / 非 http(s) 协议（http 仅允许 localhost）。
 * 加载时非法条目会被跳过（不拖垮服务）；跳过的原因写入 warnings。
 */

const fs = require('node:fs');

const { timingEqual } = require('./util');

const DEFAULT_GRANTS = ['authorization_code'];

function isLoopbackHost(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

/**
 * 校验单个 redirect URI。
 * @returns {string|null} 错误描述；null 表示通过
 */
function redirectUriError(uri) {
  if (typeof uri !== 'string' || !uri) return 'redirect_uri 必须是非空字符串';
  if (uri.includes('*')) return 'redirect_uri 不允许通配符 *';
  let u;
  try {
    u = new URL(uri);
  } catch {
    return `redirect_uri 不是合法 URL: ${uri}`;
  }
  if (u.hash) return 'redirect_uri 不允许携带 fragment';
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return `redirect_uri 协议不允许: ${u.protocol}`;
  if (u.protocol === 'http:' && !isLoopbackHost(u.hostname)) {
    return `http 协议仅允许 localhost 调试: ${uri}`;
  }
  return null;
}

/**
 * 校验客户端注册项。
 * @returns {{ok:true, client:object} | {ok:false, errors:string[]}}
 */
function validateClient(raw) {
  const errors = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, errors: ['客户端必须是对象'] };
  }
  const clientId = raw.client_id;
  if (typeof clientId !== 'string' || !clientId.trim()) errors.push('client_id 必填');

  const redirectUris = raw.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    errors.push('redirect_uris 必填且非空');
  } else {
    for (const uri of redirectUris) {
      const e = redirectUriError(uri);
      if (e) errors.push(e);
    }
  }

  const postLogout = raw.post_logout_redirect_uris;
  if (postLogout !== undefined) {
    if (!Array.isArray(postLogout)) {
      errors.push('post_logout_redirect_uris 必须是数组');
    } else {
      for (const uri of postLogout) {
        const e = redirectUriError(uri);
        if (e) errors.push(`post_logout_redirect_uris: ${e}`);
      }
    }
  }

  if (raw.client_secret !== undefined && typeof raw.client_secret !== 'string') {
    errors.push('client_secret 必须是字符串');
  }
  if (raw.first_party !== undefined && typeof raw.first_party !== 'boolean') {
    errors.push('first_party 必须是布尔');
  }
  if (raw.cookie_domain !== undefined && typeof raw.cookie_domain !== 'string') {
    errors.push('cookie_domain 必须是字符串');
  }
  if (raw.grant_types !== undefined && !Array.isArray(raw.grant_types)) {
    errors.push('grant_types 必须是数组');
  }
  if (raw.scopes !== undefined && !Array.isArray(raw.scopes)) {
    errors.push('scopes 必须是数组');
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    client: {
      client_id: clientId,
      client_secret: typeof raw.client_secret === 'string' ? raw.client_secret : '',
      redirect_uris: redirectUris.slice(),
      post_logout_redirect_uris: Array.isArray(postLogout) ? postLogout.slice() : [],
      grant_types: Array.isArray(raw.grant_types) ? raw.grant_types.slice() : DEFAULT_GRANTS.slice(),
      scopes: Array.isArray(raw.scopes) ? raw.scopes.slice() : [],
      first_party: raw.first_party === true,
      cookie_domain: typeof raw.cookie_domain === 'string' ? raw.cookie_domain : '',
    },
  };
}

class ClientRegistry {
  /**
   * @param {string} file clients.json 路径
   */
  constructor(file) {
    this.file = file;
    this.clients = new Map();
    this.warnings = [];
    this.load();
  }

  load() {
    if (!this.file || !fs.existsSync(this.file)) return;
    let data;
    try {
      data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      this.warnings.push(`clients.json 解析失败，按空注册表处理: ${err.message}`);
      return;
    }
    const list = Array.isArray(data) ? data : data && Array.isArray(data.clients) ? data.clients : null;
    if (!list) {
      this.warnings.push('clients.json 结构非法（应为数组或 {clients: []}），按空注册表处理');
      return;
    }
    for (const raw of list) {
      const res = validateClient(raw);
      if (!res.ok) {
        this.warnings.push(`跳过非法客户端 ${raw && raw.client_id ? raw.client_id : '(无 id)'}: ${res.errors.join('; ')}`);
        continue;
      }
      this.clients.set(res.client.client_id, res.client);
    }
  }

  get(clientId) {
    return this.clients.get(clientId) || null;
  }

  isConfidential(client) {
    return typeof client.client_secret === 'string' && client.client_secret.length > 0;
  }

  checkSecret(client, provided) {
    if (!this.isConfidential(client)) return true;
    if (typeof provided !== 'string' || !provided) return false;
    return timingEqual(client.client_secret, provided);
  }

  matchRedirect(client, uri) {
    return typeof uri === 'string' && client.redirect_uris.includes(uri);
  }

  matchPostLogout(client, uri) {
    return typeof uri === 'string' && client.post_logout_redirect_uris.includes(uri);
  }

  allowsGrant(client, grant) {
    return client.grant_types.includes(grant);
  }

  allowsScope(client, scope) {
    if (!client.scopes.length) return true;
    return client.scopes.includes(scope);
  }
}

module.exports = { ClientRegistry, validateClient, redirectUriError };
