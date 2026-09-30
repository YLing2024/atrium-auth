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

const fs: typeof import('node:fs') = require('node:fs');

import type { UtilExports } from './util.ts';

const { timingEqual }: Pick<UtilExports, 'timingEqual'> = require('./util.ts');

export type ClientRecord = {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: string[];
  scopes: string[];
  first_party: boolean;
  cookie_domain: string;
};

const DEFAULT_GRANTS: string[] = ['authorization_code'];

function isLoopbackHost(host: string): boolean {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
}

/**
 * 校验单个 redirect URI。
 * @returns {string|null} 错误描述；null 表示通过
 */
function redirectUriError(uri: unknown): string | null {
  if (typeof uri !== 'string' || !uri) return 'redirect_uri 必须是非空字符串';
  if (uri.includes('*')) return 'redirect_uri 不允许通配符 *';
  let u: URL;
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
function validateClient(raw: unknown): { ok: true; client: ClientRecord } | { ok: false; errors: string[] } {
  const errors: string[] = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, errors: ['客户端必须是对象'] };
  }
  const r = raw as Record<string, unknown>;
  const clientId = r.client_id;
  if (typeof clientId !== 'string' || !clientId.trim()) errors.push('client_id 必填');

  const redirectUris = r.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    errors.push('redirect_uris 必填且非空');
  } else {
    for (const uri of redirectUris) {
      const e = redirectUriError(uri);
      if (e) errors.push(e);
    }
  }

  const postLogout = r.post_logout_redirect_uris;
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

  if (r.client_secret !== undefined && typeof r.client_secret !== 'string') {
    errors.push('client_secret 必须是字符串');
  }
  if (r.first_party !== undefined && typeof r.first_party !== 'boolean') {
    errors.push('first_party 必须是布尔');
  }
  if (r.cookie_domain !== undefined && typeof r.cookie_domain !== 'string') {
    errors.push('cookie_domain 必须是字符串');
  }
  if (r.grant_types !== undefined && !Array.isArray(r.grant_types)) {
    errors.push('grant_types 必须是数组');
  }
  if (r.scopes !== undefined && !Array.isArray(r.scopes)) {
    errors.push('scopes 必须是数组');
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    client: {
      client_id: clientId as string,
      client_secret: typeof r.client_secret === 'string' ? r.client_secret : '',
      redirect_uris: (redirectUris as string[]).slice(),
      post_logout_redirect_uris: Array.isArray(postLogout) ? (postLogout as string[]).slice() : [],
      grant_types: Array.isArray(r.grant_types) ? (r.grant_types as string[]).slice() : DEFAULT_GRANTS.slice(),
      scopes: Array.isArray(r.scopes) ? (r.scopes as string[]).slice() : [],
      first_party: r.first_party === true,
      cookie_domain: typeof r.cookie_domain === 'string' ? r.cookie_domain : '',
    },
  };
}

class ClientRegistry {
  file: string;
  clients: Map<string, ClientRecord>;
  warnings: string[];

  /**
   * @param {string} file clients.json 路径
   */
  constructor(file: string) {
    this.file = file;
    this.clients = new Map();
    this.warnings = [];
    this.load();
  }

  load(): void {
    if (!this.file || !fs.existsSync(this.file)) return;
    try {
      fs.chmodSync(this.file, 0o600); // 注册表含 client_secret，收紧为 0600
    } catch (e) {
      /* 部分文件系统不支持，忽略 */
    }
    let data: unknown;
    try {
      data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } catch (err) {
      this.warnings.push(`clients.json 解析失败，按空注册表处理: ${(err as Error).message}`);
      return;
    }
    const obj = data as { clients?: unknown };
    const list: unknown[] | null = Array.isArray(data) ? data : obj && Array.isArray(obj.clients) ? obj.clients : null;
    if (!list) {
      this.warnings.push('clients.json 结构非法（应为数组或 {clients: []}），按空注册表处理');
      return;
    }
    for (const raw of list) {
      const res = validateClient(raw);
      if (!res.ok) {
        const rawId = raw && (raw as { client_id?: unknown }).client_id;
        this.warnings.push(`跳过非法客户端 ${rawId ? rawId : '(无 id)'}: ${res.errors.join('; ')}`);
        continue;
      }
      this.clients.set(res.client.client_id, res.client);
    }
  }

  get(clientId: string | undefined): ClientRecord | null {
    return this.clients.get(clientId as string) || null;
  }

  isConfidential(client: ClientRecord): boolean {
    return typeof client.client_secret === 'string' && client.client_secret.length > 0;
  }

  checkSecret(client: ClientRecord, provided: unknown): boolean {
    if (!this.isConfidential(client)) return true;
    if (typeof provided !== 'string' || !provided) return false;
    return timingEqual(client.client_secret, provided);
  }

  matchRedirect(client: ClientRecord, uri: unknown): boolean {
    return typeof uri === 'string' && client.redirect_uris.includes(uri);
  }

  matchPostLogout(client: ClientRecord, uri: unknown): boolean {
    return typeof uri === 'string' && client.post_logout_redirect_uris.includes(uri);
  }

  allowsGrant(client: ClientRecord, grant: string): boolean {
    return client.grant_types.includes(grant);
  }

  allowsScope(client: ClientRecord, scope: string): boolean {
    if (!client.scopes.length) return true;
    return client.scopes.includes(scope);
  }
}

// 类型-only 导出：让 TS 认为本文件是模块并拿到 require 的真实形状；运行时被类型剥离删除。
export type ClientsExports = {
  ClientRegistry: typeof ClientRegistry;
  validateClient: typeof validateClient;
  redirectUriError: typeof redirectUriError;
};

module.exports = { ClientRegistry, validateClient, redirectUriError };
