'use strict';

// src/oidc/clients.ts 纯逻辑测试（零依赖，node:test）。
// 只加载模块本身：不实例化真实注册表文件，构造函数传不存在的路径即得到空注册表。
const test = require('node:test');
const assert = require('node:assert');

const { ClientRegistry, validateClient, redirectUriError } = require('../src/oidc/clients.ts');

const MISSING = '/nonexistent-auth-server-test/clients.json';

function registry(): InstanceType<typeof ClientRegistry> {
  return new ClientRegistry(MISSING);
}

function makeClient(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    client_id: 'c1',
    client_secret: 's3cret',
    redirect_uris: ['https://app.example/cb'],
    ...overrides,
  };
}

/* ---------------- redirectUriError ---------------- */

test('redirectUriError: 合法 https / loopback http 通过', () => {
  assert.strictEqual(redirectUriError('https://app.example/cb'), null);
  assert.strictEqual(redirectUriError('http://localhost:3000/cb'), null);
  assert.strictEqual(redirectUriError('http://127.0.0.1/cb'), null);
  assert.strictEqual(redirectUriError('http://[::1]/cb'), null);
});

test('redirectUriError: 拒绝通配符 / fragment / 非 http(s) / 非环回 http', () => {
  assert.match(redirectUriError('https://app.example/*'), /通配符/);
  assert.match(redirectUriError('https://app.example/cb#frag'), /fragment/);
  assert.match(redirectUriError('ftp://app.example/cb'), /协议/);
  assert.match(redirectUriError('http://app.example/cb'), /localhost/);
});

test('redirectUriError: 非字符串 / 空串 / 非法 URL', () => {
  assert.ok(redirectUriError(123));
  assert.ok(redirectUriError(undefined));
  assert.ok(redirectUriError(''));
  assert.match(redirectUriError('not a url'), /不是合法 URL/);
});

/* ---------------- validateClient ---------------- */

test('validateClient: 合法项 + 默认值', () => {
  const res = validateClient(makeClient());
  assert.strictEqual(res.ok, true);
  if (!res.ok) return;
  assert.strictEqual(res.client.client_id, 'c1');
  assert.strictEqual(res.client.client_secret, 's3cret');
  assert.deepStrictEqual(res.client.redirect_uris, ['https://app.example/cb']);
  assert.deepStrictEqual(res.client.post_logout_redirect_uris, []);
  assert.deepStrictEqual(res.client.grant_types, ['authorization_code']);
  assert.deepStrictEqual(res.client.scopes, []);
  assert.strictEqual(res.client.first_party, false);
  assert.strictEqual(res.client.cookie_domain, '');
});

test('validateClient: 非对象 / 数组被拒', () => {
  assert.strictEqual(validateClient(null).ok, false);
  assert.strictEqual(validateClient('x').ok, false);
  assert.strictEqual(validateClient([]).ok, false);
});

test('validateClient: 缺 client_id / redirect_uris 被拒', () => {
  const r1 = validateClient(makeClient({ client_id: '  ' }));
  assert.strictEqual(r1.ok, false);
  if (!r1.ok) assert.match(r1.errors.join(';'), /client_id/);

  const r2 = validateClient(makeClient({ redirect_uris: [] }));
  assert.strictEqual(r2.ok, false);
  if (!r2.ok) assert.match(r2.errors.join(';'), /redirect_uris/);
});

test('validateClient: 通配 redirect_uri 被拒', () => {
  const res = validateClient(makeClient({ redirect_uris: ['https://app.example/*'] }));
  assert.strictEqual(res.ok, false);
});

test('validateClient: 类型错误被拒（secret / first_party / grant_types）', () => {
  assert.strictEqual(validateClient(makeClient({ client_secret: 5 })).ok, false);
  assert.strictEqual(validateClient(makeClient({ first_party: 'yes' })).ok, false);
  assert.strictEqual(validateClient(makeClient({ grant_types: 'authorization_code' })).ok, false);
});

test('validateClient: first_party / scopes / cookie_domain 保留', () => {
  const res = validateClient(
    makeClient({
      first_party: true,
      scopes: ['openid', 'profile'],
      cookie_domain: '.example.com',
      post_logout_redirect_uris: ['https://app.example/bye'],
    })
  );
  assert.strictEqual(res.ok, true);
  if (!res.ok) return;
  assert.strictEqual(res.client.first_party, true);
  assert.deepStrictEqual(res.client.scopes, ['openid', 'profile']);
  assert.strictEqual(res.client.cookie_domain, '.example.com');
  assert.deepStrictEqual(res.client.post_logout_redirect_uris, ['https://app.example/bye']);
});

/* ---------------- ClientRegistry 方法 ---------------- */

test('ClientRegistry: 文件不存在 → 空注册表，get 返回 null', () => {
  const r = registry();
  assert.strictEqual(r.get('c1'), null);
  assert.strictEqual(r.warnings.length, 0);
});

test('matchRedirect / matchPostLogout: 精确匹配，不作前缀', () => {
  const r = registry();
  const c = { redirect_uris: ['https://app.example/cb'], post_logout_redirect_uris: ['https://app.example/bye'] };
  assert.strictEqual(r.matchRedirect(c, 'https://app.example/cb'), true);
  assert.strictEqual(r.matchRedirect(c, 'https://app.example/cb/'), false);
  assert.strictEqual(r.matchRedirect(c, 'https://app.example/x'), false);
  assert.strictEqual(r.matchRedirect(c, 123), false);
  assert.strictEqual(r.matchPostLogout(c, 'https://app.example/bye'), true);
  assert.strictEqual(r.matchPostLogout(c, 'https://app.example/'), false);
});

test('allowsGrant: 仅注册的 grant', () => {
  const r = registry();
  const c = { grant_types: ['authorization_code', 'refresh_token'] };
  assert.strictEqual(r.allowsGrant(c, 'authorization_code'), true);
  assert.strictEqual(r.allowsGrant(c, 'refresh_token'), true);
  assert.strictEqual(r.allowsGrant(c, 'client_credentials'), false);
});

test('allowsScope: 空 scopes 视为放开，否则白名单', () => {
  const r = registry();
  assert.strictEqual(r.allowsScope({ scopes: [] }, 'openid'), true);
  assert.strictEqual(r.allowsScope({ scopes: ['openid'] }, 'openid'), true);
  assert.strictEqual(r.allowsScope({ scopes: ['openid'] }, 'email'), false);
});

test('isConfidential / checkSecret: 公开客户端放行，机密客户端定时安全比较', () => {
  const r = registry();
  assert.strictEqual(r.isConfidential({ client_secret: '' }), false);
  assert.strictEqual(r.checkSecret({ client_secret: '' }, ''), true);
  assert.strictEqual(r.checkSecret({ client_secret: '' }, undefined), true);

  const secret = 's3cret-value';
  assert.strictEqual(r.isConfidential({ client_secret: secret }), true);
  assert.strictEqual(r.checkSecret({ client_secret: secret }, secret), true);
  assert.strictEqual(r.checkSecret({ client_secret: secret }, secret + 'x'), false);
  assert.strictEqual(r.checkSecret({ client_secret: secret }, ''), false);
  assert.strictEqual(r.checkSecret({ client_secret: secret }, 123), false);
});
