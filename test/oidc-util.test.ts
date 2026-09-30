'use strict';

// src/oidc/util.ts 纯函数测试（零依赖，node:test）。
// util.ts 是纯 CommonJS，require 即可，不触碰 Redis / 文件 / 网络。
const test = require('node:test');
const assert = require('node:assert');

const {
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
} = require('../src/oidc/util.ts');

/* ---------------- base64url ---------------- */

test('b64url: 去掉尾部 padding', () => {
  // base64('f')='Zg==', ('fo')='Zm8=', ('foo')='Zm9v'
  assert.strictEqual(b64url('f'), 'Zg');
  assert.strictEqual(b64url('fo'), 'Zm8');
  assert.strictEqual(b64url('foo'), 'Zm9v');
});

test('b64url: 空输入返回空串', () => {
  assert.strictEqual(b64url(''), '');
  assert.strictEqual(b64url(Buffer.alloc(0)), '');
});

test('b64url: 非 ASCII 按 UTF-8 编码', () => {
  // '中文' 的 UTF-8 字节为 e4 b8 ad e6 96 87
  assert.strictEqual(b64url('中文'), '5Lit5paH');
  assert.strictEqual(Buffer.from(b64url('中文'), 'base64url').toString('utf8'), '中文');
});

test('b64url: 使用 URL 安全字母表（+ / 换成 - _）', () => {
  // 0xfb 0xff 的标准 base64 是 '+/8='，url 变体应为 '-_8'
  assert.strictEqual(b64url(Buffer.from([0xfb, 0xff])), '-_8');
});

test('b64urlDecode: 解码 padding / url 安全字符 / 空串', () => {
  assert.strictEqual(b64urlDecode('Zg').toString('utf8'), 'f');
  assert.strictEqual(b64urlDecode('Zm9v').toString('utf8'), 'foo');
  assert.strictEqual(b64urlDecode('-_8').toString('hex'), 'fbff');
  assert.strictEqual(b64urlDecode('').length, 0);
  assert.ok(Buffer.isBuffer(b64urlDecode('5Lit5paH')));
});

test('b64url/b64urlDecode: 往返一致（含非 ASCII）', () => {
  for (const s of ['', 'a', 'hello world', '中文测试', 'emoji \u{1f600}']) {
    assert.strictEqual(b64urlDecode(b64url(s)).toString('utf8'), s);
  }
});

test('b64urlJson: 等于其 JSON 串的 base64url', () => {
  assert.strictEqual(b64urlJson({ a: 1 }), 'eyJhIjoxfQ');
  assert.strictEqual(b64urlJson({ a: 1 }), b64url('{"a":1}'));
});

/* ---------------- 哈希 / PKCE ---------------- */

test('sha256hex: 已知向量 abc', () => {
  assert.strictEqual(sha256hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.strictEqual(sha256hex('').length, 64);
});

test('pkceChallenge: RFC 7636 Appendix B 已知向量', () => {
  // https://www.rfc-editor.org/rfc/rfc7636#appendix-B
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  assert.strictEqual(pkceChallenge(verifier), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('pkceChallenge: 不同 verifier 得到不同 challenge', () => {
  assert.notStrictEqual(pkceChallenge('a'.repeat(43)), pkceChallenge('b'.repeat(43)));
});

/* ---------------- timingEqual ---------------- */

test('timingEqual: 相等 / 不等 / 长度不同', () => {
  assert.strictEqual(timingEqual('abc', 'abc'), true);
  assert.strictEqual(timingEqual('abc', 'abd'), false);
  assert.strictEqual(timingEqual('abc', 'abcd'), false);
  assert.strictEqual(timingEqual('', ''), true);
});

test('timingEqual: 非字符串入参按 String 归一', () => {
  assert.strictEqual(timingEqual(123, '123'), true);
  assert.strictEqual(timingEqual(123, 124), false);
});

/* ---------------- randomToken ---------------- */

test('randomToken: 长度符合 base64url(32 字节)=43，字符集合法', () => {
  const t = randomToken();
  assert.strictEqual(t.length, 43);
  assert.match(t, /^[A-Za-z0-9_-]+$/);
  assert.strictEqual(randomToken(16).length, 22);
});

test('randomToken: 两次生成不相同', () => {
  assert.notStrictEqual(randomToken(), randomToken());
});

/* ---------------- cookie 解析 ---------------- */

test('parseCookies: 常规解析 + 忽略无 = 片段', () => {
  assert.deepStrictEqual(parseCookies('a=1; b=2'), { a: '1', b: '2' });
  assert.deepStrictEqual(parseCookies('a=1; broken; b=2'), { a: '1', b: '2' });
});

test('parseCookies: 空 / undefined / 空键', () => {
  assert.deepStrictEqual(parseCookies(undefined), {});
  assert.deepStrictEqual(parseCookies(''), {});
  assert.deepStrictEqual(parseCookies('=1'), {});
});

test('parseCookies: 去空白，重复键后者覆盖，值内等号保留', () => {
  assert.deepStrictEqual(parseCookies(' a = b '), { a: 'b' });
  assert.deepStrictEqual(parseCookies('a=1; a=3'), { a: '3' });
  assert.deepStrictEqual(parseCookies('t=abc=def'), { t: 'abc=def' });
});

/* ---------------- htmlEscape ---------------- */

test('htmlEscape: 五个字符全部转义且 & 优先', () => {
  assert.strictEqual(htmlEscape('<a b=\'c\'>&"'), '&lt;a b=&#39;c&#39;&gt;&amp;&quot;');
  // & 先替换，保证不会二次转义成 &amp;lt;
  assert.strictEqual(htmlEscape('<'), '&lt;');
  assert.strictEqual(htmlEscape('&'), '&amp;');
});

test('htmlEscape: 非字符串入参按 String 归一', () => {
  assert.strictEqual(htmlEscape(5), '5');
  assert.strictEqual(htmlEscape(null), 'null');
});

/* ---------------- str ---------------- */

test('str: 只接受字符串，其余返回空串', () => {
  assert.strictEqual(str('x'), 'x');
  assert.strictEqual(str(''), '');
  assert.strictEqual(str(5), '');
  assert.strictEqual(str(undefined), '');
  assert.strictEqual(str(null), '');
  assert.strictEqual(str(['a']), '');
  assert.strictEqual(str({ a: 1 }), '');
});
