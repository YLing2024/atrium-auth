'use strict';

/**
 * 认证中心「全局登出」隔离实例自测（auth-server 无测试框架，故独立脚本）。
 *
 * 用独立 DATA_DIR + REDIS_DB=15 + 非生产端口起一个 auth-server 实例，
 * 对面起一个假的网关 back-channel 端点（记录收到的通知体）。断言：
 *   - 完整 OIDC 授权码流程拿到 access / refresh / id_token(sid)；
 *   - /end_session（带该实例 SSO cookie）→ 假端点收到 {sid, sub}（不打印令牌）；
 *   - 同 sid 的 access / refresh 全部 active:false，另一个 sid 的记录完好无损；
 *   - 假端点超时 / 500 → /end_session 仍正常 302 回跳且总耗时 < 3 秒；
 *   - 收尾杀掉实例、清 Redis DB15，不监听生产端口、不留驻留进程。
 *
 * 运行：node scripts/global-logout-isolated.js
 */

const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, execFileSync } = require('node:child_process');
const { generateTotp } = require('../lib/totp-auth/lib/totp.js');

const ROOT = path.join(__dirname, '..');
const PORT = Number(process.env.SELFTEST_SSO_PORT || 13201);
const MOCK_PORT = Number(process.env.SELFTEST_BC_PORT || 13202);
const BASE = `http://127.0.0.1:${PORT}`;
const CLIENT_ID = 'gw-app';
const CLIENT_SECRET = crypto.randomBytes(24).toString('hex');
const SUBJECT = 'linden';

let pass = 0;
let fail = 0;
function check(name, cond) {
  if (cond) {
    pass += 1;
    console.log(`  [PASS] ${name}`);
  } else {
    fail += 1;
    console.log(`  [FAIL] ${name}`);
  }
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
function jwtPayload(token) {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}
function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
function cookieValue(setCookies, name) {
  for (const c of setCookies || []) {
    const m = new RegExp(`^${name}=([^;]*)`).exec(c);
    if (m) return m[1];
  }
  return '';
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-global-logout.'));
  const internalToken = crypto.randomBytes(32).toString('hex');
  const tokenFile = path.join(tmp, 'internal-token');
  fs.writeFileSync(tokenFile, internalToken, { mode: 0o600 });
  fs.writeFileSync(
    path.join(tmp, 'clients.json'),
    JSON.stringify({
      clients: [
        {
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uris: [`${BASE}/cb`],
          post_logout_redirect_uris: [`${BASE}/after`],
          grant_types: ['authorization_code', 'refresh_token'],
          scopes: ['openid', 'profile'],
          first_party: false,
          cookie_domain: '',
        },
      ],
    }),
    { mode: 0o600 }
  );

  // ── 假网关 back-channel 端点 ────────────────────────────────────────────
  let mockMode = 'ok'; // ok | error500 | hang
  const received = [];
  const mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => {
      body += c;
    });
    req.on('end', () => {
      if (req.url !== '/_auth/backchannel-logout') {
        res.statusCode = 404;
        return res.end();
      }
      let parsed = {};
      try {
        parsed = JSON.parse(body);
      } catch {
        /* 记录为解析失败 */
      }
      received.push({
        tokenOk: req.headers['x-internal-token'] === internalToken,
        sid: parsed.sid,
        sub: parsed.sub,
      });
      if (mockMode === 'error500') {
        res.statusCode = 500;
        return res.end('err');
      }
      if (mockMode === 'hang') {
        return; // 故意不响应，模拟超时
      }
      res.statusCode = 204;
      return res.end();
    });
  });
  await new Promise((resolve) => mock.listen(MOCK_PORT, '127.0.0.1', resolve));

  // ── 隔离 auth-server 实例 ───────────────────────────────────────────────
  const logPath = path.join(tmp, 'auth-server.log');
  const logFd = fs.openSync(logPath, 'w');
  const child = spawn(process.execPath, ['src/index.ts'], {
    cwd: ROOT,
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      REDIS_DB: '15',
      DATA_DIR: tmp,
      ISSUER: BASE,
      INTERNAL_TOKEN_FILE: tokenFile,
      GATEWAY_BACKCHANNEL_URL: `http://127.0.0.1:${MOCK_PORT}/_auth/backchannel-logout`,
      SSO_SUBJECT: SUBJECT,
      SSO_DISPLAY_NAME: SUBJECT,
      ALLOWED_REDIRECT_ROOTS: '',
    },
    stdio: ['ignore', logFd, logFd],
  });

  const cleanup = () => {
    try {
      child.kill('SIGTERM');
    } catch {
      /* 已退出 */
    }
    if (typeof mock.closeAllConnections === 'function') mock.closeAllConnections();
    mock.close();
    fs.closeSync(logFd);
    try {
      execFileSync('redis-cli', ['-n', '15', 'flushdb'], { timeout: 5000, stdio: 'ignore' });
    } catch {
      /* 清库失败不掩盖测试结论 */
    }
    fs.rmSync(tmp, { recursive: true, force: true });
  };

  try {
    // 等实例就绪
    let ready = false;
    for (let i = 0; i < 100; i += 1) {
      try {
        const r = await fetch(`${BASE}/.well-known/openid-configuration`);
        if (r.ok) {
          ready = true;
          break;
        }
      } catch {
        /* 未就绪 */
      }
      await sleep(100);
    }
    if (!ready) throw new Error('auth-server 未就绪');

    const disc = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
    check('0.1 discovery issuer 指向隔离实例', disc.issuer === BASE);

    // TOTP 初始化并登录
    const setup = await (await fetch(`${BASE}/api/totp/setup`, { method: 'POST' })).json();
    const secret = setup.secret;
    check('0.2 TOTP secret 已生成', typeof secret === 'string' && secret.length > 0);

    async function login(ua) {
      const code = generateTotp(secret);
      const res = await fetch(`${BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': ua },
        body: JSON.stringify({ code, deviceName: ua }),
      });
      const data = await res.json();
      if (!data.token) throw new Error(`login 失败: ${JSON.stringify(data)}`);
      return data.token;
    }

    async function oidcFlow(ua) {
      const sessionToken = await login(ua);
      const { verifier, challenge } = pkce();
      const redirectUri = `${BASE}/cb`;
      const authUrl =
        `${BASE}/authorize?` +
        new URLSearchParams({
          client_id: CLIENT_ID,
          redirect_uri: redirectUri,
          response_type: 'code',
          scope: 'openid profile',
          state: `st-${crypto.randomBytes(4).toString('hex')}`,
          code_challenge: challenge,
          code_challenge_method: 'S256',
          token: sessionToken,
        });
      const ares = await fetch(authUrl, { redirect: 'manual', headers: { 'User-Agent': ua } });
      const loc = ares.headers.get('location');
      if (!loc) throw new Error(`authorize 未跳转: ${ares.status}`);
      const code = new URL(loc).searchParams.get('code');
      const sso = cookieValue(ares.headers.getSetCookie(), 'HomeAuth');
      const tr = await fetch(`${BASE}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': ua },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri,
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code_verifier: verifier,
        }),
      });
      const tokens = await tr.json();
      if (!tokens.access_token || !tokens.refresh_token) {
        throw new Error(`token 失败: ${JSON.stringify(tokens)}`);
      }
      return { tokens, sso, sid: jwtPayload(tokens.id_token).sid };
    }

    async function active(token) {
      const r = await fetch(`${BASE}/introspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      });
      return (await r.json()).active === true;
    }

    // 两次不同设备登录 → 两个不同 sid
    const a = await oidcFlow('selftest-device-A');
    const b = await oidcFlow('selftest-device-B');
    check('1.1 登录 A 拿到 sid', typeof a.sid === 'string' && a.sid.length > 0);
    check('1.2 登录 B 拿到 sid', typeof b.sid === 'string' && b.sid.length > 0);
    check('1.3 两次 sid 不同', a.sid !== b.sid);
    check('1.4 A access 初始 active', await active(a.tokens.access_token));
    check('1.5 A refresh 初始 active', await active(a.tokens.refresh_token));
    check('1.6 B access 初始 active', await active(b.tokens.access_token));

    // /end_session（带 A 的 SSO cookie）→ 302 回跳 + 异步通知
    const t0 = Date.now();
    const endA = await fetch(
      `${BASE}/end_session?` +
        new URLSearchParams({ client_id: CLIENT_ID, post_logout_redirect_uri: `${BASE}/after` }),
      { redirect: 'manual', headers: { Cookie: `HomeAuth=${a.sso}` } }
    );
    const endMs = Date.now() - t0;
    check('2.1 /end_session 302 回跳', endA.status === 302);
    check('2.2 /end_session 回跳地址正确', endA.headers.get('location') === `${BASE}/after`);

    // 等异步通知到达（最多 2s）
    let note = null;
    for (let i = 0; i < 40 && !note; i += 1) {
      note = received.find((r) => r.sid === a.sid) || null;
      if (!note) await sleep(50);
    }
    check('3.1 假网关收到 back-channel 通知', !!note);
    check('3.2 通知 sid 参数正确', !!note && note.sid === a.sid);
    check('3.3 通知 sub 参数正确', !!note && note.sub === SUBJECT);
    check('3.4 通知携带正确内部令牌', !!note && note.tokenOk === true);

    // E：同 sid 令牌全撤，另一个 sid 不受影响
    check('4.1 A access 已撤销 active:false', (await active(a.tokens.access_token)) === false);
    check('4.2 A refresh 已撤销 active:false', (await active(a.tokens.refresh_token)) === false);
    check('4.3 B access 完好 active:true（不误杀）', await active(b.tokens.access_token));
    check('4.4 B refresh 完好 active:true（不误杀）', await active(b.tokens.refresh_token));

    // 不阻塞：假端点超时（hang）→ /end_session 仍 <3s 且 302
    const c = await oidcFlow('selftest-device-C');
    mockMode = 'hang';
    const t1 = Date.now();
    const endC = await fetch(
      `${BASE}/end_session?` +
        new URLSearchParams({ client_id: CLIENT_ID, post_logout_redirect_uri: `${BASE}/after` }),
      { redirect: 'manual', headers: { Cookie: `HomeAuth=${c.sso}` } }
    );
    const hangMs = Date.now() - t1;
    check('5.1 假端点超时 /end_session 仍 302', endC.status === 302);
    check('5.2 假端点超时总耗时 < 3s', hangMs < 3000);

    // 不阻塞：假端点 500 → 仍 302
    mockMode = 'error500';
    const d = await oidcFlow('selftest-device-D');
    const t2 = Date.now();
    const endD = await fetch(
      `${BASE}/end_session?` +
        new URLSearchParams({ client_id: CLIENT_ID, post_logout_redirect_uri: `${BASE}/after` }),
      { redirect: 'manual', headers: { Cookie: `HomeAuth=${d.sso}` } }
    );
    const errMs = Date.now() - t2;
    check('5.3 假端点 500 /end_session 仍 302', endD.status === 302);
    check('5.4 假端点 500 总耗时 < 3s', errMs < 3000);
    mockMode = 'ok';

    console.log(`  [INFO] end_session 耗时: 正常=${endMs}ms hang=${hangMs}ms 500=${errMs}ms`);
  } finally {
    cleanup();
  }
}

main()
  .then(() => {
    console.log(`\nPASS=${pass} FAIL=${fail}`);
    if (fail > 0) process.exitCode = 1;
    else console.log('ALL CASES PASSED');
  })
  .catch((err) => {
    console.error(`FATAL: ${err.message}`);
    process.exitCode = 2;
  });
