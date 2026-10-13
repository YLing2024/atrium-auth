import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  ConfigProvider,
  Input,
  Steps,
  Typography,
  theme,
} from 'antd';
import type { InputRef, ThemeConfig } from 'antd';
import zhCN from 'antd/locale/zh_CN';

declare global {
  interface Window {
    __AUTH_CONFIG__?: { allowedRedirectRoots?: string[] };
  }
}

const FONT_FAMILY =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif';

/* ------------------------------------------------------------------ *
 * 回跳白名单（逻辑与改造前言必一致，逐条照搬，不优化）
 * ------------------------------------------------------------------ */

function allowedRedirectRoots(): string[] {
  const cfg = (typeof window !== 'undefined' && window.__AUTH_CONFIG__) || {};
  return Array.isArray(cfg.allowedRedirectRoots) ? cfg.allowedRedirectRoots : [];
}

function isAllowedRedirect(u: unknown): boolean {
  if (typeof u !== 'string' || !u) return false;
  if (u.charAt(0) === '/') return u.charAt(1) !== '/' && u.charAt(1) !== '\\';
  let p: URL;
  try {
    p = new URL(u);
  } catch {
    return false;
  }
  if (p.protocol !== 'https:' && p.protocol !== 'http:') return false;
  const h = p.hostname.toLowerCase();
  if (p.origin === location.origin) return true;
  if (h === 'localhost' || h === '127.0.0.1' || h === '[::1]') return true;
  const roots = allowedRedirectRoots();
  for (let i = 0; i < roots.length; i++) {
    const root = String(roots[i] || '').toLowerCase();
    if (root && (h === root || h.slice(-(root.length + 1)) === '.' + root)) return true;
  }
  return false;
}

function resolveRedirect(): { redirect: string; rejected: boolean } {
  const rawParam = new URLSearchParams(location.search).get('redirect');
  const raw = typeof rawParam === 'string' && rawParam ? rawParam : '/';
  if (!raw.startsWith('/') && !/^https?:\/\//i.test(raw)) return { redirect: '/', rejected: false };
  if (!isAllowedRedirect(raw)) return { redirect: '/', rejected: true };

  let url: URL;
  try {
    url = /^https?:\/\//i.test(raw) ? new URL(raw) : new URL(raw, 'http://placeholder.invalid');
  } catch {
    return { redirect: '/', rejected: false };
  }

  const pathname = url.pathname;
  if (!pathname.endsWith('/') && !/\.[^/]+$/.test(pathname)) {
    url.pathname = pathname + '/';
  }

  return {
    redirect: raw.startsWith('/') ? url.pathname + url.search + url.hash : url.href,
    rejected: false,
  };
}

const { redirect: REDIRECT, rejected: REDIRECT_REJECTED } = resolveRedirect();

// 回跳用 URL query（?token=，OAuth2 风格）：fragment 经 nginx 301 重定向会被丢弃，query 不会
function redirectWithToken(token: string): void {
  const sep = REDIRECT.indexOf('?') === -1 ? '?' : '&';
  window.location.href = REDIRECT + sep + 'token=' + encodeURIComponent(token);
}

// 从 User-Agent 推导设备名（浏览器 · 系统），与后端 deviceNameFromUA 同一套规则
function deviceName(): string {
  const ua = navigator.userAgent || '';
  const name: string[] = [];
  let m: RegExpExecArray | null;
  if ((m = /Edg\/([\d.]+)/.exec(ua))) name.push('Edge ' + m[1]);
  else if (/OPR\//.test(ua) || /Opera/.test(ua)) name.push('Opera');
  else if ((m = /Firefox\/([\d.]+)/.exec(ua))) name.push('Firefox ' + m[1]);
  else if (/SamsungBrowser\//.test(ua)) name.push('Samsung Browser');
  else if (/MicroMessenger\//.test(ua)) name.push('WeChat');
  else if ((m = /CriOS\/([\d.]+)/.exec(ua))) name.push('Chrome ' + m[1]);
  else if ((m = /Chrome\/([\d.]+)/.exec(ua))) name.push('Chrome ' + m[1]);
  else if (/Safari\//.test(ua)) name.push('Safari');
  if (/Windows NT/.test(ua)) name.push('Windows');
  else if (/iPhone|iPad|iPod/.test(ua)) name.push('iOS');
  else if (/Mac OS X/.test(ua)) name.push('macOS');
  else if (/Android/.test(ua)) name.push('Android');
  else if (/CrOS/.test(ua)) name.push('ChromeOS');
  else if (/Linux/.test(ua)) name.push('Linux');
  return name.join(' · ').slice(0, 64);
}

/* ------------------------------------------------------------------ *
 * 主题令牌（antd token 映射；圆角一律 0）
 * ------------------------------------------------------------------ */

const SHARED_TOKENS: ThemeConfig['token'] = {
  borderRadius: 0,
  borderRadiusLG: 0,
  borderRadiusSM: 0,
  borderRadiusXS: 0,
  controlHeight: 32,
  motionDurationFast: '0.1s',
  motionDurationMid: '0.15s',
  motionDurationSlow: '0.15s',
  wireframe: false,
  fontFamily: FONT_FAMILY,
};

const LIGHT_TOKENS: ThemeConfig['token'] = {
  ...SHARED_TOKENS,
  colorPrimary: '#a05b0c',
  colorBgBase: '#f7f6f3',
  colorBgLayout: '#f7f6f3',
  colorBgContainer: '#fbfaf8',
  colorText: '#171512',
  colorTextSecondary: '#6f6a63',
  colorBorder: 'rgba(23,21,18,0.16)',
  colorBorderSecondary: 'rgba(23,21,18,0.16)',
};

const DARK_TOKENS: ThemeConfig['token'] = {
  ...SHARED_TOKENS,
  colorPrimary: '#c77c1f',
  colorBgBase: '#13110f',
  colorBgLayout: '#13110f',
  colorBgContainer: '#191715',
  colorText: '#efeae3',
  colorTextSecondary: '#a29b92',
  colorBorder: 'rgba(239,234,227,0.16)',
  colorBorderSecondary: 'rgba(239,234,227,0.16)',
};

function usePrefersDark(): boolean {
  const [dark, setDark] = useState<boolean>(() =>
    typeof window !== 'undefined' && window.matchMedia
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
      : false
  );
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => setDark(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  return dark;
}

/* ------------------------------------------------------------------ *
 * 登录页
 * ------------------------------------------------------------------ */

type LoginData = { token?: string; code?: string; retryAfter?: number; message?: string };
type SetupData = { secret?: string; otpauthUri?: string; message?: string };

function LoginPage() {
  const { token } = theme.useToken();
  const inputRef = useRef<InputRef>(null);
  const [code, setCode] = useState('');
  const [showCode, setShowCode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(
    REDIRECT_REJECTED ? '回跳地址不在允许范围内，登录后将留在本站' : ''
  );
  const [setup, setSetup] = useState<{ secret: string; otpauthUri?: string } | null>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  async function setupInit(): Promise<void> {
    try {
      const res = await fetch('/api/totp/setup', { method: 'POST' });
      const data = (await res.json()) as SetupData;
      if (!data.secret) {
        setError('初始化失败：' + (data.message || '未知错误'));
        return;
      }
      setSetup({ secret: data.secret, otpauthUri: data.otpauthUri });
    } catch {
      setError('初始化失败，请刷新重试');
    }
  }

  async function login(): Promise<void> {
    const value = code.replace(/\s/g, '');
    if (!/^\d{6}$/.test(value)) {
      setError('请输入 6 位数字验证码');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: value, deviceName: deviceName() }),
      });
      const data = (await res.json().catch(() => ({}))) as LoginData;
      if (data && data.token) {
        redirectWithToken(data.token);
        return;
      }
      if (res.status === 403 && data && data.code === 'totp_setup_required') {
        setError('首次使用：请先完成下方绑定，再输入动态码');
        await setupInit();
        return;
      }
      if (res.status === 429) {
        setError('尝试次数过多，请 ' + (data.retryAfter || 60) + ' 秒后重试');
        return;
      }
      setError('验证码错误，请重试');
    } catch {
      setError('网络错误，请重试');
    } finally {
      setLoading(false);
      setCode('');
      inputRef.current?.focus();
    }
  }

  function onVisibleChange(visible: boolean): void {
    setShowCode(visible);
    inputRef.current?.focus();
  }

  return (
    <div
      className="auth-root"
      style={{ background: token.colorBgLayout, color: token.colorText }}
    >
      <Card className="auth-card" bordered>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
          <span
            style={{
              width: 10,
              height: 10,
              background: token.colorPrimary,
              transform: 'rotate(45deg)',
              flex: 'none',
            }}
          />
          <Typography.Title
            level={4}
            style={{
              margin: 0,
              fontSize: 20,
              fontWeight: 600,
              letterSpacing: '0.02em',
              textTransform: 'uppercase',
            }}
          >
            HomeAuth
          </Typography.Title>
        </div>
        <div
          style={{
            fontSize: 10,
            color: token.colorTextSecondary,
            textTransform: 'uppercase',
            letterSpacing: '0.18em',
            marginBottom: 44,
          }}
        >
          Single Sign-On
        </div>

        <label
          htmlFor="code"
          style={{
            display: 'block',
            fontSize: 10,
            fontWeight: 600,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: token.colorTextSecondary,
            marginBottom: 10,
          }}
        >
          Authenticator Code
        </label>
        <Input.Password
          id="code"
          ref={inputRef}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onPressEnter={login}
          inputMode="numeric"
          maxLength={6}
          autoComplete="one-time-code"
          autoFocus
          size="large"
          placeholder="······"
          visibilityToggle={{ visible: showCode, onVisibleChange }}
          style={{ fontSize: 24, letterSpacing: '0.4em', textAlign: 'center' }}
        />

        {error ? (
          <Alert
            type="error"
            showIcon={false}
            closable={false}
            message={error}
            style={{ marginTop: 16 }}
          />
        ) : null}

        <Button
          type="primary"
          block
          loading={loading}
          onClick={login}
          style={{ marginTop: 32, height: 44, letterSpacing: '0.22em', textTransform: 'uppercase' }}
        >
          Login
        </Button>

        {setup ? (
          <div
            style={{
              marginTop: 28,
              borderTop: `1px solid ${token.colorBorderSecondary}`,
              paddingTop: 22,
            }}
          >
            <Alert
              type="info"
              showIcon={false}
              message="首次使用 · 绑定身份验证器"
              style={{ marginBottom: 14 }}
            />
            <Steps
              direction="vertical"
              size="small"
              current={-1}
              items={[
                { title: '复制下方密钥，或点击 otpauth 链接添加' },
                { title: '在 Google Authenticator / Authy / 1Password 中新建条目' },
                { title: '回到本页输入 6 位动态码完成登录' },
              ]}
            />
            <Typography.Paragraph
              code
              copyable={{ text: setup.secret }}
              style={{ wordBreak: 'break-all', marginTop: 14, marginBottom: 10 }}
            >
              {setup.secret}
            </Typography.Paragraph>
            {setup.otpauthUri ? (
              <Typography.Link href={setup.otpauthUri} target="_blank" rel="noopener">
                添加 otpauth:// 条目
              </Typography.Link>
            ) : null}
          </div>
        ) : null}

        <div
          style={{
            marginTop: 36,
            fontSize: 9,
            color: token.colorTextSecondary,
            letterSpacing: '0.2em',
            textAlign: 'center',
            textTransform: 'uppercase',
          }}
        >
          HOME AUTH
        </div>
      </Card>
    </div>
  );
}

export default function App() {
  const dark = usePrefersDark();
  const themeConfig = useMemo<ThemeConfig>(
    () => ({
      cssVar: true,
      algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
      token: dark ? DARK_TOKENS : LIGHT_TOKENS,
    }),
    [dark]
  );

  return (
    <ConfigProvider locale={zhCN} theme={themeConfig}>
      <LoginPage />
    </ConfigProvider>
  );
}
