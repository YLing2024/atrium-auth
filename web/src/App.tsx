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
import { deviceName, resolveRedirect } from './auth-logic';

const FONT_FAMILY =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif';

// 回跳目标与是否被拒（页面加载时解析一次）
const { redirect: REDIRECT, rejected: REDIRECT_REJECTED } = resolveRedirect();

// 回跳用 URL query（?token=，OAuth2 风格）：fragment 经 nginx 301 重定向会被丢弃，query 不会
function redirectWithToken(token: string): void {
  const sep = REDIRECT.indexOf('?') === -1 ? '?' : '&';
  window.location.href = REDIRECT + sep + 'token=' + encodeURIComponent(token);
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
