import { FormEvent, useId, useState } from "react";
import { NerveButton } from "../Button";
import { NerveInput } from "../Input";

export type NerveLoginPageProps = {
  productName: string;
  productTagline: string;
  headline: string;
  description: string;
  points: [string, string, string];
  footer: string;
  mark?: string;
  /** 演示入口等场景预填，不在页面展示默认口令文案 */
  initialUsername?: string;
  initialPassword?: string;
  /** 为 true 时允许密码为空（如本机无 API Key 的控制台） */
  allowEmptyPassword?: boolean;
  /** 密码框占位；默认「密码」 */
  passwordPlaceholder?: string;
  onLogin: (username: string, password: string) => Promise<void>;
};

function LoginShieldArt({ gradId }: { gradId: string }) {
  const shieldGrad = `${gradId}-shield`;
  const glowGrad = `${gradId}-glow`;

  return (
    <svg
      className="cloud-login-art"
      viewBox="0 0 480 320"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <defs>
        <linearGradient id={shieldGrad} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor="#1677ff" stopOpacity="0.9" />
          <stop offset="100%" stopColor="#0958d9" stopOpacity="0.75" />
        </linearGradient>
        <linearGradient id={glowGrad} x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" stopColor="#1677ff" stopOpacity="0.18" />
          <stop offset="100%" stopColor="#1677ff" stopOpacity="0" />
        </linearGradient>
      </defs>
      <ellipse cx="240" cy="280" rx="180" ry="24" fill="#1677ff" fillOpacity="0.08" />
      <path
        d="M240 48 L340 88 V168 C340 228 240 272 240 272 C240 272 140 228 140 168 V88 Z"
        fill={`url(#${shieldGrad})`}
        fillOpacity="0.12"
        stroke="#1677ff"
        strokeWidth="2"
        strokeOpacity="0.35"
      />
      <path
        d="M240 72 L310 102 V162 C310 206 240 240 240 240 C240 240 170 206 170 162 V102 Z"
        fill={`url(#${glowGrad})`}
      />
      <path
        d="M240 96 L280 112 V158 C280 182 240 200 240 200 C240 200 200 182 200 158 V112 Z"
        fill="#1677ff"
        fillOpacity="0.15"
        stroke="#1677ff"
        strokeWidth="1.5"
        strokeOpacity="0.5"
      />
      <circle cx="240" cy="148" r="20" fill="#fff" fillOpacity="0.95" stroke="#1677ff" strokeWidth="2" />
      <path
        d="M232 148 L238 154 L250 140"
        stroke="#1677ff"
        strokeWidth="2.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="120" cy="120" r="6" fill="#1677ff" fillOpacity="0.5" />
      <circle cx="360" cy="100" r="5" fill="#1677ff" fillOpacity="0.4" />
      <path d="M126 120 L200 130" stroke="#1677ff" strokeOpacity="0.25" strokeWidth="1" strokeDasharray="4 4" />
      <path d="M280 130 L354 100" stroke="#1677ff" strokeOpacity="0.25" strokeWidth="1" strokeDasharray="4 4" />
    </svg>
  );
}

function EyeIcon({ hidden }: { hidden: boolean }) {
  if (hidden) {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
        <path d="M12 7c2.76 0 5 2.24 5 5 0 .65-.13 1.26-.36 1.83l2.92 2.92c1.51-1.26 2.7-2.89 3.43-4.75-1.73-4.39-6-7.5-11-7.5-1.4 0-2.74.25-3.98.7l2.16 2.16C10.74 7.13 11.35 7 12 7zM2 4.27l2.28 2.28.46.46C3.08 8.3 1.78 10.02 1 12c1.73 4.39 6 7.5 11 7.5 1.55 0 3.03-.3 4.38-.84l.42.42L19.73 22 21 20.73 3.27 3 2 4.27zM7.53 9.8l1.55 1.55c-.05.21-.08.43-.08.65 0 1.66 1.34 3 3 3 .22 0 .44-.03.65-.08l1.55 1.55c-.67.33-1.41.53-2.2.53-2.76 0-5-2.24-5-5 0-.79.2-1.53.53-2.2zm4.31-.78l3.15 3.15.02-.16c0-1.66-1.34-3-3-3l-.17.01z" />
      </svg>
    );
  }

  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
      <path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z" />
    </svg>
  );
}

/** 全产品线统一登录页 */
export function NerveLoginPage({
  productName,
  productTagline,
  headline,
  description,
  points,
  footer,
  mark = "N",
  initialUsername = "",
  initialPassword = "",
  allowEmptyPassword = false,
  passwordPlaceholder = "密码",
  onLogin,
}: NerveLoginPageProps) {
  const gradId = useId().replace(/:/g, "");
  const [username, setUsername] = useState(initialUsername);
  const [password, setPassword] = useState(initialPassword);
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit =
    Boolean(username.trim()) && (allowEmptyPassword || Boolean(password));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    setError(null);
    setBusy(true);
    try {
      await onLogin(username.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="cloud-login">
      <div className="cloud-login-bg" aria-hidden />
      <header className="cloud-login-topbar">
        <div className="cloud-login-topbar-inner">
          <div className="cloud-login-topbar-brand">
            <span className="cloud-login-mark" aria-hidden>
              {mark}
            </span>
            <span className="cloud-login-topbar-name">{productName}</span>
          </div>
        </div>
      </header>
      <div className="cloud-login-center">
        <div className="cloud-login-card">
          <aside className="cloud-login-card-left" aria-label="产品介绍">
            <h2 className="cloud-login-welcome">欢迎使用 {productName}</h2>
            <p className="cloud-login-card-tagline">{productTagline}</p>
            <h3 className="cloud-login-headline">{headline}</h3>
            <p className="cloud-login-desc">{description}</p>
            <LoginShieldArt gradId={gradId} />
            <ul className="cloud-login-points">
              {points.map((point) => (
                <li key={point}>{point}</li>
              ))}
            </ul>
          </aside>
          <div className="cloud-login-card-split" aria-hidden />
          <main className="cloud-login-card-right" aria-label="登录">
            <div className="cloud-login-tabs" role="tablist">
              <span className="cloud-login-tab active" role="tab" aria-selected>
                密码登录
              </span>
            </div>
            <form className="cloud-login-form" onSubmit={submit}>
              <div className="cloud-login-field">
                <NerveInput
                  wide
                  className="cloud-login-input"
                  autoComplete="username"
                  placeholder="用户名"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  disabled={busy}
                />
              </div>
              <div className="cloud-login-field cloud-login-field-password">
                <NerveInput
                  wide
                  className="cloud-login-input"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  placeholder={passwordPlaceholder}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={busy}
                />
                <button
                  type="button"
                  className="cloud-login-eye"
                  aria-label={showPassword ? "隐藏密码" : "显示密码"}
                  onClick={() => setShowPassword((value) => !value)}
                  tabIndex={-1}
                >
                  <EyeIcon hidden={showPassword} />
                </button>
              </div>
              {error ? (
                <div className="cloud-login-error" role="alert">
                  {error}
                </div>
              ) : null}
              <NerveButton
                variant="primary"
                htmlType="submit"
                disabled={busy || !canSubmit}
                className="cloud-login-submit"
              >
                {busy ? "登录中…" : "登录"}
              </NerveButton>
            </form>
          </main>
        </div>
      </div>
      <footer className="cloud-login-page-footer">{footer}</footer>
    </div>
  );
}
