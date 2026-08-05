export type AuthConfig = {
  enabled: boolean;
  mode: "local" | "keycloak" | "none";
  local?: { enabled: boolean };
};

export type AuthPhase = "loading" | "login" | "ready";

const TOKEN_KEY = "nerve_native_token";
const USER_KEY = "nerve_native_user";

let token: string | null = null;
let username: string | null = null;
let authMode: AuthConfig["mode"] = "none";

function loadStoredSession(): boolean {
  const stored = sessionStorage.getItem(TOKEN_KEY);
  const user = sessionStorage.getItem(USER_KEY);
  if (!stored) return false;
  token = stored;
  username = user;
  return true;
}

function saveSession(nextToken: string, nextUser: string) {
  token = nextToken;
  username = nextUser;
  sessionStorage.setItem(TOKEN_KEY, nextToken);
  sessionStorage.setItem(USER_KEY, nextUser);
}

function clearSession() {
  token = null;
  username = null;
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
}

export function getAuthHeaders(): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function getUsername(): string | null {
  return username;
}

export function getAuthMode(): AuthConfig["mode"] {
  return authMode;
}

export async function logout(): Promise<void> {
  clearSession();
  window.location.reload();
}

let initAuthPromise: Promise<AuthPhase> | null = null;

export function initAuth(): Promise<AuthPhase> {
  if (initAuthPromise) return initAuthPromise;
  initAuthPromise = doInitAuth().catch((e) => {
    initAuthPromise = null;
    throw e;
  });
  return initAuthPromise;
}

async function doInitAuth(): Promise<AuthPhase> {
  let cfg: AuthConfig;
  try {
    const res = await fetch("/api/auth/config");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    cfg = (await res.json()) as AuthConfig;
  } catch {
    authMode = "none";
    return "ready";
  }

  authMode = cfg.mode ?? "none";
  if (!cfg.enabled || authMode === "none") {
    return "ready";
  }
  if (authMode === "local" && cfg.local?.enabled) {
    if (loadStoredSession()) return "ready";
    return "login";
  }
  return "ready";
}

export async function loginLocal(user: string, pass: string): Promise<void> {
  const res = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: user, password: pass }),
  });
  const text = await res.text();
  let data: { token?: string; username?: string; error?: string } = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    /* ignore */
  }
  if (!res.ok) {
    throw new Error(data.error || "用户名或密码错误");
  }
  if (!data.token) {
    throw new Error("登录响应无效");
  }
  saveSession(data.token, data.username || user);
}
