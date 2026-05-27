import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type SessionRole = 'employee' | 'admin';
export type Permission =
  | 'chat:read'
  | 'contact:read'
  | 'settings:read'
  | 'settings:write'
  | 'admin:access'
  | 'admin:dashboard:read'
  | 'admin:users:read'
  | 'admin:audit:read';

type AuthScope = 'employee' | 'admin' | 'mfa';

type SessionData = {
  role: SessionRole;
  permissions: Permission[];
  issuedAt: number;
  expiresAt: number;
  maxExpiresAt: number;
  mfaVerified: boolean;
};

type AttemptEntry = {
  count: number;
  firstAttemptAt: number;
  lockoutUntil: number;
};

type SecurityState = Record<AuthScope, AttemptEntry>;

type SessionContextValue = {
  role: SessionRole | null;
  isSessionReady: boolean;
  isAuthenticated: boolean;
  isAdminAuthenticated: boolean;
  isMfaVerified: boolean;
  sessionExpiresAt: number | null;
  hasPermission: (permission: Permission) => boolean;
  canAttempt: (scope: AuthScope) => boolean;
  getRemainingLockoutMs: (scope: AuthScope) => number;
  registerFailedAttempt: (scope: AuthScope) => void;
  clearFailedAttempts: (scope: AuthScope) => void;
  signInEmployee: () => void;
  signInAdmin: () => void;
  touchSession: () => void;
  signOut: () => void;
};

const SESSION_KEY = 'edoble.secure.session.v1';
const SECURITY_KEY = 'edoble.secure.security.v1';
const IDLE_TTL_MS = 30 * 60 * 1000;
const ABSOLUTE_TTL_MS = 24 * 60 * 60 * 1000;
const ATTEMPT_WINDOW_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 10 * 60 * 1000;

const employeePermissions: Permission[] = ['chat:read', 'contact:read', 'settings:read', 'settings:write'];
const adminPermissions: Permission[] = ['admin:access', 'admin:dashboard:read', 'admin:users:read', 'admin:audit:read'];

const initialAttemptEntry = (): AttemptEntry => ({
  count: 0,
  firstAttemptAt: 0,
  lockoutUntil: 0,
});

const initialSecurityState = (): SecurityState => ({
  employee: initialAttemptEntry(),
  admin: initialAttemptEntry(),
  mfa: initialAttemptEntry(),
});

const SessionContext = createContext<SessionContextValue | null>(null);

const isWebRuntime = typeof window !== 'undefined';

function getNativeSecureStore() {
  if (isWebRuntime) {
    return null;
  }

  return require('expo-secure-store') as typeof import('expo-secure-store');
}

async function getStorageItem(key: string) {
  if (isWebRuntime) {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  const nativeSecureStore = getNativeSecureStore();

  if (!nativeSecureStore) {
    return null;
  }

  return nativeSecureStore.getItemAsync(key);
}

async function setStorageItem(key: string, value: string) {
  if (isWebRuntime) {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // No-op fallback when storage is blocked.
    }

    return;
  }

  const nativeSecureStore = getNativeSecureStore();

  if (!nativeSecureStore) {
    return;
  }

  await nativeSecureStore.setItemAsync(key, value);
}

async function deleteStorageItem(key: string) {
  if (isWebRuntime) {
    try {
      window.localStorage.removeItem(key);
    } catch {
      // No-op fallback when storage is blocked.
    }

    return;
  }

  const nativeSecureStore = getNativeSecureStore();

  if (!nativeSecureStore) {
    return;
  }

  await nativeSecureStore.deleteItemAsync(key);
}

function isSessionValid(session: SessionData | null, now = Date.now()) {
  if (!session) {
    return false;
  }

  return now < session.expiresAt && now < session.maxExpiresAt;
}

function parseSession(rawValue: string | null): SessionData | null {
  if (!rawValue) {
    return null;
  }

  try {
    const parsed = JSON.parse(rawValue) as SessionData;

    if (!parsed?.role || !Array.isArray(parsed.permissions)) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

function parseSecurityState(rawValue: string | null): SecurityState {
  if (!rawValue) {
    return initialSecurityState();
  }

  try {
    const parsed = JSON.parse(rawValue) as SecurityState;

    if (!parsed?.employee || !parsed?.admin || !parsed?.mfa) {
      return initialSecurityState();
    }

    return parsed;
  } catch {
    return initialSecurityState();
  }
}

function buildSession(role: SessionRole): SessionData {
  const now = Date.now();
  const base = {
    role,
    issuedAt: now,
    expiresAt: now + IDLE_TTL_MS,
    maxExpiresAt: now + ABSOLUTE_TTL_MS,
    mfaVerified: true,
  };

  if (role === 'admin') {
    return { ...base, permissions: adminPermissions };
  }

  return { ...base, permissions: employeePermissions };
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionData | null>(null);
  const [securityState, setSecurityState] = useState<SecurityState>(initialSecurityState());
  const [isSessionReady, setIsSessionReady] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function hydrate() {
      try {
        const [rawSession, rawSecurity] = await Promise.all([
          getStorageItem(SESSION_KEY),
          getStorageItem(SECURITY_KEY),
        ]);

        if (cancelled) {
          return;
        }

        const restoredSession = parseSession(rawSession);
        const restoredSecurity = parseSecurityState(rawSecurity);

        if (isSessionValid(restoredSession)) {
          setSession(restoredSession);
        } else {
          setSession(null);
        }

        setSecurityState(restoredSecurity);
      } finally {
        if (!cancelled) {
          setIsSessionReady(true);
        }
      }
    }

    hydrate();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!isSessionReady) {
      return;
    }

    if (!session) {
      deleteStorageItem(SESSION_KEY);
      return;
    }

    setStorageItem(SESSION_KEY, JSON.stringify(session));
  }, [session, isSessionReady]);

  useEffect(() => {
    if (!isSessionReady) {
      return;
    }

    setStorageItem(SECURITY_KEY, JSON.stringify(securityState));
  }, [securityState, isSessionReady]);

  useEffect(() => {
    const timer = setInterval(() => {
      setSession((current) => (isSessionValid(current) ? current : null));
    }, 15 * 1000);

    return () => clearInterval(timer);
  }, []);

  const value = useMemo<SessionContextValue>(() => {
    const authenticated = isSessionValid(session);

    const getRemainingLockoutMs = (scope: AuthScope) => {
      const remaining = securityState[scope].lockoutUntil - Date.now();
      return remaining > 0 ? remaining : 0;
    };

    const canAttempt = (scope: AuthScope) => getRemainingLockoutMs(scope) === 0;

    return {
      role: authenticated ? session?.role ?? null : null,
      isSessionReady,
      isAuthenticated: authenticated,
      isAdminAuthenticated: authenticated && session?.role === 'admin' && session.permissions.includes('admin:access'),
      isMfaVerified: authenticated && Boolean(session?.mfaVerified),
      sessionExpiresAt: authenticated ? session?.expiresAt ?? null : null,
      hasPermission: (permission: Permission) => authenticated && Boolean(session?.permissions.includes(permission)),
      canAttempt,
      getRemainingLockoutMs,
      registerFailedAttempt: (scope: AuthScope) => {
        setSecurityState((current) => {
          const now = Date.now();
          const currentEntry = current[scope];

          if (now < currentEntry.lockoutUntil) {
            return current;
          }

          const inWindow = now - currentEntry.firstAttemptAt <= ATTEMPT_WINDOW_MS;
          const nextCount = inWindow ? currentEntry.count + 1 : 1;
          const nextEntry: AttemptEntry = {
            count: nextCount,
            firstAttemptAt: inWindow ? currentEntry.firstAttemptAt : now,
            lockoutUntil: nextCount >= MAX_ATTEMPTS ? now + LOCKOUT_MS : 0,
          };

          return { ...current, [scope]: nextEntry };
        });
      },
      clearFailedAttempts: (scope: AuthScope) => {
        setSecurityState((current) => ({
          ...current,
          [scope]: initialAttemptEntry(),
        }));
      },
      signInEmployee: () => {
        setSession(buildSession('employee'));
      },
      signInAdmin: () => {
        setSession(buildSession('admin'));
      },
      touchSession: () => {
        setSession((current) => {
          if (!current || !isSessionValid(current)) {
            return null;
          }

          const now = Date.now();
          const nextExpiry = Math.min(now + IDLE_TTL_MS, current.maxExpiresAt);

          return { ...current, expiresAt: nextExpiry };
        });
      },
      signOut: () => {
        setSession(null);
      },
    };
  }, [session, securityState, isSessionReady]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession() {
  const context = useContext(SessionContext);

  if (!context) {
    throw new Error('useSession must be used within SessionProvider');
  }

  return context;
}