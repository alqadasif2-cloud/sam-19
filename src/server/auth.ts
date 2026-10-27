import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';

export interface UserPayload {
  id: number;
  username: string;
  displayName: string;
  role: 'owner' | 'moderator' | 'user' | 'guest';
  avatarUrl?: string | null;
  isGuest?: boolean;
  iat?: number;
  exp?: number;
}

declare global {
  namespace Express {
    interface Request {
      user?: UserPayload;
    }
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'sami_trading_secret_key_prod_2026_secure_key_32chars';

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf8');
}

export function generateToken(user: {
  id: number;
  username: string;
  displayName: string;
  role: string;
  avatarUrl?: string | null;
  isGuest?: boolean;
}): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: UserPayload = {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    role: user.role as any,
    avatarUrl: user.avatarUrl || null,
    isGuest: !!user.isGuest,
    iat: now,
    exp: now + 7 * 24 * 3600, // 7 days expiration
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${data}.${signature}`;
}

export function verifyToken(token: string): UserPayload | null {
  if (!token || typeof token !== 'string') return null;
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;

  const [headerB64, payloadB64, signature] = parts;
  const expectedSig = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  if (signature !== expectedSig) {
    return null;
  }

  try {
    const payloadStr = base64UrlDecode(payloadB64);
    const payload: UserPayload = JSON.parse(payloadStr);
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export async function authenticateToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else if (req.headers['x-auth-token']) {
    token = String(req.headers['x-auth-token']);
  } else if (req.query && req.query.token) {
    token = String(req.query.token);
  }

  if (token) {
    const user = verifyToken(token);
    if (user) {
      req.user = user;
      return next();
    }
  }

  // Also support x-sami-session header (URL-encoded or raw JSON), ?session= query param, or _ownerSession body fallback
  const rawSessionInput =
    req.headers['x-sami-session'] ||
    (req.query && req.query.session ? String(req.query.session) : undefined) ||
    (req.body && typeof req.body === 'object' ? req.body._ownerSession : undefined);

  if (rawSessionInput) {
    try {
      let parsed: any = rawSessionInput;
      if (typeof rawSessionInput === 'string') {
        const trimmed = rawSessionInput.trim();
        const decoded = trimmed.startsWith('%7B') || trimmed.includes('%22')
          ? decodeURIComponent(trimmed)
          : trimmed;
        parsed = JSON.parse(decoded);
      }
      if (parsed && parsed.id) {
        const numericId = Number(parsed.id);
        const isGuestAccount =
          parsed.isGuest === true ||
          parsed.role === 'guest' ||
          numericId > 9000000 ||
          String(parsed.username || '').startsWith('guest_');

        if (isGuestAccount && numericId > 0) {
          req.user = {
            id: numericId,
            username: String(parsed.username || `guest_${numericId}`),
            displayName: String(parsed.displayName || 'ضيف'),
            role: 'guest', // strictly locked to guest - zero privilege escalation
            avatarUrl: null,
            isGuest: true,
          };
          return next();
        }

        const {
          getUserById,
          getCachedCloudUserById,
          cacheVerifiedCloudUser,
          isFirestoreRestInQuotaBackoff,
          noteFirestoreRestStatus,
          projectId,
          databaseId,
        } = await import('./db.ts');

        const candidateUsername = String(parsed.username || '').trim().toLowerCase();
        const candidateDisplayName = String(parsed.displayName || '').trim().toLowerCase();

        const matchesRecord = (u: any): boolean => {
          if (!u) return false;
          const dbUname = String(u.username || '').trim().toLowerCase();
          const dbDname = String(u.displayName || '').trim().toLowerCase();
          return Boolean(
            (candidateUsername && (candidateUsername === dbUname || candidateUsername === dbDname)) ||
              (candidateDisplayName && (candidateDisplayName === dbDname || candidateDisplayName === dbUname))
          );
        };

        let verifiedUser: any = getCachedCloudUserById(numericId);
        if (!matchesRecord(verifiedUser)) {
          const localCandidate = await getUserById(numericId);
          if (matchesRecord(localCandidate)) {
            verifiedUser = localCandidate;
          } else {
            verifiedUser = null;
          }
        }

        let cloudUnavailableOrQuotaExceeded = isFirestoreRestInQuotaBackoff();

        // If local diskStore didn't match (e.g., community_users IDs 2..20+ stored in shared Firestore),
        // verify against shared Firestore community_users/{id} when quota allows.
        if (!verifiedUser && numericId > 0 && !cloudUnavailableOrQuotaExceeded) {
          try {
            const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/${databaseId}/documents/community_users/${encodeURIComponent(String(numericId))}`;
            const resp = await fetch(url);
            noteFirestoreRestStatus(resp.status);
            if (resp.ok) {
              const docJson: any = await resp.json();
              const f = docJson?.fields;
              if (f) {
                const uname = f.username?.stringValue || '';
                const rawRole = f.role?.stringValue || 'user';
                const cloudUser = {
                  id: numericId,
                  username: uname,
                  displayName: f.displayName?.stringValue || uname || 'متداول',
                  role: (numericId === 1 ? 'owner' : rawRole === 'moderator' ? 'moderator' : 'user') as
                    | 'owner'
                    | 'moderator'
                    | 'user',
                  avatarUrl: f.avatarUrl?.stringValue || null,
                  createdAt: Date.now(),
                  updatedAt: Date.now(),
                };
                cacheVerifiedCloudUser(cloudUser);
                if (matchesRecord(cloudUser)) {
                  verifiedUser = cloudUser;
                }
              }
            } else if (resp.status === 429 || resp.status >= 500) {
              cloudUnavailableOrQuotaExceeded = true;
            }
          } catch {
            cloudUnavailableOrQuotaExceeded = true;
          }
        }

        if (verifiedUser) {
          req.user = {
            id: verifiedUser.id,
            username: verifiedUser.username,
            displayName: verifiedUser.displayName,
            role: verifiedUser.role, // strictly verified from database!
            avatarUrl: verifiedUser.avatarUrl || null,
            isGuest: false,
          };
          return next();
        }

        if (
          cloudUnavailableOrQuotaExceeded &&
          numericId > 1 &&
          numericId < 9000000 &&
          (candidateUsername.length > 0 || candidateDisplayName.length > 0)
        ) {
          // Graceful fallback during temporary Firestore 429 quota exhaustion for standard non-privileged accounts:
          // Strictly locked to 'user' (NEVER 'owner' or 'moderator') so FCM token registration & user chat pushes keep working.
          const safeUname = String(parsed.username || parsed.displayName || `user_${numericId}`).trim();
          const safeDname = String(parsed.displayName || parsed.username || safeUname).trim();
          req.user = {
            id: numericId,
            username: safeUname,
            displayName: safeDname,
            role: 'user',
            avatarUrl: null,
            isGuest: false,
          };
          return next();
        }
      }
    } catch {}
  }

  next();
}

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'يرجى تسجيل الدخول للوصول إلى هذا المحتوى' });
    return;
  }
  next();
}

export function requireRole(allowedRoles: string | string[]) {
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'يرجى تسجيل الدخول' });
      return;
    }
    if (!roles.includes(req.user.role)) {
      res.status(403).json({ error: 'ليس لديك الصلاحيات الكافية للقيام بهذا الإجراء' });
      return;
    }
    next();
  };
}
