/**
 * Firebase Cloud Messaging and Native Bridge service for Sami App
 */

const DEFAULT_PUSH_SERVER_URL = 'https://ais-pre-m6d2jiswkimjkpxhc2mb3j-539156456102.europe-west2.run.app';
const DEAD_LEGACY_PUSH_URL = 'ais-pre-v2pd4io33vpee4p7cqhqoz-27831794049';

function resolvePushApiBase(bridge: any): string {
  try {
    if (typeof window !== 'undefined' && /^https?:$/i.test(window.location.protocol)) {
      const host = window.location.hostname || '';
      if (host && host !== 'appassets.androidplatform.net' && host !== 'localhost') {
        return '';
      }
    }
    const bridgeUrl =
      bridge && typeof bridge.getPushServerUrl === 'function' ? String(bridge.getPushServerUrl() || '').trim() : '';
    if (bridgeUrl && !bridgeUrl.includes(DEAD_LEGACY_PUSH_URL)) {
      return bridgeUrl.replace(/\/+$/, '');
    }
    const stored = String(localStorage.getItem('sami_push_server_url') || '').trim();
    if (stored && !stored.includes(DEAD_LEGACY_PUSH_URL)) {
      return stored.replace(/\/+$/, '');
    }
  } catch {}
  return DEFAULT_PUSH_SERVER_URL;
}

function buildSessionHeader(userId: number, username: string, displayName?: string): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const jwt = localStorage.getItem('sami_jwt_token');
  if (jwt) {
    headers['Authorization'] = `Bearer ${jwt}`;
  }
  if (userId > 0 && username) {
    headers['X-Sami-Session'] = encodeURIComponent(
      JSON.stringify({
        id: userId,
        username,
        displayName: displayName || username,
      })
    );
  }
  return headers;
}

export function syncUserSessionToNative(userId: number, username: string, displayName?: string): void {
  try {
    const cleanUsername = String(username || displayName || '').trim();
    const cleanDisplay = String(displayName || username || '').trim();
    const bridge =
      (window as any).SamiBridge ||
      (window as any).AndroidBridge ||
      (window as any).Android;

    if (bridge) {
      if (typeof bridge.syncUserSessionFull === 'function') {
        try {
          bridge.syncUserSessionFull(String(userId), cleanUsername, cleanDisplay);
        } catch {}
      } else if (typeof bridge.syncUserSession === 'function') {
        try {
          bridge.syncUserSession(String(userId), cleanUsername);
        } catch {
          try {
            bridge.syncUserSession(userId, cleanUsername);
          } catch {}
        }
      }
    }

    const token =
      (bridge && typeof bridge.getFcmToken === 'function' && bridge.getFcmToken()) ||
      localStorage.getItem('sami_fcm_token');
    const deviceId =
      (bridge && typeof bridge.getDeviceId === 'function' && bridge.getDeviceId()) ||
      localStorage.getItem('sami_stable_device_id') ||
      undefined;

    if (token && userId > 0 && cleanUsername) {
      const apiBase = resolvePushApiBase(bridge);
      fetch(`${apiBase}/api/fcm/register`, {
        method: 'POST',
        headers: buildSessionHeader(userId, cleanUsername, cleanDisplay),
        body: JSON.stringify({
          token,
          deviceId,
          userId,
          username: cleanUsername,
          displayName: cleanDisplay,
          platform: bridge ? 'android' : 'web',
        }),
      }).catch(() => {});
    }
  } catch (err) {
    console.debug('[FCM Bridge] Error syncing to native:', err);
  }
}

export async function unregisterUserFcmToken(
  userId: number,
  username?: string,
  displayName?: string
): Promise<void> {
  try {
    const bridge =
      (window as any).SamiBridge ||
      (window as any).AndroidBridge ||
      (window as any).Android;

    const token =
      (bridge && typeof bridge.getFcmToken === 'function' && bridge.getFcmToken()) ||
      localStorage.getItem('sami_fcm_token');
    const deviceId =
      (bridge && typeof bridge.getDeviceId === 'function' && bridge.getDeviceId()) ||
      localStorage.getItem('sami_stable_device_id') ||
      undefined;

    if (bridge) {
      if (typeof bridge.unregisterFcmToken === 'function') {
        try {
          bridge.unregisterFcmToken();
        } catch {
          try {
            bridge.unregisterFcmToken(String(userId));
          } catch {}
        }
      } else if (typeof bridge.onLogout === 'function') {
        try {
          bridge.onLogout();
        } catch {}
      }
    }

    localStorage.removeItem('sami_fcm_token');

    if (userId > 0 && (username || displayName)) {
      const apiBase = resolvePushApiBase(bridge);
      await fetch(`${apiBase}/api/fcm/unregister`, {
        method: 'POST',
        headers: buildSessionHeader(userId, username || displayName || '', displayName),
        body: JSON.stringify({ userId, token: token || undefined, deviceId }),
      }).catch(() => {});
    }
  } catch (err) {
    console.debug('[FCM Bridge] Error unregistering FCM token:', err);
  }
}
