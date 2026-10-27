import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import {
  firestoreClient,
  projectId,
  databaseId,
  getChannelById,
  isChannelOpenPublic,
  getAllUsersList,
  isFirestoreRestInQuotaBackoff,
  noteFirestoreRestStatus,
} from './db.ts';

/**
 * Firebase Cloud Messaging (FCM) Push Notification Service for Sami
 * - Stores device tokens & durable retry outbox locally (`data/fcm_tokens.json`, `data/fcm_outbox.json`)
 *   and syncs with shared Firestore `community_notifications` (preserving existing projectId + databaseId
 *   and all user/chat data, with automatic 429 quota protection).
 * - Dispatches OS-level Android notifications via FCM HTTP v1 API (hybrid notification + data with HIGH
 *   priority, non-collapsible 7-day offline storage TTL, Direct Boot support, monochrome icon, and
 *   OPEN_SAMI_CHAT click_action) so notifications arrive reliably when Sami is open, backgrounded,
 *   screen-locked, offline-then-reconnected, or completely swiped away from Android Recents.
 */

export interface DeviceTokenRecord {
  id: string;
  token: string;
  userId: number;
  username: string;
  displayName?: string;
  deviceId: string;
  platform: string;
  deviceModel?: string;
  updatedAt: number;
  createdAt: number;
}

interface LocalOutboxJob {
  jobId: string;
  targetUserIds: number[];
  payload: ChatPushPayload;
  createdAt: number;
  attempts: number;
  nextAttemptAt: number;
  lastError?: string;
}

const DATA_DIR = path.resolve('data');
const TOKENS_FILE = path.join(DATA_DIR, 'fcm_tokens.json');
const OUTBOX_FILE = path.join(DATA_DIR, 'fcm_outbox.json');
const DEDUP_FILE = path.join(DATA_DIR, 'fcm_sent_dedup.json');
const SHARED_NOTIF_COLLECTION = 'community_notifications';

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadJsonFile<T>(filePath: string, fallback: T): T {
  try {
    if (fs.existsSync(filePath)) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8')) as T;
    }
  } catch {}
  return fallback;
}

function saveJsonFile(filePath: string, data: unknown): void {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.warn(`[FCM] Error saving ${path.basename(filePath)}:`, e);
  }
}

const localTokens: Record<string, DeviceTokenRecord> = loadJsonFile(TOKENS_FILE, {});
const localRetryOutbox: Record<string, LocalOutboxJob> = loadJsonFile(OUTBOX_FILE, {});
const persistedDedupRaw: Record<string, number> = loadJsonFile(DEDUP_FILE, {});

// In-memory cache of Firestore tokens to prevent burning Firestore's 50k/day free read quota
let cloudTokensCache: Array<{ token: string; userId: number; deviceId: string }> = [];
let cloudTokensLastSyncAt = 0;
const CLOUD_TOKENS_CACHE_TTL_MS = 5 * 60 * 1000;

function getFirestoreBaseUrl(): string {
  const dbSeg = encodeURIComponent(databaseId || '(default)');
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/${dbSeg}/documents`;
}

function sanitizeDocIdPart(val: string): string {
  return String(val || 'android').replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 64) || 'android';
}

function buildTokenDocId(userId: number, deviceId: string): string {
  return `fcm_tok_${userId}_${sanitizeDocIdPart(deviceId)}`;
}

// ==========================================
// 1. TOKEN REGISTRATION, REFRESH & CLEANUP
// ==========================================

export function getRegisteredDeviceTokensSummary(userId?: number): {
  totalDevices: number;
  userDevices: number;
  platforms: string[];
} {
  const all = Object.values(localTokens).filter((r) => Boolean(r?.token && r.userId > 0));
  const userRecs = userId && userId > 0 ? all.filter((r) => r.userId === userId) : [];
  const platforms = Array.from(new Set((userId ? userRecs : all).map((r) => r.platform || 'android')));
  return {
    totalDevices: all.length,
    userDevices: userRecs.length,
    platforms,
  };
}

export function getLocalRegisteredNonGuestUserIds(): number[] {
  const ids = new Set<number>();
  for (const rec of Object.values(localTokens)) {
    if (rec?.token && rec.userId > 0 && rec.userId < 9000000) {
      ids.add(rec.userId);
    }
  }
  for (const rec of cloudTokensCache) {
    if (rec?.token && rec.userId > 0 && rec.userId < 9000000) {
      ids.add(rec.userId);
    }
  }
  return Array.from(ids);
}

export async function registerDeviceToken(params: {
  token: string;
  userId: number;
  username: string;
  displayName?: string;
  deviceId?: string;
  platform?: string;
  deviceModel?: string;
}): Promise<DeviceTokenRecord> {
  const cleanToken = String(params.token || '').trim();
  const userId = Number(params.userId);
  if (!cleanToken || cleanToken.length < 16 || !userId || userId <= 0) {
    throw new Error('بيانات تسجيل رمز الإشعارات غير صالحة');
  }

  const deviceId = sanitizeDocIdPart(
    params.deviceId?.trim() || crypto.createHash('sha1').update(cleanToken).digest('hex').slice(0, 16)
  );
  const now = Date.now();
  const docId = buildTokenDocId(userId, deviceId);

  // Clean up any stale bindings on the same physical device or same FCM token (account switch protection)
  for (const [k, existing] of Object.entries(localTokens)) {
    if (k !== docId && (existing.token === cleanToken || existing.deviceId === deviceId)) {
      delete localTokens[k];
    }
  }

  const record: DeviceTokenRecord = {
    id: docId,
    token: cleanToken,
    userId,
    username: params.username || `user_${userId}`,
    displayName: params.displayName || params.username || `user_${userId}`,
    deviceId,
    platform: params.platform || 'android',
    deviceModel: params.deviceModel || 'Android',
    updatedAt: now,
    createdAt: localTokens[docId]?.createdAt || now,
  };

  localTokens[docId] = record;
  saveJsonFile(TOKENS_FILE, localTokens);

  // Update in-memory cloud cache immediately without needing a Firestore read
  cloudTokensCache = cloudTokensCache.filter(
    (item) => item.token !== cleanToken && item.deviceId !== deviceId
  );
  cloudTokensCache.push({ token: cleanToken, userId, deviceId });

  if (isFirestoreRestInQuotaBackoff() && !firestoreClient) {
    return record;
  }

  // Clean stale bindings in shared Firestore community_notifications (type == 'fcm_device_token')
  if (!isFirestoreRestInQuotaBackoff()) {
    try {
      for (const filterField of [
        { field: 'deviceId', value: deviceId },
        { field: 'token', value: cleanToken },
      ]) {
        const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            structuredQuery: {
              from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
              where: {
                compositeFilter: {
                  op: 'AND',
                  filters: [
                    {
                      fieldFilter: {
                        field: { fieldPath: 'type' },
                        op: 'EQUAL',
                        value: { stringValue: 'fcm_device_token' },
                      },
                    },
                    {
                      fieldFilter: {
                        field: { fieldPath: filterField.field },
                        op: 'EQUAL',
                        value: { stringValue: filterField.value },
                      },
                    },
                  ],
                },
              },
              limit: 10,
            },
          }),
        });
        noteFirestoreRestStatus(res.status);
        if (res.ok) {
          const rows: any[] = await res.json();
          for (const row of rows) {
            const docName = row?.document?.name;
            if (docName && !String(docName).endsWith(`/${docId}`)) {
              await fetch(`https://firestore.googleapis.com/v1/${docName}`, { method: 'DELETE' }).catch(() => {});
            }
          }
        } else if (res.status === 429) {
          break;
        }
      }
    } catch {}
  }

  if (firestoreClient) {
    try {
      await firestoreClient.collection(SHARED_NOTIF_COLLECTION).doc(docId).set(
        {
          ...record,
          type: 'fcm_device_token',
          title: 'fcm_token',
          body: '',
          senderId: userId,
          senderName: record.displayName || record.username,
          targetUserIds: [],
          timestamp: now,
        },
        { merge: true }
      );
      return record;
    } catch {}
  }

  if (!isFirestoreRestInQuotaBackoff()) {
    try {
      const url = `${getFirestoreBaseUrl()}/${SHARED_NOTIF_COLLECTION}/${encodeURIComponent(docId)}`;
      const patchRes = await fetch(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fields: {
            id: { stringValue: record.id },
            type: { stringValue: 'fcm_device_token' },
            title: { stringValue: 'fcm_token' },
            body: { stringValue: '' },
            token: { stringValue: record.token },
            userId: { integerValue: String(record.userId) },
            senderId: { integerValue: String(record.userId) },
            username: { stringValue: record.username },
            senderName: { stringValue: record.displayName || record.username },
            deviceId: { stringValue: record.deviceId },
            platform: { stringValue: record.platform },
            deviceModel: { stringValue: record.deviceModel || 'Android' },
            targetUserIds: { arrayValue: { values: [] } },
            timestamp: { integerValue: String(record.updatedAt) },
            updatedAt: { integerValue: String(record.updatedAt) },
            createdAt: { integerValue: String(record.createdAt) },
          },
        }),
      });
      noteFirestoreRestStatus(patchRes.status);
    } catch (err: any) {
      console.warn('[FCM] Firestore REST token save notice:', err?.message);
    }
  }

  return record;
}

export async function unregisterDeviceToken(userId: number, token?: string, deviceId?: string): Promise<void> {
  const cleanTok = token?.trim();
  const cleanDev = deviceId ? sanitizeDocIdPart(deviceId.trim()) : undefined;

  for (const [k, rec] of Object.entries(localTokens)) {
    const matchesUser = rec.userId === userId;
    const matchesTok = Boolean(cleanTok && rec.token === cleanTok);
    const matchesDev = Boolean(cleanDev && rec.deviceId === cleanDev);
    if (matchesTok || (matchesUser && matchesDev) || (matchesUser && !cleanTok && !cleanDev)) {
      delete localTokens[k];
    }
  }
  saveJsonFile(TOKENS_FILE, localTokens);

  cloudTokensCache = cloudTokensCache.filter((item) => {
    const matchesUser = item.userId === userId;
    const matchesTok = Boolean(cleanTok && item.token === cleanTok);
    const matchesDev = Boolean(cleanDev && item.deviceId === cleanDev);
    return !(matchesTok || (matchesUser && matchesDev) || (matchesUser && !cleanTok && !cleanDev));
  });

  if (isFirestoreRestInQuotaBackoff()) return;

  if (cleanDev && userId > 0) {
    const docId = buildTokenDocId(userId, cleanDev);
    await fetch(`${getFirestoreBaseUrl()}/${SHARED_NOTIF_COLLECTION}/${encodeURIComponent(docId)}`, {
      method: 'DELETE',
    }).catch(() => {});
  }

  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            compositeFilter: {
              op: 'AND',
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: 'type' },
                    op: 'EQUAL',
                    value: { stringValue: 'fcm_device_token' },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: 'userId' },
                    op: 'EQUAL',
                    value: { integerValue: String(userId) },
                  },
                },
              ],
            },
          },
          limit: 20,
        },
      }),
    });
    noteFirestoreRestStatus(res.status);
    if (res.ok) {
      const rows: any[] = await res.json();
      for (const row of rows) {
        const doc = row?.document;
        if (!doc?.name || !doc?.fields) continue;
        const docTok = doc.fields.token?.stringValue || '';
        const docDev = doc.fields.deviceId?.stringValue || '';
        if (
          (cleanTok && docTok === cleanTok) ||
          (cleanDev && docDev === cleanDev) ||
          (!cleanTok && !cleanDev)
        ) {
          await fetch(`https://firestore.googleapis.com/v1/${doc.name}`, { method: 'DELETE' }).catch(() => {});
        }
      }
    }
  } catch {}
}

async function pruneInvalidToken(badToken: string): Promise<void> {
  let modified = false;
  for (const [k, rec] of Object.entries(localTokens)) {
    if (rec.token === badToken) {
      delete localTokens[k];
      modified = true;
    }
  }
  if (modified) {
    saveJsonFile(TOKENS_FILE, localTokens);
  }
  cloudTokensCache = cloudTokensCache.filter((item) => item.token !== badToken);

  if (isFirestoreRestInQuotaBackoff()) return;

  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            compositeFilter: {
              op: 'AND',
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: 'type' },
                    op: 'EQUAL',
                    value: { stringValue: 'fcm_device_token' },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: 'token' },
                    op: 'EQUAL',
                    value: { stringValue: badToken },
                  },
                },
              ],
            },
          },
          limit: 15,
        },
      }),
    });
    noteFirestoreRestStatus(res.status);
    if (res.ok) {
      const rows: any[] = await res.json();
      for (const row of rows) {
        if (row?.document?.name) {
          await fetch(`https://firestore.googleapis.com/v1/${row.document.name}`, { method: 'DELETE' }).catch(() => {});
        }
      }
    }
  } catch {}
}

async function refreshCloudTokensIfDue(): Promise<void> {
  const now = Date.now();
  if (isFirestoreRestInQuotaBackoff()) return;
  if (cloudTokensLastSyncAt > 0 && now - cloudTokensLastSyncAt < CLOUD_TOKENS_CACHE_TTL_MS) {
    return;
  }

  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'type' },
              op: 'EQUAL',
              value: { stringValue: 'fcm_device_token' },
            },
          },
          limit: 250,
        },
      }),
    });
    noteFirestoreRestStatus(res.status);
    if (res.ok) {
      cloudTokensLastSyncAt = now;
      const rows: any[] = await res.json();
      const loaded: Array<{ token: string; userId: number; deviceId: string }> = [];
      let localChanged = false;
      for (const row of rows) {
        const f = row?.document?.fields;
        if (!f) continue;
        const uid = Number(f.userId?.integerValue || 0);
        const tok = String(f.token?.stringValue || '').trim();
        const devId = sanitizeDocIdPart(String(f.deviceId?.stringValue || 'android'));
        if (!tok || uid <= 0) continue;
        loaded.push({ token: tok, userId: uid, deviceId: devId });
        const docId = buildTokenDocId(uid, devId);
        if (!localTokens[docId]) {
          localTokens[docId] = {
            id: docId,
            token: tok,
            userId: uid,
            username: String(f.username?.stringValue || `user_${uid}`),
            displayName: String(f.senderName?.stringValue || f.username?.stringValue || `user_${uid}`),
            deviceId: devId,
            platform: String(f.platform?.stringValue || 'android'),
            deviceModel: String(f.deviceModel?.stringValue || 'Android'),
            updatedAt: Number(f.updatedAt?.integerValue || now),
            createdAt: Number(f.createdAt?.integerValue || now),
          };
          localChanged = true;
        }
      }
      cloudTokensCache = loaded;
      if (localChanged) {
        saveJsonFile(TOKENS_FILE, localTokens);
      }
    }
  } catch {}
}

export async function getTokensForUsers(
  userIds: number[],
  excludeSenderId?: number
): Promise<Array<{ token: string; userId: number }>> {
  const allowedIds = Array.from(
    new Set(userIds.filter((id) => id > 0 && id !== excludeSenderId))
  );
  if (allowedIds.length === 0) return [];

  await refreshCloudTokensIfDue();

  const tokenToUser = new Map<string, number>();
  const senderTokens = new Set<string>();

  for (const rec of Object.values(localTokens)) {
    if (!rec.token) continue;
    if (excludeSenderId && rec.userId === excludeSenderId) {
      senderTokens.add(rec.token);
      continue;
    }
    if (allowedIds.includes(rec.userId)) {
      tokenToUser.set(rec.token, rec.userId);
    }
  }

  for (const rec of cloudTokensCache) {
    if (!rec.token) continue;
    if (excludeSenderId && rec.userId === excludeSenderId) {
      senderTokens.add(rec.token);
      tokenToUser.delete(rec.token);
      continue;
    }
    if (allowedIds.includes(rec.userId) && !senderTokens.has(rec.token)) {
      tokenToUser.set(rec.token, rec.userId);
    }
  }

  for (const sTok of senderTokens) {
    tokenToUser.delete(sTok);
  }

  return Array.from(tokenToUser.entries()).map(([token, userId]) => ({ token, userId }));
}

// ==========================================
// 2. OAUTH2 / CREDENTIAL VALIDATION FOR FCM HTTP v1 API
// ==========================================

let cachedAccessToken: string | null = null;
let cachedAccessProjectId: string | null = null;
let cachedTokenExpiry = 0;
let cachedMetadataProjectId: string | null | undefined = undefined;
let loggedMissingCredsWarning = false;

function parseValidServiceAccountJson(): { client_email: string; private_key: string; project_id: string } | null {
  const saRaw = (process.env.FIREBASE_SERVICE_ACCOUNT_KEY || process.env.GCP_SERVICE_ACCOUNT_KEY || '').trim();
  if (!saRaw || saRaw.length < 120) return null;
  try {
    const jsonStr = saRaw.startsWith('{') ? saRaw : Buffer.from(saRaw, 'base64').toString('utf8');
    if (!jsonStr.trim().startsWith('{')) return null;
    const creds = JSON.parse(jsonStr);
    if (
      creds?.type === 'service_account' &&
      typeof creds.client_email === 'string' &&
      typeof creds.private_key === 'string' &&
      creds.private_key.includes('BEGIN PRIVATE KEY')
    ) {
      // Service Account's own project_id MUST match the Firebase project that issued the Android FCM tokens
      const resolvedProj = String(creds.project_id || process.env.FCM_PROJECT_ID || projectId).trim();
      return {
        client_email: creds.client_email,
        private_key: creds.private_key,
        project_id: resolvedProj,
      };
    }
  } catch {}
  return null;
}

function getValidLegacyServerKey(): string | null {
  const raw = (process.env.FCM_SERVER_KEY || process.env.FIREBASE_SERVER_KEY || '').trim();
  if (!raw || raw.length < 80) return null;
  if (raw.startsWith('ai-studio-') || raw.endsWith('-media') || raw.includes(' ')) return null;
  return raw;
}

export function hasServerFcmCredentials(): {
  configured: boolean;
  mode: string;
  fcmProjectId?: string;
  reason?: string;
} {
  const sa = parseValidServiceAccountJson();
  if (sa) {
    return { configured: true, mode: 'service_account_v1', fcmProjectId: sa.project_id };
  }
  const targetFcmProject = (process.env.FCM_PROJECT_ID || projectId).trim();
  if (cachedMetadataProjectId && cachedMetadataProjectId === targetFcmProject) {
    return { configured: true, mode: 'gce_metadata_adc_v1', fcmProjectId: targetFcmProject };
  }
  const legacy = getValidLegacyServerKey();
  if (legacy) {
    return { configured: true, mode: 'legacy_server_key', fcmProjectId: targetFcmProject };
  }
  return {
    configured: false,
    mode: 'missing_credentials',
    fcmProjectId: targetFcmProject,
    reason:
      'FIREBASE_SERVICE_ACCOUNT_KEY (Firebase Service Account JSON) is required in server environment secrets to send FCM HTTP v1 pushes when the app is closed.',
  };
}

function base64UrlEncode(input: Buffer | string): string {
  const buf = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function getGoogleOAuth2Auth(): Promise<{ accessToken: string; fcmProjectId: string } | null> {
  const now = Date.now();
  if (cachedAccessToken && cachedAccessProjectId && now < cachedTokenExpiry - 60_000) {
    return { accessToken: cachedAccessToken, fcmProjectId: cachedAccessProjectId };
  }

  // 1. Service Account JSON (FIREBASE_SERVICE_ACCOUNT_KEY or GCP_SERVICE_ACCOUNT_KEY)
  const creds = parseValidServiceAccountJson();
  if (creds) {
    try {
      const iat = Math.floor(now / 1000);
      const exp = iat + 3600;
      const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const claimSet = base64UrlEncode(
        JSON.stringify({
          iss: creds.client_email,
          scope: 'https://www.googleapis.com/auth/firebase.messaging',
          aud: 'https://oauth2.googleapis.com/token',
          iat,
          exp,
        })
      );
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(`${header}.${claimSet}`);
      signer.end();
      const signature = base64UrlEncode(signer.sign(creds.private_key));
      const assertion = `${header}.${claimSet}.${signature}`;

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion,
        }).toString(),
      });

      if (tokenRes.ok) {
        const tokenData: any = await tokenRes.json();
        if (tokenData.access_token) {
          cachedAccessToken = tokenData.access_token;
          cachedAccessProjectId = creds.project_id;
          cachedTokenExpiry = now + (Number(tokenData.expires_in) || 3500) * 1000;
          return { accessToken: cachedAccessToken!, fcmProjectId: creds.project_id };
        }
      } else {
        const errBody = await tokenRes.text().catch(() => '');
        console.warn('[FCM] Service Account OAuth2 token exchange failed:', tokenRes.status, errBody.slice(0, 180));
      }
    } catch (e: any) {
      console.warn('[FCM] Service Account JWT signing failed:', e?.message);
    }
  }

  // 2. GCE / Cloud Run Metadata Server ADC — ONLY if running inside the matching Firebase GCP project
  const targetFcmProject = (process.env.FCM_PROJECT_ID || projectId).trim();
  try {
    if (cachedMetadataProjectId === undefined) {
      const ctrlProj = new AbortController();
      const tProj = setTimeout(() => ctrlProj.abort(), 1500);
      const projRes = await fetch('http://metadata.google.internal/computeMetadata/v1/project/project-id', {
        headers: { 'Metadata-Flavor': 'Google' },
        signal: ctrlProj.signal,
      });
      clearTimeout(tProj);
      cachedMetadataProjectId = projRes.ok ? (await projRes.text()).trim() : null;
    }

    if (cachedMetadataProjectId && cachedMetadataProjectId === targetFcmProject) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1800);
      const metaRes = await fetch(
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
        {
          headers: { 'Metadata-Flavor': 'Google' },
          signal: controller.signal,
        }
      );
      clearTimeout(timeout);
      if (metaRes.ok) {
        const metaData: any = await metaRes.json();
        if (metaData.access_token) {
          cachedAccessToken = metaData.access_token;
          cachedAccessProjectId = targetFcmProject;
          cachedTokenExpiry = now + (Number(metaData.expires_in) || 1800) * 1000;
          return { accessToken: cachedAccessToken!, fcmProjectId: targetFcmProject };
        }
      }
    }
  } catch {
    cachedMetadataProjectId = null;
  }

  if (!loggedMissingCredsWarning && !getValidLegacyServerKey()) {
    loggedMissingCredsWarning = true;
    console.warn(
      `[FCM] Server FCM HTTP v1 credentials are not configured. ` +
        `Set FIREBASE_SERVICE_ACCOUNT_KEY to a valid Firebase Service Account JSON to enable closed-app FCM pushes.`
    );
  }

  return null;
}

// ==========================================
// 3. DEDUPLICATION, RETRY OUTBOX & ACTUAL PUSH SENDING
// ==========================================

const DEDUP_WINDOW_MS = 60 * 60 * 1000; // 1 hour persistent deduplication window
const recentSentPushKeys = new Map<string, number>(
  Object.entries(persistedDedupRaw).filter(([, ts]) => Date.now() - Number(ts) < DEDUP_WINDOW_MS)
);

function persistDedupKeys(): void {
  const now = Date.now();
  const obj: Record<string, number> = {};
  for (const [k, ts] of recentSentPushKeys.entries()) {
    if (now - ts < DEDUP_WINDOW_MS) {
      obj[k] = ts;
    } else {
      recentSentPushKeys.delete(k);
    }
  }
  saveJsonFile(DEDUP_FILE, obj);
}

function isAlreadySentRecently(dedupKey: string): boolean {
  const now = Date.now();
  const prev = recentSentPushKeys.get(dedupKey);
  if (prev && now - prev < DEDUP_WINDOW_MS) return true;
  recentSentPushKeys.set(dedupKey, now);
  if (recentSentPushKeys.size > 1200) {
    for (const [k, ts] of recentSentPushKeys.entries()) {
      if (now - ts >= DEDUP_WINDOW_MS) recentSentPushKeys.delete(k);
    }
  }
  return false;
}

export interface ChatPushPayload {
  title: string;
  body: string;
  chatType: 'channel' | 'private';
  notifType?: string;
  channelId?: string;
  partnerId?: number;
  messageId?: string;
  senderName?: string;
  senderId?: number;
  timestamp?: number;
}

function buildDataPayload(recipientUserId: number, payload: ChatPushPayload): Record<string, string> {
  const partnerStr = payload.partnerId ? String(payload.partnerId) : '';
  const resolvedType =
    payload.notifType || (payload.chatType === 'private' ? 'private_message' : 'channel_important');
  return {
    title: payload.title,
    body: payload.body,
    chatType: payload.chatType,
    type: resolvedType,
    channelId: payload.channelId || '',
    partnerId: partnerStr,
    partnerIdStr: partnerStr,
    privateChatWithUserId: partnerStr,
    recipientUserId: String(recipientUserId),
    messageId: payload.messageId || '',
    senderName: payload.senderName || 'Sami',
    senderId: payload.senderId ? String(payload.senderId) : '',
    timestamp: String(payload.timestamp || Date.now()),
    fromNotification: 'true',
  };
}

async function sendSingleFcmV1(
  accessToken: string,
  fcmProjectId: string,
  targetToken: string,
  recipientUserId: number,
  payload: ChatPushPayload
): Promise<{ ok: boolean; invalidToken?: boolean; senderMismatch?: boolean; transient?: boolean; error?: string }> {
  const url = `https://fcm.googleapis.com/v1/projects/${encodeURIComponent(fcmProjectId)}/messages:send`;
  const channelIdAndroid = payload.chatType === 'private' ? 'sami_private_messages_v2' : 'sami_channel_messages_v2';
  const tagKey = (payload.messageId || `${payload.chatType}_${payload.channelId || payload.partnerId || 'msg'}`).slice(
    0,
    64
  );
  const dataMap = buildDataPayload(recipientUserId, payload);

  // IMPORTANT FOR OFFLINE & SWIPED-FROM-RECENTS DELIVERY:
  // 1. Hybrid `notification` + `data` with `android.priority = "HIGH"` ensures Google Play Services displays
  //    the system notification immediately even when Sami was swiped away from Android Recents or screen is off,
  //    and launches MainActivity via `OPEN_SAMI_CHAT` with all `data` extras attached when tapped.
  // 2. Do NOT set a unique `collapse_key` per message! FCM limits each device to 4 distinct collapse keys while
  //    offline. Leaving chat pushes non-collapsible with `ttl: "604800s"` (7 days) lets FCM store up to 100
  //    offline messages per device and deliver all of them upon internet reconnection.
  // 3. `android.notification.tag = tagKey` ensures duplicate retries of the SAME `messageId` coalesce into one
  //    single notification in the Android shade without overwriting other messages.
  const messageBody = {
    message: {
      token: targetToken,
      notification: {
        title: payload.title,
        body: payload.body,
      },
      data: dataMap,
      android: {
        priority: 'HIGH',
        ttl: '604800s',
        direct_boot_ok: true,
        notification: {
          channel_id: channelIdAndroid,
          icon: 'ic_stat_sami_notification',
          color: '#F59E0B',
          sound: 'default',
          default_sound: true,
          default_vibrate_timings: true,
          notification_priority: 'PRIORITY_HIGH',
          visibility: payload.chatType === 'private' ? 'PRIVATE' : 'PUBLIC',
          tag: tagKey,
          click_action: 'OPEN_SAMI_CHAT',
        },
      },
    },
  };

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(messageBody),
    });

    if (res.ok) {
      return { ok: true };
    }

    const errText = await res.text().catch(() => '');
    const isInvalid =
      res.status === 404 ||
      errText.includes('UNREGISTERED') ||
      errText.includes('registration-token-not-registered') ||
      (res.status === 400 && errText.includes('The registration token is not a valid FCM registration token'));

    const isSenderMismatch = res.status === 403 && errText.includes('SENDER_ID_MISMATCH');
    const isTransient = res.status === 429 || res.status >= 500;

    return {
      ok: false,
      invalidToken: isInvalid,
      senderMismatch: isSenderMismatch,
      transient: isTransient,
      error: `${res.status}: ${errText.slice(0, 200)}`,
    };
  } catch (err: any) {
    return {
      ok: false,
      transient: true,
      error: err?.message || 'network_error',
    };
  }
}

async function sendSingleFcmLegacy(
  legacyServerKey: string,
  targetToken: string,
  recipientUserId: number,
  payload: ChatPushPayload
): Promise<{ ok: boolean; invalidToken?: boolean; transient?: boolean; error?: string }> {
  const channelIdAndroid = payload.chatType === 'private' ? 'sami_private_messages_v2' : 'sami_channel_messages_v2';
  const tagKey = (payload.messageId || `${payload.chatType}_${payload.channelId || payload.partnerId || 'msg'}`).slice(
    0,
    64
  );
  const dataMap = buildDataPayload(recipientUserId, payload);

  try {
    const res = await fetch('https://fcm.googleapis.com/fcm/send', {
      method: 'POST',
      headers: {
        Authorization: `key=${legacyServerKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        to: targetToken,
        priority: 'high',
        time_to_live: 604800,
        direct_boot_ok: true,
        notification: {
          title: payload.title,
          body: payload.body,
          icon: 'ic_stat_sami_notification',
          color: '#F59E0B',
          sound: 'default',
          android_channel_id: channelIdAndroid,
          tag: tagKey,
          click_action: 'OPEN_SAMI_CHAT',
        },
        data: dataMap,
      }),
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => '');
      return {
        ok: false,
        transient: res.status === 429 || res.status >= 500,
        error: `${res.status}: ${errText.slice(0, 180)}`,
      };
    }

    const json: any = await res.json().catch(() => ({}));
    if (Number(json?.success) > 0) {
      return { ok: true };
    }
    const errCode = String(json?.results?.[0]?.error || 'legacy_send_failed');
    const isInvalid = errCode === 'NotRegistered' || errCode === 'InvalidRegistration';
    const isTransient = errCode === 'Unavailable' || errCode === 'InternalServerError' || errCode === 'DeviceMessageRateExceeded';
    return { ok: false, invalidToken: isInvalid, transient: isTransient, error: errCode };
  } catch (err: any) {
    return { ok: false, transient: true, error: err?.message || 'network_error' };
  }
}

function enqueueLocalRetryJob(targetUserIds: number[], payload: ChatPushPayload, reason: string): void {
  const cleanTargets = Array.from(new Set(targetUserIds.filter((id) => id > 0 && id !== payload.senderId)));
  if (cleanTargets.length === 0) return;

  const jobId = payload.messageId || `retry_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const existing = localRetryOutbox[jobId];
  const attempts = (existing?.attempts || 0) + 1;
  if (attempts > 8) {
    delete localRetryOutbox[jobId];
    saveJsonFile(OUTBOX_FILE, localRetryOutbox);
    return;
  }

  const backoffMs = Math.min(120_000, 10_000 * Math.pow(2, attempts - 1));
  localRetryOutbox[jobId] = {
    jobId,
    targetUserIds: cleanTargets,
    payload: {
      ...payload,
      messageId: payload.messageId || jobId,
      timestamp: payload.timestamp || Date.now(),
    },
    createdAt: existing?.createdAt || Date.now(),
    attempts,
    nextAttemptAt: Date.now() + backoffMs,
    lastError: reason,
  };
  saveJsonFile(OUTBOX_FILE, localRetryOutbox);
}

async function markMatchingPendingOutboxDocsSent(messageId: string): Promise<void> {
  if (!messageId || isFirestoreRestInQuotaBackoff()) return;
  try {
    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            compositeFilter: {
              op: 'AND',
              filters: [
                {
                  fieldFilter: {
                    field: { fieldPath: 'messageId' },
                    op: 'EQUAL',
                    value: { stringValue: messageId },
                  },
                },
                {
                  fieldFilter: {
                    field: { fieldPath: 'fcmStatus' },
                    op: 'EQUAL',
                    value: { stringValue: 'pending' },
                  },
                },
              ],
            },
          },
          limit: 5,
        },
      }),
    });
    noteFirestoreRestStatus(res.status);
    if (!res.ok) return;
    const rows: any[] = await res.json();
    for (const row of rows) {
      if (row?.document?.name) {
        await updateOutboxDocStatus(row.document.name, 'sent');
      }
    }
  } catch {}
}

export async function sendNotificationToUsers(
  targetUserIds: number[],
  payload: ChatPushPayload,
  options?: { fromRetryWorker?: boolean }
): Promise<{ sentCount: number; failedCount: number; queuedForRetry?: boolean; credentialsConfigured: boolean }> {
  const recipients = await getTokensForUsers(targetUserIds, payload.senderId);
  if (recipients.length === 0) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const v1Auth = await getGoogleOAuth2Auth();
  const legacyKey = v1Auth ? null : getValidLegacyServerKey();
  if (!v1Auth && !legacyKey) {
    if (!options?.fromRetryWorker && payload.messageId) {
      enqueueLocalRetryJob(targetUserIds, payload, 'missing_fcm_credentials');
    }
    return {
      sentCount: 0,
      failedCount: recipients.length,
      queuedForRetry: Boolean(!options?.fromRetryWorker && payload.messageId),
      credentialsConfigured: false,
    };
  }

  let sentCount = 0;
  let failedCount = 0;
  const failedTransientUserIds = new Set<number>();
  let dedupDirty = false;

  await Promise.allSettled(
    recipients.map(async ({ token, userId }) => {
      const dedupKey = `${payload.messageId || `${payload.title}_${payload.body}`}::${token}`;
      if (payload.messageId && isAlreadySentRecently(dedupKey)) {
        return;
      }

      const result = v1Auth
        ? await sendSingleFcmV1(v1Auth.accessToken, v1Auth.fcmProjectId, token, userId, payload)
        : await sendSingleFcmLegacy(legacyKey!, token, userId, payload);

      if (result.ok) {
        sentCount++;
        dedupDirty = true;
      } else {
        failedCount++;
        recentSentPushKeys.delete(dedupKey);
        if (result.invalidToken) {
          await pruneInvalidToken(token);
        } else if ((result as any).senderMismatch) {
          console.error(
            '[FCM] SENDER_ID_MISMATCH: The Android APK google_app_id / gcm_defaultSenderId does not match the server FIREBASE_SERVICE_ACCOUNT_KEY project!'
          );
        } else {
          if (result.transient) {
            failedTransientUserIds.add(userId);
          }
          if (result.error) {
            console.warn('[FCM] Push delivery error:', result.error);
          }
        }
      }
    })
  );

  if (dedupDirty) {
    persistDedupKeys();
  }

  if (failedTransientUserIds.size > 0 && payload.messageId) {
    enqueueLocalRetryJob(Array.from(failedTransientUserIds), payload, 'transient_fcm_error');
  } else if (payload.messageId && localRetryOutbox[payload.messageId]) {
    delete localRetryOutbox[payload.messageId];
    saveJsonFile(OUTBOX_FILE, localRetryOutbox);
  }

  if (sentCount > 0 && payload.messageId) {
    markMatchingPendingOutboxDocsSent(payload.messageId).catch(() => {});
  }

  return {
    sentCount,
    failedCount,
    queuedForRetry: failedTransientUserIds.size > 0,
    credentialsConfigured: true,
  };
}

// ==========================================
// 4. AUTHORIZED MESSAGE PUSH DISPATCHER (STRICT RBAC & PRIVACY)
// ==========================================

export async function dispatchAuthorizedChatPush(params: {
  senderId: number;
  senderName: string;
  senderRole: string;
  chatType: 'channel' | 'private';
  notifType?: string;
  channelId?: string;
  receiverId?: number;
  authorizedTargetUserIds?: number[];
  customTitle?: string;
  messageId: string;
  snippet: string;
  timestamp?: number;
}): Promise<{ sentCount: number; failedCount: number; queuedForRetry?: boolean; credentialsConfigured: boolean }> {
  const {
    senderId,
    senderName,
    senderRole,
    chatType,
    notifType,
    channelId,
    receiverId,
    authorizedTargetUserIds,
    customTitle,
    messageId,
    snippet,
    timestamp,
  } = params;

  // 1. PRIVATE MESSAGES: Strictly delivered ONLY to the single authorized recipient (never broadcast!)
  if (chatType === 'private') {
    if (!receiverId || receiverId <= 0 || receiverId === senderId) {
      return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
    }
    const title = senderId === 1 ? '👑 رسالة خاصة من القائد Sami' : `💬 رسالة خاصة من ${senderName}`;
    const body = snippet && snippet.trim() ? snippet.trim().slice(0, 120) : 'لديك رسالة خاصة جديدة';
    return sendNotificationToUsers([receiverId], {
      title,
      body,
      chatType: 'private',
      notifType: 'private_message',
      partnerId: senderId,
      messageId,
      senderName,
      senderId,
      timestamp,
    });
  }

  // 2. CHANNEL MESSAGES / MODERATION ALERTS
  if (!channelId) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const channel = await getChannelById(channelId);
  if (!channel) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const openPublic = isChannelOpenPublic(channel);
  const authorizedMembers = Array.from(
    new Set([...(channel.allowedMemberIds || []), ...(channel.memberIds || []), 1])
  ).filter((id) => id > 0 && id < 9000000);

  if (!openPublic && senderRole !== 'owner' && senderId !== 1 && !authorizedMembers.includes(senderId)) {
    return { sentCount: 0, failedCount: 0, credentialsConfigured: hasServerFcmCredentials().configured };
  }

  const sanitizedClientTargets = Array.isArray(authorizedTargetUserIds)
    ? authorizedTargetUserIds
        .map((n) => Number(n))
        .filter((n) => Number.isFinite(n) && n > 0 && n < 9000000 && n !== senderId)
    : [];

  let recipientIds: number[] = [];

  if ((notifType === 'warning' || notifType === 'kick') && (senderRole === 'owner' || senderRole === 'moderator' || senderId === 1)) {
    // Moderation alerts go strictly to targeted user(s) + Owner
    recipientIds = sanitizedClientTargets.length > 0 ? Array.from(new Set([...sanitizedClientTargets, 1])) : [1];
  } else if (channel.visibility === 'hidden' || !openPublic) {
    // Strictly send ONLY to authorized members of hidden / password-protected / VIP channels!
    // Never reveal hidden channel names or message snippets to unauthorized accounts.
    if (senderId === 1 && senderRole === 'owner' && authorizedMembers.length <= 1 && sanitizedClientTargets.length > 0) {
      // If Firestore is in 429 quota backoff and Owner sends to a VIP channel whose live member list was passed by Owner
      recipientIds = Array.from(new Set([...authorizedMembers, ...sanitizedClientTargets]));
    } else {
      recipientIds = authorizedMembers;
    }
  } else {
    // Open public channel: send to all registered non-guest users + joined members + registered non-guest devices
    const allUsers = await getAllUsersList();
    const tokenUsers = getLocalRegisteredNonGuestUserIds();
    recipientIds = Array.from(
      new Set([
        ...allUsers.map((u) => u.id).filter((id) => id > 0 && id < 9000000),
        ...authorizedMembers,
        ...tokenUsers,
        ...sanitizedClientTargets,
      ])
    ).filter((id) => id !== senderId);
  }

  const senderPrefix =
    senderRole === 'owner' || senderId === 1
      ? '👑 القائد Sami'
      : senderRole === 'moderator'
        ? `🛡️ المشرف ${senderName}`
        : senderName;

  const resolvedTitle =
    (notifType === 'warning' || notifType === 'kick') && customTitle && customTitle.trim()
      ? customTitle.trim().slice(0, 90)
      : `${senderPrefix} • ${channel.name}`;

  return sendNotificationToUsers(recipientIds, {
    title: resolvedTitle,
    body: snippet && snippet.trim() ? snippet.trim().slice(0, 120) : 'رسالة جديدة في القناة',
    chatType: 'channel',
    notifType: notifType || 'channel_important',
    channelId: channel.id,
    messageId,
    senderName,
    senderId,
    timestamp,
  });
}

// ==========================================
// 5. DURABLE RETRY WORKER & QUOTA-SAFE FIRESTORE OUTBOX WORKER
// ==========================================

let outboxPollingActive = false;
let localRetryActive = false;

async function processLocalRetryOutbox(): Promise<void> {
  if (localRetryActive) return;
  const entries = Object.values(localRetryOutbox);
  if (entries.length === 0) return;

  const v1Auth = await getGoogleOAuth2Auth();
  const legacyKey = v1Auth ? null : getValidLegacyServerKey();
  if (!v1Auth && !legacyKey) return;

  localRetryActive = true;
  try {
    const now = Date.now();
    let changed = false;
    for (const job of entries) {
      if (now - job.createdAt > 30 * 60 * 1000) {
        delete localRetryOutbox[job.jobId];
        changed = true;
        continue;
      }
      if (now < job.nextAttemptAt) continue;

      const res = await sendNotificationToUsers(job.targetUserIds, job.payload, { fromRetryWorker: true });
      if (res.sentCount > 0 || !res.queuedForRetry) {
        delete localRetryOutbox[job.jobId];
        changed = true;
      }
    }
    if (changed) {
      saveJsonFile(OUTBOX_FILE, localRetryOutbox);
    }
  } catch {
  } finally {
    localRetryActive = false;
  }
}

async function updateOutboxDocStatus(docName: string, status: string): Promise<void> {
  if (isFirestoreRestInQuotaBackoff()) return;
  const res = await fetch(
    `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=fcmStatus&updateMask.fieldPaths=fcmProcessedAt`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fields: {
          fcmStatus: { stringValue: status },
          fcmProcessedAt: { integerValue: String(Date.now()) },
        },
      }),
    }
  ).catch(() => null);
  if (res) noteFirestoreRestStatus(res.status);
}

async function pollPendingFcmOutbox(): Promise<void> {
  if (outboxPollingActive || isFirestoreRestInQuotaBackoff()) return;
  outboxPollingActive = true;
  try {
    const v1Auth = await getGoogleOAuth2Auth();
    const legacyKey = v1Auth ? null : getValidLegacyServerKey();
    if (!v1Auth && !legacyKey) {
      return;
    }

    const res = await fetch(`${getFirestoreBaseUrl()}:runQuery`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: SHARED_NOTIF_COLLECTION }],
          where: {
            fieldFilter: {
              field: { fieldPath: 'fcmStatus' },
              op: 'EQUAL',
              value: { stringValue: 'pending' },
            },
          },
          limit: 15,
        },
      }),
    });
    noteFirestoreRestStatus(res.status);
    if (!res.ok) return;
    const rows: any[] = await res.json();
    if (!Array.isArray(rows)) return;

    const now = Date.now();
    for (const row of rows) {
      const doc = row?.document;
      const f = doc?.fields;
      if (!doc?.name || !f) continue;

      const notifType = f.type?.stringValue || '';
      if (notifType === 'fcm_device_token') continue;

      const jobId = f.id?.stringValue || String(doc.name).split('/').pop() || '';
      const createdAt = Number(f.timestamp?.integerValue || f.createdAt?.integerValue || 0);
      if (createdAt > 0 && now - createdAt > 30 * 60 * 1000) {
        await updateOutboxDocStatus(doc.name, 'expired');
        continue;
      }

      const senderId = Number(f.senderId?.integerValue || 0);
      const senderName = String(f.senderName?.stringValue || 'Sami');
      const senderRole = String(f.senderRole?.stringValue || (senderId === 1 ? 'owner' : 'user'));
      const chatType =
        f.chatType?.stringValue === 'private' || notifType === 'private_message' ? 'private' : 'channel';
      const channelId = f.channelId?.stringValue || undefined;
      const partnerId = Number(f.partnerId?.integerValue || f.privateChatWithUserId?.integerValue || 0);
      const messageId = f.messageId?.stringValue || jobId;
      const bodyText = String(f.body?.stringValue || 'رسالة جديدة');
      const titleText = String(f.title?.stringValue || '');
      const targetUserIds: number[] = Array.isArray(f.targetUserIds?.arrayValue?.values)
        ? f.targetUserIds.arrayValue.values
            .map((v: any) => Number(v.integerValue || 0))
            .filter((n: number) => n > 0)
        : [];

      const receiverId = chatType === 'private' ? targetUserIds[0] : undefined;

      await updateOutboxDocStatus(doc.name, 'processing');

      const dispatchRes = await dispatchAuthorizedChatPush({
        senderId,
        senderName,
        senderRole,
        chatType,
        notifType,
        channelId,
        receiverId: receiverId || (partnerId && partnerId !== senderId ? partnerId : undefined),
        authorizedTargetUserIds: targetUserIds,
        customTitle: titleText || undefined,
        messageId,
        snippet: bodyText,
        timestamp: createdAt || now,
      });

      const finalStatus =
        dispatchRes.sentCount > 0
          ? 'sent'
          : dispatchRes.queuedForRetry
            ? 'retrying'
            : dispatchRes.failedCount > 0
              ? 'failed'
              : 'no_registered_devices';
      await updateOutboxDocStatus(doc.name, finalStatus);
    }
  } catch {
    // Ignore transient network errors
  } finally {
    outboxPollingActive = false;
  }
}

// Local disk retry queue check (0 Firestore reads)
setInterval(() => {
  processLocalRetryOutbox().catch(() => {});
}, 15_000);

// Quota-friendly backup Firestore outbox check (30s interval, pauses automatically on 429)
setInterval(() => {
  pollPendingFcmOutbox().catch(() => {});
}, 30_000);
