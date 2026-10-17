// Tiny fetch client for the admin API. Injects X-Admin-Token from localStorage
// on every request. On 401 we wipe the token and reload so the session falls
// back to the login screen - this also covers token-rotated / expired cases
// without per-component error handling.

import { readAdminToken, clearAdminToken, adminAuthHeaders } from '../../lib/admin-token';
import { errMessage } from '../../lib/log';

const BASE = '/api/v1/admin';

function headers(): HeadersInit {
  return {
    ...adminAuthHeaders(),
    'content-type': 'application/json',
  };
}

// Module-level guard: prevent N concurrent in-flight 401s from each firing
// their own `window.location.reload()`. PublishedTab fans out a /social/<slug>
// fetch per row, so a stale token used to schedule M reloads simultaneously.
let reloadingForAuth = false;
function handleUnauthorized(): void {
  if (reloadingForAuth) return;
  reloadingForAuth = true;
  clearAdminToken();
  // window.location.reload bounces back to the login screen - simplest UX.
  window.location.reload();
}

/** Pull `{error}` + `{message}` out of the body for nicer messages, fall back to status.
 *  Many admin endpoints return both - `error` is a short machine-friendly
 *  code (e.g. "rewrite_failed"), `message` is the human-friendly detail
 *  (e.g. "validation failed: missing section: ## Lessons learned").
 *  We surface both so a 4xx/5xx failure shows the actual reason. */
async function extractError(r: Response): Promise<string> {
  let detail = `${r.status} ${r.statusText}`;
  try {
    const body = (await r.clone().json()) as { error?: string; message?: string; detail?: string };
    if (body.error) {
      const extra = body.message ?? body.detail;
      detail = extra ? `${body.error}: ${extra}` : body.error;
    }
  } catch (_catchErr) {
    console.error('extractError failed:', errMessage(_catchErr));
    /* ignore parse errors */
  }
  return detail;
}

export async function getJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(BASE + path, { ...init, headers: headers(), credentials: 'same-origin' });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(await extractError(r));
  return r.json() as Promise<T>;
}

export async function postJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const r = await fetch(BASE + path, { ...init, method: 'POST', headers: headers(), credentials: 'same-origin' });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(await extractError(r));
  return r.json() as Promise<T>;
}

/** Fetch a binary resource from the admin API with the admin token injected,
 *  then return an object URL suitable for use in <img src> / <a href>.
 *  The caller MUST revoke the returned URL (URL.revokeObjectURL) when done. */
export async function getObjectUrl(path: string): Promise<string> {
  const r = await fetch(BASE + path, { headers: headers(), credentials: 'same-origin' });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(await extractError(r));
  const blob = await r.blob();
  return URL.createObjectURL(blob);
}

export async function postJsonWithBody<T>(path: string, body: unknown, init: RequestInit = {}): Promise<T> {
  const r = await fetch(BASE + path, {
    ...init,
    method: 'POST',
    headers: headers(),
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(await extractError(r));
  return r.json() as Promise<T>;
}

// Briefing admin/read endpoints live at /api/v1/briefings/* (NOT under the
// /api/v1/admin BASE). The build/backfill/sweep mutations require the admin
// token (sent on both headers via adminAuthHeaders); list/get are public but
// sending the token is harmless. Same 401 + error handling as the BASE helpers.
const BRIEFINGS_BASE = '/api/v1/briefings';

export async function briefingsGet<T>(path: string): Promise<T> {
  const r = await fetch(BRIEFINGS_BASE + path, { headers: headers(), credentials: 'same-origin' });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(await extractError(r));
  return r.json() as Promise<T>;
}

export async function briefingsPost<T>(path: string): Promise<T> {
  const r = await fetch(BRIEFINGS_BASE + path, { method: 'POST', headers: headers(), credentials: 'same-origin' });
  if (r.status === 401) {
    handleUnauthorized();
    throw new Error('unauthorized');
  }
  if (!r.ok) throw new Error(await extractError(r));
  return r.json() as Promise<T>;
}

// ─── Social approval helpers ─────────────────────────────────────────────────

export interface SocialQueueItem {
  slug: string;
  platform: string;
  status: string;
  scheduledAt?: string;
  postUrl?: string;
  error?: string;
  attempts?: number;
}

export interface SocialQueueResponse {
  autopostEnabled: boolean;
  queue: SocialQueueItem[];
}

export interface SocialScheduleEntryResponse {
  ok: boolean;
  schedule: {
    slug: string;
    twitter?: { scheduledAt?: string; status: string; postUrl?: string; error?: string; attempts?: number };
    linkedin?: { scheduledAt?: string; status: string; postUrl?: string; error?: string; attempts?: number };
    instagram?: { scheduledAt?: string; status: string; postUrl?: string; error?: string; attempts?: number };
    updatedAt: string;
  };
}

/** Approve a platform's social copy for auto-posting.
 *  Optional `scheduledAt` (ISO) sets the publish time; defaults to now. */
export function approveSocialPlatform(
  slug: string,
  platform: string,
  scheduledAt?: string
): Promise<SocialScheduleEntryResponse> {
  const body = scheduledAt ? { scheduledAt } : {};
  return postJsonWithBody<SocialScheduleEntryResponse>(
    `/social-schedule/${encodeURIComponent(slug)}/${encodeURIComponent(platform)}/approve`,
    body
  );
}

/** Revert an approved platform entry back to pending (unapprove). */
export function unapproveSocialPlatform(slug: string, platform: string): Promise<SocialScheduleEntryResponse> {
  return postJson<SocialScheduleEntryResponse>(
    `/social-schedule/${encodeURIComponent(slug)}/${encodeURIComponent(platform)}/unapprove`
  );
}

/** Fetch the content-calendar agenda: autopost switch state + sorted queue. */
export function getSocialQueue(): Promise<SocialQueueResponse> {
  return getJson<SocialQueueResponse>('/social-queue');
}

// ─── Social analytics helpers ─────────────────────────────────────────────────

export interface SocialPostMetrics {
  impressions?: number;
  likes?: number;
  reposts?: number;
  replies?: number;
  clicks?: number;
}

export interface SocialAnalyticsPost {
  slug: string;
  platform: 'twitter' | 'linkedin' | 'instagram';
  type: string;
  postUrl?: string;
  metrics: SocialPostMetrics;
  fetchedAt: string;
  engagement: number;
}

export interface SocialAnalyticsByType {
  type: string;
  posts: number;
  totalEngagement: number;
  avgEngagement: number;
  totalImpressions: number;
}

export interface SocialAnalyticsResponse {
  posts: SocialAnalyticsPost[];
  byType: SocialAnalyticsByType[];
}

export interface SaveSocialMetricsResponse {
  ok: boolean;
  record: unknown;
}

/** Fetch engagement analytics for all posted social content. */
export function getSocialAnalytics(): Promise<SocialAnalyticsResponse> {
  return getJson<SocialAnalyticsResponse>('/social-analytics');
}

/** Store a manual metrics entry for a post + platform (LinkedIn / Instagram). */
export function saveSocialMetrics(
  slug: string,
  platform: 'twitter' | 'linkedin' | 'instagram',
  metrics: SocialPostMetrics & { postUrl?: string }
): Promise<SaveSocialMetricsResponse> {
  return postJsonWithBody<SaveSocialMetricsResponse>(
    `/social-metrics/${encodeURIComponent(slug)}/${encodeURIComponent(platform)}`,
    metrics
  );
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Probe the admin token without mounting the shell. Used by AdminApp on
 * mount: if the cached token is stale, we surface the login screen
 * immediately instead of letting the first tab's fetch trigger a reload
 * loop.
 */
export async function probeAuth(): Promise<boolean> {
  const t = readAdminToken();
  if (!t) return false;
  try {
    const r = await fetch(`${BASE}/health`, { headers: headers(), credentials: 'same-origin' });
    return r.status !== 401;
  } catch (_catchErr) {
    console.error('probeAuth failed:', errMessage(_catchErr));
    return false;
  }
}
