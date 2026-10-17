import { useEffect, useState, type FormEvent } from 'react';
import { getJson, postJsonWithBody } from './adminApi';
import { adminAuthHeaders } from '../../lib/admin-token';
import { errMessage } from '../../lib/log';

interface CookieStatus {
  source: 'kv' | 'env' | 'none';
  configured: boolean;
  authToken: { set: boolean; last4: string };
  ct0: { set: boolean; last4: string };
  bearerOverridden: boolean;
  updatedAt: string | null;
}

interface HealthResult {
  ok: boolean;
  configured: boolean;
  auth: 'ok' | 'missing' | 'expired';
  qids: 'ok' | 'stale' | 'unknown';
  rateLimited: boolean;
  handle: string;
  detail?: string;
  checkedAt: string;
}

interface QidsStatus {
  source: 'kv' | 'default';
  qids: { userByScreenName: string; userTweets: string; userTweetsAndReplies: string; searchTimeline: string };
  overridden: {
    userByScreenName: boolean;
    userTweets: boolean;
    userTweetsAndReplies: boolean;
    searchTimeline: boolean;
  };
  updatedAt: string | null;
}

const QID_FIELDS: Array<{ key: keyof QidsStatus['qids']; label: string }> = [
  { key: 'userByScreenName', label: 'UserByScreenName' },
  { key: 'userTweets', label: 'UserTweets' },
  { key: 'userTweetsAndReplies', label: 'UserTweetsAndReplies' },
  { key: 'searchTimeline', label: 'SearchTimeline' },
];

const SOURCE_LABEL: Record<CookieStatus['source'], string> = {
  kv: 'Admin override (KV)',
  env: 'Worker secrets',
  none: 'Not configured',
};

export default function XCookiesTab() {
  const [status, setStatus] = useState<CookieStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const [authToken, setAuthToken] = useState('');
  const [ct0, setCt0] = useState('');
  const [bearer, setBearer] = useState('');
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [health, setHealth] = useState<HealthResult | null>(null);
  const [testing, setTesting] = useState(false);

  const [qids, setQids] = useState<QidsStatus['qids']>({
    userByScreenName: '',
    userTweets: '',
    userTweetsAndReplies: '',
    searchTimeline: '',
  });
  const [qidsStatus, setQidsStatus] = useState<QidsStatus | null>(null);
  const [qidsSaving, setQidsSaving] = useState(false);
  const [qidsClearing, setQidsClearing] = useState(false);
  const [qidsMsg, setQidsMsg] = useState<string | null>(null);

  async function load() {
    try {
      setLoading(true);
      const data = await getJson<CookieStatus>('/x-cookies');
      setStatus(data);
      setError(null);
    } catch (e) {
      console.error('load x-cookies failed:', errMessage(e));
      setError(errMessage(e, 'failed to load status'));
    } finally {
      setLoading(false);
    }
  }

  async function handleTest() {
    setTesting(true);
    setHealth(null);
    setError(null);
    try {
      const r = await fetch('/api/v1/x-firehose?status=deep', { credentials: 'same-origin' });
      const data = (await r.json()) as HealthResult;
      setHealth(data);
    } catch (e) {
      console.error('test x connection failed:', errMessage(e));
      setError(errMessage(e, 'test failed'));
    } finally {
      setTesting(false);
    }
  }

  useEffect(() => {
    void load();
    void loadQids();
  }, []);

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setSaving(true);
    setSaved(null);
    setError(null);
    try {
      await postJsonWithBody('/x-cookies', {
        authToken: authToken.trim(),
        ct0: ct0.trim(),
        bearer: bearer.trim() || undefined,
      });
      setAuthToken('');
      setCt0('');
      setBearer('');
      setSaved('Cookies saved - the X integration now uses the admin override.');
      void load();
    } catch (err) {
      console.error('save x-cookies failed:', errMessage(err));
      setError(errMessage(err, 'failed to save'));
    } finally {
      setSaving(false);
    }
  }

  async function handleClear() {
    if (
      !confirm(
        'Clear the admin cookie override? The X integration will fall back to the X_AUTH_TOKEN / X_CT0 worker secrets.'
      )
    )
      return;
    setClearing(true);
    setError(null);
    setSaved(null);
    try {
      const r = await fetch('/api/v1/admin/x-cookies', {
        method: 'DELETE',
        headers: adminAuthHeaders(),
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`${r.status}`);
      setSaved('Admin override cleared.');
      void load();
    } catch (err) {
      console.error('clear x-cookies failed:', errMessage(err));
      setError(errMessage(err, 'failed to clear'));
    } finally {
      setClearing(false);
    }
  }

  async function loadQids() {
    try {
      const data = await getJson<QidsStatus>('/x-qids');
      setQidsStatus(data);
      setQids(data.qids);
    } catch (e) {
      console.error('load x-qids failed:', errMessage(e));
    }
  }

  async function handleSaveQids(e: FormEvent) {
    e.preventDefault();
    setQidsSaving(true);
    setQidsMsg(null);
    setError(null);
    try {
      await postJsonWithBody('/x-qids', qids);
      setQidsMsg('Query IDs saved - takes effect within ~60s.');
      void loadQids();
    } catch (err) {
      console.error('save x-qids failed:', errMessage(err));
      setError(errMessage(err, 'failed to save query IDs'));
    } finally {
      setQidsSaving(false);
    }
  }

  async function handleClearQids() {
    if (!confirm('Clear the query-ID override and revert to the hardcoded defaults?')) return;
    setQidsClearing(true);
    setError(null);
    setQidsMsg(null);
    try {
      const r = await fetch('/api/v1/admin/x-qids', {
        method: 'DELETE',
        headers: adminAuthHeaders(),
        credentials: 'same-origin',
      });
      if (!r.ok) throw new Error(`${r.status}`);
      setQidsMsg('Query-ID override cleared - using defaults.');
      void loadQids();
    } catch (err) {
      console.error('clear x-qids failed:', errMessage(err));
      setError(errMessage(err, 'failed to clear query IDs'));
    } finally {
      setQidsClearing(false);
    }
  }

  const inputCls =
    'w-full px-3 py-2 bg-white dark:bg-input-200 border border-line-1 rounded text-sm text-heading font-mono focus:outline-none focus:border-brand-500';

  return (
    <div className="space-y-8">
      {/* Current status */}
      <section className="rounded-xl border border-line-1 bg-surface-200/50 p-5">
        <h2 className="text-sm font-semibold text-heading mb-4">X (Twitter) Session Cookies</h2>
        {loading ? (
          <p className="text-sm text-muted">Loading…</p>
        ) : status ? (
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-xs font-medium border ${
                  status.configured
                    ? 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-500/30'
                    : 'bg-rose-100 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-500/30'
                }`}
              >
                {status.configured ? 'Configured' : 'Not configured'}
              </span>
              <span className="text-xs text-muted">Source: {SOURCE_LABEL[status.source]}</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
              <div className="px-3 py-2 rounded border border-line-1 bg-surface-100">
                <span className="text-muted">auth_token: </span>
                <span className={status.authToken.set ? 'text-heading' : 'text-rose-500'}>
                  {status.authToken.set ? `set ····${status.authToken.last4}` : 'missing'}
                </span>
              </div>
              <div className="px-3 py-2 rounded border border-line-1 bg-surface-100">
                <span className="text-muted">ct0: </span>
                <span className={status.ct0.set ? 'text-heading' : 'text-rose-500'}>
                  {status.ct0.set ? `set ····${status.ct0.last4}` : 'missing'}
                </span>
              </div>
            </div>
            <p className="text-xs text-muted">
              {status.bearerOverridden ? 'Custom bearer token in use. ' : ''}
              {status.updatedAt ? `Override updated ${new Date(status.updatedAt).toLocaleString()}.` : ''}
            </p>
          </div>
        ) : null}
        <p className="mt-4 text-xs text-muted leading-relaxed">
          Cookies from a logged-in x.com session (DevTools → Application → Cookies → x.com). The admin override stored
          here takes precedence over the <code>X_AUTH_TOKEN</code> / <code>X_CT0</code> worker secrets. Values are never
          shown back in full - only the last 4 characters.
        </p>
        <div className="mt-4 flex items-center gap-3 flex-wrap">
          <button
            type="button"
            onClick={() => void handleTest()}
            disabled={testing}
            className="px-4 py-2 border border-line-2 rounded text-sm text-body hover:bg-surface-300 dark:hover:bg-surface-300 disabled:opacity-50"
          >
            {testing ? 'Testing…' : 'Test connection'}
          </button>
          {health && (
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium border ${
                health.ok
                  ? 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-500/30'
                  : 'bg-rose-100 dark:bg-rose-500/10 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-500/30'
              }`}
            >
              {health.ok
                ? 'Healthy - auth + query IDs OK'
                : health.auth === 'expired'
                  ? 'Cookies expired - re-extract and save above'
                  : health.qids === 'stale'
                    ? 'GraphQL query IDs stale - update twitter-auth-graphql.ts'
                    : health.rateLimited
                      ? 'Rate-limited - retry shortly'
                      : `Unhealthy (${health.auth}/${health.qids})`}
            </span>
          )}
        </div>
        {health?.detail && <p className="mt-2 text-xs font-mono text-muted break-all">{health.detail}</p>}
      </section>

      {/* Set override */}
      <section className="rounded-xl border border-line-1 bg-surface-200/50 p-5">
        <h2 className="text-sm font-semibold text-heading mb-4">Set Admin Override</h2>
        {error && <p className="text-sm text-rose-600 dark:text-rose-400 mb-4">{error}</p>}
        {saved && <p className="text-sm text-emerald-600 dark:text-emerald-400 mb-4">{saved}</p>}
        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label htmlFor="x-auth-token" className="block text-xs text-muted mb-1">
              auth_token
            </label>
            <input
              id="x-auth-token"
              type="password"
              autoComplete="off"
              value={authToken}
              onChange={(e) => setAuthToken(e.target.value)}
              placeholder="paste auth_token cookie"
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="x-ct0" className="block text-xs text-muted mb-1">
              ct0
            </label>
            <input
              id="x-ct0"
              type="password"
              autoComplete="off"
              value={ct0}
              onChange={(e) => setCt0(e.target.value)}
              placeholder="paste ct0 cookie"
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="x-bearer" className="block text-xs text-muted mb-1">
              Bearer token (optional - defaults to the public web bearer)
            </label>
            <input
              id="x-bearer"
              type="password"
              autoComplete="off"
              value={bearer}
              onChange={(e) => setBearer(e.target.value)}
              placeholder="optional"
              className={inputCls}
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={saving || !authToken.trim() || !ct0.trim()}
              className="px-4 py-2 bg-brand-600 text-on-fill text-sm font-medium rounded hover:bg-brand-500 disabled:opacity-50 transition-colors"
            >
              {saving ? 'Saving…' : 'Save cookies'}
            </button>
            {status?.source === 'kv' && (
              <button
                type="button"
                onClick={() => void handleClear()}
                disabled={clearing}
                className="px-4 py-2 text-sm text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800/50 rounded hover:bg-rose-50 dark:hover:bg-rose-950/30 disabled:opacity-50"
              >
                {clearing ? 'Clearing…' : 'Clear override'}
              </button>
            )}
          </div>
        </form>
      </section>

      {/* Query IDs */}
      <section className="rounded-xl border border-line-1 bg-surface-200/50 p-5">
        <h2 className="text-sm font-semibold text-heading mb-4">GraphQL Query IDs</h2>
        <p className="text-xs text-muted leading-relaxed mb-4">
          X rotates these query IDs every few weeks; stale IDs break every authenticated fetch. Paste fresh IDs from
          x.com DevTools → Network → filter <code>graphql</code> (the ID is the path segment after{' '}
          <code>/graphql/</code>
          ). The override takes precedence over the hardcoded defaults; a field left as-is keeps its current value.
        </p>
        {qidsMsg && <p className="text-sm text-emerald-600 dark:text-emerald-400 mb-4">{qidsMsg}</p>}
        {qidsStatus && (
          <p className="text-xs text-muted mb-4">
            Source: {qidsStatus.source === 'kv' ? 'Admin override (KV)' : 'Hardcoded defaults'}
            {qidsStatus.updatedAt ? ` · updated ${new Date(qidsStatus.updatedAt).toLocaleString()}` : ''}
          </p>
        )}
        <form onSubmit={handleSaveQids} className="space-y-4">
          {QID_FIELDS.map((f) => (
            <div key={f.key}>
              <label htmlFor={`qid-${f.key}`} className="block text-xs text-muted mb-1">
                {f.label}
                {qidsStatus?.overridden[f.key] && (
                  <span className="ml-2 text-emerald-600 dark:text-emerald-400">(overridden)</span>
                )}
              </label>
              <input
                id={`qid-${f.key}`}
                type="text"
                autoComplete="off"
                spellCheck={false}
                value={qids[f.key]}
                onChange={(e) => setQids((prev) => ({ ...prev, [f.key]: e.target.value }))}
                className={inputCls}
              />
            </div>
          ))}
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={qidsSaving}
              className="px-4 py-2 bg-brand-600 text-on-fill text-sm font-medium rounded hover:bg-brand-500 disabled:opacity-50 transition-colors"
            >
              {qidsSaving ? 'Saving…' : 'Save query IDs'}
            </button>
            {qidsStatus?.source === 'kv' && (
              <button
                type="button"
                onClick={() => void handleClearQids()}
                disabled={qidsClearing}
                className="px-4 py-2 text-sm text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800/50 rounded hover:bg-rose-50 dark:hover:bg-rose-950/30 disabled:opacity-50"
              >
                {qidsClearing ? 'Clearing…' : 'Clear override'}
              </button>
            )}
          </div>
        </form>
      </section>
    </div>
  );
}
