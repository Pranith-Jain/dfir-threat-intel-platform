import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useState, useCallback } from 'react';
import { DataState } from '../../components/DataState';
import { DataPageLayout } from '../../components/DataPageLayout';
import { RefreshCw, Radio, ExternalLink, Check, X, Search, Lock } from 'lucide-react';
import { adminAuthHeaders, readAdminToken, writeAdminToken } from '../../lib/admin-token';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface DiscoveredChannel {
  id: number;
  handle: string;
  source_message: string | null;
  reviewed: number;
  added_to_watch: number;
  discovered_at: string;
}

type Action = 'approve' | 'reject';

export default function TelegramDiscoveredChannels(): JSX.Element {
  const [channels, setChannels] = useState<DiscoveredChannel[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  /** In-flight mutation, keyed `${action}:${handle}`. */
  const [busy, setBusy] = useState<string | null>(null);
  const [filterReviewed, setFilterReviewed] = useState<string>('false');
  const [search, setSearch] = useState('');

  // Operator admin token (shared localStorage key with the rest of the admin UI).
  const [token, setToken] = useState<string>(() => readAdminToken() ?? '');
  const [showToken, setShowToken] = useState(false);
  const authed = token.trim().length > 0;

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (filterReviewed === 'true') params.set('reviewed', 'true');
      else if (filterReviewed === 'false') params.set('reviewed', 'false');
      const res = await fetch(`/api/v1/telegram-leaks/discovered-channels?${params}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const d = (await res.json()) as { channels: DiscoveredChannel[] };
      setChannels(d.channels ?? []);
    } catch (e) {
      console.error('TelegramDiscoveredChannels failed:', errMessage(e));
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  }, [filterReviewed]);

  useEffect(() => {
    fetchData();
  }, [fetchData, refreshKey]);

  const saveToken = () => {
    writeAdminToken(token.trim());
    setShowToken(false);
    setError(null);
  };

  const mutate = async (handle: string, action: Action) => {
    if (!readAdminToken()) {
      setError('Admin token required to review channels - set it above.');
      setShowToken(true);
      return;
    }
    setBusy(`${action}:${handle}`);
    setError(null);
    try {
      const res = await fetch(`/api/v1/telegram-leaks/${action}-channel`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...adminAuthHeaders() },
        body: JSON.stringify(action === 'approve' ? { handle, category: 'auto-discovered' } : { handle }),
        credentials: 'same-origin',
      });
      if (res.status === 401 || res.status === 403) {
        setError('Admin token rejected - check the value and try again.');
        setShowToken(true);
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // Drop every row for this handle from the current view (approve and reject
      // both remove it from the unreviewed queue).
      setChannels((prev) => prev.filter((ch) => ch.handle !== handle));
    } catch (e) {
      logCatch(e);
      setError(errMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const filtered = channels.filter((ch) => !search || ch.handle.toLowerCase().includes(search.toLowerCase()));

  return (
    <DataPageLayout
      title="Discovered Telegram Channels"
      icon={<Radio size={28} />}
      backTo="/threatintel/telegram-monitor"
      description="Channels auto-discovered from messages in monitored feeds and bot-subscribed chats. Approve to add a channel to the watchlist for leak scanning, or reject to dismiss it - rejected channels are remembered and won't be surfaced again."
      headerExtra={
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowToken((s) => !s)}
            className={`text-mini font-mono px-2.5 py-1.5 rounded border inline-flex items-center gap-1 ${
              authed
                ? 'border-emerald-600/40 text-emerald-700 dark:text-emerald-400'
                : 'border-amber-500/40 text-amber-600 dark:text-amber-400'
            }`}
            aria-label="Admin token"
          >
            <Lock size={11} /> {authed ? 'admin' : 'set token'}
          </button>
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="text-mini font-mono px-2.5 py-1.5 rounded border border-line-2 hover:border-rose-500/40 inline-flex items-center gap-1"
            aria-label="Refresh"
          >
            <RefreshCw size={11} /> refresh
          </button>
        </div>
      }
    >
      {showToken && (
        <div className="animate-fade-in-up mb-6 surface-card p-3.5">
          <label htmlFor="vt-admin-token" className="block text-micro uppercase tracking-wider text-muted mb-1.5">
            Admin token - stored locally, sent only with approve/reject requests
          </label>
          <div className="flex items-center gap-2">
            <input
              id="vt-admin-token"
              type="password"
              autoComplete="off"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') saveToken();
              }}
              placeholder="paste ADMIN_TOKEN…"
              className="flex-1 px-3 py-1.5 text-sm rounded border border-line-2 bg-surface-100 text-heading placeholder:text-muted font-mono"
            />
            <button
              type="button"
              onClick={saveToken}
              disabled={!token.trim()}
              className="text-mini font-mono px-3 py-1.5 rounded border border-rose-500/40 text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 disabled:opacity-40 transition-colors"
            >
              save
            </button>
          </div>
        </div>
      )}

      <div className="animate-fade-in-up mb-8 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <Search size={14} className="text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter handles…"
            className="w-48 px-3 py-1.5 text-sm rounded border border-line-2 bg-surface-100 text-heading placeholder:text-muted font-mono"
          />
        </div>

        <select
          value={filterReviewed}
          onChange={(e) => setFilterReviewed(e.target.value)}
          className="px-3 py-1.5 text-sm rounded border border-line-2 bg-surface-100 text-heading font-mono"
        >
          <option value="false">Unreviewed only</option>
          <option value="true">Reviewed only</option>
          <option value="">All</option>
        </select>
      </div>

      <DataState loading={loading} error={error} rows={6}>
        {filtered.length === 0 ? (
          <div className="text-center py-16 text-muted">
            <Radio size={40} className="mx-auto mb-4 opacity-40" />
            <p className="text-sm font-mono">No discovered channels</p>
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((ch) => (
              <div key={ch.id} className="surface-card p-3.5 flex items-center justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-sm font-semibold text-heading">{ch.handle}</span>
                    {ch.reviewed === 1 && ch.added_to_watch === 0 ? (
                      <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-line-3/40 bg-slate-400/10 text-muted">
                        rejected
                      </span>
                    ) : ch.reviewed === 1 ? (
                      <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                        reviewed
                      </span>
                    ) : null}
                    {ch.added_to_watch === 1 && (
                      <span className="text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400">
                        watched
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-micro font-mono text-muted">
                    <span>discovered {new Date(ch.discovered_at).toLocaleString()}</span>
                    {ch.source_message && sanitizeUrl(ch.source_message) && (
                      <a
                        href={sanitizeUrl(ch.source_message)}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400 hover:underline transition-colors"
                      >
                        <ExternalLink size={10} /> source
                      </a>
                    )}
                  </div>
                </div>

                {ch.reviewed === 0 && (
                  <div className="shrink-0 flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => mutate(ch.handle, 'approve')}
                      disabled={busy !== null}
                      className="text-mini font-mono px-3 py-1.5 rounded border border-emerald-600/40 text-emerald-700 dark:text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-40 inline-flex items-center gap-1.5"
                    >
                      <Check size={12} /> {busy === `approve:${ch.handle}` ? 'approving…' : 'approve'}
                    </button>
                    <button
                      type="button"
                      onClick={() => mutate(ch.handle, 'reject')}
                      disabled={busy !== null}
                      className="text-mini font-mono px-3 py-1.5 rounded border border-rose-600/40 text-rose-700 dark:text-rose-400 hover:bg-rose-500/10 disabled:opacity-40 inline-flex items-center gap-1.5"
                    >
                      <X size={12} /> {busy === `reject:${ch.handle}` ? 'rejecting…' : 'reject'}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </DataState>
    </DataPageLayout>
  );
}
