import { logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Compass, ExternalLink, KeyRound, Loader2, LogOut, Plus, Search, Trash2 } from 'lucide-react';
import { Modal } from '../../components/ui/Modal';
import {
  RESOURCES,
  KIND_LABELS,
  KIND_BLURB,
  KIND_PILL,
  TAG_LABELS,
  TAG_PILL,
  type ExternalResource,
  type ResourceKind,
  type ResourceTag,
} from '../../data/threatintel/external-resources';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { createAdminSession, clearAdminSession, readAdminToken } from '../../lib/admin-token';

const ALL_KINDS = Object.keys(KIND_LABELS) as ResourceKind[];
const ALL_TAGS = Object.keys(TAG_LABELS) as ResourceTag[];

/**
 * Runtime-editable layer on top of the static catalog.
 *
 * The admin token is exchanged for an HttpOnly session cookie by
 * `createAdminSession()`. The token itself never touches localStorage or any
 * other JavaScript-readable storage; the cookie is sent automatically on API
 * requests, and `clearAdminSession()` revokes it on sign-out.
 */

interface DynamicEntry extends ExternalResource {
  added_at?: string;
  /** Frontend-only flag so we can tag a card as dynamic without checking by id. */
  dynamic?: true;
}

const RESEARCH_KINDS: ResourceKind[] = ['research', 'training', 'lab'];

export default function ExternalResources(): JSX.Element {
  const [searchParams, setSearchParams] = useSearchParams();
  const [query, setQuery] = useState(searchParams.get('q') ?? '');
  const [featuredOnly, setFeaturedOnly] = useState(searchParams.get('featured') === '1');

  const initialKinds = (searchParams.get('kind')?.split(',').filter(Boolean) ?? []) as ResourceKind[];
  const [activeKinds, setActiveKinds] = useState<Set<ResourceKind>>(
    new Set(initialKinds.filter((k) => (ALL_KINDS as string[]).includes(k)))
  );

  const initialTags = (searchParams.get('tag')?.split(',').filter(Boolean) ?? []) as ResourceTag[];
  const [activeTags, setActiveTags] = useState<Set<ResourceTag>>(
    new Set(initialTags.filter((t) => (ALL_TAGS as string[]).includes(t)))
  );

  // Dynamic entries fetched from /api/v1/external-resources.
  const [dynamicEntries, setDynamicEntries] = useState<DynamicEntry[]>([]);
  // Admin session state. The HttpOnly cookie is the credential; this is only
  // a UI hint so the editor controls appear while the session is active.
  const [signedIn, setSignedIn] = useState<boolean>(() => readAdminToken() !== null);
  const [signInOpen, setSignInOpen] = useState(false);
  const [tokenDraft, setTokenDraft] = useState('');
  const [signingIn, setSigningIn] = useState(false);
  const [signInError, setSignInError] = useState<string | null>(null);

  // Fetch dynamic entries on mount + after a successful add/delete. The
  // refreshKey bump triggers the effect; we also optimistically update local
  // state on writes so the UI doesn't flicker waiting for the refetch.
  const [refreshKey, setRefreshKey] = useState(0);
  // Surface the fetch error so the analyst knows when community-contributed
  // entries are missing because of an upstream/KV problem (rather than
  // silently rendering only the curated static list).
  const [dynamicError, setDynamicError] = useState<string | null>(null);
  const [dynamicLoading, setDynamicLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setDynamicError(null);
    setDynamicLoading(true);
    fetch('/api/v1/external-resources', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((j: { items?: DynamicEntry[] }) => {
        if (cancelled) return;
        setDynamicEntries((j.items ?? []).map((it) => ({ ...it, dynamic: true })));
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setDynamicEntries([]);
        setDynamicError(e.message ?? 'failed to load community entries');
      })
      .finally(() => {
        if (!cancelled) setDynamicLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  // Keep filter state in the URL so a curated view is shareable.
  useEffect(() => {
    setSearchParams(
      (prev) => {
        const out = new URLSearchParams(prev);
        if (query.trim()) out.set('q', query.trim());
        else out.delete('q');
        if (activeKinds.size > 0) out.set('kind', [...activeKinds].join(','));
        else out.delete('kind');
        if (activeTags.size > 0) out.set('tag', [...activeTags].join(','));
        else out.delete('tag');
        if (featuredOnly) out.set('featured', '1');
        else out.delete('featured');
        return out;
      },
      { replace: true }
    );
  }, [query, activeKinds, activeTags, featuredOnly, setSearchParams]);

  // Merge static + dynamic, dedup by URL (dynamic wins if the same URL
  // somehow exists in both). Dynamic entries sort first so newly-added
  // links surface immediately.
  const merged = useMemo<DynamicEntry[]>(() => {
    const out: DynamicEntry[] = [...dynamicEntries];
    const seen = new Set(out.map((it) => it.url));
    for (const it of RESOURCES) {
      if (seen.has(it.url)) continue;
      out.push(it as DynamicEntry);
      seen.add(it.url);
    }
    return out;
  }, [dynamicEntries]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return merged.filter((r) => {
      if (featuredOnly && !('featured' in r)) return false;
      if (activeKinds.size > 0 && !activeKinds.has(r.kind)) return false;
      if (activeTags.size > 0 && !(r.tags ?? []).some((t) => activeTags.has(t))) return false;
      if (!q) return true;
      const tagStr = (r.tags ?? []).map((t) => TAG_LABELS[t]).join(' ');
      const hay = `${r.name} ${r.description} ${r.why ?? ''} ${tagStr}`.toLowerCase();
      return q
        .split(/\s+/)
        .filter(Boolean)
        .every((tok) => hay.includes(tok));
    });
  }, [query, activeKinds, activeTags, featuredOnly, merged]);

  const kindCounts = useMemo(() => {
    const map = new Map<ResourceKind, number>();
    for (const r of filtered) map.set(r.kind, (map.get(r.kind) ?? 0) + 1);
    return map;
  }, [filtered]);

  const tagCounts = useMemo(() => {
    const map = new Map<ResourceTag, number>();
    for (const r of filtered) for (const t of r.tags ?? []) map.set(t, (map.get(t) ?? 0) + 1);
    return map;
  }, [filtered]);

  const toggleKind = (k: ResourceKind) =>
    setActiveKinds((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const toggleTag = (t: ResourceTag) =>
    setActiveTags((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });

  const clearAll = () => {
    setQuery('');
    setActiveKinds(new Set());
    setActiveTags(new Set());
    setFeaturedOnly(false);
  };

  const activateResearch = () => {
    setActiveKinds(new Set(RESEARCH_KINDS));
    setActiveTags(new Set());
    setFeaturedOnly(false);
    setQuery('');
  };

  const activateMalware = () => {
    setActiveKinds(new Set());
    setActiveTags(new Set(['malware']));
    setFeaturedOnly(false);
    setQuery('');
  };

  const activateThreatIntel = () => {
    setActiveKinds(new Set());
    setActiveTags(new Set(['threat-intel']));
    setFeaturedOnly(false);
    setQuery('');
  };

  const featuredCount = merged.filter((r) => 'featured' in r).length;

  const submitToken = async () => {
    const trimmed = tokenDraft.trim();
    if (!trimmed) return;
    setSigningIn(true);
    setSignInError(null);
    const ok = await createAdminSession(trimmed);
    setSigningIn(false);
    if (!ok) {
      setSignInError('Token rejected. Check the value and try again.');
      return;
    }
    setSignedIn(true);
    setTokenDraft('');
    setSignInOpen(false);
    setRefreshKey((k) => k + 1);
  };

  const signOut = async () => {
    await clearAdminSession();
    setSignedIn(false);
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Compass size={28} />}
      title="External Resources"
      maxWidthClass="max-w-6xl"
      description={
        <>
          <span className="block max-w-3xl">
            {merged.length} off-site sources I cross-reference: dashboards, OSINT directories, training labs, malware
            samples, and research portfolios. Filter by kind or search across name and description.
          </span>
          <span className="block text-xs text-muted font-mono mt-2">
            External sites change ownership and quality over time. Verify a specific link before relying on it.
          </span>
        </>
      }
    >
      {/* Auth + Add row (compact when signed out) */}
      {signedIn && (
        <AddResourceCard
          onAdded={(entry) => {
            // Optimistic: prepend immediately so the UI feels instant; the
            // server is the source of truth on the next refresh.
            setDynamicEntries((prev) => [{ ...entry, dynamic: true }, ...prev]);
            setRefreshKey((k) => k + 1);
          }}
          onAuthExpired={signOut}
        />
      )}

      {/* Research discovery + featured toggle */}
      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={activateResearch}
            className={`text-mini font-mono px-3 py-1.5 rounded border transition-colors ${
              !featuredOnly && RESEARCH_KINDS.every((k) => activeKinds.has(k))
                ? 'border-violet-500/50 bg-violet-500/10 text-violet-700 dark:text-violet-300'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-violet-500/40'
            }`}
            aria-label="Show research, training, and lab resources"
          >
            Research discovery
          </button>
          <button
            type="button"
            onClick={activateMalware}
            className={`text-mini font-mono px-3 py-1.5 rounded border transition-colors ${
              activeTags.has('malware')
                ? 'border-rose-500/50 bg-rose-500/10 text-rose-700 dark:text-rose-300'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/40'
            }`}
            aria-label="Show malware samples and repositories"
          >
            Malware repos
          </button>
          <button
            type="button"
            onClick={activateThreatIntel}
            className={`text-mini font-mono px-3 py-1.5 rounded border transition-colors ${
              activeTags.has('threat-intel')
                ? 'border-orange-500/50 bg-orange-500/10 text-orange-700 dark:text-orange-300'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-orange-500/40'
            }`}
            aria-label="Show threat intelligence feeds"
          >
            Threat intel feeds
          </button>
          <button
            type="button"
            onClick={() => setFeaturedOnly((v) => !v)}
            className={`text-mini font-mono px-3 py-1.5 rounded border transition-colors ${
              featuredOnly
                ? 'border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-amber-500/40'
            }`}
            aria-label="Show featured quality resources only"
          >
            Featured · {featuredCount}
          </button>
          <button
            type="button"
            onClick={() => {
              setQuery('');
              setActiveKinds(new Set());
              setActiveTags(new Set());
              setFeaturedOnly(false);
            }}
            className="text-mini font-mono px-3 py-1.5 rounded border border-line-2 text-muted hover:border-rose-500/40 transition-colors"
            aria-label="Clear all filters"
          >
            Show all
          </button>
        </div>
      </section>

      {/* Search */}
      <section className="surface-card p-4 mb-6">
        <div className="relative">
          <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search name, description (e.g. 'osint', 'ransomware', 'llm')"
            className="w-full pl-9 pr-4 py-2.5 bg-surface-200 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500 dark:focus:border-rose-400"
            aria-label="Search external resources"
          />
        </div>
      </section>

      {/* Kind pills */}
      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini font-mono text-muted mr-1">kind:</span>
          {ALL_KINDS.map((k) => {
            const count = kindCounts.get(k) ?? 0;
            const active = activeKinds.has(k);
            const cls = active ? KIND_PILL[k] : 'border-slate-300 dark:border-line-1 text-slate-500';
            const isDisabled = count === 0 && !active;
            return (
              <button
                key={k}
                type="button"
                onClick={() => toggleKind(k)}
                className={`text-mini font-mono px-2 py-1 rounded border ${cls} ${count === 0 ? 'opacity-30' : ''}`}
                title={isDisabled ? `${KIND_LABELS[k]} - no entries match the current search` : KIND_BLURB[k]}
                disabled={isDisabled}
                aria-pressed={active}
                aria-label={`Filter by ${KIND_LABELS[k]} (${count} ${count === 1 ? 'entry' : 'entries'})`}
              >
                {KIND_LABELS[k]} <span className="opacity-70">· {count}</span>
              </button>
            );
          })}
        </div>
      </section>

      {/* Tag pills */}
      <section className="surface-card p-4 mb-6">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-mini font-mono text-muted mr-1">tag:</span>
          {ALL_TAGS.map((t) => {
            const count = tagCounts.get(t) ?? 0;
            const active = activeTags.has(t);
            const cls = active ? TAG_PILL[t] : 'border-slate-300 dark:border-line-1 text-slate-500';
            const isDisabled = count === 0 && !active;
            return (
              <button
                key={t}
                type="button"
                onClick={() => toggleTag(t)}
                className={`text-mini font-mono px-2 py-1 rounded border ${cls} ${count === 0 ? 'opacity-30' : ''}`}
                disabled={isDisabled}
                aria-pressed={active}
                aria-label={`Filter by ${TAG_LABELS[t]} (${count} ${count === 1 ? 'entry' : 'entries'})`}
              >
                {TAG_LABELS[t]} <span className="opacity-70">· {count}</span>
              </button>
            );
          })}
        </div>
      </section>

      <p className="text-mini font-mono text-muted mb-4">
        Showing {filtered.length} of {merged.length}
        {featuredOnly && ' (featured quality resources)'}
        {dynamicLoading && (
          <span className="ml-2 inline-flex items-center gap-1 text-muted">
            <Loader2 size={11} className="animate-spin" /> loading community entries…
          </span>
        )}
      </p>

      {dynamicError && (
        <div
          role="status"
          className="mb-4 rounded-xl border border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 px-3 py-2 font-mono text-mini text-amber-700 dark:text-amber-300"
        >
          Community-contributed entries couldn't be loaded ({dynamicError}). Showing curated list only.{' '}
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="underline hover:text-amber-900 dark:hover:text-amber-100"
          >
            retry
          </button>
        </div>
      )}

      <ul className="grid gap-3 md:grid-cols-2">
        {filtered.map((r) => (
          <li key={r.id} className="surface-card p-4">
            <div className="flex items-baseline justify-between gap-2 mb-1">
              <a
                href={sanitizeUrl(r.url)}
                target="_blank"
                rel="noopener noreferrer"
                className="font-display font-semibold text-base text-heading hover:text-rose-600 dark:hover:text-rose-400 inline-flex items-center gap-1 min-w-0 break-words transition-colors"
              >
                {r.name} <ExternalLink size={12} className="opacity-60 shrink-0" />
              </a>
              <div className="flex items-center gap-1 shrink-0">
                {'featured' in r && (
                  <span
                    className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded bg-amber-500/10 text-amber-700 dark:text-amber-300 border border-amber-500/30"
                    title="Featured quality resource"
                  >
                    featured
                  </span>
                )}
                {r.dynamic && (
                  <span
                    className="text-micro font-mono uppercase tracking-wider px-1 py-0.5 rounded bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30"
                    title="Added via runtime editor"
                  >
                    live
                  </span>
                )}
                <button
                  type="button"
                  onClick={() => toggleKind(r.kind)}
                  className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${KIND_PILL[r.kind]}`}
                  title={`Filter by ${KIND_LABELS[r.kind]}`}
                  aria-pressed={activeKinds.has(r.kind)}
                  aria-label={`${KIND_LABELS[r.kind]} - toggle filter`}
                >
                  {KIND_LABELS[r.kind]}
                </button>
                {signedIn && r.dynamic && (
                  <DeleteButton
                    id={r.id}
                    name={r.name}
                    onDeleted={() => {
                      setDynamicEntries((prev) => prev.filter((it) => it.id !== r.id));
                      setRefreshKey((k) => k + 1);
                    }}
                    onAuthExpired={signOut}
                  />
                )}
              </div>
            </div>
            <p className="text-meta font-mono text-muted leading-relaxed mb-2 break-words">{r.description}</p>
            {(r.tags ?? []).length > 0 && (
              <div className="flex flex-wrap gap-1 mb-1">
                {(r.tags ?? []).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => toggleTag(t)}
                    className={`text-micro font-mono uppercase tracking-wider px-1.5 py-0.5 rounded border ${TAG_PILL[t]}`}
                    title={`Filter by ${TAG_LABELS[t]}`}
                  >
                    {TAG_LABELS[t]}
                  </button>
                ))}
              </div>
            )}
            {r.why && (
              <p className="text-meta font-mono italic text-muted leading-relaxed">
                <span className="text-muted not-italic">why:</span> {r.why}
              </p>
            )}
          </li>
        ))}
      </ul>

      {filtered.length === 0 && (
        <p className="text-sm font-mono text-muted mt-6">
          Nothing matches the current filters.{' '}
          <button type="button" onClick={clearAll} className="underline text-rose-600 dark:text-rose-400">
            Clear all
          </button>
          .
        </p>
      )}

      {/* Footer auth control - minimal so unauth visitors don't see admin UI */}
      <div className="mt-12 text-right">
        {signedIn ? (
          <button
            type="button"
            onClick={signOut}
            className="inline-flex items-center gap-1.5 text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
            title="Sign out of the editor session"
          >
            <LogOut size={11} /> sign out
          </button>
        ) : (
          <button
            type="button"
            onClick={() => setSignInOpen(true)}
            className="inline-flex items-center gap-1.5 text-mini font-mono text-muted hover:text-rose-600 dark:hover:text-rose-400"
            title="Paste your admin token to enable runtime editing"
          >
            <KeyRound size={11} /> editor sign in
          </button>
        )}
      </div>

      <Modal open={signInOpen} onClose={() => setSignInOpen(false)} title="Editor sign in">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submitToken();
          }}
          className="space-y-3"
        >
          <p className="text-tool text-muted">
            Paste your admin token. It is exchanged for an HttpOnly session cookie and is never stored in
            JavaScript-readable storage.
          </p>
          <input
            type="password"
            autoFocus
            value={tokenDraft}
            onChange={(e) => {
              setTokenDraft(e.target.value);
              setSignInError(null);
            }}
            placeholder="admin token"
            aria-label="Admin token"
            className="w-full px-3 py-2 rounded border border-line-1 bg-surface-100 text-sm font-mono focus:outline-none focus:border-rose-500"
          />
          {signInError && (
            <p role="alert" className="text-xs font-mono text-rose-700 dark:text-rose-300">
              {signInError}
            </p>
          )}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => {
                setSignInOpen(false);
                setSignInError(null);
              }}
              className="px-3 py-1.5 text-tool text-muted hover:text-body dark:hover:text-inverted"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!tokenDraft.trim() || signingIn}
              className="px-3 py-1.5 rounded bg-rose-600 text-on-fill text-tool font-semibold hover:bg-rose-500 disabled:opacity-40 transition-colors"
            >
              {signingIn ? 'Signing in…' : 'Sign in'}
            </button>
          </div>
        </form>
      </Modal>
    </DataPageLayout>
  );
}

/**
 * Inline form to POST a new dynamic resource. Auth-gated by the parent
 * (only rendered while an admin session is active). Minimal schema: name + URL + kind.
 */
function AddResourceCard({
  onAdded,
  onAuthExpired,
}: {
  onAdded: (entry: DynamicEntry) => void;
  onAuthExpired: () => void;
}): JSX.Element {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [kind, setKind] = useState<ResourceKind>('tool');
  const [why, setWhy] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reset = () => {
    setName('');
    setUrl('');
    setKind('tool');
    setWhy('');
    setError(null);
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !url.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/external-resources', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          name: name.trim(),
          url: url.trim(),
          kind,
          why: why.trim() || undefined,
        }),
      });
      if (res.status === 401 || res.status === 403) {
        onAuthExpired();
        setError('Token rejected. Sign in again.');
        return;
      }
      const body = (await res.json().catch(() => ({}))) as { error?: string; entry?: DynamicEntry };
      if (!res.ok) {
        setError(body.error ?? `HTTP ${res.status}`);
        return;
      }
      if (body.entry) onAdded(body.entry);
      reset();
      setOpen(false);
    } catch (err) {
      logCatch(err);
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <div className="mb-6 flex justify-end">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1.5 text-xs font-mono px-3 py-2 min-h-[44px] sm:min-h-0 rounded border border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300 hover:bg-rose-500/15"
        >
          <Plus size={14} /> add resource
        </button>
      </div>
    );
  }

  return (
    <section className="mb-6 rounded-xl border border-rose-500/40 bg-rose-500/5 p-4">
      <form onSubmit={submit} className="space-y-3">
        <div className="grid sm:grid-cols-[1fr_140px] gap-3">
          <label className="block">
            <span className="text-mini font-mono uppercase tracking-wider text-muted">
              URL <span className="text-rose-600">*</span>
            </span>
            <input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
              placeholder="https://example.com"
              className="mt-1 w-full px-3 py-2 min-h-[44px] sm:min-h-0 bg-surface-100 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500"
            />
          </label>
          <label className="block">
            <span className="text-mini font-mono uppercase tracking-wider text-muted">
              Kind <span className="text-rose-600">*</span>
            </span>
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as ResourceKind)}
              className="mt-1 w-full px-3 py-2 min-h-[44px] sm:min-h-0 bg-surface-100 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500"
            >
              {ALL_KINDS.map((k) => (
                <option key={k} value={k}>
                  {KIND_LABELS[k]}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label className="block">
          <span className="text-mini font-mono uppercase tracking-wider text-muted">
            Name <span className="text-rose-600">*</span>
          </span>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            placeholder="hunter.how"
            className="mt-1 w-full px-3 py-2 min-h-[44px] sm:min-h-0 bg-surface-100 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500"
          />
        </label>
        <label className="block">
          <span className="text-mini font-mono uppercase tracking-wider text-muted">Why (optional)</span>
          <input
            type="text"
            value={why}
            onChange={(e) => setWhy(e.target.value)}
            placeholder="one-line note: what this site fills that the existing catalog doesn't"
            className="mt-1 w-full px-3 py-2 bg-surface-100 border border-line-1 rounded font-mono text-sm focus:outline-none focus:border-rose-500"
          />
        </label>
        {error && (
          <p role="alert" className="text-xs font-mono text-rose-700 dark:text-rose-300">
            {error}
          </p>
        )}
        <div className="flex flex-col-reverse sm:flex-row sm:justify-end gap-2">
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              reset();
            }}
            className="text-xs font-mono px-3 py-2 min-h-[44px] sm:min-h-0 rounded border border-line-2 text-body hover:bg-surface-300 dark:hover:bg-surface-300"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !name.trim() || !url.trim()}
            className="text-xs font-mono px-3 py-2 min-h-[44px] sm:min-h-0 rounded bg-rose-600 dark:bg-rose-500 text-on-fill font-semibold disabled:opacity-40 hover:bg-rose-700 dark:hover:bg-rose-400 inline-flex items-center justify-center gap-1.5 transition-colors"
          >
            {busy && <Loader2 size={12} className="animate-spin" />}
            {busy ? 'Saving…' : 'Save resource'}
          </button>
        </div>
      </form>
    </section>
  );
}

function DeleteButton({
  id,
  name,
  onDeleted,
  onAuthExpired,
}: {
  id: string;
  name: string;
  onDeleted: () => void;
  onAuthExpired: () => void;
}): JSX.Element {
  const [busy, setBusy] = useState(false);

  const onClick = async () => {
    if (!window.confirm(`Delete "${name}" from the live catalog?`)) return;
    setBusy(true);
    try {
      const res = await fetch(`/api/v1/external-resources/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      if (res.status === 401 || res.status === 403) {
        onAuthExpired();
        return;
      }
      if (res.ok) onDeleted();
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      aria-label={`Delete ${name}`}
      title="Delete from the live catalog"
      className="inline-flex items-center justify-center min-h-[44px] min-w-[44px] sm:min-h-0 sm:min-w-0 sm:p-1 rounded text-rose-500 hover:text-rose-700 hover:bg-rose-500/10 disabled:opacity-40 transition-colors"
    >
      {busy ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
    </button>
  );
}
