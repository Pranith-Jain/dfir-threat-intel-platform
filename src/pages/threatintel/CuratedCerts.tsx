import { errMessage, logCatch } from '../../lib/log';
import { useEffect, useMemo, useState } from 'react';
import { Search, RefreshCw, ExternalLink, Layers, Info, ChevronRight } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { relativeAgoSeeded } from '../../lib/relativeTime';

interface CuratedTool {
  section: string;
  title: string;
  url: string;
  description?: string;
}

interface Payload {
  source: string;
  sourceUrl: string;
  fetchedAt: string;
  ok: boolean;
  error?: string;
  sections: { name: string; tools: CuratedTool[] }[];
  totalTools: number;
  totalSections: number;
}

interface Meta {
  ok?: boolean;
  source?: string;
  sourceUrl?: string;
  fetchedAt?: string;
  totalTools?: number;
  totalSections?: number;
  error?: string;
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch (_catchErr) {
    console.error('hostnameOf failed:', errMessage(_catchErr));
    return url;
  }
}

/**
 * Curated Certs - Syberseeker's "Free Certification Courses" start.me
 * page, mirrored via Jina Reader on a daily cron (the only reliable
 * way to read start.me, which is behind a Cloudflare bot challenge).
 * The page reads /api/v1/curated-certs and groups the results by
 * section, with a search filter that matches title, host, description,
 * and section name.
 *
 * Why a mirror (not an iframe): start.me blocks its pages from being
 * framed by arbitrary origins, and their embed widget is still a black
 * box. This gives us full control over the layout, search, and deep
 * links back to our own pages.
 *
 * Sister page to CuratedToolbox: both share the same Jina-Reader
 * pipeline and KV shape; only the upstream start.me URL and the
 * backing KV key differ.
 */
export default function CuratedCerts(): JSX.Element {
  const [data, setData] = useState<Payload | null>(null);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  // Sections collapsed by default for the wide catalog; user's last choice
  // persisted in localStorage so the experience is stable across visits.
  const [openSet, setOpenSet] = useState<Set<string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    Promise.all([
      fetch('/api/v1/curated-certs', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) }).then(
        (r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      ),
      fetch('/api/v1/curated-certs/meta', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) }).then(
        (r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      ),
    ])
      .then(([payload, m]) => {
        if (cancelled) return;
        setData(payload);
        setMeta(m);
      })
      .catch((e: { name?: string; message?: string }) => {
        if (cancelled || e.name === 'AbortError') return;
        setError(e.message ?? 'fetch failed');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [refreshKey]);

  // Lazy-init the open set from localStorage once we know section names.
  useEffect(() => {
    if (openSet !== null || !data?.sections?.length) return;
    try {
      const raw = window.localStorage.getItem('curated-certs:open');
      if (raw) {
        const parsed = JSON.parse(raw) as string[];
        if (Array.isArray(parsed)) {
          setOpenSet(new Set(parsed));
          return;
        }
      }
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    }
    setOpenSet(new Set([data.sections[0]?.name].filter(Boolean) as string[]));
  }, [data, openSet]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    if (!q) return data.sections;
    return data.sections
      .map((s) => ({
        ...s,
        tools: s.tools.filter((t) => {
          const hay = `${t.title} ${t.url} ${t.description ?? ''} ${hostnameOf(t.url)} ${s.name}`.toLowerCase();
          return hay.includes(q);
        }),
      }))
      .filter((s) => s.tools.length > 0);
  }, [data, query]);

  const totalMatches = filtered.reduce((n, s) => n + s.tools.length, 0);

  const isOpen = (name: string): boolean => {
    if (openSet === null) return false;
    if (openSet.has('__all__')) return true;
    return openSet.has(name);
  };

  const toggle = (name: string) => {
    setOpenSet((prev) => {
      const next = new Set(prev ?? []);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      try {
        window.localStorage.setItem('curated-certs:open', JSON.stringify(Array.from(next)));
      } catch (_catchErr) {
        logCatch(_catchErr);
        /* ignore */
      }
      return next;
    });
  };

  const expandAll = () => {
    const all = new Set(['__all__']);
    setOpenSet(all);
    try {
      window.localStorage.setItem('curated-certs:open', JSON.stringify(['__all__']));
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    }
  };
  const collapseAll = () => {
    setOpenSet(new Set());
    try {
      window.localStorage.setItem('curated-certs:open', JSON.stringify([]));
    } catch (_catchErr) {
      logCatch(_catchErr);
      /* ignore */
    }
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      backLabel="back to threat intel"
      icon={<Layers className="h-6 w-6" />}
      title="Free Certification Courses"
      description={
        <span>
          Mirror of{' '}
          <a
            href="https://start.me/p/xb2ReR/free-certification-courses-by-syberseeker"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            Syberseeker’s Free Certification Courses
          </a>{' '}
          on start.me. Auto-synced daily via Jina Reader - the only reliable way to read start.me, which is behind a
          Cloudflare bot challenge.
        </span>
      }
      headerExtra={
        <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
          <button
            type="button"
            onClick={() => setRefreshKey((k) => k + 1)}
            className="inline-flex items-center gap-1.5 rounded border border-line-2 px-2 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" /> refresh
          </button>
          <span className="rounded border border-line-2 px-2 py-1 text-muted font-mono">
            synced <span className="text-body">{relativeAgoSeeded(meta?.fetchedAt ?? data?.fetchedAt)}</span>
          </span>
          {meta?.ok === false && (
            <span
              className="rounded border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-950/40 px-2 py-1 text-amber-700 dark:text-amber-300 font-mono"
              title={meta.error}
            >
              sync failing - showing last good snapshot
            </span>
          )}
          {meta?.ok && meta.fetchedAt && !meta.fetchedAt.startsWith('1970') && (
            <span className="rounded border border-emerald-300 dark:border-emerald-700 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-1 text-emerald-700 dark:text-emerald-300 font-mono">
              live
            </span>
          )}
        </div>
      }
      loading={loading}
      error={error}
      onRetry={() => setRefreshKey((k) => k + 1)}
      empty={!loading && !data}
      emptyMessage="No certification data available."
      maxWidthClass="max-w-6xl"
    >
      {data && (
        <>
          {/* Toolbar */}
          <section className="surface-card p-4 mb-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={`Search ${data.totalTools} courses across ${data.totalSections} sections…`}
                  className="w-full rounded-xl border border-line-2 bg-surface-100 py-2 pl-9 pr-3 text-sm text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
                />
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={expandAll}
                  className="text-mini font-mono rounded border border-line-2 px-2.5 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                >
                  expand all
                </button>
                <button
                  type="button"
                  onClick={collapseAll}
                  className="text-mini font-mono rounded border border-line-2 px-2.5 py-1 text-muted hover:border-rose-500/50 hover:text-rose-600 dark:hover:text-rose-400 transition-colors"
                >
                  collapse all
                </button>
              </div>
            </div>
          </section>

          {/* Header cards */}
          <div className="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label="Tools" value={data.totalTools} />
            <Stat label="Sections" value={data.totalSections} />
            <Stat label="Matches" value={query ? totalMatches : data.totalTools} />
            <Stat
              label="Source"
              value={
                <a
                  href={data.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-rose-600 dark:text-rose-400 hover:underline truncate transition-colors"
                >
                  start.me
                </a>
              }
            />
          </div>

          {data.error && (
            <div className="mb-3 flex items-start gap-2 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3 text-sm text-amber-700 dark:text-amber-200">
              <Info className="mt-0.5 h-4 w-4 shrink-0" />
              <span>Last sync failed ({data.error}). Showing the previous successful snapshot.</span>
            </div>
          )}

          {/* Section list */}
          {filtered.length === 0 ? (
            <div className="rounded-xl border border-line-1 bg-surface-200 p-8 text-center text-sm text-muted">
              <Search className="mx-auto mb-2 h-8 w-8 text-muted" />
              No courses match &quot;{query}&quot;.
            </div>
          ) : (
            <div className="space-y-2">
              {filtered.map((s) => (
                <SectionCard key={s.name} section={s} open={isOpen(s.name)} onToggle={() => toggle(s.name)} />
              ))}
            </div>
          )}
        </>
      )}
    </DataPageLayout>
  );
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="surface-card px-3 py-2">
      <div className="text-micro font-mono uppercase tracking-wider text-muted">{label}</div>
      <div className="text-lg font-semibold text-heading truncate">{value}</div>
    </div>
  );
}

function SectionCard({
  section,
  open,
  onToggle,
}: {
  section: { name: string; tools: CuratedTool[] };
  open: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-line-1 bg-surface-100">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-surface-200 dark:hover:bg-surface-200/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <ChevronRight className={`h-4 w-4 text-muted transition-transform ${open ? 'rotate-90' : ''}`} />
          <span className="font-medium text-heading">{section.name}</span>
        </div>
        <span className="text-micro font-mono rounded-full border border-line-2 px-2 py-0.5 text-muted">
          {section.tools.length} tools
        </span>
      </button>
      {open && (
        <ul className="border-t border-line-1">
          {section.tools.map((t, i) => (
            <li
              key={`${t.url}-${i}`}
              className="flex items-start gap-3 border-b border-line-1/60 px-4 py-2.5 last:border-b-0 hover:bg-surface-200 dark:hover:bg-surface-200/30 transition-colors"
            >
              <span className="mt-1.5 inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-rose-500 dark:bg-rose-400" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <a
                    href={t.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-heading hover:text-rose-600 dark:hover:text-rose-400 hover:underline transition-colors"
                  >
                    {t.title}
                  </a>
                  <a
                    href={t.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs text-muted hover:text-rose-600 dark:hover:text-rose-400 transition-colors inline-flex items-center"
                  >
                    {hostnameOf(t.url)}
                    <ExternalLink className="ml-1 inline h-3 w-3" />
                  </a>
                </div>
                {t.description && <p className="mt-0.5 text-xs text-muted leading-relaxed">{t.description}</p>}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
