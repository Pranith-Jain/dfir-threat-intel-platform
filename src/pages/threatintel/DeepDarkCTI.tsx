import { useEffect, useMemo, useState } from 'react';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Copy, ExternalLink, Globe, Search } from 'lucide-react';
import { FeedAggregateCard } from '../../components/intel/FeedAggregateCard';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { PostAnalysisButton } from '../../components/threatintel/PostAnalysisButton';
import { errMessage } from '../../lib/log';

interface DDCEntry {
  name: string;
  url: string;
  onion: boolean;
  status: 'online' | 'offline' | 'valid' | 'expired' | 'unknown';
  category: string;
  source_file: string;
  notes?: string;
  actor?: string;
  attack_type?: string;
}

interface DDCResponse {
  generated_at: string;
  sources: Array<{ source_file: string; ok: boolean; count: number; total_seen: number; stale?: boolean }>;
  categories: Array<{ id: string; label: string; count: number }>;
  total: number;
  entries: DDCEntry[];
}

const STATUS_STYLE: Record<DDCEntry['status'], string> = {
  online: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  valid: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
  offline: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  expired: 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  unknown: 'border-slate-400/40 bg-slate-400/10 text-muted',
};

export default function DeepDarkCTI(): JSX.Element {
  const [data, setData] = useState<DDCResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [cat, setCat] = useState<string>('all');
  const [hideDown, setHideDown] = useState(true);
  const [onionOnly, setOnionOnly] = useState<'all' | 'onion' | 'clearnet'>('all');
  const [copied, setCopied] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let alive = true;
    const ctrl = new AbortController();
    setError(null);
    fetch('/api/v1/deepdarkcti', { signal: AbortSignal.any([ctrl.signal, AbortSignal.timeout(15_000)]) })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d: DDCResponse) => {
        if (alive) setData(d);
      })
      .catch((e) => {
        if (alive && (e as { name?: string }).name !== 'AbortError') {
          setError(errMessage(e));
        }
      });
    return () => {
      alive = false;
      ctrl.abort();
    };
  }, [refreshKey]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const q = query.trim().toLowerCase();
    return data.entries.filter((e) => {
      if (cat !== 'all' && e.category !== cat) return false;
      if (hideDown && (e.status === 'offline' || e.status === 'expired')) return false;
      if (onionOnly === 'onion' && !e.onion) return false;
      if (onionOnly === 'clearnet' && e.onion) return false;
      if (!q) return true;
      return `${e.name} ${e.notes ?? ''} ${e.actor ?? ''} ${e.attack_type ?? ''}`.toLowerCase().includes(q);
    });
  }, [data, query, cat, hideDown, onionOnly]);

  const copy = (text: string) => {
    void navigator.clipboard?.writeText(text);
    setCopied(text);
    window.setTimeout(() => setCopied((c) => (c === text ? null : c)), 1200);
  };

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Globe className="h-6 w-6" />}
      title="deepdarkCTI Index"
      description={
        <>
          Parsed mirror of{' '}
          <a
            href="https://github.com/fastfire/deepdarkCTI"
            target="_blank"
            rel="noopener noreferrer"
            className="text-rose-600 dark:text-rose-400 hover:underline transition-colors"
          >
            fastfire/deepdarkCTI
          </a>{' '}
          - ransomware leak sites, dark markets, criminal forums, infostealer & threat-actor channels. Onion addresses
          are copy-only (clearnet browsers can't open <code>.onion</code>).
        </>
      }
      loading={!data && !error}
      error={error}
      empty={!!data && data.total === 0}
      emptyMessage="deepdarkCTI temporarily unavailable - upstream fetch failed and no cached copy exists yet."
      onRetry={() => setRefreshKey((k) => k + 1)}
      maxWidthClass="max-w-6xl"
    >
      {data && (
        <>
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <div className="relative flex-1 min-w-[200px]">
              <Search
                size={14}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted"
                aria-hidden="true"
              />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search name, notes, actor…"
                className="w-full rounded-xl border border-line-1 bg-surface-100 py-2 pl-9 pr-3 font-mono text-tool text-heading placeholder:text-muted focus:border-rose-500/60 focus:outline-none"
                aria-label="Search deepdarkCTI"
              />
            </div>
            <select
              value={cat}
              onChange={(e) => setCat(e.target.value)}
              className="rounded-xl border border-line-1 bg-surface-100 py-2 px-3 font-mono text-meta"
              aria-label="Category filter"
            >
              <option value="all">All categories ({data.total})</option>
              {data.categories.map((c) => (
                <option key={c.id} value={c.label}>
                  {c.label} ({c.count})
                </option>
              ))}
            </select>
            <select
              value={onionOnly}
              onChange={(e) => setOnionOnly(e.target.value as typeof onionOnly)}
              className="rounded-xl border border-line-1 bg-surface-100 py-2 px-3 font-mono text-meta"
              aria-label="Network filter"
            >
              <option value="all">Onion + clearnet</option>
              <option value="onion">Onion only</option>
              <option value="clearnet">Clearnet only</option>
            </select>
            <label className="flex items-center gap-1.5 font-mono text-meta text-muted">
              <input type="checkbox" checked={hideDown} onChange={(e) => setHideDown(e.target.checked)} />
              hide offline/expired
            </label>
          </div>

          <p className="font-mono text-mini text-muted mb-3">
            {filtered.length} shown · {data.total} total ·{' '}
            {data.sources.filter((s) => s.stale).length > 0 && (
              <span className="text-amber-600 dark:text-amber-400">
                {data.sources.filter((s) => s.stale).length} source(s) cached
              </span>
            )}
          </p>

          {/* Page-level AI summary across the visible directory entries.
              Public (requireAdmin={false}) so every visitor sees it. The
              directory is intelligence-about (actors, malware, attack types),
              so the summary surfaces the threat-landscape shape, not content. */}
          {filtered.length > 0 && (
            <>
              <PostAnalysisButton
                title="deepdarkCTI Index Digest"
                description="AI-powered threat analysis of the current feed."
                source="deepdarkcti"
              />
              <AiSummaryCard
                surface="deepdarkCTI Index"
                items={filtered.slice(0, 30).map((e) => ({
                  title: e.name,
                  body: `${e.category} · ${e.actor ?? ''} · ${e.attack_type ?? ''} · ${e.notes ?? ''}`,
                  source: e.category,
                }))}
                requireAdmin={false}
              />
            </>
          )}

          {/* Aggregate STIX 2.1 view of the directory - extraction yield is
                low (mostly forum/market metadata), but actor + attack_type
                fields surface known threat actors and malware. Intelligence-
                about, never content. */}
          {filtered.length > 0 && (
            <FeedAggregateCard
              sourceId="darkweb:deepdarkcti"
              sourceName="deepdarkCTI Index"
              title="deepdarkCTI directory · today"
              items={filtered.map((e) => ({
                title: e.name,
                body: `${e.category} · ${e.actor ?? ''} · ${e.attack_type ?? ''} · ${e.notes ?? ''}`,
              }))}
            />
          )}

          <ul className="grid gap-2 md:grid-cols-2">
            {filtered.map((e, idx) => (
              <li key={`${e.source_file}:${e.url}:${idx}`} className="surface-card p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="font-display font-semibold text-sm truncate">{e.name}</span>
                      <span
                        className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-micro uppercase ${STATUS_STYLE[e.status]}`}
                      >
                        {e.status}
                      </span>
                      {e.attack_type && (
                        <span className="shrink-0 rounded border border-rose-500/40 bg-rose-500/10 px-1.5 py-0.5 font-mono text-micro text-rose-700 dark:text-rose-300">
                          {e.attack_type}
                        </span>
                      )}
                    </div>
                    {e.actor && <div className="font-mono text-mini text-muted mt-0.5">actor: {e.actor}</div>}
                    {e.onion ? (
                      <code className="block mt-1 font-mono text-mini text-muted break-all">{e.url}</code>
                    ) : (
                      <a
                        href={sanitizeUrl(e.url) || undefined}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mt-1 inline-flex items-center gap-1 font-mono text-mini text-rose-600 dark:text-rose-400 hover:underline break-all transition-colors"
                      >
                        {e.url}
                        <ExternalLink size={10} className="shrink-0" />
                      </a>
                    )}
                    {e.notes && <p className="font-mono text-mini text-muted mt-1">{e.notes}</p>}
                  </div>
                  <button
                    type="button"
                    onClick={() => copy(e.url)}
                    className="shrink-0 rounded border border-line-1 p-1.5 text-muted hover:text-rose-600 dark:hover:text-rose-400"
                    aria-label="Copy URL"
                  >
                    <Copy size={12} />
                  </button>
                </div>
                <div className="mt-1.5 flex items-center gap-2">
                  <span className="font-mono text-micro uppercase tracking-wider text-muted">{e.category}</span>
                  <a
                    href={`https://github.com/fastfire/deepdarkCTI/blob/main/${e.source_file}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-mono text-micro text-muted hover:text-rose-500 transition-colors"
                  >
                    {e.source_file}
                  </a>
                  {copied === e.url && (
                    <span className="font-mono text-micro text-emerald-600 dark:text-emerald-400">copied</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </DataPageLayout>
  );
}
