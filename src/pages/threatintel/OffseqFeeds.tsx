import { useMemo, useState } from 'react';
import { ExternalLink, RefreshCw, Search } from 'lucide-react';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { relativeAgo } from '../../lib/relativeTime';
import { Link } from 'react-router-dom';

/**
 * Source catalog from radar.offseq.com/feeds (OffSeq Threat Radar).
 *
 * The upstream page lists every feed OffSeq aggregates, with type/format,
 * item counts and the newest item timestamp. The snapshot is written by
 * scripts/sync-offseq.mjs + scripts/build-offseq.mjs into
 * public/data/threat-intel/offseq/feeds.json (GitHub Actions, every 30 min).
 * The existing OffSeq threat list is a tab on the same CVE page.
 */

interface FeedRecord {
  name: string;
  url: string | null;
  type: string | null;
  format: string | null;
  enabled: boolean;
  archived: boolean;
  itemCount: number;
  lastUpdated: string | null;
  lastFetchStatus: string | null;
  updateInterval: number | string | null;
  description: string | null;
}

interface FeedsManifest {
  source: string;
  sourceUrl: string;
  description: string;
  license: string;
  syncedAt: string;
  total: number | null;
  distinctCves: number | null;
  counts: { sources: number; enabled: number; archived: number };
  bySource: Array<{ name: string; count: number }>;
  latestBySource: Record<string, string>;
  feeds: FeedRecord[];
}

function fmt(value: number | null | undefined): string {
  return value == null ? '-' : value.toLocaleString('en-US');
}

function typeTone(type: string | null): string {
  switch ((type ?? '').toLowerCase()) {
    case 'api':
      return 'border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300';
    case 'rss':
      return 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300';
    case 'misp':
      return 'border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300';
    case 'community':
      return 'border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300';
    default:
      return 'border-line-1 bg-surface-100 text-muted';
  }
}

export default function OffseqFeeds(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<FeedsManifest>({
    url: '/data/threat-intel/offseq/feeds.json',
    ttl: 10 * 60_000,
  });
  const [query, setQuery] = useState('');

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.feeds ?? []).filter((f) => {
      if (!q) return true;
      return (
        (f.name ?? '').toLowerCase().includes(q) ||
        (f.description ?? '').toLowerCase().includes(q) ||
        (f.type ?? '').toLowerCase().includes(q)
      );
    });
  }, [data, query]);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-bold text-heading">OffSeq source catalog</h2>
          <p className="mt-1 text-[11px] text-muted">
            Mirrors{' '}
            <a
              href={data?.sourceUrl ?? 'https://radar.offseq.com/feeds'}
              target="_blank"
              rel="noopener noreferrer"
              className="underline hover:text-accent"
            >
              radar.offseq.com/feeds
            </a>{' '}
            · synced {data ? relativeAgo(data.syncedAt) : '…'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refetch()}
          className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-1 text-[11px] text-muted hover:text-heading"
        >
          <RefreshCw size={11} /> refresh
        </button>
      </div>

      {loading && !data && <p className="py-8 text-center text-sm text-muted">Loading OffSeq source catalog…</p>}
      {error && !data && (
        <p className="py-8 text-center text-sm text-rose-600 dark:text-rose-400">OffSeq catalog unavailable: {error}</p>
      )}

      {data && (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: 'Sources', value: fmt(data.counts.sources) },
              { label: 'Enabled', value: fmt(data.counts.enabled) },
              { label: 'Threats indexed', value: fmt(data.total) },
              { label: 'Distinct CVEs', value: fmt(data.distinctCves) },
            ].map((s) => (
              <div key={s.label} className="surface-card rounded-xl border border-line-1 px-4 py-3">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">{s.label}</div>
                <div className="text-xl font-semibold tabular-nums text-heading">{s.value}</div>
              </div>
            ))}
          </div>

          <div className="relative max-w-md">
            <span className="sr-only">Search sources</span>
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Source name, type, description…"
              className="w-full rounded-lg border border-line-1 bg-surface-100 py-2 pl-8 pr-3 text-sm text-body placeholder:text-muted focus:border-brand-500 focus:outline-none"
            />
          </div>

          <div className="overflow-x-auto rounded-xl border border-line-1">
            <table className="w-full min-w-[860px] text-left text-xs">
              <thead className="border-b border-line-1 bg-surface-100 text-[10px] uppercase tracking-wider text-muted">
                <tr>
                  <th className="px-3 py-2 font-semibold">Source</th>
                  <th className="px-3 py-2 font-semibold">Type</th>
                  <th className="px-3 py-2 font-semibold">Format</th>
                  <th className="px-3 py-2 text-right font-semibold">Items</th>
                  <th className="px-3 py-2 font-semibold">Last fetched</th>
                  <th className="px-3 py-2 font-semibold">Latest item</th>
                  <th className="px-3 py-2 font-semibold">Links</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-1">
                {rows.map((feed) => {
                  const latest = data.latestBySource[feed.name];
                  const upstream = sanitizeUrl(feed.url);
                  return (
                    <tr key={feed.name} className={feed.enabled ? '' : 'opacity-60'}>
                      <td className="max-w-[360px] px-3 py-2">
                        <div className="font-semibold text-heading">
                          {feed.name}
                          {feed.archived && <span className="ml-1 text-[10px] text-muted">(archived)</span>}
                        </div>
                        {feed.description && (
                          <div className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-muted">
                            {feed.description}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${typeTone(feed.type)}`}>
                          {feed.type ?? '-'}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-[10px] text-muted">{feed.format ?? '-'}</td>
                      <td className="px-3 py-2 text-right font-mono tabular-nums text-heading">
                        {fmt(feed.itemCount)}
                      </td>
                      <td className="px-3 py-2 font-mono text-[10px] text-muted">
                        {feed.lastUpdated ? relativeAgo(feed.lastUpdated) : '-'}
                      </td>
                      <td className="px-3 py-2 font-mono text-[10px] text-muted">
                        {latest ? relativeAgo(latest) : '-'}
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2 font-mono text-[10px]">
                          <Link
                            to="/threatintel/cves/cves?tab=offseq"
                            className="text-rose-600 hover:underline dark:text-rose-400"
                          >
                            threats
                          </Link>
                          {upstream && (
                            <a
                              href={upstream}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-muted hover:text-accent"
                            >
                              source <ExternalLink size={9} />
                            </a>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {rows.length === 0 && <p className="text-center text-sm text-muted">No sources match that search.</p>}

          <div className="border-t border-line-1 pt-3 text-[11px] leading-relaxed text-muted">
            <p>
              Source: <strong className="text-body">OffSeq Threat Radar</strong> (radar.offseq.com/feeds) ·{' '}
              {data.license} · © 2026 SEQ SIA. Feed descriptions and counts are verbatim upstream values; all IPs in the
              Mirage telemetry are masked upstream.
            </p>
          </div>
        </>
      )}
    </div>
  );
}
