import { useEffect, useMemo, useState } from 'react';
import { ExternalLink, Library, Search, Star } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { errMessage } from '../../lib/log';

/**
 * Mirror of the AX Intel Tools directory (tools.axi68.com): 200+ vetted
 * OSINT / threat-intel / OPSEC tools, each with its category, pricing tag
 * and the publisher's practitioner note. Data is re-scraped from the
 * upstream homepage HTML daily (scripts/sync-axi68-tools.mjs) because the
 * site publishes no JSON API.
 */

interface AxiTool {
  name: string;
  url: string;
  category: string;
  pricing: string | null;
  note: string;
}

interface AxiIndex {
  generated_at: string;
  upstream: {
    directory: string;
    sitemap_lastmod: string | null;
    title: string;
  };
  count: number;
  categories: Array<{ name: string; count: number }>;
  tools: AxiTool[];
}

export default function AxiTools(): JSX.Element {
  const [data, setData] = useState<AxiIndex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [pricing, setPricing] = useState<'all' | 'Free' | 'Paid'>('all');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/data/axi68-tools/index.json', { signal: AbortSignal.timeout(15000) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as AxiIndex;
        if (!cancelled) setData(json);
      } catch (e) {
        if (!cancelled) setError(errMessage(e, 'Failed to load tool directory'));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.tools || []).filter((t) => {
      if (category !== 'all' && t.category !== category) return false;
      if (pricing !== 'all' && t.pricing !== pricing) return false;
      if (!q) return true;
      return (
        t.name.toLowerCase().includes(q) ||
        t.note.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.url.toLowerCase().includes(q)
      );
    });
  }, [data, query, category, pricing]);

  return (
    <DataPageLayout
      backTo="/threatintel/catalog?cat=osint"
      icon={<Library size={28} />}
      title="AX Intel Tool Directory"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="px-2 py-1 rounded bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-300 text-xs font-mono">
            {data?.count ?? '...'} vetted tools
          </span>
          <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted">
            Mirror of tools.axi68.com
          </span>
          {data?.upstream.sitemap_lastmod && (
            <span className="px-2 py-1 rounded bg-surface-300 border border-line-1 text-xs font-mono text-muted">
              Upstream lastmod {data.upstream.sitemap_lastmod}
            </span>
          )}
        </span>
      }
      maxWidthClass="max-w-6xl"
      error={error}
      loading={!data && !error}
    >
      <div className="space-y-4">
        <div className="flex flex-wrap gap-2 items-center">
          <div className="relative flex-1 min-w-56">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search tools, notes, categories..."
              className="w-full pl-9 pr-3 py-2 rounded-lg bg-surface-100 border border-line-1 text-sm text-heading placeholder:text-muted/60"
            />
          </div>
          <select
            value={pricing}
            onChange={(e) => setPricing(e.target.value as 'all' | 'Free' | 'Paid')}
            className="px-3 py-2 rounded-lg bg-surface-100 border border-line-1 text-xs font-mono text-heading"
          >
            <option value="all">Free + Paid</option>
            <option value="Free">Free only</option>
            <option value="Paid">Paid only</option>
          </select>
        </div>

        {/* Category chips */}
        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => setCategory('all')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors ${
              category === 'all'
                ? 'bg-sky-500 text-on-fill font-bold'
                : 'bg-surface-100 border border-line-1 text-muted hover:text-heading'
            }`}
          >
            All {data ? `(${data.count})` : ''}
          </button>
          {(data?.categories || []).map((c) => (
            <button
              key={c.name}
              onClick={() => setCategory(c.name)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors ${
                category === c.name
                  ? 'bg-sky-500 text-on-fill font-bold'
                  : 'bg-surface-100 border border-line-1 text-muted hover:text-heading'
              }`}
            >
              {c.name} <span className="opacity-60">{c.count}</span>
            </button>
          ))}
        </div>

        <div className="text-xs font-mono text-muted">{filtered.length} tools</div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {filtered.map((t) => (
            <div key={t.url} className="rounded-xl bg-surface-100 border border-line-1 p-4 flex flex-col">
              <div className="flex items-start justify-between gap-2">
                <a
                  href={t.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-bold text-heading hover:text-sky-500 inline-flex items-center gap-1"
                >
                  {t.name} <ExternalLink size={11} className="opacity-60" />
                </a>
                {t.pricing && (
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono shrink-0 ${
                      t.pricing === 'Free'
                        ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-700 dark:text-emerald-300'
                        : 'bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300'
                    }`}
                  >
                    {t.pricing === 'Free' ? <Star size={9} className="inline mr-1 -mt-0.5" /> : null}
                    {t.pricing}
                  </span>
                )}
              </div>
              <span className="text-[10px] font-mono text-sky-600 dark:text-sky-400 mt-0.5">{t.category}</span>
              <p className="text-sm text-body mt-2 leading-relaxed flex-1">{t.note}</p>
              <span className="text-[10px] font-mono text-muted mt-2 truncate">{t.url}</span>
            </div>
          ))}
        </div>

        {filtered.length === 0 && data && (
          <div className="text-center py-10 text-muted text-sm">No tools match the current filters.</div>
        )}
      </div>

      <div className="mt-8 pt-4 border-t border-line-1 text-[11px] font-mono text-muted leading-relaxed">
        Directory mirrored from{' '}
        <a
          href={data?.upstream.directory || 'https://tools.axi68.com/'}
          target="_blank"
          rel="noopener noreferrer"
          className="underline hover:text-sky-500"
        >
          tools.axi68.com
        </a>{' '}
        (AX Global). Listings are editorial and belong to their publisher; inclusion here is a mirror, not an
        endorsement. Re-scraped daily from the upstream homepage - the source publishes no data API. Synced{' '}
        {data?.generated_at ? new Date(data.generated_at).toISOString().slice(0, 16).replace('T', ' ') : ''} UTC.
      </div>
    </DataPageLayout>
  );
}
