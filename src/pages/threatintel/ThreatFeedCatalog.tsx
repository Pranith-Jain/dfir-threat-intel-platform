/** ThreatFeed — MIT-licensed catalog of 181 security feeds in 15 categories. */
import { useMemo, useState, type JSX } from 'react';
import { ExternalLink, Rss, Search } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface Feed {
  id: string;
  name: string;
  url: string | null;
  category: string;
  tags: string[];
  enabled: boolean;
  upstreamUrl: string;
}

interface Index {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  feedUrl: string;
  license: string;
  note: string;
  counts: { feeds: number; categories: number; enabled: number; retired: number };
  categories: Array<{ name: string; count: number; feeds: string[] }>;
  feeds: Feed[];
}

export default function ThreatFeedCatalog(): JSX.Element {
  const { data, loading, error } = useDataFetch<Index>({ url: '/api/v1/threatfeed/', ttl: 10 * 60_000 });
  const [category, setCategory] = useState('all');
  const [q, setQ] = useState('');

  const feeds = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.feeds ?? []).filter(
      (f) =>
        (category === 'all' || f.category === category) &&
        (!needle || `${f.name} ${f.id} ${f.tags.join(' ')}`.toLowerCase().includes(needle))
    );
  }, [data?.feeds, category, q]);

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Rss size={28} />}
      title="Threat Feed Catalog"
      description="181 security intelligence feeds across 15 categories from jozeta/ThreatFeed (MIT) — subscribe directly through upstream URLs."
      maxWidthClass="max-w-7xl"
    >
      <PageMeta
        title="Threat Feed Catalog — 181 security RSS feeds"
        description="A full metadata mirror of the MIT-licensed ThreatFeed catalog. Article bodies are not vendored; every feed links to its upstream URL."
        section="Threat Intel"
        canonicalPath="/threatintel/threat-feed-catalog"
      />

      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-mini text-muted">
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.feeds}</span> feeds
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.categories}</span> categories
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.enabled}</span> enabled
          </span>
          <a
            href={sanitizeUrl(data.sourceUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            jozeta/ThreatFeed <ExternalLink size={10} />
          </a>
        </div>
      )}

      <div className="mb-4 space-y-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search feeds by name, id or tag…"
            className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setCategory('all')}
            aria-pressed={category === 'all'}
            className={`rounded-full border px-2.5 py-1 text-mini font-mono ${category === 'all' ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'}`}
          >
            all ({data?.counts.feeds ?? 0})
          </button>
          {(data?.categories ?? []).map((c) => (
            <button
              key={c.name}
              type="button"
              onClick={() => setCategory(c.name)}
              aria-pressed={category === c.name}
              className={`rounded-full border px-2.5 py-1 text-mini font-mono ${category === c.name ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300' : 'border-line-1 text-muted'}`}
            >
              {c.name} ({c.count})
            </button>
          ))}
        </div>
      </div>

      {loading && !data && <p className="text-mini font-mono text-muted">loading the feed catalog…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
        {feeds.map((f) => (
          <div key={f.id} className="surface-card p-3">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-heading">{f.name}</div>
                <div className="mt-0.5 font-mono text-micro text-muted">{f.category}</div>
              </div>
              {f.url && (
                <a
                  href={sanitizeUrl(f.url) ?? undefined}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`Open ${f.name} feed`}
                  className="shrink-0 text-muted hover:text-heading"
                >
                  <Rss size={14} />
                </a>
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              {f.tags.slice(0, 5).map((t) => (
                <span key={t} className="rounded border border-line-1 px-1.5 py-0.5 text-micro text-muted">
                  {t}
                </span>
              ))}
              {!f.enabled && (
                <span className="rounded border border-rose-500/40 px-1.5 py-0.5 font-mono text-micro text-rose-600 dark:text-rose-300">
                  retired
                </span>
              )}
            </div>
            <a
              href={sanitizeUrl(f.upstreamUrl) ?? undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-micro text-sky-600 hover:underline dark:text-sky-400"
            >
              upstream entry <ExternalLink size={10} />
            </a>
          </div>
        ))}
      </div>

      {data && feeds.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No feeds match that filter.</p>
      )}
    </DataPageLayout>
  );
}
