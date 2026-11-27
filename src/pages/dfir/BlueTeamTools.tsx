/**
 * BlueTeam-Tools — metadata-only blue-team reference page.
 *
 * A-poc/BlueTeam-Tools has no reuse licence, so this page mirrors only tool
 * names, one-line summaries and public destination links. No upstream prose,
 * commands, images or code are vendored; every card deep-links the source.
 */
import { useMemo, useState, type JSX } from 'react';
import { ExternalLink, Filter, Search, ShieldCheck } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { PageMeta } from '../../components/PageMeta';
import { useDataFetch } from '../../hooks/useDataFetch';
import { sanitizeUrl } from '../../lib/sanitize-url';

interface BttTool {
  slug: string;
  name: string;
  category: string;
  summary: string;
  url: string | null;
  upstreamUrl: string;
}

interface BttIndex {
  generatedAt: string;
  source: string;
  sourceUrl: string;
  license: string;
  counts: { categories: number; tools: number; withLinks: number };
  categories: Array<{ name: string; statedCount: string; toolCount: number; tools: string[] }>;
  tools: BttTool[];
}

export default function BlueTeamTools(): JSX.Element {
  const { data, loading, error } = useDataFetch<BttIndex>({ url: '/api/v1/blue-team-tools/', ttl: 10 * 60_000 });
  const [category, setCategory] = useState('all');
  const [q, setQ] = useState('');
  const [linkedOnly, setLinkedOnly] = useState(false);

  const tools = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.tools ?? []).filter((t) => {
      if (category !== 'all' && t.category !== category) return false;
      if (linkedOnly && !t.url) return false;
      if (needle && !`${t.name} ${t.summary} ${t.category}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data?.tools, category, q, linkedOnly]);

  return (
    <DataPageLayout
      backTo="/dfir"
      icon={<ShieldCheck size={28} />}
      title="BlueTeam-Tools"
      description="A metadata-only directory of 75 blue-team tools across 13 categories — detection, hunting, forensics, recovery and response."
      maxWidthClass="max-w-7xl"
    >
      <PageMeta
        title="BlueTeam-Tools — blue-team reference directory"
        description="Tool names, one-line summaries and public links from A-poc/BlueTeam-Tools, mirrored as metadata only with deep links upstream."
        section="DFIR"
        canonicalPath="/dfir/blue-team-tools"
      />

      <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2 text-mini leading-relaxed text-amber-800 dark:text-amber-200">
        No project licence — all rights reserved. Only factual tool metadata is shown; open the upstream link for the
        full article and any commands.
      </div>

      {data && (
        <div className="mb-4 flex flex-wrap items-center gap-x-6 gap-y-2 text-mini text-muted">
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.tools}</span> tools
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.categories}</span> categories
          </span>
          <span>
            <span className="font-mono font-semibold text-fg">{data.counts.withLinks}</span> with public links
          </span>
          <a
            href={sanitizeUrl(data.sourceUrl) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
          >
            upstream repository <ExternalLink size={11} />
          </a>
        </div>
      )}

      <div className="mb-4 space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search tools by name, purpose or category…"
              className="w-full rounded-lg border border-line-1 bg-surface-100 py-1.5 pl-8 pr-3 text-mini text-fg placeholder:text-muted focus:border-sky-500 focus:outline-none"
            />
          </div>
          <button
            type="button"
            onClick={() => setLinkedOnly((v) => !v)}
            aria-pressed={linkedOnly}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-mini transition-colors ${
              linkedOnly
                ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                : 'border-line-1 text-muted hover:text-fg'
            }`}
          >
            <Filter size={12} /> With links only
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setCategory('all')}
            aria-pressed={category === 'all'}
            className={`rounded-full border px-2.5 py-1 text-mini font-mono transition-colors ${
              category === 'all'
                ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                : 'border-line-2 text-muted hover:border-sky-500/40 dark:border-line-1'
            }`}
          >
            all ({data?.counts.tools ?? 0})
          </button>
          {(data?.categories ?? []).map((c) => (
            <button
              key={c.name}
              type="button"
              onClick={() => setCategory(c.name)}
              aria-pressed={category === c.name}
              className={`rounded-full border px-2.5 py-1 text-mini font-mono transition-colors ${
                category === c.name
                  ? 'border-sky-500/50 bg-sky-500/10 text-sky-700 dark:text-sky-300'
                  : 'border-line-2 text-muted hover:border-sky-500/40 dark:border-line-1'
              }`}
            >
              {c.name} ({c.toolCount})
            </button>
          ))}
        </div>
      </div>

      {loading && !data && <p className="text-mini font-mono text-muted">loading the tool directory…</p>}
      {error && !data && <p className="text-mini text-rose-600 dark:text-rose-400">{error}</p>}

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {tools.map((t) => (
          <div key={t.slug} className="surface-card p-3">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="text-sm font-semibold text-heading">{t.name}</div>
                <div className="mt-0.5 font-mono text-micro text-muted">{t.category}</div>
              </div>
              {t.url && (
                <a
                  href={sanitizeUrl(t.url) ?? undefined}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label={`Open ${t.name}`}
                  className="shrink-0 text-muted hover:text-heading"
                >
                  <ExternalLink size={13} />
                </a>
              )}
            </div>
            {t.summary && <p className="mt-2 text-mini leading-relaxed text-body">{t.summary}</p>}
            <a
              href={sanitizeUrl(t.upstreamUrl) ?? undefined}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-micro text-sky-600 hover:underline dark:text-sky-400"
            >
              upstream entry <ExternalLink size={10} />
            </a>
          </div>
        ))}
      </div>

      {data && tools.length === 0 && (
        <p className="surface-card p-6 text-center text-mini text-muted">No tools match that filter.</p>
      )}
    </DataPageLayout>
  );
}
