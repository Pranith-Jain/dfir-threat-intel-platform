import { useEffect, useMemo, useState } from 'react';
import { Wrench, Search, ExternalLink, Star, Archive } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { sanitizeUrl } from '../../lib/sanitize-url';
import { errMessage } from '../../lib/log';

interface Tool {
  slug: string;
  repo: string;
  category: string;
  scope: string[];
  stars: number;
  description: string;
  homepage: string | null;
  added: string | null;
  checkedAt: string | null;
  pushedAt: string | null;
  daysIdle: number | null;
  archived: boolean;
  license: string | null;
}

const CATS = ['all', 'agent', 'scanner', 'mcp', 'skill'] as const;

function fmtStars(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

export default function AiSecurityMatrix(): JSX.Element {
  const [tools, setTools] = useState<Tool[]>([]);
  const [byCategory, setByCategory] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [cat, setCat] = useState<(typeof CATS)[number]>('all');
  const [openSlug, setOpenSlug] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await fetch('/api/v1/ai-security/matrix?limit=200');
      if (!r.ok) throw new Error(`matrix HTTP ${r.status}`);
      const j = (await r.json()) as { total: number; byCategory: Record<string, number>; tools: Tool[] };
      setTools(j.tools ?? []);
      setByCategory(j.byCategory ?? {});
      setTotal(j.total ?? 0);
    } catch (e) {
      setError(errMessage(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered = useMemo(() => {
    const needle = query.toLowerCase().trim();
    return tools.filter((t) => {
      if (cat !== 'all' && t.category !== cat) return false;
      if (needle && !`${t.repo} ${t.description} ${t.scope.join(' ')}`.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [tools, cat, query]);

  return (
    <DataPageLayout
      backTo="/threatintel/ai-security"
      backLabel="AI Security"
      icon={<Wrench size={28} />}
      title="AI Security Matrix"
      description={
        <>
          Daily mirror of{' '}
          <a
            href="https://aisecuritymatrix.com"
            target="_blank"
            rel="noopener noreferrer nofollow"
            className="text-sky-600 dark:text-sky-400 hover:underline"
          >
            aisecuritymatrix.com/data.json
          </a>{' '}
          — AI-enabled security testing tools (agents, scanners, MCP servers, skills), ranked by GitHub stars. Sync runs
          daily via the ai-security workflow.
        </>
      }
      loading={loading && tools.length === 0}
      error={error}
      onRetry={load}
    >
      <AiSummaryCard
        surface="AI Security Matrix"
        items={filtered.slice(0, 15).map((t) => ({
          title: t.repo,
          body: `${t.category} · ★${fmtStars(t.stars)} · ${(t.scope ?? []).join('/')}`,
          source: t.homepage ?? `https://github.com/${t.repo}`,
        }))}
        requireAdmin={false}
      />
      <div className="relative my-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
        <input
          type="text"
          placeholder="Search repos, descriptions, scopes…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full pl-9 pr-3 py-2 bg-surface-100 border border-line-1 rounded-xl text-sm text-heading placeholder:text-muted focus:outline-none focus:border-rose-500"
        />
      </div>
      <div className="flex flex-wrap items-center gap-1.5 mb-4">
        {CATS.map((c) => (
          <button
            key={c}
            onClick={() => setCat(c)}
            className={`px-2 py-1 rounded text-xs font-mono font-medium border transition ${
              cat === c
                ? 'border-rose-500/60 bg-rose-500/10 text-rose-600 dark:text-rose-400'
                : 'border-slate-300 dark:border-line-1 text-slate-500 hover:border-rose-500/30'
            }`}
          >
            {c === 'all' ? 'All' : c} · {c === 'all' ? total : (byCategory[c] ?? 0)}
          </button>
        ))}
        <span className="ml-auto text-xs font-mono text-muted">
          {filtered.length} / {total}
        </span>
      </div>
      <div className="grid gap-2">
        {filtered.map((t) => {
          const open = openSlug === t.slug;
          return (
            <div key={t.slug} className="rounded-xl border border-line-1 bg-surface-100/50 p-4">
              <button
                type="button"
                onClick={() => setOpenSlug(open ? null : t.slug)}
                className="w-full text-left"
                aria-expanded={open}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-1.5 py-0.5 text-micro font-mono rounded border border-line-2 text-muted">
                        {t.category}
                      </span>
                      {(t.scope ?? []).slice(0, 4).map((s) => (
                        <span
                          key={s}
                          className="px-1.5 py-0.5 text-micro font-mono rounded bg-surface-300 dark:bg-surface-100/5 text-body"
                        >
                          {s}
                        </span>
                      ))}
                      {t.archived && (
                        <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 text-micro font-mono rounded border border-amber-500/40 text-amber-700 dark:text-amber-300">
                          <Archive className="w-2.5 h-2.5" /> archived
                        </span>
                      )}
                    </div>
                    <h3 className="text-sm font-bold text-heading mt-1 font-mono">{t.repo}</h3>
                    <p className="text-xs text-muted mt-0.5 leading-relaxed">{t.description}</p>
                  </div>
                  <span className="inline-flex items-center gap-1 text-sm font-mono font-bold text-heading shrink-0">
                    <Star className="w-3.5 h-3.5 text-amber-500" /> {fmtStars(t.stars)}
                  </span>
                </div>
              </button>
              {open && (
                <div className="mt-2 pt-2 border-t border-line-1 flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
                  <span className="font-mono">license: {t.license ?? '—'}</span>
                  <span className="font-mono">added: {t.added ?? '—'}</span>
                  <span className="font-mono">
                    pushed: {t.pushedAt ?? '—'}
                    {t.daysIdle != null ? ` (${t.daysIdle}d idle)` : ''}
                  </span>
                  <span className="font-mono">scope: {(t.scope ?? []).join(', ') || '—'}</span>
                  <span className="flex gap-2">
                    <a
                      href={sanitizeUrl(`https://github.com/${t.repo}`) ?? undefined}
                      target="_blank"
                      rel="noopener noreferrer nofollow"
                      className="inline-flex items-center gap-0.5 text-sky-600 dark:text-sky-400 hover:underline"
                    >
                      GitHub <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                    {t.homepage && (
                      <a
                        href={sanitizeUrl(t.homepage) ?? undefined}
                        target="_blank"
                        rel="noopener noreferrer nofollow"
                        className="inline-flex items-center gap-0.5 text-sky-600 dark:text-sky-400 hover:underline"
                      >
                        Homepage <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    )}
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </DataPageLayout>
  );
}
