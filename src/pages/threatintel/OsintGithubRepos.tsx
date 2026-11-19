import { useMemo, useState } from 'react';
import { ExternalLink, Github, Library, RefreshCw, Search, Star } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { AiSummaryCard } from '../../components/intel/AiSummaryCard';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';

/**
 * The OSINT Toolbox — github.com/The-Osint-Toolbox (CQCore).
 *
 * A single page for the entire GitHub account: all 35 public repositories as
 * category cards, plus a flat searchable index of the ~2,000 external tools
 * linked from their READMEs. Snapshot built by
 * scripts/sync-osint-toolbox.mjs (GitHub Actions, daily).
 *
 * This is a mirror, not an endorsement: link text and URLs are upstream's
 * verbatim. Some resources are paid and links can go stale.
 */

interface ToolLink {
  name: string;
  url: string;
  repo: string;
  category: string;
}

interface RepoRecord {
  name: string;
  fullName: string;
  url: string;
  description: string;
  homepage: string | null;
  category: string;
  stars: number;
  forks: number;
  topics: string[];
  createdAt: string | null;
  pushedAt: string | null;
  defaultBranch: string;
  toolCount: number;
}

interface ToolboxDataset {
  generatedAt: string;
  source: {
    name: string;
    login: string;
    url: string;
    api: string;
    description: string;
    followers: number;
    publicRepos: number;
  };
  stats: { repos: number; tools: number; stars: number; categories: number };
  categories: string[];
  repos: RepoRecord[];
  tools: ToolLink[];
}

type TabId = 'repos' | 'tools';
type RepoSort = 'stars' | 'tools' | 'name' | 'updated';

const REPO_PAGE = 24;
const TOOL_PAGE = 60;

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return '';
  }
}

function fmt(n: number): string {
  return n.toLocaleString('en-US');
}

export default function OsintGithubRepos(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<ToolboxDataset>({
    url: '/data/osint-toolbox/index.json',
    ttl: 15 * 60_000,
  });

  const [tab, setTab] = useState<TabId>('repos');
  const [repoQuery, setRepoQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [repoSort, setRepoSort] = useState<RepoSort>('stars');
  const [repoVisible, setRepoVisible] = useState(REPO_PAGE);

  const [toolQuery, setToolQuery] = useState('');
  const [toolRepo, setToolRepo] = useState('all');
  const [toolVisible, setToolVisible] = useState(TOOL_PAGE);

  const repos = useMemo(() => {
    const q = repoQuery.trim().toLowerCase();
    return (data?.repos ?? [])
      .filter((r) => {
        if (category !== 'all' && r.category !== category) return false;
        if (!q) return true;
        return (
          r.name.toLowerCase().includes(q) ||
          r.category.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          r.topics.some((t) => t.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => {
        switch (repoSort) {
          case 'tools':
            return b.toolCount - a.toolCount || b.stars - a.stars;
          case 'name':
            return a.name.localeCompare(b.name);
          case 'updated':
            return String(b.pushedAt ?? '').localeCompare(String(a.pushedAt ?? ''));
          default:
            return b.stars - a.stars || a.name.localeCompare(b.name);
        }
      });
  }, [data, repoQuery, category, repoSort]);

  const tools = useMemo(() => {
    const q = toolQuery.trim().toLowerCase();
    return (data?.tools ?? []).filter((t) => {
      if (toolRepo !== 'all' && t.repo !== toolRepo) return false;
      if (!q) return true;
      return (
        t.name.toLowerCase().includes(q) ||
        t.category.toLowerCase().includes(q) ||
        t.repo.toLowerCase().includes(q) ||
        t.url.toLowerCase().includes(q)
      );
    });
  }, [data, toolQuery, toolRepo]);

  return (
    <DataPageLayout
      backTo="/threatintel/catalog?cat=osint"
      icon={<Library size={28} />}
      title="The OSINT Toolbox"
      description={
        <span className="inline-flex flex-wrap items-center gap-2">
          <span className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-1 font-mono text-xs text-emerald-700 dark:text-emerald-300">
            {data ? fmt(data.stats.repos) : '...'} repositories · {data ? fmt(data.stats.tools) : '...'} tools
          </span>
          <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
            Mirror of github.com/The-Osint-Toolbox
          </span>
          {data && (
            <span className="rounded border border-line-1 bg-surface-300 px-2 py-1 font-mono text-xs text-muted">
              by {data.source.name} · synced {relativeAgo(data.generatedAt)}
            </span>
          )}
        </span>
      }
      maxWidthClass="max-w-6xl"
      loading={loading && !data}
      error={error}
      onRetry={() => void refetch()}
    >
      {data && (
        <div className="space-y-5">
          <AiSummaryCard
            surface="The OSINT Toolbox"
            items={[...data.repos]
              .sort((a, b) => b.stars - a.stars)
              .slice(0, 15)
              .map((r) => ({
                title: `${r.category}: ${r.name}`,
                body: `${r.description || 'Curated OSINT resource list'} · ${fmt(r.toolCount)} tool links · ${fmt(r.stars)} stars`,
                source: r.url,
              }))}
            dayKey={data.generatedAt.slice(0, 10)}
            requireAdmin={false}
          />

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[
              { label: 'Repositories', value: fmt(data.stats.repos) },
              { label: 'Tool links', value: fmt(data.stats.tools) },
              { label: 'Combined stars', value: fmt(data.stats.stars) },
              { label: 'Categories', value: fmt(data.stats.categories) },
            ].map((s) => (
              <div key={s.label} className="surface-card rounded-xl border border-line-1 px-4 py-3">
                <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">{s.label}</div>
                <div className="text-xl font-semibold tabular-nums text-heading">{s.value}</div>
              </div>
            ))}
          </div>

          <nav className="flex gap-1 border-b border-line-1" role="tablist" aria-label="OSINT Toolbox views">
            {(
              [
                ['repos', `Repositories (${data.stats.repos})`],
                ['tools', `All tools (${fmt(data.stats.tools)})`],
              ] as Array<[TabId, string]>
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={tab === id}
                onClick={() => setTab(id)}
                className={`border-b-2 px-3 py-2 font-mono text-xs font-semibold transition-colors ${
                  tab === id
                    ? 'border-emerald-600 text-emerald-700 dark:border-emerald-400 dark:text-emerald-300'
                    : 'border-transparent text-muted hover:text-heading'
                }`}
              >
                {label}
              </button>
            ))}
          </nav>

          {tab === 'repos' && (
            <section role="tabpanel" aria-labelledby="osint-repos" className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <label className="relative min-w-[220px] flex-1">
                  <span className="sr-only">Search repositories</span>
                  <Search
                    size={14}
                    className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"
                  />
                  <input
                    type="search"
                    value={repoQuery}
                    onChange={(e) => {
                      setRepoQuery(e.target.value);
                      setRepoVisible(REPO_PAGE);
                    }}
                    placeholder="Category, repo, description, topic…"
                    className="w-full rounded-lg border border-line-1 bg-surface-100 py-2 pl-8 pr-3 text-sm text-body placeholder:text-muted focus:border-emerald-500 focus:outline-none"
                  />
                </label>
                <label>
                  <span className="sr-only">Filter by category</span>
                  <select
                    value={category}
                    onChange={(e) => {
                      setCategory(e.target.value);
                      setRepoVisible(REPO_PAGE);
                    }}
                    className="rounded-lg border border-line-1 bg-surface-100 px-2 py-2 text-xs text-body focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="all">All categories</option>
                    {data.categories.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span className="sr-only">Sort repositories</span>
                  <select
                    value={repoSort}
                    onChange={(e) => setRepoSort(e.target.value as RepoSort)}
                    className="rounded-lg border border-line-1 bg-surface-100 px-2 py-2 text-xs text-body focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="stars">Sort: stars</option>
                    <option value="tools">Sort: tool count</option>
                    <option value="name">Sort: name</option>
                    <option value="updated">Sort: recently updated</option>
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => void refetch()}
                  className="inline-flex items-center gap-1 rounded border border-line-1 px-2 py-2 text-[11px] text-muted hover:text-heading"
                >
                  <RefreshCw size={11} /> refresh
                </button>
              </div>

              <p className="font-mono text-[11px] text-muted">
                {repos.length} repos · showing {Math.min(repoVisible, repos.length)}
              </p>

              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {repos.slice(0, repoVisible).map((r) => (
                  <article key={r.name} className="surface-card flex flex-col rounded-xl border border-line-1 p-4">
                    <div className="mb-2 flex items-start justify-between gap-2">
                      <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[10px] text-emerald-700 dark:text-emerald-300">
                        {r.category}
                      </span>
                      <span
                        className="inline-flex items-center gap-1 font-mono text-[10px] text-muted"
                        title={`${r.stars} stars`}
                      >
                        <Star size={10} /> {fmt(r.stars)}
                      </span>
                    </div>
                    <a
                      href={sanitizeUrl(r.url) ?? undefined}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-sm font-bold text-heading hover:text-emerald-700 dark:hover:text-emerald-300"
                    >
                      {r.name} <ExternalLink size={11} />
                    </a>
                    <p className="mt-1 line-clamp-3 flex-1 text-xs leading-relaxed text-body">
                      {r.description || 'Curated OSINT resource list.'}
                    </p>
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-[10px] font-mono text-muted">
                      <span className="rounded border border-line-1 px-1.5 py-0.5">{r.toolCount} tools</span>
                      <span>{r.forks} forks</span>
                      {r.pushedAt && <span>updated {relativeAgo(r.pushedAt)}</span>}
                    </div>
                    {r.topics.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {r.topics.slice(0, 5).map((t) => (
                          <span
                            key={t}
                            className="rounded bg-surface-100 px-1.5 py-0.5 font-mono text-[10px] text-muted"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </article>
                ))}
              </div>
              {repoVisible < repos.length && (
                <div className="flex justify-center">
                  <button
                    type="button"
                    onClick={() => setRepoVisible((v) => v + REPO_PAGE)}
                    className="rounded border border-line-1 px-4 py-2 font-mono text-xs text-muted hover:border-emerald-500/40 hover:text-heading"
                  >
                    load {Math.min(REPO_PAGE, repos.length - repoVisible)} more
                  </button>
                </div>
              )}
              {repos.length === 0 && (
                <p className="py-8 text-center text-sm text-muted">No repos match those filters.</p>
              )}
            </section>
          )}

          {tab === 'tools' && (
            <section role="tabpanel" aria-labelledby="osint-tools" className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <label className="relative min-w-[240px] flex-1">
                  <span className="sr-only">Search tools</span>
                  <Search
                    size={14}
                    className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted"
                  />
                  <input
                    type="search"
                    value={toolQuery}
                    onChange={(e) => {
                      setToolQuery(e.target.value);
                      setToolVisible(TOOL_PAGE);
                    }}
                    placeholder="Tool name, host, category, repo…"
                    className="w-full rounded-lg border border-line-1 bg-surface-100 py-2 pl-8 pr-3 text-sm text-body placeholder:text-muted focus:border-emerald-500 focus:outline-none"
                  />
                </label>
                <label>
                  <span className="sr-only">Filter by repository</span>
                  <select
                    value={toolRepo}
                    onChange={(e) => {
                      setToolRepo(e.target.value);
                      setToolVisible(TOOL_PAGE);
                    }}
                    className="max-w-[260px] rounded-lg border border-line-1 bg-surface-100 px-2 py-2 text-xs text-body focus:border-emerald-500 focus:outline-none"
                  >
                    <option value="all">All repositories</option>
                    {data.repos.map((r) => (
                      <option key={r.name} value={r.name}>
                        {r.category} ({r.toolCount})
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <p className="font-mono text-[11px] text-muted">
                {fmt(tools.length)} tools · showing {Math.min(toolVisible, tools.length)}
              </p>

              <ul className="divide-y divide-line-1 overflow-hidden rounded-xl border border-line-1">
                {tools.slice(0, toolVisible).map((t, i) => {
                  const href = sanitizeUrl(t.url);
                  return (
                    <li
                      key={`${t.repo}-${t.url}-${i}`}
                      className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-xs"
                    >
                      <span className="min-w-[200px] flex-[2] truncate">
                        {href ? (
                          <a
                            href={href}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex max-w-full items-center gap-1 font-semibold text-heading hover:text-emerald-700 dark:hover:text-emerald-300"
                          >
                            <span className="truncate">{t.name}</span> <ExternalLink size={10} className="shrink-0" />
                          </a>
                        ) : (
                          <span className="font-semibold text-heading">{t.name}</span>
                        )}
                      </span>
                      <span className="flex-1 truncate font-mono text-[10px] text-muted" title={t.url}>
                        {hostOf(t.url)}
                      </span>
                      <span className="rounded border border-line-1 bg-surface-100 px-1.5 py-0.5 font-mono text-[10px] text-muted">
                        {t.category}
                      </span>
                      <span className="font-mono text-[10px] text-muted">{t.repo}</span>
                    </li>
                  );
                })}
              </ul>
              {toolVisible < tools.length && (
                <div className="flex justify-center">
                  <button
                    type="button"
                    onClick={() => setToolVisible((v) => v + TOOL_PAGE)}
                    className="rounded border border-line-1 px-4 py-2 font-mono text-xs text-muted hover:border-emerald-500/40 hover:text-heading"
                  >
                    load {Math.min(TOOL_PAGE, tools.length - toolVisible)} more
                  </button>
                </div>
              )}
              {tools.length === 0 && (
                <p className="py-8 text-center text-sm text-muted">No tools match those filters.</p>
              )}
            </section>
          )}

          <section className="surface-card rounded-xl border border-line-1 p-4 text-[11px] leading-relaxed text-muted">
            <p className="mb-1 flex items-center gap-1.5 font-semibold text-heading">
              <Github size={13} /> Provenance & caveat
            </p>
            <p>
              Mirror of{' '}
              <a
                href={data.source.url}
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-accent"
              >
                github.com/The-Osint-Toolbox ({data.source.name})
              </a>
              . Repository metadata comes from the public GitHub API; tool names and URLs are the external links in each
              upstream README. Categories follow the author's Quick Links table. Inclusion here is a mirror, not a
              recommendation or endorsement; upstream notes that some resources are paid, links can go stale, and you
              should understand any tool before using it and mind your own OPSEC. Snapshot synced{' '}
              {relativeAgo(data.generatedAt)}.
            </p>
          </section>
        </div>
      )}
    </DataPageLayout>
  );
}
