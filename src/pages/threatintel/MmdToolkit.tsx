import { useMemo, useState } from 'react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { Modal } from '../../components/ui/Modal';
import { useDataFetch } from '../../hooks/useDataFetch';
import { api } from '../../lib/api-client';
import { renderMarkdown } from '../../components/dfir/report-view-helpers';
import { Bug, ExternalLink, FolderTree, GitCommitHorizontal, Loader2, Search, Skull } from 'lucide-react';
import { DetectionAiBriefing } from '../../components/threatintel/DetectionAiBriefing';

/**
 * MMD Toolkit — the shared codes & tools collection of the MalwareMustDie
 * (MMD) non-profit malware awareness team (github.com/unixfreaxjp/
 * malwaremustdie), auto-synced weekly from the upstream GitHub tree + commits.
 *
 * Catalog of malware-analysis tooling organized by implementation language,
 * plus a recent-activity feed so upstream updates are visible. The manifest
 * lives in public/data/mmd/ (built by scripts/build-mmd-manifest.mjs).
 *
 * Reads the replicated manifest through the platform API:
 *   GET  /api/v1/mmd/            → slim index (counts, categories, files, commits)
 *   GET  /api/v1/mmd/categories/:cat → per-category file listing
 *   GET  /api/v1/mmd/readme      → upstream README body
 */

interface MmdFile {
  path: string;
  name: string;
  category: string;
  ext: string;
  kind: string;
  size: number;
}

interface MmdCommit {
  sha: string;
  date: string | null;
  author: string | null;
  message: string;
}

interface MmdIndex {
  source: string;
  sourceUrl: string;
  siteUrl: string;
  license: string;
  builtAt: string;
  branch: string;
  about: string;
  counts: {
    files: number;
    categories: number;
    scripts: number;
    docs: number;
    binaries: number;
    totalSize: number;
    commitsTracked: number;
    recentCommits: number;
  };
  categories: Array<{
    category: string;
    description: string;
    count: number;
    totalSize: number;
    kinds: Record<string, number>;
  }>;
  files: MmdFile[];
  recentCommits: MmdCommit[];
  lastCommit: string | null;
}

interface MmdCategoryBody {
  category: string;
  description: string;
  count: number;
  totalSize: number;
  files: MmdFile[];
}

const inputCls =
  'w-full px-3 py-2 bg-white dark:bg-surface-200 border border-line-1 rounded-xl text-sm text-heading placeholder-slate-500 dark:placeholder-slate-600';

const KIND_STYLES: Record<string, string> = {
  script:
    'text-emerald-700 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800',
  source: 'text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/40 border-sky-300 dark:border-sky-800',
  doc: 'text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/40 border-slate-300 dark:border-slate-700',
  webtool:
    'text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 border-violet-300 dark:border-violet-800',
  slides: 'text-amber-700 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800',
  binary: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  archive: 'text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800',
  r2script:
    'text-fuchsia-700 dark:text-fuchsia-300 bg-fuchsia-50 dark:bg-fuchsia-950/40 border-fuchsia-300 dark:border-fuchsia-800',
};

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtDate(d: string | null): string {
  if (!d) return '';
  const t = new Date(d);
  return Number.isNaN(t.getTime())
    ? d.slice(0, 10)
    : t.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

type Tab = 'tools' | 'categories' | 'activity' | 'about';

export default function MmdToolkit(): JSX.Element {
  const { data, loading, error, refetch } = useDataFetch<MmdIndex>({ url: '/api/v1/mmd/', ttl: 300_000 });
  const { data: readmeData } = useDataFetch<{ body: string }>({ url: '/api/v1/mmd/readme', ttl: 300_000 });
  const [tab, setTab] = useState<Tab>('tools');
  const [category, setCategory] = useState('');
  const [kind, setKind] = useState('');
  const [q, setQ] = useState('');
  const [catBody, setCatBody] = useState<MmdCategoryBody | null>(null);
  const [catLoading, setCatLoading] = useState(false);

  const files = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.files ?? []).filter((f) => {
      if (category && f.category !== category) return false;
      if (kind && f.kind !== kind) return false;
      if (needle && !f.path.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [data, category, kind, q]);

  const kindOptions = useMemo(() => {
    const s = new Set<string>();
    for (const f of data?.files ?? []) s.add(f.kind);
    return [...s].sort();
  }, [data]);

  const briefingItems = useMemo(
    () =>
      (data?.files ?? []).slice(0, 50).map((f) => ({
        title: f.name || f.path,
        body: `${f.category} · ${f.kind} · .${f.ext} · ${fmtSize(f.size)} — ${f.path}`,
        source: `https://github.com/unixfreaxjp/malwaremustdie/blob/master/${f.path}`,
      })),
    [data]
  );

  async function openCategory(cat: string) {
    setCatLoading(true);
    setCatBody(null);
    try {
      setCatBody(await api.get<MmdCategoryBody>(`/api/v1/mmd/categories/${encodeURIComponent(cat)}`));
    } catch {
      setCatBody(null);
    } finally {
      setCatLoading(false);
    }
  }

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: 'tools', label: `Tools (${data?.counts.files ?? '…'})` },
    { id: 'categories', label: `Categories (${data?.counts.categories ?? '…'})` },
    { id: 'activity', label: 'Activity' },
    { id: 'about', label: 'About' },
  ];

  return (
    <DataPageLayout
      backTo="/threatintel"
      icon={<Skull size={28} />}
      title="MMD Toolkit"
      description={
        <>
          Shared codes &amp; tools collection of the{' '}
          <a
            href="https://en.wikipedia.org/wiki/MalwareMustDie"
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            MalwareMustDie
          </a>{' '}
          non-profit malware awareness team (est. 2012), auto-synced weekly from{' '}
          <a
            href="https://github.com/unixfreaxjp/malwaremustdie"
            target="_blank"
            rel="noreferrer"
            className="underline decoration-dotted"
          >
            unixfreaxjp/malwaremustdie
          </a>
          . {data?.counts.files ?? '…'} malware-analysis files across {data?.counts.categories ?? '…'} language
          categories
          {data?.counts.commitsTracked ? ` · ${data.counts.commitsTracked} upstream commits tracked` : ''}.
        </>
      }
      onRetry={refetch}
      loading={loading}
      error={error}
      maxWidthClass="max-w-5xl"
    >
      <div className="flex flex-wrap gap-2 mb-5">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-1.5 rounded-full text-sm font-medium border transition-colors ${
              tab === t.id
                ? 'bg-brand-600 text-white border-brand-600'
                : 'text-muted border-line-1 hover:border-brand-400'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <DetectionAiBriefing
        surface="MMD Toolkit"
        source="mmd"
        items={briefingItems}
        dayKey={data?.builtAt?.slice(0, 10)}
        label="files"
      />

      {tab === 'tools' && (
        <div className="flex flex-col sm:flex-row gap-2 mb-4">
          <select value={category} onChange={(e) => setCategory(e.target.value)} className={`${inputCls} sm:w-44`}>
            <option value="">All categories</option>
            {(data?.categories ?? []).map((c) => (
              <option key={c.category} value={c.category}>
                {c.category} ({c.count})
              </option>
            ))}
          </select>
          <select value={kind} onChange={(e) => setKind(e.target.value)} className={`${inputCls} sm:w-40`}>
            <option value="">All kinds</option>
            {kindOptions.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search file paths…"
              className={`${inputCls} pl-9`}
            />
          </div>
        </div>
      )}

      {tab === 'categories' && (
        <div className="flex flex-col sm:flex-row gap-2 mb-4">
          <div className="relative flex-1">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search categories…"
              className={`${inputCls} pl-9`}
            />
          </div>
        </div>
      )}

      {tab === 'tools' && (
        <div className="grid gap-2">
          {files.map((f) => (
            <div key={f.path} className="surface-card p-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span
                  className={`text-[11px] font-bold px-2 py-0.5 rounded border ${
                    KIND_STYLES[f.kind] ?? KIND_STYLES.doc
                  }`}
                >
                  {f.kind}
                </span>
                <span className="font-mono text-sm text-heading break-all">{f.path}</span>
                <a
                  href={`https://github.com/unixfreaxjp/malwaremustdie/blob/master/${f.path}`}
                  target="_blank"
                  rel="noreferrer"
                  className="ml-auto text-muted hover:text-brand-500"
                  title="Open upstream file"
                >
                  <ExternalLink size={13} />
                </a>
              </div>
              <p className="text-xs text-muted mt-1">
                {f.category} · .{f.ext} · {fmtSize(f.size)}
              </p>
            </div>
          ))}
          {files.length === 0 && !loading && <p className="text-sm text-muted">No files match.</p>}
        </div>
      )}

      {tab === 'categories' && (
        <div className="grid gap-2">
          {(data?.categories ?? [])
            .filter((c) => !q.trim() || `${c.category} ${c.description}`.toLowerCase().includes(q.trim().toLowerCase()))
            .map((c) => (
              <button
                key={c.category}
                onClick={() => openCategory(c.category)}
                className="surface-card text-left p-3 hover:border-brand-400 transition-colors"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <FolderTree size={14} className="text-brand-500" />
                  <span className="font-semibold text-heading">{c.category}</span>
                  <span className="text-xs text-muted ml-auto">
                    {c.count} files · {fmtSize(c.totalSize)}
                  </span>
                </div>
                <p className="text-sm text-body mt-1">{c.description}</p>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {Object.entries(c.kinds)
                    .sort((a, b) => b[1] - a[1])
                    .map(([k, n]) => (
                      <span
                        key={k}
                        className="text-[11px] px-2 py-0.5 rounded border text-muted bg-surface-100 border-line-1"
                      >
                        {k} ×{n}
                      </span>
                    ))}
                </div>
              </button>
            ))}
        </div>
      )}

      {tab === 'activity' && (
        <div className="grid gap-2">
          <div className="surface-card p-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
            <span className="text-muted">
              Last upstream commit: {fmtDate(data?.lastCommit ?? null)} · weekly sync rebuilds automatically.
            </span>
            <a
              href="https://github.com/unixfreaxjp/malwaremustdie/commits/master"
              target="_blank"
              rel="noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              Commit history <ExternalLink size={11} />
            </a>
            <a
              href="https://unixfreaxjp.github.io/malwaremustdie/"
              target="_blank"
              rel="noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              MMD web page (GitHub Pages) <ExternalLink size={11} />
            </a>
            <a
              href="https://blog.malwaremustdie.org"
              target="_blank"
              rel="noreferrer"
              className="text-brand-600 dark:text-brand-400 hover:underline inline-flex items-center gap-1"
            >
              MMD blog <ExternalLink size={11} />
            </a>
          </div>
          {(data?.recentCommits ?? []).map((c) => (
            <a
              key={c.sha}
              href={`https://github.com/unixfreaxjp/malwaremustdie/commit/${c.sha}`}
              target="_blank"
              rel="noreferrer"
              className="surface-card p-3 hover:border-brand-400 transition-colors"
            >
              <div className="flex items-center gap-2 flex-wrap">
                <GitCommitHorizontal size={14} className="text-brand-500" />
                <span className="font-mono text-xs text-heading">{c.sha}</span>
                <span className="text-xs text-muted">{fmtDate(c.date)}</span>
                <span className="text-xs text-muted ml-auto">{c.author}</span>
              </div>
              <p className="text-sm text-body mt-1">{c.message}</p>
            </a>
          ))}
        </div>
      )}

      {tab === 'about' && (
        <div className="surface-card p-4 prose-sm max-w-none text-body [&_h2]:text-base [&_h2]:font-semibold [&_h2]:mt-4 [&_h2]:text-heading [&_h3]:text-sm [&_h3]:font-semibold [&_h3]:text-heading [&_a]:text-brand-600 dark:[&_a]:text-brand-400 [&_a]:underline [&_code]:text-xs [&_blockquote]:border-l-2 [&_blockquote]:border-line-1 [&_blockquote]:pl-3 [&_blockquote]:text-muted [&_hr]:my-4 [&_p]:my-2 [&_ul]:list-disc [&_ul]:pl-5 [&_li]:my-1">
          {readmeData?.body ? (
            renderMarkdown(readmeData.body)
          ) : (
            <p className="text-sm text-muted">
              {data?.about}{' '}
              <a
                href={data?.siteUrl ?? 'https://unixfreaxjp.github.io/malwaremustdie/'}
                target="_blank"
                rel="noreferrer"
                className="underline decoration-dotted"
              >
                Upstream site
              </a>
            </p>
          )}
          <div className="mt-4 flex items-center gap-2 text-xs text-muted border-t border-line-1 pt-3">
            <Bug size={13} />
            <span>
              License: public share — upstream disclaimer applies. Use the tools for defensive purposes only, per the
              MMD team's sharing rules.
            </span>
          </div>
        </div>
      )}

      <Modal
        open={catLoading || catBody !== null}
        onClose={() => setCatBody(null)}
        title={catBody?.category ?? 'Loading…'}
        size="lg"
      >
        {catLoading && (
          <div className="flex items-center gap-2 py-8 justify-center text-muted">
            <Loader2 size={18} className="animate-spin" /> Loading category…
          </div>
        )}
        {catBody && (
          <div className="space-y-3">
            <p className="text-sm text-body">{catBody.description}</p>
            <p className="text-xs text-muted">
              {catBody.count} files · {fmtSize(catBody.totalSize)} ·{' '}
              <a
                href={`https://github.com/unixfreaxjp/malwaremustdie/tree/master/${catBody.category}`}
                target="_blank"
                rel="noreferrer"
                className="underline decoration-dotted"
              >
                upstream directory <ExternalLink size={10} className="inline" />
              </a>
            </p>
            <div className="grid gap-1.5 max-h-[60vh] overflow-y-auto">
              {catBody.files.map((f) => (
                <div
                  key={f.path}
                  className="flex items-center gap-2 text-sm border-b border-line-1 pb-1.5 last:border-0"
                >
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded border ${KIND_STYLES[f.kind] ?? KIND_STYLES.doc}`}
                  >
                    {f.kind}
                  </span>
                  <span className="font-mono text-xs text-heading truncate">{f.path}</span>
                  <span className="text-[11px] text-muted ml-auto shrink-0">{fmtSize(f.size)}</span>
                  <a
                    href={`https://github.com/unixfreaxjp/malwaremustdie/blob/master/${f.path}`}
                    target="_blank"
                    rel="noreferrer"
                    className="text-muted hover:text-brand-500 shrink-0"
                  >
                    <ExternalLink size={12} />
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </DataPageLayout>
  );
}
