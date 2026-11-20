import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft, Check, ExternalLink, Rss, Search, ShieldAlert, Sparkles, X } from 'lucide-react';
import { DataPageLayout } from '../../components/DataPageLayout';
import { useDataFetch } from '../../hooks/useDataFetch';
import { relativeAgo } from '../../lib/relativeTime';
import { sanitizeUrl } from '../../lib/sanitize-url';

/**
 * Replication of https://tldrcve.com (server-rendered static site, robots
 * allows all paths), mirrored by scripts/sync-tldrcve.mjs. The upstream tool
 * asks three questions per CVE: how scary is it, are you affected, what to do.
 * This view mirrors the homepage feed, the full CVE list with its scare
 * ranking, the safe-versions table and each CVE detail page.
 */

interface Urgency {
  level: string;
  label: string;
}

interface TldrItem {
  guid: string;
  name: string;
  title: string;
  url: string;
  published: string | null;
  isNew: boolean;
  cves: string[];
  verdict: string | null;
  urgency: Urgency;
  description: string;
}

interface TldrFeed {
  generatedAt: string;
  upstream: { feed: string; site: string; scale: string };
  scale: Array<{ level: string; label: string; meaning: string }>;
  stats: { items: number; cves: number; byUrgency: Record<string, number> };
  items: TldrItem[];
}

interface Fold {
  num: string;
  title: string;
  hint: string | null;
  body: string;
  code: string[];
}
interface CveDetail {
  slug: string;
  kicker: string;
  name: string;
  verdict: string;
  verdictHint: string;
  summary: string;
  meterLabel: string;
  meterHint: string;
  checklist: Array<{ yes: boolean; text: string }>;
  affected: Fold[];
  actions: Fold[];
  sources: Array<{ url: string; title: string; date: string | null }>;
  changes: Array<{ date: string; text: string }>;
  url: string;
}
interface CveRow {
  slug: string;
  name: string;
  meta: string;
  line: string;
  verdict: string;
  scareLevel: number | null;
  meterLabel: string;
  disclosed: string | null;
  url: string;
  detail: CveDetail | null;
}
interface VersionCard {
  slug: string;
  name: string;
  meta: string;
  nofix: boolean;
  chips: Array<{ line: string; version: string }>;
  url: string;
}
interface TldrIndex {
  generatedAt: string;
  upstream: { site: string; list: string; versions: string; feed: string; scale: string };
  stats: { cves: number; details: number; versions: number; byVerdict: Record<string, number> };
  scale: Array<{ level: number; label: string; meaning: string }>;
  cves: CveRow[];
  versions: VersionCard[];
}

const TONE: Record<string, string> = {
  'drop-everything': 'border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300',
  'check-today': 'border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300',
  'keep-an-eye': 'border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300',
  shrug: 'border-line-2 text-muted',
};
const FILTER_LEVEL: Record<string, number> = { 'drop-everything': 4, 'check-today': 3, 'keep-an-eye': 2, shrug: 1 };
const VERDICT_LEVEL: Record<string, string> = {
  'Patch now': 'drop-everything',
  'Patch now if…': 'check-today',
  'Next cycle': 'keep-an-eye',
};

type View = 'latest' | 'all' | 'versions' | 'detail';
const VIEWS: Array<{ id: View; label: string }> = [
  { id: 'latest', label: 'Latest updates' },
  { id: 'all', label: 'All CVEs' },
  { id: 'versions', label: 'Safe versions' },
];

export default function Tldrcve({ bare = false }: { bare?: boolean }): JSX.Element {
  const feed = useDataFetch<TldrFeed>({ url: '/data/cve-intel/tldrcve.json', ttl: 600_000 });
  const index = useDataFetch<TldrIndex>({ url: '/data/tldrcve/index.json', ttl: 600_000 });
  const [view, setView] = useState<View>('latest');
  const [filter, setFilter] = useState<'all' | string>('all');
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState<'scare' | 'recent'>('scare');
  const [nofix, setNofix] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const out = (index.data?.cves ?? []).filter((c) => {
      if (filter !== 'all' && VERDICT_LEVEL[c.verdict] !== filter) return false;
      if (!needle) return true;
      return `${c.name} ${c.meta} ${c.line}`.toLowerCase().includes(needle);
    });
    return out.sort((a, b) =>
      sort === 'scare'
        ? (b.scareLevel ?? 0) - (a.scareLevel ?? 0)
        : String(b.disclosed ?? '').localeCompare(String(a.disclosed ?? ''))
    );
  }, [index.data, filter, query, sort]);

  const versions = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (index.data?.versions ?? []).filter(
      (v) =>
        (!nofix || v.nofix) &&
        (!needle || `${v.name} ${v.meta} ${v.chips.map((c) => c.version).join(' ')}`.toLowerCase().includes(needle))
    );
  }, [index.data, nofix, query]);

  const detail = selected ? (index.data?.cves.find((c) => c.slug === selected)?.detail ?? null) : null;

  const searchBox = (
    <div className="relative w-full sm:w-64">
      <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" aria-hidden="true" />
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Filter by CVE, product or nickname"
        aria-label="Filter tldrcve entries"
        className="w-full rounded-control border border-line-input bg-input-200 py-1.5 pl-8 pr-2 font-mono text-xs text-heading placeholder:text-muted"
      />
    </div>
  );

  const subnav = (
    <nav className="mb-4 flex flex-wrap gap-1 border-b border-line-1" aria-label="tldrcve sections">
      {VIEWS.map((v) => (
        <button
          key={v.id}
          type="button"
          aria-pressed={view === v.id}
          onClick={() => {
            setView(v.id);
            setSelected(null);
          }}
          className={`border-b-2 px-3 py-2 font-mono text-xs font-semibold transition-colors ${
            view === v.id
              ? 'border-rose-500 text-rose-600 dark:text-rose-400'
              : 'border-transparent text-muted hover:text-heading'
          }`}
        >
          {v.label}
          {v.id === 'all' && index.data ? ` (${index.data.stats.cves})` : ''}
          {v.id === 'versions' && index.data ? ` (${index.data.stats.versions})` : ''}
        </button>
      ))}
      {selected && (
        <button
          type="button"
          onClick={() => {
            setSelected(null);
            setView('all');
          }}
          className="ml-auto inline-flex items-center gap-1 py-2 font-mono text-xs text-accent-text hover:underline"
        >
          <ArrowLeft size={12} /> Back to all CVEs
        </button>
      )}
    </nav>
  );

  let content = null;
  if (view === 'latest') {
    const data = feed.data;
    content = data ? (
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-1">
            {(['all', 'drop-everything', 'check-today', 'keep-an-eye', 'shrug'] as const).map((f) => (
              <button
                key={f}
                type="button"
                aria-pressed={filter === f}
                onClick={() => setFilter(f)}
                className={`rounded-control border px-2.5 py-1 font-mono text-[11px] ${filter === f ? 'border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400' : 'border-line-1 text-muted hover:text-heading'}`}
              >
                {f === 'all' ? 'All' : data.scale.find((s) => s.level === f)?.label}
              </button>
            ))}
          </div>
          {searchBox}
        </div>
        <div className="surface-card flex flex-wrap gap-x-5 gap-y-2 rounded-xl border border-line-1 px-4 py-3">
          {data.scale.map((s) => (
            <div key={s.level} className="flex items-center gap-1.5 text-[11px]" title={s.meaning}>
              <span className={`rounded border px-1.5 py-0.5 font-mono ${TONE[s.level] ?? ''}`}>{s.label}</span>
              <span className="text-muted">{s.meaning}</span>
            </div>
          ))}
        </div>
        <ol className="space-y-2">
          {data.items
            .filter((i) => filter === 'all' || i.urgency.level === filter)
            .filter(
              (i) =>
                !query || `${i.name} ${i.cves.join(' ')} ${i.description}`.toLowerCase().includes(query.toLowerCase())
            )
            .map((item) => (
              <li key={item.guid} className="surface-card rounded-xl border border-line-1 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`rounded border px-2 py-0.5 font-mono text-[10px] font-bold uppercase ${TONE[item.urgency.level] ?? ''}`}
                  >
                    {item.urgency.label}
                  </span>
                  {item.isNew && (
                    <span className="rounded border border-sky-500/40 px-1.5 py-0.5 font-mono text-[10px] text-sky-600 dark:text-sky-400">
                      new
                    </span>
                  )}
                  <a
                    href={sanitizeUrl(item.url) ?? '#'}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-sm font-semibold text-heading hover:text-accent-text"
                  >
                    {item.name} <ExternalLink size={11} />
                  </a>
                  <span className="ml-auto font-mono text-[10px] text-muted">
                    {item.published ? relativeAgo(item.published) : ''}
                  </span>
                </div>
                <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-muted">
                  {item.description.replace(/Verdict:.*$/, '').trim()}
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {item.cves.map((cve) => (
                    <Link
                      key={cve}
                      to={`/dfir/cve?cve=${encodeURIComponent(cve)}`}
                      className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-[10px] text-accent-text hover:border-brand-400"
                    >
                      {cve}
                    </Link>
                  ))}
                </div>
              </li>
            ))}
        </ol>
        <div className="flex flex-wrap items-center gap-4 border-t border-line-1 pt-3 text-[11px] text-muted">
          <a
            href={data.upstream.feed}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-accent-text hover:underline"
          >
            <Rss size={10} /> RSS feed
          </a>
          <span className="ml-auto">synced {relativeAgo(data.generatedAt)}</span>
        </div>
      </div>
    ) : null;
  } else if (view === 'all') {
    const data = index.data;
    content = data ? (
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-1">
            {(['all', 'drop-everything', 'check-today', 'keep-an-eye'] as const).map((f) => (
              <button
                key={f}
                type="button"
                aria-pressed={filter === f}
                onClick={() => setFilter(f)}
                className={`rounded-control border px-2.5 py-1 font-mono text-[11px] ${filter === f ? 'border-rose-500/40 bg-rose-500/10 text-rose-600 dark:text-rose-400' : 'border-line-1 text-muted hover:text-heading'}`}
              >
                {f === 'all' ? 'All verdicts' : (data.scale.find((s) => s.level === FILTER_LEVEL[f])?.label ?? f)}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as typeof sort)}
              aria-label="Sort CVEs"
              className="rounded-control border border-line-input bg-input-200 px-2 py-1.5 font-mono text-xs text-heading"
            >
              <option value="scare">Most important</option>
              <option value="recent">Most recent</option>
            </select>
            {searchBox}
          </div>
        </div>
        <div className="surface-card overflow-hidden rounded-xl border border-line-1">
          <div className="hidden grid-cols-[90px_1fr_1.4fr_130px_90px] gap-3 border-b border-line-1 px-4 py-2 font-mono text-[10px] uppercase tracking-wide text-muted sm:grid">
            <span>Scare</span>
            <span>Vulnerability</span>
            <span>In short</span>
            <span>Verdict</span>
            <span>Released</span>
          </div>
          {rows.map((c) => (
            <button
              key={c.slug}
              type="button"
              onClick={() => {
                setSelected(c.slug);
                setView('detail');
              }}
              className="grid w-full gap-1 border-b border-line-1 px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-surface-200 sm:grid-cols-[90px_1fr_1.4fr_130px_90px] sm:items-center sm:gap-3"
            >
              <span
                className={`justify-self-start rounded border px-1.5 py-0.5 font-mono text-[10px] ${TONE[VERDICT_LEVEL[c.verdict] ?? 'shrug'] ?? ''}`}
              >
                {c.meterLabel}
              </span>
              <span className="min-w-0">
                <span className="block truncate text-sm font-semibold text-heading">{c.name}</span>
                <span className="block truncate font-mono text-[10px] text-muted">{c.meta}</span>
              </span>
              <span className="line-clamp-2 text-xs text-muted">{c.line}</span>
              <span className="font-mono text-[11px] text-body">{c.verdict}</span>
              <span className="font-mono text-[10px] text-muted">{c.disclosed?.slice(0, 10) ?? ''}</span>
            </button>
          ))}
          {rows.length === 0 && <p className="px-4 py-10 text-center text-xs text-muted">No CVEs match this filter.</p>}
        </div>
        <p className="text-[11px] text-muted">
          synced {relativeAgo(data.generatedAt)} · {data.stats.cves} vulnerabilities from {data.upstream.site}
        </p>
      </div>
    ) : null;
  } else if (view === 'versions') {
    content = index.data ? (
      <div className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="inline-flex items-center gap-2 font-mono text-xs text-muted">
            <input type="checkbox" checked={nofix} onChange={(e) => setNofix(e.target.checked)} /> No fix yet
          </label>
          {searchBox}
        </div>
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {versions.map((v) => (
            <li key={v.slug} className="surface-card rounded-xl border border-line-1 p-3">
              <a
                href={sanitizeUrl(v.url) ?? '#'}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between gap-2 text-sm font-semibold text-heading hover:text-accent-text"
              >
                {v.name} <ExternalLink size={11} />
              </a>
              <p className="mt-0.5 font-mono text-[10px] text-muted">{v.meta}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {v.chips.map((chip) => (
                  <span
                    key={`${chip.line}-${chip.version}`}
                    className="rounded border border-line-1 px-1.5 py-0.5 font-mono text-[10px] text-body"
                    title={chip.line}
                  >
                    <span className="text-muted">{chip.line}:</span> {chip.version}
                  </span>
                ))}
                {v.nofix && (
                  <span className="rounded border border-rose-500/40 px-1.5 py-0.5 font-mono text-[10px] text-rose-600 dark:text-rose-400">
                    no fix yet
                  </span>
                )}
              </div>
            </li>
          ))}
        </ul>
      </div>
    ) : null;
  } else if (detail) {
    content = (
      <article className="space-y-4">
        <header className="surface-card rounded-xl border border-line-1 p-5">
          <p className="font-mono text-[11px] uppercase tracking-wide text-muted">{detail.kicker}</p>
          <h2 className="mt-1 text-2xl font-bold text-heading">{detail.name}</h2>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span
              className={`rounded border px-2 py-0.5 font-mono text-xs font-bold ${TONE[VERDICT_LEVEL[detail.verdict] ?? 'shrug'] ?? ''}`}
            >
              {detail.verdict}
            </span>
            <span className="text-xs text-muted">{detail.verdictHint}</span>
          </div>
          <p className="mt-3 text-sm leading-relaxed text-body">{detail.summary}</p>
          <a
            href={sanitizeUrl(detail.url) ?? '#'}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-flex items-center gap-1 font-mono text-xs text-accent-text hover:underline"
          >
            View upstream page <ExternalLink size={11} />
          </a>
        </header>

        <section className="surface-card rounded-xl border border-line-1 p-5">
          <h3 className="text-sm font-bold text-heading">How scary is it?</h3>
          <ul className="mt-3 grid gap-1.5 sm:grid-cols-2">
            {detail.checklist.map((c, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-body">
                <span
                  className={`mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded border ${c.yes ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'border-line-1 text-muted'}`}
                >
                  {c.yes ? <Check size={11} /> : <X size={11} />}
                </span>
                {c.text}
              </li>
            ))}
          </ul>
          {detail.meterLabel && (
            <p className="mt-3 rounded-lg border border-line-1 bg-surface-100 px-3 py-2 font-mono text-xs text-body">
              Scare-o-meter: <strong>{detail.meterLabel}</strong> · {detail.meterHint}
            </p>
          )}
        </section>

        {(['affected', 'actions'] as const).map(
          (key) =>
            detail[key].length > 0 && (
              <section key={key} className="surface-card rounded-xl border border-line-1 p-5">
                <h3 className="text-sm font-bold text-heading">
                  {key === 'affected' ? 'Are you affected?' : 'What to do'}
                </h3>
                <ol className="mt-3 space-y-3">
                  {detail[key].map((f, i) => (
                    <li key={i} className="rounded-lg border border-line-1 p-3">
                      <div className="flex items-center gap-2">
                        <span className="grid h-5 w-5 place-items-center rounded bg-surface-200 font-mono text-[10px] text-muted">
                          {f.num}
                        </span>
                        <span className="text-sm font-semibold text-heading">{f.title}</span>
                        {f.hint && <span className="ml-auto font-mono text-[10px] text-muted">{f.hint}</span>}
                      </div>
                      <p className="mt-2 text-xs leading-relaxed text-muted">{f.body}</p>
                      {f.code.map((code, j) => (
                        <pre
                          key={j}
                          className="mt-2 overflow-x-auto rounded bg-surface-200 p-2 font-mono text-[11px] text-body"
                        >
                          <code>{code}</code>
                        </pre>
                      ))}
                    </li>
                  ))}
                </ol>
              </section>
            )
        )}

        {detail.sources.length > 0 && (
          <details className="surface-card rounded-xl border border-line-1 p-4" open>
            <summary className="cursor-pointer text-sm font-bold text-heading">
              Sources ({detail.sources.length}) and changelog
            </summary>
            <ol className="mt-3 space-y-1.5">
              {detail.sources.map((s, i) => (
                <li key={i} className="text-xs">
                  <a
                    href={sanitizeUrl(s.url) ?? '#'}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-accent-text hover:underline"
                  >
                    {s.title} <ExternalLink size={10} />
                  </a>
                  {s.date && <span className="ml-2 font-mono text-[10px] text-muted">{s.date}</span>}
                </li>
              ))}
            </ol>
            {detail.changes.length > 0 && (
              <ul className="mt-3 border-t border-line-1 pt-2 font-mono text-[10px] text-muted">
                {detail.changes.map((c, i) => (
                  <li key={i}>
                    {c.date} · {c.text}
                  </li>
                ))}
              </ul>
            )}
          </details>
        )}
        <p className="flex items-center gap-1 text-[11px] text-muted">
          <ShieldAlert size={12} /> This page shows how to check. It cannot tell you you are safe.
        </p>
      </article>
    );
  } else if (selected) {
    content = <p className="font-mono text-xs text-muted">Detail not available for this entry.</p>;
  }

  const body = (
    <>
      {(feed.loading || index.loading) && !feed.data && !index.data && (
        <p className="font-mono text-xs text-muted">Loading tldrcve data…</p>
      )}
      {(feed.error || index.error) && (
        <p className="font-mono text-xs text-rose-500">error: {feed.error ?? index.error}</p>
      )}
      {(feed.data || index.data) && subnav}
      {content}
    </>
  );

  return bare ? (
    body
  ) : (
    <DataPageLayout
      backTo="/threatintel/cves/cves"
      icon={<Sparkles size={28} />}
      title="tl;drCVE — Plain English"
      description="Replication of tldrcve.com: plain-English CVE write-ups, scare-o-meter verdicts, affected checks, patch steps and safe versions."
      onRetry={() => {
        feed.refetch();
        index.refetch();
      }}
      loading={feed.loading || index.loading}
      error={feed.error ?? index.error}
      maxWidthClass="max-w-6xl"
    >
      {body}
    </DataPageLayout>
  );
}
